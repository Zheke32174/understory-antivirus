package com.understory.antivirus

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest

/**
 * Static analysis for APKs and installed apps.
 *
 * Two entry points:
 *   - [analyzeUri]: user picks an APK file via SAF; we copy it to
 *     cache (hashing as we go), hand a read-only fd to the isolated
 *     ApkParserService for the actual parsing (ZIP / manifest / cert
 *     extraction — the CVE-prone part), then interpret the returned
 *     facts against KnownBad + RiskRules here. Cache file is deleted
 *     after. A parser crash on a malformed APK is contained to the
 *     isolated process and reported as a SUSPICIOUS result.
 *   - [analyzeInstalled]: walk PackageManager-visible installed apps
 *     and run the same analysis on each, surfacing only those with
 *     CRITICAL or HIGH findings to keep the output focused. Installed
 *     apps stay on the PackageManager path — the system already parsed
 *     them at install time, so there are no untrusted bytes to isolate.
 *
 * What we DON'T do (rootless limits):
 *   - Real-time process monitoring (would need root or accessibility,
 *     refused).
 *   - Memory scanning of running apps (root-only).
 *   - Behavioral analysis (root-only).
 *
 * The MVP is a *static* scanner. That's intentionally bounded; phase 2
 * adds richer rule sets but doesn't escalate.
 */
object ApkAnalyzer {

    /** Hard cap on APK size we'll analyze. 200 MiB covers everything. */
    private const val MAX_APK_BYTES: Long = 200L * 1024 * 1024

    enum class Verdict { CLEAN, SUSPICIOUS, KNOWN_BAD, UNKNOWN }

    data class Report(
        val verdict: Verdict,
        val packageName: String,
        val versionName: String?,
        val versionCode: Long,
        val apkSha256: String,
        val certSha256: String?,
        val findings: List<RiskRules.Finding>,
        val notes: List<String>,
    ) {
        /** A short single-line summary for the UI list. */
        val summary: String
            get() {
                val sev = findings.firstOrNull()?.severity?.name ?: "no findings"
                return "$packageName — $verdict ($sev)"
            }
    }

    /**
     * Analyze a SAF-picked APK. Caller already has read permission for
     * the URI; we copy it to cache because the isolated parser needs a
     * seekable fd and SAF streams from cloud providers are often pipes.
     * SHA-256 is computed during the copy (trusted fixed-function code,
     * safe to run here). The cache file is deleted in a finally block
     * so we don't leak APK bytes on disk.
     *
     * Must be called off the main thread (it already is — the scan
     * screen runs it on Dispatchers.IO); ApkParserClient enforces that.
     */
    fun analyzeUri(ctx: Context, uri: Uri): Report {
        val cache = File(ctx.cacheDir, "av-scan-${System.nanoTime()}.apk")
        try {
            val md = MessageDigest.getInstance("SHA-256")
            ctx.contentResolver.openInputStream(uri).use { input ->
                requireNotNull(input) { "couldn't open APK input stream" }
                FileOutputStream(cache).use { output ->
                    val buf = ByteArray(8192)
                    var total = 0L
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        total += n
                        require(total <= MAX_APK_BYTES) {
                            "APK too large (>${MAX_APK_BYTES / (1024 * 1024)} MiB)"
                        }
                        md.update(buf, 0, n)
                        output.write(buf, 0, n)
                    }
                }
            }
            val apkSha = md.digest().joinToString("") { "%02x".format(it) }
            return reportFromIsolatedParse(ApkParserClient.parse(ctx, cache), apkSha)
        } finally {
            runCatching { cache.delete() }
        }
    }

    /**
     * Analyze a single installed app by package name.
     */
    fun analyzeInstalled(ctx: Context, packageName: String): Report? {
        val pm = ctx.packageManager
        val info = try {
            pm.getPackageInfo(
                packageName,
                PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES,
            )
        } catch (_: PackageManager.NameNotFoundException) {
            return null
        }
        val applicationInfo = info.applicationInfo
        val apkPath = applicationInfo?.sourceDir ?: return null
        val apkFile = File(apkPath)
        return analyzeFromPackageInfo(ctx, info, apkFile)
    }

    /**
     * Walk every PackageManager-visible installed app and return reports
     * for those with at least one finding. Results are sorted with the
     * most-severe at the top.
     */
    fun auditInstalled(ctx: Context): List<Report> {
        val pm = ctx.packageManager
        val all = pm.getInstalledApplications(0)
        val reports = mutableListOf<Report>()
        for (app in all) {
            // Skip system apps the user can't uninstall — they pollute
            // the list with permissions the user can't act on. Still
            // include user-installed-OEM-bundled apps (FLAG_UPDATED_SYSTEM_APP).
            val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val isUpdatedSystem = (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            if (isSystem && !isUpdatedSystem) continue

            val report = analyzeInstalled(ctx, app.packageName) ?: continue
            if (report.findings.isNotEmpty() || report.verdict == Verdict.KNOWN_BAD) {
                reports += report
            }
        }
        return reports.sortedWith(
            compareByDescending<Report> {
                if (it.verdict == Verdict.KNOWN_BAD) 100
                else it.findings.firstOrNull()?.severity?.ordinal ?: -1
            }.thenBy { it.packageName },
        )
    }

    /**
     * Turn the isolated parser's raw facts into a Report. null means
     * the parser process died (or never answered) — per the threat
     * model that's a *finding*: legitimate APKs don't crash parsers,
     * malformed-on-purpose ones do.
     */
    private fun reportFromIsolatedParse(parsed: ApkParseResult?, apkSha: String): Report {
        if (parsed == null) {
            return Report(
                verdict = Verdict.SUSPICIOUS,
                packageName = "(parser crashed)",
                versionName = null,
                versionCode = 0,
                apkSha256 = apkSha,
                certSha256 = null,
                findings = emptyList(),
                notes = listOf(
                    "The APK parser crashed on this file. Malformed-on-purpose APKs " +
                        "that break parsers are a known malware-delivery trick, so " +
                        "treat the file as suspicious. The crash was contained to a " +
                        "sandboxed process with no permissions; this app is fine.",
                ),
            )
        }
        if (ApkParseResult.FLAG_BAD_ZIP in parsed.flags ||
            ApkParseResult.FLAG_BAD_MANIFEST in parsed.flags
        ) {
            return Report(
                verdict = Verdict.UNKNOWN,
                packageName = "(unparseable)",
                versionName = null,
                versionCode = 0,
                apkSha256 = apkSha,
                certSha256 = parsed.certSha256s.firstOrNull(),
                findings = emptyList(),
                notes = listOf("Couldn't parse the APK; likely corrupt or malformed."),
            )
        }
        val findings = RiskRules.analyze(parsed.permissions.toSet())
        val notes = mutableListOf<String>()
        val dupManifest = ApkParseResult.FLAG_DUPLICATE_MANIFEST in parsed.flags
        if (dupManifest) {
            notes += "APK contains more than one AndroidManifest.xml entry — a " +
                "parser-confusion trick (different parsers see different manifests). " +
                "Legitimate build tools never produce this."
        }
        if (ApkParseResult.FLAG_NO_CERT in parsed.flags) {
            notes += "No signing certificate found; Android would refuse to install this APK."
        }
        val verdict = when {
            KnownBad.isKnownBadApk(apkSha) -> {
                notes += "APK hash matches the built-in deny-list."
                Verdict.KNOWN_BAD
            }
            parsed.certSha256s.any { KnownBad.isKnownBadCert(it) } -> {
                notes += "Signing cert matches the built-in deny-list."
                Verdict.KNOWN_BAD
            }
            dupManifest -> Verdict.SUSPICIOUS
            findings.any { it.severity == RiskRules.Severity.CRITICAL } -> Verdict.SUSPICIOUS
            findings.any { it.severity == RiskRules.Severity.HIGH } -> Verdict.SUSPICIOUS
            else -> Verdict.CLEAN
        }
        return Report(
            verdict = verdict,
            packageName = parsed.packageName ?: "(unknown)",
            versionName = parsed.versionName,
            versionCode = parsed.versionCode,
            apkSha256 = apkSha,
            certSha256 = parsed.certSha256s.firstOrNull(),
            findings = findings,
            notes = notes,
        )
    }

    /**
     * Installed-app analysis. Only reached from [analyzeInstalled] —
     * the data comes from PackageManager (parsed by the system at
     * install time), never from untrusted APK bytes; those go through
     * the isolated parser instead.
     */
    private fun analyzeFromPackageInfo(
        ctx: Context,
        info: PackageInfo,
        apkFile: File,
    ): Report {
        val apkSha = sha256(apkFile)
        val certSha = signingCertSha256(info)
        val perms = info.requestedPermissions?.toSet() ?: emptySet()
        val findings = RiskRules.analyze(perms).toMutableList()

        // Hidden-launcher detection (Trustd-style): user-installed apps with
        // no launcher entry are invisible from the app drawer. Some legitimate
        // cases (services, plugins, background utilities) but textbook
        // stalkerware property — hiding from the target.
        run {
            val pkg = info.packageName
            val applicationInfo = info.applicationInfo
            if (pkg != null && applicationInfo != null) {
                val isSystem = (applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                val isUpdatedSystem = (applicationInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                // System apps without launchers are normal (services /
                // background components). Only flag user-installed (or
                // updated-system, which the user actively interacts with).
                if (!isSystem || isUpdatedSystem) {
                    val hasLauncher = try {
                        ctx.packageManager.getLaunchIntentForPackage(pkg) != null
                    } catch (_: Throwable) {
                        true // fail-safe: don't flag if we can't determine
                    }
                    if (!hasLauncher) {
                        findings.add(
                            0,
                            RiskRules.Finding(
                                severity = RiskRules.Severity.HIGH,
                                title = "No launcher icon",
                                explain = "This app has no launcher entry, so it doesn't appear " +
                                    "in your app drawer. Some legitimate apps (services, " +
                                    "background utilities, plugins for other apps) intentionally " +
                                    "have no launcher. But hidden-from-launcher is also a " +
                                    "textbook stalkerware property — it makes the spying app " +
                                    "harder for the target to find or uninstall. If you don't " +
                                    "recognize this app, scrutinize it.",
                            ),
                        )
                    }
                }
            }
        }

        val notes = mutableListOf<String>()
        val verdict = when {
            apkSha != null && KnownBad.isKnownBadApk(apkSha) -> {
                notes += "APK hash matches the built-in deny-list."
                Verdict.KNOWN_BAD
            }
            certSha != null && KnownBad.isKnownBadCert(certSha) -> {
                notes += "Signing cert matches the built-in deny-list."
                Verdict.KNOWN_BAD
            }
            findings.any { it.severity == RiskRules.Severity.CRITICAL } -> Verdict.SUSPICIOUS
            findings.any { it.severity == RiskRules.Severity.HIGH } -> Verdict.SUSPICIOUS
            findings.isEmpty() -> Verdict.CLEAN
            else -> Verdict.CLEAN
        }
        @Suppress("DEPRECATION")
        val versionCode = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P)
            info.longVersionCode
        else info.versionCode.toLong()

        return Report(
            verdict = verdict,
            packageName = info.packageName ?: "(unknown)",
            versionName = info.versionName,
            versionCode = versionCode,
            apkSha256 = apkSha ?: "(unhashable)",
            certSha256 = certSha,
            findings = findings,
            notes = notes,
        )
    }

    /**
     * SHA-256 of the APK bytes. Returns null on read failure.
     */
    private fun sha256(file: File): String? = runCatching {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(8192)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        md.digest().joinToString("") { "%02x".format(it) }
    }.getOrNull()

    /**
     * SHA-256 of the first apkContentsSigners certificate. Matches the
     * Tamper.kt / SuiteAttestation.kt approach — we explicitly use
     * apkContentsSigners (not signingCertificateHistory) so rotated-out
     * certs don't satisfy a deny-list match.
     */
    private fun signingCertSha256(info: PackageInfo): String? {
        val signingInfo = info.signingInfo ?: return null
        val sigs = signingInfo.apkContentsSigners ?: return null
        val first = sigs.firstOrNull() ?: return null
        return runCatching {
            MessageDigest.getInstance("SHA-256").digest(first.toByteArray())
                .joinToString("") { "%02x".format(it) }
        }.getOrNull()
    }
}
