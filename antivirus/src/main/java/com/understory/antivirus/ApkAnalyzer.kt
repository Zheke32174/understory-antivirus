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
 *   - [analyzeUri]: user picks an APK file via SAF; we copy it to cache
 *     (hashing as we go), hand a read-only fd to the isolated ApkParserService
 *     for the actual parsing (ZIP / manifest / cert extraction — the CVE-prone
 *     part), then interpret the returned facts against KnownBad + RiskRules
 *     here. Cache file is deleted after. A parser crash on a malformed APK is
 *     contained to the isolated process and reported as a SUSPICIOUS result; a
 *     timeout is reported as UNKNOWN, not suspicious.
 *   - [analyzeInstalled] / [auditInstalled]: walk PackageManager-visible
 *     installed apps and run the same analysis on each. Installed apps stay on
 *     the PackageManager path — the system already parsed them at install time,
 *     so there are no untrusted bytes to isolate — and we additionally read
 *     their declared components (accessibility / device-admin / notif-listener)
 *     and cross-reference the device-wide currently-enabled abuser set.
 *
 * What we DON'T do (rootless limits): real-time process monitoring, memory
 * scanning, or behavioral analysis — all need root or accessibility, which the
 * suite refuses. This is a bounded static + posture auditor, on purpose.
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
        /** null = the APK was not hashed (no APK-hash definitions loaded). */
        val apkSha256: String?,
        val certSha256: String?,
        val findings: List<RiskRules.Finding>,
        val notes: List<String>,
    )

    /**
     * Analyze a SAF-picked APK. Caller already has read permission for the
     * URI; we copy it to cache because the isolated parser needs a seekable fd
     * and SAF streams from cloud providers are often pipes. SHA-256 is computed
     * during the copy (trusted fixed-function code). The cache file is deleted
     * in a finally block so we don't leak APK bytes on disk.
     *
     * Must be called off the main thread.
     */
    fun analyzeUri(ctx: Context, uri: Uri): Report {
        BlocklistStore.ensureLoaded(ctx)
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
            // Single-file SAF scan always hashes — the hash is shown to the
            // user as evidence, and it's one file, not a whole-device pass.
            val apkSha = md.digest().joinToString("") { "%02x".format(it) }
            return reportFromIsolatedParse(ApkParserClient.parse(ctx, cache), apkSha)
        } finally {
            runCatching { cache.delete() }
        }
    }

    /**
     * Analyze a single installed app by package name.
     */
    fun analyzeInstalled(ctx: Context, packageName: String, enabled: EnabledAbusers.Snapshot): Report? {
        val pm = ctx.packageManager
        val info = try {
            pm.getPackageInfo(
                packageName,
                PackageManager.GET_PERMISSIONS or
                    PackageManager.GET_SIGNING_CERTIFICATES or
                    PackageManager.GET_SERVICES or
                    PackageManager.GET_RECEIVERS,
            )
        } catch (_: PackageManager.NameNotFoundException) {
            return null
        }
        val applicationInfo = info.applicationInfo
        val apkPath = applicationInfo?.sourceDir ?: return null
        val apkFile = File(apkPath)
        return analyzeFromPackageInfo(ctx, info, apkFile, enabled)
    }

    /**
     * Walk every PackageManager-visible installed app and return reports for
     * those with at least one finding (or a KNOWN_BAD verdict). Results are
     * sorted most-severe-first (KNOWN_BAD pinned top).
     *
     * @param onProgress invoked per package scanned (done, total) so the UI can
     *   render a determinate progress bar. Runs on the calling thread.
     */
    fun auditInstalled(ctx: Context, onProgress: (done: Int, total: Int) -> Unit = { _, _ -> }): List<Report> {
        BlocklistStore.ensureLoaded(ctx)
        val enabled = EnabledAbusers.snapshot(ctx)
        val pm = ctx.packageManager
        val all = pm.getInstalledApplications(0)
        val candidates = all.filter { app ->
            // Skip system apps the user can't uninstall — they pollute the list
            // with permissions the user can't act on. Still include
            // user-installed-OEM-bundled apps (FLAG_UPDATED_SYSTEM_APP).
            val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val isUpdatedSystem = (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            !isSystem || isUpdatedSystem
        }
        val total = candidates.size
        val reports = mutableListOf<Report>()
        candidates.forEachIndexed { i, app ->
            val report = analyzeInstalled(ctx, app.packageName, enabled)
            if (report != null && (report.findings.isNotEmpty() || report.verdict == Verdict.KNOWN_BAD)) {
                reports += report
            }
            onProgress(i + 1, total)
        }
        return rankReports(reports)
    }

    /**
     * Rank reports for the audit list: KNOWN_BAD pinned top, then most-severe
     * first (findings are already CRITICAL-first, so the first finding is the
     * most severe). Alphabetical within a tier. Extracted as a pure helper so
     * the ordering is unit-testable (locks D#1 in the list path).
     */
    fun rankReports(reports: List<Report>): List<Report> =
        reports.sortedWith(
            compareBy<Report> {
                if (it.verdict == Verdict.KNOWN_BAD) -1
                else it.findings.firstOrNull()?.severity?.ordinal ?: Int.MAX_VALUE
            }.thenBy { it.packageName },
        )

    /**
     * Turn the isolated parser's [ApkParserClient.Outcome] into a Report.
     *   - TimedOut → UNKNOWN (large file / busy device, NOT a maliciousness
     *     signal). A false SUSPICIOUS on a slow-but-clean file erodes trust.
     *   - Died → SUSPICIOUS (a parser that CRASHED on malformed input is the
     *     real signal — legitimate APKs don't crash parsers, crafted ones do).
     */
    private fun reportFromIsolatedParse(outcome: ApkParserClient.Outcome, apkSha: String): Report {
        when (outcome) {
            is ApkParserClient.Outcome.TimedOut -> return Report(
                verdict = Verdict.UNKNOWN,
                packageName = "(scan timed out)",
                versionName = null,
                versionCode = 0,
                apkSha256 = apkSha,
                certSha256 = null,
                findings = emptyList(),
                notes = listOf(
                    "The scan timed out — the file is large or the device is busy. " +
                        "This doesn't mean it's malicious. Try again.",
                ),
            )
            is ApkParserClient.Outcome.Died -> return Report(
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
            is ApkParserClient.Outcome.Ok -> Unit // fall through
        }
        val parsed = (outcome as ApkParserClient.Outcome.Ok).result

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
        val permSet = parsed.permissions.toSet()
        val findings = (
            RiskRules.analyze(permSet) +
                RiskRules.analyzeComponents(
                    parsed.servicePermissions,
                    parsed.receiverPermissions,
                    permSet,
                )
            ).sortedBy { it.severity.ordinal }
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
                notes += knownBadNote(apkSha, "APK hash")
                Verdict.KNOWN_BAD
            }
            parsed.certSha256s.any { KnownBad.isKnownBadCert(it) } -> {
                val hit = parsed.certSha256s.first { KnownBad.isKnownBadCert(it) }
                notes += knownBadNote(hit, "Signing cert")
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
     * Installed-app analysis. The data comes from PackageManager (parsed by the
     * system at install time), never from untrusted APK bytes.
     */
    private fun analyzeFromPackageInfo(
        ctx: Context,
        info: PackageInfo,
        apkFile: File,
        enabled: EnabledAbusers.Snapshot,
    ): Report {
        val perms = info.requestedPermissions?.toSet() ?: emptySet()
        val pkg = info.packageName

        // Declared-component abuse (a11y / device-admin / notif-listener) —
        // read off the components, the CORRECT input.
        val servicePerms = info.services?.mapNotNull { it.permission } ?: emptyList()
        val receiverPerms = info.receivers?.mapNotNull { it.permission } ?: emptyList()

        val findings = (
            RiskRules.analyze(perms) +
                RiskRules.analyzeComponents(servicePerms, receiverPerms, perms) +
                enabledAbuserFindings(pkg, enabled)
            ).toMutableList()

        // Hidden-launcher detection (stalkerware-style): user-installed apps
        // with no launcher entry are invisible from the app drawer.
        run {
            val applicationInfo = info.applicationInfo
            if (pkg != null && applicationInfo != null) {
                val isSystem = (applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                val isUpdatedSystem = (applicationInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                if (!isSystem || isUpdatedSystem) {
                    val hasLauncher = try {
                        ctx.packageManager.getLaunchIntentForPackage(pkg) != null
                    } catch (_: Throwable) {
                        true // fail-safe: don't flag if we can't determine
                    }
                    if (!hasLauncher) {
                        findings.add(
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

        findings.sortBy { it.severity.ordinal }

        // Cert digest is cheap (one already-parsed cert) — always computed.
        val certSha = signingCertSha256(info)
        // APK hash is only paid when APK-hash definitions can actually match.
        val apkSha = if (BlocklistStore.apkHashes().isNotEmpty()) sha256(apkFile) else null

        val notes = mutableListOf<String>()
        val verdict = when {
            apkSha != null && KnownBad.isKnownBadApk(apkSha) -> {
                notes += knownBadNote(apkSha, "APK hash")
                Verdict.KNOWN_BAD
            }
            certSha != null && KnownBad.isKnownBadCert(certSha) -> {
                notes += knownBadNote(certSha, "Signing cert")
                Verdict.KNOWN_BAD
            }
            findings.any { it.severity == RiskRules.Severity.CRITICAL } -> Verdict.SUSPICIOUS
            findings.any { it.severity == RiskRules.Severity.HIGH } -> Verdict.SUSPICIOUS
            else -> Verdict.CLEAN
        }
        @Suppress("DEPRECATION")
        val versionCode = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P)
            info.longVersionCode
        else info.versionCode.toLong()

        return Report(
            verdict = verdict,
            packageName = pkg ?: "(unknown)",
            versionName = info.versionName,
            versionCode = versionCode,
            apkSha256 = apkSha,
            certSha256 = certSha,
            findings = findings,
            notes = notes,
        )
    }

    /**
     * Currently-enabled abuser findings — the strongest signal (the app is
     * exercising the power right now). Each carries a "Fix in Settings" revoke
     * deep-link.
     */
    private fun enabledAbuserFindings(
        pkg: String?,
        enabled: EnabledAbusers.Snapshot,
    ): List<RiskRules.Finding> {
        if (pkg == null) return emptyList()
        val out = mutableListOf<RiskRules.Finding>()
        if (pkg in enabled.enabledAccessibility) {
            out += RiskRules.Finding(
                severity = RiskRules.Severity.CRITICAL,
                title = "Accessibility service is ENABLED right now",
                explain = "This app's accessibility service is currently enabled — it can " +
                    "read everything on your screen and act as you right now. If you didn't " +
                    "turn this on for a reason you recognize, revoke it.",
                deepLink = SettingsDeepLinks.Target.ACCESSIBILITY,
            )
        }
        if (pkg in enabled.activeDeviceAdmins) {
            out += RiskRules.Finding(
                severity = RiskRules.Severity.CRITICAL,
                title = "Active device administrator right now",
                explain = "This app is currently an active device administrator — it can " +
                    "lock or wipe the device and resist uninstall. Revoke it unless it's an " +
                    "MDM / work profile you recognize.",
                deepLink = SettingsDeepLinks.Target.DEVICE_ADMIN,
            )
        }
        if (pkg in enabled.enabledNotificationListeners) {
            out += RiskRules.Finding(
                severity = RiskRules.Severity.HIGH,
                title = "Reading all your notifications right now",
                explain = "This app currently has notification access — it can read the " +
                    "content of every notification, including one-time codes and message " +
                    "previews. Revoke it unless you recognize why it needs this.",
                deepLink = SettingsDeepLinks.Target.NOTIFICATION_LISTENER,
            )
        }
        return out
    }

    /** Legible KNOWN_BAD note, naming the matched definition label when known. */
    private fun knownBadNote(hash: String, kind: String): String {
        val label = KnownBad.labelFor(hash)
        return if (label != null) {
            "$kind matches the deny-list: $label."
        } else {
            "$kind matches the deny-list."
        }
    }

    /** SHA-256 of the APK bytes. Returns null on read failure. */
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
     * Tamper.kt / SuiteAttestation.kt approach — apkContentsSigners (not
     * signingCertificateHistory) so rotated-out certs don't satisfy a match.
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
