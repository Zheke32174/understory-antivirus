package com.understory.antivirus

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

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
        /**
         * Aggregate numeric risk + rating over [findings] (deny-list hits pin to
         * CRITICAL). Present on every real report; the crash/timeout/unparseable
         * sentinels carry an empty-finding [RiskRules.score] of LOW/0.
         */
        val risk: RiskRules.RiskScore = RiskRules.score(emptyList()),
        /**
         * Where the app was installed from, for the detail screen. null on the
         * SAF-scanned-APK path (a raw file has no install source) and on the
         * sentinel reports.
         */
        val installSource: InstallSource? = null,
        /** The app's declared permissions, for the grouped permission list. */
        val permissions: List<String> = emptyList(),
        /**
         * Precise inputs for the elevated CONTAINMENT controls (quarantine,
         * appops revoke, de-admin, wipe, disable-component). Present ONLY on the
         * installed-app path (a SAF-scanned raw APK isn't installed, so it stays
         * null and those controls never render). See [ContainmentFacts].
         */
        val containment: ContainmentFacts? = null,
    )

    /**
     * The recorded origin of an installed app: the installer package (e.g.
     * `com.android.vending`), a coarse [trust] classification, and a
     * human-readable [label] for the detail screen.
     */
    data class InstallSource(
        val installerPackage: String?,
        val trust: RiskRules.InstallerTrust,
        val label: String,
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
                    PackageManager.GET_RECEIVERS or
                    PackageManager.GET_ACTIVITIES or
                    PackageManager.GET_PROVIDERS,
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
    fun auditInstalled(ctx: Context, onProgress: (done: Int, total: Int) -> Unit = { _, _ -> }): List<Report> =
        auditInstalledWithSummary(ctx, onProgress).flagged

    /**
     * The outcome of a whole-device sweep: the ranked [flagged] reports plus a
     * [summary] the UI shows above the list ("N of M user apps flagged", with a
     * per-rating breakdown). [scanned] is every candidate audited (not just the
     * flagged ones), so "0 flagged of 128 scanned" reads honestly.
     */
    data class AuditResult(val flagged: List<Report>, val summary: AuditSummary)

    /**
     * Whole-sweep summary. [rulesFired] is the total finding count across every
     * flagged app; the per-rating map counts flagged apps by their aggregate
     * [RiskRules.Rating] so the header can say e.g. "2 Critical, 3 High".
     */
    data class AuditSummary(
        val scanned: Int,
        val flagged: Int,
        val knownBad: Int,
        val byRating: Map<RiskRules.Rating, Int>,
    )

    /**
     * Walk every PackageManager-visible user/updated-system app, audit each, and
     * return the ranked flagged reports plus a device-wide [AuditSummary]. Off
     * the main thread; [onProgress] drives the determinate bar.
     */
    fun auditInstalledWithSummary(
        ctx: Context,
        onProgress: (done: Int, total: Int) -> Unit = { _, _ -> },
    ): AuditResult {
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
        val ranked = rankReports(reports)
        val summary = AuditSummary(
            scanned = total,
            flagged = ranked.size,
            knownBad = ranked.count { it.verdict == Verdict.KNOWN_BAD },
            byRating = ranked.groupingBy { it.risk.rating }.eachCount(),
        )
        return AuditResult(ranked, summary)
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
        val facts = ApkFactsBuilder.fromParsed(parsed)
        val findings = facts.findings()
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
            risk = RiskRules.score(findings, knownBad = verdict == Verdict.KNOWN_BAD),
            installSource = null, // a SAF-scanned raw file has no install source
            permissions = parsed.permissions,
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
        val applicationInfo = info.applicationInfo

        // Declared-component abuse (a11y / device-admin / notif-listener) —
        // read off the components, the CORRECT input.
        val servicePerms = info.services?.mapNotNull { it.permission } ?: emptyList()
        val receiverPerms = info.receivers?.mapNotNull { it.permission } ?: emptyList()

        // Structural posture from the metadata the system already parsed at
        // install time (no untrusted bytes on this path). Install source and
        // signing posture come from PackageManager, which the SAF-scanned path
        // can't see.
        val installSource = installSourceOf(ctx, pkg)
        val exportedUnprotected = exportedUnprotectedCount(info)
        val structural = if (applicationInfo != null) {
            RiskRules.analyzeStructural(
                debuggable = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
                allowBackup = (applicationInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0,
                usesCleartextTraffic =
                    (applicationInfo.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0,
                testOnly = (applicationInfo.flags and ApplicationInfo.FLAG_TEST_ONLY) != 0,
                minSdk = applicationInfo.minSdkVersion,
                targetSdk = applicationInfo.targetSdkVersion,
                exportedUnprotectedComponents = exportedUnprotected,
                installer = installSource.trust,
                signing = signingPostureOf(info),
            )
        } else {
            emptyList()
        }

        val findings = (
            RiskRules.analyze(perms) +
                RiskRules.analyzeComponents(servicePerms, receiverPerms, perms) +
                structural +
                enabledAbuserFindings(pkg, enabled)
            ).toMutableList()

        // Hidden-launcher detection (stalkerware-style): user-installed apps
        // with no launcher entry are invisible from the app drawer.
        run {
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
            risk = RiskRules.score(findings, knownBad = verdict == Verdict.KNOWN_BAD),
            installSource = installSource,
            permissions = perms.toList().sorted(),
            containment = if (pkg != null) buildContainment(ctx, pkg, perms, enabled) else null,
        )
    }

    /**
     * Build the precise containment inputs for one installed app from the facts
     * we already have (declared permissions + the live abuser snapshot). Pure
     * assembly — no privileged calls here; the elevated ops run later, gated on
     * the user's granted tier. Protected packages ([ContainmentFacts.isProtected])
     * still get a facts object (so the UI can say "excluded"), but with an empty
     * control set.
     */
    private fun buildContainment(
        ctx: Context,
        pkg: String,
        perms: Set<String>,
        enabled: EnabledAbusers.Snapshot,
    ): ContainmentFacts {
        val protectedPkg = ContainmentFacts.isProtected(pkg, launcherPackage(ctx))

        val adminComponents = enabled.deviceAdminComponents[pkg].orEmpty()
            .map { it.flattenToString() }
        val disableTargets = buildList {
            enabled.accessibilityComponents[pkg].orEmpty().forEach {
                add(ContainmentFacts.DisableTarget(it.flattenToString(), ContainmentFacts.DisableTarget.Kind.ACCESSIBILITY))
            }
            enabled.notificationListenerComponents[pkg].orEmpty().forEach {
                add(
                    ContainmentFacts.DisableTarget(
                        it.flattenToString(),
                        ContainmentFacts.DisableTarget.Kind.NOTIFICATION_LISTENER,
                    ),
                )
            }
            enabled.deviceAdminComponents[pkg].orEmpty().forEach {
                add(ContainmentFacts.DisableTarget(it.flattenToString(), ContainmentFacts.DisableTarget.Kind.DEVICE_ADMIN))
            }
        }

        return ContainmentFacts(
            packageName = pkg,
            revocableDangerousPerms = if (protectedPkg) emptyList()
            else PermissionGroups.revocableDangerous(perms.toList()),
            hasOverlayPermission = !protectedPkg &&
                "android.permission.SYSTEM_ALERT_WINDOW" in perms,
            hasUsageStatsPermission = !protectedPkg &&
                "android.permission.PACKAGE_USAGE_STATS" in perms,
            activeDeviceAdminComponents = if (protectedPkg) emptyList() else adminComponents,
            disableTargets = if (protectedPkg) emptyList() else disableTargets,
            suiteSibling = protectedPkg,
        )
    }

    /**
     * The current default home/launcher package, resolved via the HOME intent.
     * Used only to exclude the launcher from every containment action (a bricked
     * launcher is unrecoverable rootless). Null on failure — the exclusion then
     * relies on the exact-package + suite-prefix checks alone.
     */
    private fun launcherPackage(ctx: Context): String? = runCatching {
        val intent = android.content.Intent(android.content.Intent.ACTION_MAIN)
            .addCategory(android.content.Intent.CATEGORY_HOME)
        ctx.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
            ?.activityInfo?.packageName
    }.getOrNull()

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
     * Package names we treat as trusted app-store installers. The exhaustive
     * list is impossible (every OEM store), so this is a small allowlist of the
     * common ones; anything NOT here reads as SIDELOAD — the fail-toward-visible
     * direction (we'd rather show a benign sideload note than silently trust an
     * unknown installer).
     */
    private val TRUSTED_INSTALLERS = setOf(
        "com.android.vending", // Google Play
        "com.google.android.packageinstaller",
        "com.google.android.feedback",
        "com.amazon.venezia", // Amazon Appstore
        "com.sec.android.app.samsungapps", // Galaxy Store
        "com.samsung.android.mateagent",
        "com.huawei.appmarket",
        "com.xiaomi.market",
        "com.oppo.market",
        "com.heytap.market",
        "com.vivo.appstore",
        "com.aurora.store", // Aurora (Play proxy)
        "org.fdroid.fdroid", // F-Droid
        "com.aurora.adroid",
    )

    /**
     * Resolve where [pkg] was installed from. Uses the modern
     * [PackageManager.getInstallSourceInfo] API. A null / bare-package-installer
     * / browser / adb source reads as SIDELOAD; a recognised store as TRUSTED;
     * a failure to read (rare) as UNKNOWN (no invented signal).
     */
    private fun installSourceOf(ctx: Context, pkg: String?): InstallSource {
        if (pkg == null) return InstallSource(null, RiskRules.InstallerTrust.UNKNOWN, "unknown")
        return runCatching {
            val src = ctx.packageManager.getInstallSourceInfo(pkg)
            // installingPackageName is the app that actually performed the
            // install (initiating/originating are spoofable hints); prefer it.
            val installer = src.installingPackageName
            when {
                installer == null -> InstallSource(
                    null, RiskRules.InstallerTrust.SIDELOAD, "no recorded installer (sideload / adb)",
                )
                installer in TRUSTED_INSTALLERS -> InstallSource(
                    installer, RiskRules.InstallerTrust.TRUSTED, installer,
                )
                else -> InstallSource(
                    installer, RiskRules.InstallerTrust.SIDELOAD, installer,
                )
            }
        }.getOrElse {
            InstallSource(null, RiskRules.InstallerTrust.UNKNOWN, "unknown")
        }
    }

    /**
     * Count exported-and-unprotected components from PackageManager metadata.
     * A component is counted when it is [exported] with no `permission` guard.
     * We only count components whose exported flag is explicitly reflected by
     * PackageManager (which already resolved the intent-filter default), so this
     * is the accurate installed-app analogue of the binary-manifest heuristic.
     */
    private fun exportedUnprotectedCount(info: PackageInfo): Int {
        var n = 0
        info.activities?.forEach { if (it.exported && it.permission == null) n++ }
        info.services?.forEach { if (it.exported && it.permission == null) n++ }
        info.receivers?.forEach { if (it.exported && it.permission == null) n++ }
        info.providers?.forEach {
            // ProviderInfo has no single `permission` — it guards reads/writes
            // separately; treat "no guard at all" as unprotected.
            if (it.exported && it.readPermission == null && it.writePermission == null) {
                n++
            }
        }
        return n
    }

    /**
     * Signing posture from the already-parsed signing info: no signers →
     * UNSIGNED; a single self-signed (subject == issuer) leaf → SELF_SIGNED;
     * anything else → OK. Best-effort — a parse failure reads as OK (we don't
     * fabricate a signing finding we couldn't verify).
     */
    private fun signingPostureOf(info: PackageInfo): RiskRules.SigningPosture {
        val signers = info.signingInfo?.apkContentsSigners
        if (signers.isNullOrEmpty()) return RiskRules.SigningPosture.UNSIGNED
        if (signers.size > 1) return RiskRules.SigningPosture.OK
        return runCatching {
            val cf = CertificateFactory.getInstance("X.509")
            val cert = cf.generateCertificate(signers[0].toByteArray().inputStream()) as X509Certificate
            if (cert.subjectX500Principal == cert.issuerX500Principal) {
                RiskRules.SigningPosture.SELF_SIGNED
            } else {
                RiskRules.SigningPosture.OK
            }
        }.getOrDefault(RiskRules.SigningPosture.OK)
    }

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
