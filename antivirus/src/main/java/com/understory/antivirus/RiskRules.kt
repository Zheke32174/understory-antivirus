package com.understory.antivirus

/**
 * Static permission-combination rules. We classify a manifest as having a
 * HIGH-RISK posture when its declared permissions match a known-bad
 * combination (the kinds of things spyware reaches for). The user gets a flag,
 * not a verdict — these rules are heuristic by design, and many legitimate
 * apps trip them. The point is to surface what the app *can do* in plain
 * English so the user makes the call.
 *
 * Severity ordering for UI display:
 *   CRITICAL  — combinations that almost never appear in legitimate apps
 *               (e.g. RECEIVE_SMS + INTERNET + READ_CONTACTS = textbook
 *                SMS-stealer profile).
 *   HIGH      — sensitive single capabilities (declares an accessibility
 *                service, a device-admin receiver, MANAGE_EXTERNAL_STORAGE).
 *   MED       — combinations that warrant attention but have legitimate uses
 *                (RECORD_AUDIO + INTERNET, CAMERA + INTERNET).
 *   LOW       — single permissions that aren't dangerous alone.
 *
 * Findings are returned **most-severe first** — CRITICAL(ordinal 0) leads.
 *
 * Note on abuse detection: the highest-value signals (accessibility service,
 * device-admin, notification-listener) are NOT `uses-permission` entries — the
 * `BIND_*` permissions are component-protection permissions the *system*
 * holds. A real abuser DECLARES a `<service android:permission="…BIND_*">`, it
 * does not `<uses-permission>` it. So those live in [analyzeComponents], keyed
 * on declared components (installed apps) or the parsed component-permission
 * lists (SAF-scanned APKs) — never on the requested-permission set.
 */
object RiskRules {

    enum class Severity { CRITICAL, HIGH, MED, LOW }

    data class Finding(
        val severity: Severity,
        val title: String,
        val explain: String,
        /**
         * Optional "Fix in Settings" revoke destination for enabled-abuser
         * findings (§2.1b). Null for static-shape findings, which have no
         * single settings screen to jump to.
         */
        val deepLink: SettingsDeepLinks.Target? = null,
    )

    const val PERM_ACCESSIBILITY = "android.permission.BIND_ACCESSIBILITY_SERVICE"
    const val PERM_DEVICE_ADMIN = "android.permission.BIND_DEVICE_ADMIN"
    const val PERM_NOTIFICATION_LISTENER = "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"

    /**
     * Below this minSdk, an app opts out of a decade of platform security
     * hardening (runtime permissions arrived at 23; scoped storage, Play
     * restrictions, and default-secure networking came later). Malware
     * deliberately targets a low minSdk to keep those old, weaker behaviours
     * available. 23 is the floor at which runtime-permission consent exists.
     */
    const val MIN_SDK_FLOOR = 23

    /**
     * A targetSdk this old means the app is exempted from the current platform's
     * default-deny behaviours (background limits, scoped storage, stricter
     * intent resolution). Play requires recent targetSdk for new apps; a very
     * old target on a sideloaded APK is a real signal.
     */
    const val TARGET_SDK_FLOOR = 26

    /**
     * Apply the permission-combination rules to a requested-permission set and
     * return findings, most-severe first. Component-based abuse detection is
     * separate — see [analyzeComponents].
     */
    fun analyze(permissions: Set<String>): List<Finding> {
        val findings = mutableListOf<Finding>()

        val internet = "android.permission.INTERNET" in permissions
        val readSms = "android.permission.READ_SMS" in permissions
        val receiveSms = "android.permission.RECEIVE_SMS" in permissions
        val sendSms = "android.permission.SEND_SMS" in permissions
        val readContacts = "android.permission.READ_CONTACTS" in permissions
        val readCallLog = "android.permission.READ_CALL_LOG" in permissions
        val recordAudio = "android.permission.RECORD_AUDIO" in permissions
        val camera = "android.permission.CAMERA" in permissions
        val fineLoc = "android.permission.ACCESS_FINE_LOCATION" in permissions
        val backgroundLoc = "android.permission.ACCESS_BACKGROUND_LOCATION" in permissions
        val systemAlertWindow = "android.permission.SYSTEM_ALERT_WINDOW" in permissions
        val packageUsageStats = "android.permission.PACKAGE_USAGE_STATS" in permissions
        val manageExternal = "android.permission.MANAGE_EXTERNAL_STORAGE" in permissions
        val queryAll = "android.permission.QUERY_ALL_PACKAGES" in permissions
        val installPkgs = "android.permission.REQUEST_INSTALL_PACKAGES" in permissions
        val deletePkgs = "android.permission.REQUEST_DELETE_PACKAGES" in permissions
        val readPhone = "android.permission.READ_PHONE_STATE" in permissions
        val bootCompleted = "android.permission.RECEIVE_BOOT_COMPLETED" in permissions

        if (internet && (readSms || receiveSms) && readContacts) {
            findings += Finding(
                Severity.CRITICAL,
                "SMS-stealer profile",
                "Reads SMS + reads contacts + has internet. Classic SMS-exfil " +
                    "shape used by banking trojans and spyware. Legitimate " +
                    "messaging apps usually need SMS but rarely need contacts " +
                    "and internet *together* with that same permission set.",
            )
        }
        if (internet && recordAudio && backgroundLoc) {
            findings += Finding(
                Severity.CRITICAL,
                "Surveillance profile",
                "Microphone + background location + internet. Sustained-surveillance " +
                    "shape; almost never appears in legitimate apps outside specific " +
                    "fitness or audio-recording categories.",
            )
        }
        if (internet && (readSms || receiveSms) && !readContacts) {
            findings += Finding(
                Severity.HIGH,
                "SMS + internet",
                "Reads incoming SMS and has internet egress. This is the core " +
                    "of the SMS-exfil / one-time-code-theft shape — a spy app " +
                    "forwards your texts (including banking and 2FA codes) off " +
                    "the device. Legitimate messaging / backup apps exist, but " +
                    "the combination is worth a hard look.",
            )
        }
        if (installPkgs && deletePkgs) {
            findings += Finding(
                Severity.HIGH,
                "Installs and removes other apps",
                "Requests BOTH install and uninstall of other packages. That " +
                    "pairing — silently sideloading a second-stage payload and " +
                    "then removing evidence or competing apps — is a dropper " +
                    "shape. App stores are the only routinely-legitimate holder " +
                    "of both.",
            )
        }
        if (manageExternal) {
            findings += Finding(
                Severity.HIGH,
                "Full storage access",
                "MANAGE_EXTERNAL_STORAGE grants read/write across all user files, " +
                    "bypassing Scoped Storage. Modern apps should use SAF " +
                    "(per-URI grants) instead. Apps requesting MANAGE_EXTERNAL_STORAGE " +
                    "are either legitimate file managers or doing more than they " +
                    "need to.",
            )
        }
        if (systemAlertWindow) {
            findings += Finding(
                Severity.HIGH,
                "Overlay window permission",
                "SYSTEM_ALERT_WINDOW lets the app draw on top of other apps. The " +
                    "common malicious use is tap-jacking — drawing a fake UI over " +
                    "real one to capture credentials.",
            )
        }
        if (sendSms) {
            findings += Finding(
                Severity.MED,
                "Can send SMS",
                "SEND_SMS lets the app send text messages without opening the " +
                    "messaging app — the premium-SMS toll-fraud shape. Legitimate " +
                    "uses are two-factor and messaging apps; malware uses it to " +
                    "silently subscribe you to paid shortcodes.",
            )
        }
        if (readCallLog && internet) {
            findings += Finding(
                Severity.MED,
                "Call log + internet",
                "Reads your call log and can send it. Reveals who you call and " +
                    "when — a common surveillance-exfil target. Dialers and " +
                    "call-screening apps have legitimate reasons; scrutinize others.",
            )
        }
        if (internet && recordAudio) {
            findings += Finding(
                Severity.MED,
                "Mic + internet",
                "Can record audio and send it. Legitimate uses include voice " +
                    "messaging, voice search, dictation. Spyware uses include " +
                    "wiretapping. Look at what the app actually does.",
            )
        }
        if (internet && camera) {
            findings += Finding(
                Severity.MED,
                "Camera + internet",
                "Can take photos/video and send them. Legitimate uses are " +
                    "everywhere; spyware uses include covert capture. Look at " +
                    "context.",
            )
        }
        if (internet && fineLoc) {
            findings += Finding(
                Severity.MED,
                "Precise location + internet",
                "Can track precise location and send it. Most map / fitness / " +
                    "weather apps legitimately want this; tracker apps want it " +
                    "too.",
            )
        }
        if (bootCompleted && internet) {
            findings += Finding(
                Severity.MED,
                "Auto-starts on boot + internet",
                "Starts itself when the device boots and can reach the network. " +
                    "That is how surveillance and adware persist across reboots " +
                    "without you re-opening them. Many legitimate apps " +
                    "(messengers, sync clients) also auto-start — weigh it " +
                    "against what the app is for.",
            )
        }
        if (packageUsageStats) {
            findings += Finding(
                Severity.MED,
                "Usage stats access",
                "Can see which apps you've used and when. Legitimate uses include " +
                    "digital-wellbeing apps and parental controls; covert " +
                    "monitoring tools want it too.",
            )
        }
        if (installPkgs) {
            findings += Finding(
                Severity.MED,
                "Install other apps",
                "REQUEST_INSTALL_PACKAGES lets the app prompt the user to install " +
                    "additional APKs. App stores and update tools need it; " +
                    "malware sideloaders use it for second-stage payloads.",
            )
        }
        if (queryAll) {
            findings += Finding(
                Severity.LOW,
                "Enumerates all installed apps",
                "QUERY_ALL_PACKAGES lets the app see your full installed-app " +
                    "list — a fingerprinting surface. Antivirus / launcher / " +
                    "package-management apps legitimately need it; many others " +
                    "request it for analytics.",
            )
        }
        if (readPhone) {
            findings += Finding(
                Severity.LOW,
                "Phone identity access",
                "READ_PHONE_STATE exposes IMEI / SIM info. Legitimate uses include " +
                    "carrier apps and dialers; trackers use it for cross-app " +
                    "device identity.",
            )
        }

        return findings.sortedBy { it.severity.ordinal }
    }

    /**
     * Declared-component abuse detection. Works for both the installed-app path
     * (component permissions read off `ServiceInfo`/`ActivityInfo` via
     * PackageManager) and the SAF-scanned-APK path (component permissions
     * parsed out of the binary manifest). It keys on the CORRECT input — a
     * `<service>`/`<receiver>` protected by a `BIND_*` permission — not on the
     * requested-permission set, which is the A5 gap the v1 rules had.
     *
     * @param servicePermissions the `android:permission` of every `<service>`.
     * @param receiverPermissions the `android:permission` of every `<receiver>`.
     * @param requestedPermissions the app's `<uses-permission>` set (only used
     *   for the a11y+internet exfiltration combo).
     */
    fun analyzeComponents(
        servicePermissions: List<String>,
        receiverPermissions: List<String>,
        requestedPermissions: Set<String>,
    ): List<Finding> {
        val findings = mutableListOf<Finding>()
        val declaresA11y = PERM_ACCESSIBILITY in servicePermissions
        val declaresDeviceAdmin = PERM_DEVICE_ADMIN in receiverPermissions
        val declaresNotifListener = PERM_NOTIFICATION_LISTENER in servicePermissions
        val internet = "android.permission.INTERNET" in requestedPermissions
        val overlay = "android.permission.SYSTEM_ALERT_WINDOW" in requestedPermissions
        val bootCompleted = "android.permission.RECEIVE_BOOT_COMPLETED" in requestedPermissions

        if (declaresA11y && overlay) {
            findings += Finding(
                Severity.CRITICAL,
                "Accessibility + screen overlay profile",
                "Declares an accessibility service AND can draw over other apps. " +
                    "That pairing is the banking-trojan overlay-attack shape: the " +
                    "a11y service reads what's on screen while the overlay paints " +
                    "a fake input on top to steal what you type. Very few " +
                    "legitimate apps need both.",
            )
        }
        if (declaresDeviceAdmin && bootCompleted) {
            findings += Finding(
                Severity.CRITICAL,
                "Device-admin + auto-start on boot",
                "A device-admin receiver that also auto-starts on boot re-asserts " +
                    "its lock/wipe/anti-uninstall control every time the phone " +
                    "restarts — a stalkerware persistence shape designed to " +
                    "survive reboots and resist removal. Legitimate MDM behaves " +
                    "this way too; treat it as expected only for a work profile " +
                    "you recognise.",
            )
        }

        if (declaresA11y && internet) {
            findings += Finding(
                Severity.CRITICAL,
                "Accessibility + internet exfiltration profile",
                "Declares an accessibility service AND has internet. An a11y " +
                    "service can read on-screen text, type, and tap; combined with " +
                    "internet egress this is the textbook credential-stealing / " +
                    "RAT shape. A small set of legitimate apps (password managers, " +
                    "screen readers) need accessibility — scrutinize this one.",
            )
        }
        if (declaresA11y) {
            findings += Finding(
                Severity.HIGH,
                "Declares an accessibility service",
                "An accessibility service can read every on-screen UI element and " +
                    "synthesize taps + text input. Grant only where this is core " +
                    "function (screen readers, password autofill, accessibility " +
                    "tools). The Understory suite refuses accessibility for this " +
                    "reason.",
            )
        }
        if (declaresDeviceAdmin) {
            findings += Finding(
                Severity.HIGH,
                "Declares a device-admin receiver",
                "Device-admin apps can lock the device, wipe data, and resist " +
                    "uninstall. Legitimate uses are MDM / corporate-managed apps. " +
                    "If unfamiliar, refuse the grant.",
            )
        }
        if (declaresNotifListener) {
            findings += Finding(
                Severity.HIGH,
                "Declares a notification listener",
                "A notification-listener service can read the content of every " +
                    "notification — messages, one-time codes, banking alerts. " +
                    "Legitimate uses are wearables and automation apps; spyware " +
                    "uses it to harvest 2FA codes and message previews.",
            )
        }
        return findings.sortedBy { it.severity.ordinal }
    }

    /**
     * The tri-state installer trust of an APK's recorded install source.
     *   TRUSTED  — a recognised app store (Play / vendor store / a package
     *              installer we trust). Not a finding.
     *   SIDELOAD — installed by a browser, file manager, adb, or with no
     *              recorded installer. The classic sideload / drive-by shape.
     *   UNKNOWN  — the install source can't be determined (SAF-scanned raw
     *              APK, which has no install source yet). Not a finding — we
     *              never invent a signal we can't read.
     */
    enum class InstallerTrust { TRUSTED, SIDELOAD, UNKNOWN }

    /**
     * The tri-state signing posture, computed from the parsed cert set.
     *   OK          — at least one certificate present. We don't verify the
     *                 chain (that's the installer's job); presence is the fact.
     *   SELF_SIGNED — a single certificate whose subject == issuer. Almost every
     *                 Android app is self-signed, so this is a LOW note, not an
     *                 alarm — surfaced only as context, never scored high.
     *   UNSIGNED    — no certificate at all. Android would refuse to install it;
     *                 an unsigned APK reaching a scanner is anomalous.
     */
    enum class SigningPosture { OK, SELF_SIGNED, UNSIGNED }

    /**
     * Structural / manifest-posture facts — the non-permission signals. Fed by
     * [ApkFacts] from both the isolated-parser path and the PackageManager path.
     * Every field is a fact, not a verdict; [analyzeStructural] turns them into
     * findings.
     */
    fun analyzeStructural(
        debuggable: Boolean,
        allowBackup: Boolean,
        usesCleartextTraffic: Boolean,
        testOnly: Boolean,
        minSdk: Int,
        targetSdk: Int,
        exportedUnprotectedComponents: Int,
        installer: InstallerTrust,
        signing: SigningPosture,
    ): List<Finding> {
        val findings = mutableListOf<Finding>()

        if (debuggable) {
            findings += Finding(
                Severity.HIGH,
                "Ships as debuggable",
                "The app is marked android:debuggable. A debuggable app lets any " +
                    "process with adb access read its memory, run code as it, and " +
                    "extract its data — no release build ships this way. It's " +
                    "either a leaked debug build or was repackaged with debugging " +
                    "turned back on.",
            )
        }
        if (testOnly) {
            findings += Finding(
                Severity.HIGH,
                "Test-only build",
                "The app is marked android:testOnly — a build Android only allows " +
                    "to be installed over adb, never from a store. Seeing one on a " +
                    "device means it was pushed manually, which is how a tester or " +
                    "an attacker sideloads a build that skips normal install " +
                    "vetting.",
            )
        }
        if (exportedUnprotectedComponents > 0) {
            findings += Finding(
                Severity.MED,
                "Exported components with no permission guard",
                "$exportedUnprotectedComponents component(s) are exported to other " +
                    "apps with no permission requirement — any app on the device " +
                    "can invoke them. That's an IPC attack surface: badly-guarded " +
                    "exported components are a common route to trigger unintended " +
                    "behaviour or leak data. Legitimate apps export components too; " +
                    "the count is a surface measure, not proof of a bug.",
            )
        }
        if (usesCleartextTraffic) {
            findings += Finding(
                Severity.MED,
                "Allows cleartext (unencrypted) traffic",
                "The app opts back into plain-HTTP traffic, which Android blocks by " +
                    "default. Anything it sends over cleartext can be read or " +
                    "modified on the network. Rare in modern legitimate apps; " +
                    "common in hastily-built or repackaged ones.",
            )
        }
        if (minSdk in 0 until MIN_SDK_FLOOR) {
            findings += Finding(
                Severity.MED,
                "Targets very old Android (minSdk $minSdk)",
                "Runs on Android versions from before runtime permissions (API 23). " +
                    "On those releases it can hold permissions granted silently at " +
                    "install and sidestep a decade of platform hardening. Malware " +
                    "sets a low minSdk on purpose to keep those weaker behaviours.",
            )
        }
        if (targetSdk in 0 until TARGET_SDK_FLOOR) {
            findings += Finding(
                Severity.LOW,
                "Old target SDK ($targetSdk)",
                "A low targetSdk exempts the app from the current platform's " +
                    "default-deny behaviours (background limits, scoped storage, " +
                    "stricter intent handling). Play requires a recent target for " +
                    "new apps; an old one on a sideloaded APK is worth noting.",
            )
        }
        if (allowBackup) {
            findings += Finding(
                Severity.LOW,
                "Backup allowed",
                "android:allowBackup is on (the platform default), so the app's " +
                    "private data can be pulled off via adb backup or included in " +
                    "cloud/device transfers. Low risk on its own, but security- " +
                    "sensitive apps disable it so their data can't be extracted " +
                    "that way.",
            )
        }
        when (installer) {
            InstallerTrust.SIDELOAD -> findings += Finding(
                Severity.LOW,
                "Sideloaded (not from a store)",
                "Installed from outside a recognised app store — by a browser, " +
                    "file manager, adb, or with no recorded installer. Sideloading " +
                    "is normal for this app and many others, but it's also how " +
                    "malware arrives, since it skips a store's install-time checks. " +
                    "Just context for the rest of the findings.",
            )
            InstallerTrust.TRUSTED, InstallerTrust.UNKNOWN -> Unit
        }
        when (signing) {
            SigningPosture.UNSIGNED -> findings += Finding(
                Severity.MED,
                "No signing certificate",
                "No signing certificate was found. Android refuses to install " +
                    "unsigned APKs, so an unsigned file reaching this scanner is " +
                    "anomalous — likely corrupt, or hand-assembled.",
            )
            SigningPosture.SELF_SIGNED -> findings += Finding(
                Severity.LOW,
                "Self-signed certificate",
                "Signed with a self-signed certificate (subject = issuer). This is " +
                    "true of almost every Android app — Google doesn't run a CA for " +
                    "app signing — so it isn't alarming by itself. Shown only as " +
                    "context; the deny-list is what actually flags a bad signer.",
            )
            SigningPosture.OK -> Unit
        }

        return findings.sortedBy { it.severity.ordinal }
    }

    // ---------------------------------------------------------------
    // Numeric risk score + rating
    // ---------------------------------------------------------------

    /** Coarse rating band, derived from the numeric [RiskScore.score]. */
    enum class Rating { LOW, MEDIUM, HIGH, CRITICAL }

    /**
     * The aggregate risk of one app: a bounded numeric [score] (0..100), a
     * [rating] band, and the [reasons] (the finding titles, most-severe first)
     * that contributed. The number is a monotone sum of per-finding weights,
     * capped at 100 — it exists to RANK and to give the user a single legible
     * dial, NOT to imply calibrated probability. Copy stays honest about that.
     *
     * Weighting: CRITICAL=40, HIGH=18, MED=7, LOW=2. A single CRITICAL alone
     * already lands in the HIGH band; two push to CRITICAL. The bands are then:
     *   0        → LOW      (nothing fired)
     *   1..24    → LOW
     *   25..49   → MEDIUM
     *   50..79   → HIGH
     *   80..100  → CRITICAL
     * plus a floor: any CRITICAL finding forces at least HIGH, and a KNOWN_BAD
     * verdict is pinned to CRITICAL by the caller regardless of the sum.
     */
    data class RiskScore(
        val score: Int,
        val rating: Rating,
        val reasons: List<String>,
    )

    private fun weightOf(s: Severity): Int = when (s) {
        Severity.CRITICAL -> 40
        Severity.HIGH -> 18
        Severity.MED -> 7
        Severity.LOW -> 2
    }

    /**
     * Fold a finding list into a [RiskScore]. Pure + deterministic so it is
     * unit-testable and identical on both scan paths. [knownBad] pins the
     * result to CRITICAL/100 (a deny-list hit outranks any heuristic sum).
     */
    fun score(findings: List<Finding>, knownBad: Boolean = false): RiskScore {
        if (knownBad) {
            return RiskScore(
                score = 100,
                rating = Rating.CRITICAL,
                reasons = findings.map { it.title },
            )
        }
        val raw = findings.sumOf { weightOf(it.severity) }
        val capped = raw.coerceIn(0, 100)
        val hasCritical = findings.any { it.severity == Severity.CRITICAL }
        var rating = when {
            capped >= 80 -> Rating.CRITICAL
            capped >= 50 -> Rating.HIGH
            capped >= 25 -> Rating.MEDIUM
            else -> Rating.LOW
        }
        // Floor: a single CRITICAL heuristic must never read below HIGH even if
        // it's the only finding (weight 40 → HIGH band already, but the floor
        // makes the invariant explicit and survives any future re-weighting).
        if (hasCritical && rating.ordinal < Rating.HIGH.ordinal) rating = Rating.HIGH
        return RiskScore(
            score = capped,
            rating = rating,
            reasons = findings.sortedBy { it.severity.ordinal }.map { it.title },
        )
    }
}
