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
        val readPhone = "android.permission.READ_PHONE_STATE" in permissions

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
}
