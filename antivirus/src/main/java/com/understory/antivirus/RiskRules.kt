package com.understory.antivirus

/**
 * Static permission-combination rules. We classify a manifest as
 * having a HIGH-RISK posture when its declared permissions match a
 * known-bad combination (the kinds of things spyware reaches for).
 * The user gets a flag, not a verdict — these rules are heuristic by
 * design, and many legitimate apps trip them. The point is to surface
 * what the app *can do* in plain English so the user makes the call.
 *
 * Severity ordering for UI display:
 *   CRITICAL  — combinations that almost never appear in legitimate apps
 *               (e.g. RECEIVE_SMS + INTERNET + READ_CONTACTS = textbook
 *                SMS-stealer profile).
 *   HIGH      — sensitive single permissions (BIND_ACCESSIBILITY_SERVICE,
 *                MANAGE_EXTERNAL_STORAGE, BIND_DEVICE_ADMIN).
 *   MED       — combinations that warrant attention but have legitimate
 *                uses (RECORD_AUDIO + INTERNET, CAMERA + INTERNET).
 *   LOW       — single permissions that aren't dangerous alone.
 */
object RiskRules {

    enum class Severity { CRITICAL, HIGH, MED, LOW }

    data class Finding(
        val severity: Severity,
        val title: String,
        val explain: String,
    )

    /**
     * Apply the rules to a permission set and return findings ordered
     * by severity descending.
     */
    fun analyze(permissions: Set<String>): List<Finding> {
        val findings = mutableListOf<Finding>()

        // CRITICAL combos — almost-always-bad signatures.
        val internet = "android.permission.INTERNET" in permissions
        val readSms = "android.permission.READ_SMS" in permissions
        val receiveSms = "android.permission.RECEIVE_SMS" in permissions
        val readContacts = "android.permission.READ_CONTACTS" in permissions
        val readCallLog = "android.permission.READ_CALL_LOG" in permissions
        val recordAudio = "android.permission.RECORD_AUDIO" in permissions
        val camera = "android.permission.CAMERA" in permissions
        val fineLoc = "android.permission.ACCESS_FINE_LOCATION" in permissions
        val backgroundLoc = "android.permission.ACCESS_BACKGROUND_LOCATION" in permissions
        val accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions
        val deviceAdmin = "android.permission.BIND_DEVICE_ADMIN" in permissions
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
        if (accessibility && internet) {
            findings += Finding(
                Severity.CRITICAL,
                "Accessibility-service exfiltration profile",
                "Has BIND_ACCESSIBILITY_SERVICE + internet. Accessibility services " +
                    "can read on-screen text, type, and tap. Combined with " +
                    "internet egress, this is the textbook shape of a credential-" +
                    "stealing or RAT-class app. A small set of legitimate apps " +
                    "(password managers, screen readers) need accessibility, but " +
                    "scrutinize this one carefully.",
            )
        }
        if (deviceAdmin) {
            findings += Finding(
                Severity.HIGH,
                "Device admin requested",
                "Apps with device-admin can lock the device, wipe data, and resist " +
                    "uninstall. Legitimate uses are MDM tools and corporate-managed " +
                    "apps. If unfamiliar, refuse the grant.",
            )
        }
        if (accessibility) {
            findings += Finding(
                Severity.HIGH,
                "Accessibility service",
                "Accessibility services can read every on-screen UI element and " +
                    "synthesize taps + text input. Grant only to apps where this is " +
                    "core function (screen readers, password autofill, accessibility " +
                    "tools). The Understory suite explicitly refuses to use " +
                    "accessibility for this reason.",
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

        return findings.sortedByDescending { it.severity.ordinal }
    }
}
