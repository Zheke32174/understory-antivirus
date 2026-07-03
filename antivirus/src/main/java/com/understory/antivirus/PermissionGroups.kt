package com.understory.antivirus

/**
 * Groups an app's declared permissions into legible danger tiers for the detail
 * screen. This is a STATIC, structural classification of the permission name —
 * NOT a check of whether the permission is currently granted (that needs
 * per-permission PackageManager flags we don't collect here, and a declared-but-
 * ungranted dangerous permission is still worth showing as "what it asks for").
 * Honest framing: the detail copy says "requests", never "has".
 *
 * Three tiers:
 *   DANGEROUS — the runtime-consent permissions (SMS, contacts, location, mic,
 *               camera, call log, etc.) plus the high-power "special access"
 *               permissions (overlay, all-files, install-packages, usage-stats)
 *               that gate the most abuse.
 *   SIGNATURE — BIND_* / system component-protection permissions. Cargo-culted
 *               into many manifests; only meaningful when a matching component
 *               is actually declared (which the component rules handle), so we
 *               tier them below dangerous but above normal.
 *   NORMAL    — everything else (INTERNET, wake-lock, vibrate, …). Granted at
 *               install with no prompt.
 */
object PermissionGroups {

    enum class Tier { DANGEROUS, SIGNATURE, NORMAL }

    /**
     * The runtime + special-access permission names we surface as DANGEROUS.
     * Kept as an explicit set (not a prefix match) so the tiering is auditable
     * and doesn't accidentally promote a benign permission that happens to share
     * a prefix.
     */
    private val DANGEROUS = setOf(
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_MMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.BODY_SENSORS",
        "android.permission.BODY_SENSORS_BACKGROUND",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO",
        // Special-access (not runtime-dialog, but high-power) — surfaced here
        // because these are what abuse reaches for.
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.REQUEST_DELETE_PACKAGES",
        "android.permission.QUERY_ALL_PACKAGES",
    )

    fun tierOf(permission: String): Tier = when {
        permission in DANGEROUS -> Tier.DANGEROUS
        permission.startsWith("android.permission.BIND_") -> Tier.SIGNATURE
        else -> Tier.NORMAL
    }

    /**
     * Split [permissions] into the three tiers, each alphabetically sorted, with
     * empty tiers omitted. Tiers come back DANGEROUS → SIGNATURE → NORMAL so the
     * detail screen reads worst-first.
     */
    fun grouped(permissions: List<String>): List<Pair<Tier, List<String>>> =
        permissions.distinct()
            .groupBy { tierOf(it) }
            .toList()
            .sortedBy { it.first.ordinal }
            .map { (tier, list) -> tier to list.sorted() }

    /** The last dotted segment — the short human name for a permission row. */
    fun shortName(permission: String): String =
        permission.substringAfterLast('.')
}
