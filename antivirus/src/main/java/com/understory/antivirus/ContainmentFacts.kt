package com.understory.antivirus

/**
 * The precise, per-app inputs the elevated CONTAINMENT controls act on, computed
 * once on the installed-app analysis path (the SAF-scanned-APK path leaves this
 * null — a raw file isn't installed, so there's nothing to contain). Carried on
 * [ApkAnalyzer.Report] so the detail screen can render each containment control
 * ONLY when it actually applies to this finding — no dead controls.
 *
 * Every field is a fact read off PackageManager / the live abuser snapshot, not
 * a verdict. The UI in ContainmentActions.kt composes the vetted
 * [com.understory.elevation.Elevation] primitives over these facts.
 *
 * HARD EXCLUSIONS: [suiteSibling] is true for the launcher, com.android.settings,
 * Tailscale, the Shizuku manager, and any com.understory.* app. When true the
 * containment UI refuses every bulk/lockdown/kill action and says so — we never
 * quarantine, disable, wipe, or de-admin a protected package.
 */
data class ContainmentFacts(
    /** The package these facts describe. */
    val packageName: String,
    /**
     * The runtime (dangerous) permissions an elevated tier can actually
     * `pm revoke`. Special-access ops (overlay/usage) are excluded here — those
     * are handled by [overlayAppOpActive] / [usageAppOpActive] via appops.
     * Already filtered by [PermissionGroups.revocableDangerous].
     */
    val revocableDangerousPerms: List<String>,
    /** The app declares/requests SYSTEM_ALERT_WINDOW (overlay) — appops target. */
    val hasOverlayPermission: Boolean,
    /** The app declares/requests PACKAGE_USAGE_STATS (usage access) — appops target. */
    val hasUsageStatsPermission: Boolean,
    /**
     * The concrete active device-admin components for this package (usually one).
     * Non-empty ⇒ render "Neutralise device admin" (feature 3); empty ⇒ hide it.
     */
    val activeDeviceAdminComponents: List<String>,
    /**
     * Flagged abuser components that can be disabled individually (feature 5):
     * the currently-active a11y services, notification-listener services, and
     * device-admin receivers, as flattened `pkg/class` strings with a short
     * human [DisableTarget.kind]. Empty ⇒ hide the per-component disable control.
     */
    val disableTargets: List<DisableTarget>,
    /**
     * True when [packageName] is a protected package (launcher, system settings,
     * Tailscale, Shizuku manager, or a com.understory.* suite app). The
     * containment UI renders a plain "protected — excluded" note instead of any
     * action when this is set.
     */
    val suiteSibling: Boolean,
) {
    /** Any containment control at all applies to this app (and it isn't protected). */
    fun hasAnyControl(): Boolean =
        !suiteSibling && (
            revocableDangerousPerms.isNotEmpty() ||
                hasOverlayPermission ||
                hasUsageStatsPermission ||
                activeDeviceAdminComponents.isNotEmpty() ||
                disableTargets.isNotEmpty()
        )

    /** A single flagged component the user can disable in place, with a legible kind. */
    data class DisableTarget(
        /** Flattened `pkg/class` — the exact `pm disable <target>` argument. */
        val component: String,
        /** Which abuser class this component is, for the row label. */
        val kind: Kind,
    ) {
        enum class Kind { ACCESSIBILITY, NOTIFICATION_LISTENER, DEVICE_ADMIN }
    }

    companion object {
        /**
         * Packages that no bulk/lockdown/kill action may ever touch. Filtered out
         * of every containment control; the UI says so rather than silently
         * dropping the app. Mirrors the suite-wide hard-exclusion doctrine.
         */
        private val NEVER_ACT_ON_EXACT = setOf(
            "com.android.settings",
            // Tailscale holds the VPN slot the suite must never fight.
            "com.tailscale.ipn",
            // Shizuku / Sui managers — our own elevation broker; disabling it
            // would sever the very grant these controls depend on.
            "moe.shizuku.privileged.api",
            "moe.shizuku.manager",
        )

        /**
         * True when [pkg] must be excluded from every containment action:
         *   - any com.understory.* suite app (never act on a sibling),
         *   - the current default launcher/home ([launcherPackage]),
         *   - an exact match in [NEVER_ACT_ON_EXACT] (settings / Tailscale /
         *     Shizuku manager).
         */
        fun isProtected(pkg: String, launcherPackage: String?): Boolean =
            pkg.startsWith("com.understory.") ||
                pkg == launcherPackage ||
                pkg in NEVER_ACT_ON_EXACT
    }
}
