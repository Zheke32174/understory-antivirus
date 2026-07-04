package com.understory.antivirus

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.view.accessibility.AccessibilityManager
import androidx.core.app.NotificationManagerCompat

/**
 * Device-wide snapshot of which apps are *currently active as abusers* — the
 * strongest of the two abuse signals, because the app is exercising the power
 * right now, not merely declaring the component.
 *
 * All three enumerations are readable by any app rootless — we hold no slot
 * ourselves; we only enumerate *others'* holdings, which is exactly the
 * antivirus role in the suite slot matrix. Computed once per audit and
 * cross-referenced by package name.
 *
 * In addition to the per-package *sets* (used by the finding rules), the
 * snapshot carries the concrete active [ComponentName]s per package. Those
 * component identities are what the containment features act on precisely:
 * [ContainmentFacts] turns the active device-admin component into a
 * `dpm remove-active-admin` target, and the active a11y / notification-listener
 * components into a `pm disable <pkg>/<component>` target — so a specific abuser
 * receiver/service can be neutralised without touching the rest of the app.
 */
object EnabledAbusers {

    data class Snapshot(
        /** Packages whose accessibility service is currently ENABLED. */
        val enabledAccessibility: Set<String>,
        /** Packages that are currently an active device administrator. */
        val activeDeviceAdmins: Set<String>,
        /** Packages currently granted notification-listener access. */
        val enabledNotificationListeners: Set<String>,
        /**
         * The concrete currently-active components, keyed by package. Each list
         * holds the fully-qualified [ComponentName]s the platform reports as
         * live for that abuser class — the precise `pkg/component` targets the
         * containment scalpels use. Empty when a package holds the slot but the
         * component identity could not be resolved (degrade honestly; the
         * package-level finding still stands).
         */
        val accessibilityComponents: Map<String, List<ComponentName>>,
        val deviceAdminComponents: Map<String, List<ComponentName>>,
        val notificationListenerComponents: Map<String, List<ComponentName>>,
    ) {
        fun isEmpty(): Boolean =
            enabledAccessibility.isEmpty() &&
                activeDeviceAdmins.isEmpty() &&
                enabledNotificationListeners.isEmpty()
    }

    fun snapshot(ctx: Context): Snapshot {
        val a11y = enabledAccessibilityComponents(ctx)
        val admins = activeDeviceAdminComponents(ctx)
        val notif = enabledNotificationListenerComponents(ctx)
        return Snapshot(
            enabledAccessibility = a11y.keys,
            activeDeviceAdmins = admins.keys,
            enabledNotificationListeners = notif.keys,
            accessibilityComponents = a11y,
            deviceAdminComponents = admins,
            notificationListenerComponents = notif,
        )
    }

    private fun enabledAccessibilityComponents(ctx: Context): Map<String, List<ComponentName>> = runCatching {
        val am = ctx.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            ?: return emptyMap()
        am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .mapNotNull { it.resolveInfo?.serviceInfo }
            .mapNotNull { si ->
                val pkg = si.packageName ?: return@mapNotNull null
                val cls = si.name ?: return@mapNotNull null
                pkg to ComponentName(pkg, cls)
            }
            .groupBy({ it.first }, { it.second })
    }.getOrDefault(emptyMap())

    private fun activeDeviceAdminComponents(ctx: Context): Map<String, List<ComponentName>> = runCatching {
        val dpm = ctx.getSystemService(DevicePolicyManager::class.java) ?: return emptyMap()
        dpm.activeAdmins.orEmpty()
            .groupBy({ it.packageName }, { it })
    }.getOrDefault(emptyMap())

    private fun enabledNotificationListenerComponents(ctx: Context): Map<String, List<ComponentName>> = runCatching {
        // NotificationManagerCompat exposes enabled listener *packages*; the
        // enabled_notification_listeners secure setting holds the concrete
        // component list. We resolve the components from that setting and keep
        // only those whose package is actually reported enabled — so a stale
        // setting entry can't invent a target.
        val enabledPkgs = NotificationManagerCompat.getEnabledListenerPackages(ctx)
        if (enabledPkgs.isEmpty()) return emptyMap()
        val raw = android.provider.Settings.Secure.getString(
            ctx.contentResolver,
            "enabled_notification_listeners",
        ).orEmpty()
        raw.split(':')
            .mapNotNull { entry -> ComponentName.unflattenFromString(entry.trim()) }
            .filter { it.packageName in enabledPkgs }
            .groupBy({ it.packageName }, { it })
    }.getOrDefault(emptyMap())
}
