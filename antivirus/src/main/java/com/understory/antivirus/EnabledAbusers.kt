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
 */
object EnabledAbusers {

    data class Snapshot(
        /** Packages whose accessibility service is currently ENABLED. */
        val enabledAccessibility: Set<String>,
        /** Packages that are currently an active device administrator. */
        val activeDeviceAdmins: Set<String>,
        /** Packages currently granted notification-listener access. */
        val enabledNotificationListeners: Set<String>,
    ) {
        fun isEmpty(): Boolean =
            enabledAccessibility.isEmpty() &&
                activeDeviceAdmins.isEmpty() &&
                enabledNotificationListeners.isEmpty()
    }

    fun snapshot(ctx: Context): Snapshot = Snapshot(
        enabledAccessibility = enabledAccessibilityPackages(ctx),
        activeDeviceAdmins = activeDeviceAdminPackages(ctx),
        enabledNotificationListeners = enabledNotificationListenerPackages(ctx),
    )

    private fun enabledAccessibilityPackages(ctx: Context): Set<String> = runCatching {
        val am = ctx.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            ?: return emptySet()
        am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .mapNotNull { it.resolveInfo?.serviceInfo?.packageName }
            .toSet()
    }.getOrDefault(emptySet())

    private fun activeDeviceAdminPackages(ctx: Context): Set<String> = runCatching {
        val dpm = ctx.getSystemService(DevicePolicyManager::class.java) ?: return emptySet()
        dpm.activeAdmins?.map(ComponentName::getPackageName)?.toSet() ?: emptySet()
    }.getOrDefault(emptySet())

    private fun enabledNotificationListenerPackages(ctx: Context): Set<String> = runCatching {
        NotificationManagerCompat.getEnabledListenerPackages(ctx)
    }.getOrDefault(emptySet())
}
