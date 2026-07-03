package com.understory.antivirus

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.understory.security.Diagnostics
import java.util.concurrent.TimeUnit

/**
 * Controls the opt-in periodic re-scan (§5.2). Default OFF — no worker
 * enqueued, zero background cost — respecting the minimal-footprint posture.
 * The user's choice is persisted in a small SharedPreferences flag so it
 * survives restarts.
 */
internal object PeriodicScan {

    private const val PREFS = "antivirus_prefs"
    private const val KEY_ENABLED = "periodic_scan_enabled"
    private const val KEY_INSTALL_ALERTS = "install_alerts_enabled"
    private const val WORK_NAME = "av-periodic-scan"

    /** 6h cadence — battery-honest, well above the 15-min WorkManager floor. */
    private const val INTERVAL_HOURS = 6L

    fun isEnabled(ctx: Context): Boolean =
        prefs(ctx).getBoolean(KEY_ENABLED, false)

    /**
     * Opt-in: notify when a freshly installed/updated app scores High/Critical
     * while APK Check is open (§5.1 on-install surfacing). Default OFF — the
     * fresh-install banner still shows in-app regardless; this only controls the
     * out-of-app notification. Independent of the periodic-scan toggle.
     */
    fun installAlertsEnabled(ctx: Context): Boolean =
        prefs(ctx).getBoolean(KEY_INSTALL_ALERTS, false)

    fun setInstallAlertsEnabled(ctx: Context, enabled: Boolean) {
        prefs(ctx).edit().putBoolean(KEY_INSTALL_ALERTS, enabled).apply()
        Diagnostics.log("antivirus.PeriodicScan", "setInstallAlerts=$enabled")
    }

    /**
     * Turn periodic scanning on or off. On → enqueue a KEEP periodic request.
     * Off → cancel it and stop all background work.
     */
    fun setEnabled(ctx: Context, enabled: Boolean) {
        prefs(ctx).edit().putBoolean(KEY_ENABLED, enabled).apply()
        if (enabled) enqueue(ctx) else cancel(ctx)
        Diagnostics.log("antivirus.PeriodicScan", "setEnabled=$enabled")
    }

    private fun enqueue(ctx: Context) {
        val request = PeriodicWorkRequestBuilder<PeriodicScanWorker>(
            INTERVAL_HOURS, TimeUnit.HOURS,
        ).build()
        WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(
            WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, request,
        )
    }

    private fun cancel(ctx: Context) {
        WorkManager.getInstance(ctx).cancelUniqueWork(WORK_NAME)
    }

    /**
     * Whether the worker may post a notification: only if the runtime
     * POST_NOTIFICATIONS permission is granted. When not, periodic scanning
     * still runs and results appear in-app on next open (honest degradation).
     */
    fun alertsAllowed(ctx: Context): Boolean =
        ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
