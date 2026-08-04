package com.understory.antivirus

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/**
 * Single place that posts the "flagged app" notification, shared by the periodic
 * worker and the on-install (§5.1) surfacing path. Every post is guarded by the
 * runtime POST_NOTIFICATIONS permission — if it isn't granted we no-op (results
 * still appear in-app); never a crash, never a dead control.
 *
 * The notification is the ONLY out-of-app surface, and it carries no risky
 * content — just the package name and a "tap to review" that opens the app.
 */
object ScanNotifier {

    const val CHANNEL_ID = "av-periodic-scan"
    private const val NOTIF_ID_PERIODIC = 1001
    private const val NOTIF_ID_INSTALL = 1002
    private const val NOTIF_ID_SNORT = 1003
    private const val NOTIF_ID_VT = 1004

    /** Whether a notification may be posted (runtime permission granted). */
    fun canPost(ctx: Context): Boolean =
        ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    /** Post the periodic-sweep summary for [flagged] apps. */
    fun postPeriodic(ctx: Context, flagged: List<ApkAnalyzer.Report>) {
        if (flagged.isEmpty() || !canPost(ctx)) return
        val text = if (flagged.size == 1) {
            ctx.getString(R.string.av_notif_one, flagged.first().packageName)
        } else {
            ctx.getString(R.string.av_notif_many, flagged.size)
        }
        post(ctx, NOTIF_ID_PERIODIC, ctx.getString(R.string.av_notif_title), text)
    }

    /**
     * Post the on-install alert for a single freshly installed/updated [report]
     * that scored High/Critical. Caller gates on the opt-in
     * [PeriodicScan.installAlertsEnabled] flag AND the score band.
     */
    fun postInstallAlert(ctx: Context, report: ApkAnalyzer.Report) {
        if (!canPost(ctx)) return
        post(
            ctx,
            NOTIF_ID_INSTALL,
            ctx.getString(R.string.av_notif_install_title),
            ctx.getString(R.string.av_notif_install_body, report.packageName),
        )
    }

    /** Post the passive Snort pass result — [packages] with HIGH-band hits. */
    fun postSnort(ctx: Context, packages: List<String>) {
        if (packages.isEmpty() || !canPost(ctx)) return
        val text = if (packages.size == 1) {
            ctx.getString(R.string.av_notif_snort_one, packages.first())
        } else {
            ctx.getString(R.string.av_notif_snort_many, packages.size)
        }
        post(ctx, NOTIF_ID_SNORT, ctx.getString(R.string.av_notif_title), text)
    }

    /** Post the periodic VirusTotal result — [count] flagged sideloads. */
    fun postVt(ctx: Context, count: Int) {
        if (count <= 0 || !canPost(ctx)) return
        post(
            ctx,
            NOTIF_ID_VT,
            ctx.getString(R.string.av_notif_title),
            ctx.getString(R.string.av_notif_vt, count),
        )
    }

    private fun post(ctx: Context, id: Int, title: String, text: String) {
        ensureChannel(ctx)
        val intent = Intent(ctx, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val pi = PendingIntent.getActivity(
            ctx, id, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notif = NotificationCompat.Builder(ctx, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()
        runCatching { NotificationManagerCompat.from(ctx).notify(id, notif) }
    }

    private fun ensureChannel(ctx: Context) {
        val mgr = ctx.getSystemService(NotificationManager::class.java) ?: return
        if (mgr.getNotificationChannel(CHANNEL_ID) != null) return
        mgr.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                ctx.getString(R.string.av_notif_channel),
                NotificationManager.IMPORTANCE_DEFAULT,
            ),
        )
    }
}
