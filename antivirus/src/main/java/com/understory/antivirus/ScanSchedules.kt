package com.understory.antivirus

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequest
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.understory.security.Diagnostics
import java.util.concurrent.TimeUnit

/**
 * The app's own periodic checks — one independent WorkManager schedule per
 * check, each with its own opt-in toggle, all DEFAULT OFF (the suite's
 * minimal-footprint posture: zero background cost until the user opts in).
 * [PeriodicScan] (the original 6h new/changed-app diff) stays as-is; this
 * registry adds the checks around it:
 *
 *   - FULL_AUDIT   daily whole-device audit sweep ([FullAuditWorker]) — the
 *                  diff scan only looks at new/updated apps; this one re-runs
 *                  the full ruleset over everything, so definition/db imports
 *                  retroactively catch already-installed apps.
 *   - SNORT        12h passive Snort-signature pass ([SnortScanWorker]).
 *   - VIRUSTOTAL   daily hash lookup of sideloaded apps ([VtScanWorker]) —
 *                  additionally gated on [VirusTotal.isEnabled], and
 *                  constrained to a connected network.
 *
 * Toggle state persists in the same prefs file as [PeriodicScan] so the
 * Definitions tab reads one place.
 */
internal object ScanSchedules {

    private const val PREFS = "antivirus_prefs"

    enum class Check(
        val key: String,
        val workName: String,
        val intervalHours: Long,
        val needsNetwork: Boolean,
    ) {
        FULL_AUDIT("check_full_audit", "av-check-full-audit", 24L, false),
        SNORT("check_snort", "av-check-snort", 12L, false),
        VIRUSTOTAL("check_virustotal", "av-check-virustotal", 24L, true),
    }

    fun isEnabled(ctx: Context, check: Check): Boolean =
        prefs(ctx).getBoolean(check.key, false)

    /** Turn one check on/off. On → enqueue KEEP; off → cancel its work. */
    fun setEnabled(ctx: Context, check: Check, enabled: Boolean) {
        prefs(ctx).edit().putBoolean(check.key, enabled).apply()
        if (enabled) enqueue(ctx, check) else cancel(ctx, check)
        Diagnostics.log("antivirus.Schedules", "${check.name} enabled=$enabled")
    }

    /**
     * Re-assert every enabled check's schedule (KEEP policy — cheap no-op when
     * already enqueued). Called from the Definitions tab on load so a cleared
     * WorkManager DB (backup restore, force-stop edge cases) self-heals.
     */
    fun ensureScheduled(ctx: Context) {
        for (check in Check.entries) {
            if (isEnabled(ctx, check)) enqueue(ctx, check)
        }
    }

    private fun enqueue(ctx: Context, check: Check) {
        val request = when (check) {
            Check.FULL_AUDIT -> builder<FullAuditWorker>(check)
            Check.SNORT -> builder<SnortScanWorker>(check)
            Check.VIRUSTOTAL -> builder<VtScanWorker>(check)
        }
        WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(
            check.workName, ExistingPeriodicWorkPolicy.KEEP, request,
        )
    }

    private inline fun <reified W : androidx.work.ListenableWorker> builder(
        check: Check,
    ): PeriodicWorkRequest {
        val b = PeriodicWorkRequestBuilder<W>(check.intervalHours, TimeUnit.HOURS)
        if (check.needsNetwork) {
            b.setConstraints(
                Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build(),
            )
        }
        return b.build()
    }

    private fun cancel(ctx: Context, check: Check) {
        WorkManager.getInstance(ctx).cancelUniqueWork(check.workName)
    }

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
