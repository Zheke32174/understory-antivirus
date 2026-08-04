package com.understory.antivirus

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.understory.security.Diagnostics
import com.understory.security.ui.Bg
import kotlinx.coroutines.withContext

/**
 * Daily whole-device audit (opt-in, default off — [ScanSchedules]). Unlike
 * [PeriodicScanWorker]'s diff (new/updated apps only), this re-runs the full
 * analysis over every user app, so freshly imported definitions — a new .ubl,
 * an aux database, updated Snort-derived heuristics — retroactively catch
 * apps that were already installed and unchanged.
 */
class FullAuditWorker(
    ctx: Context,
    params: WorkerParameters,
) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result = withContext(Bg.io) {
        runCatching { audit() }.getOrElse {
            Diagnostics.error("antivirus.FullAudit", "worker threw: ${it.javaClass.simpleName}: ${it.message}")
            Result.success()
        }
    }

    private fun audit(): Result {
        val result = ApkAnalyzer.auditInstalledWithSummary(applicationContext)
        val notable = result.flagged.filter { report ->
            report.verdict == ApkAnalyzer.Verdict.KNOWN_BAD ||
                report.findings.any {
                    it.severity == RiskRules.Severity.CRITICAL ||
                        it.severity == RiskRules.Severity.HIGH
                }
        }
        if (notable.isNotEmpty() && PeriodicScan.alertsAllowed(applicationContext)) {
            ScanNotifier.postPeriodic(applicationContext, notable)
        }
        Diagnostics.log(
            "antivirus.FullAudit",
            "sweep done: ${result.summary.flagged} flagged of ${result.summary.scanned}, ${notable.size} notable",
        )
        return Result.success()
    }
}
