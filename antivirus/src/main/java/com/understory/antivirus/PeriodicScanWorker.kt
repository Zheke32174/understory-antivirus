package com.understory.antivirus

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.understory.security.Diagnostics
import com.understory.security.ui.Bg
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File

/**
 * Periodic re-scan worker (§5.1). This is the honest rootless shape of
 * "watch for new/changed apps": WorkManager wakes us on a floor-honest 6h
 * cadence, we diff installed packages against a stored snapshot, run the full
 * analysis on new/updated apps only, and — if the user opted into alerts —
 * post a notification when a new/updated app produces a CRITICAL/HIGH finding
 * or a KNOWN_BAD verdict.
 *
 * This is NOT background real-time (rootless-impossible; never claimed). It's
 * periodic + opt-in, default off (see [PeriodicScan]).
 */
class PeriodicScanWorker(
    ctx: Context,
    params: WorkerParameters,
) : CoroutineWorker(ctx, params) {

    override suspend fun doWork(): Result = withContext(Bg.io) {
        runCatching { scan() }.getOrElse {
            Diagnostics.error("antivirus.PeriodicScan", "worker threw: ${it.javaClass.simpleName}: ${it.message}")
            Result.success() // never surface a retry storm; try again next period
        }
    }

    private fun scan(): Result {
        BlocklistStore.ensureLoaded(applicationContext)
        AuxDatabases.ensureLoaded(applicationContext)
        val pm = applicationContext.packageManager
        val previous = loadSnapshot()
        val current = mutableMapOf<String, PkgStamp>()
        val enabled = EnabledAbusers.snapshot(applicationContext)
        val flagged = mutableListOf<ApkAnalyzer.Report>()

        for (app in pm.getInstalledApplications(0)) {
            val pkg = app.packageName
            val stamp = stampFor(pkg) ?: continue
            current[pkg] = stamp
            val prev = previous[pkg]
            val isNewOrUpdated = prev == null ||
                prev.versionCode != stamp.versionCode ||
                prev.lastUpdateTime != stamp.lastUpdateTime
            if (!isNewOrUpdated) continue

            val report = ApkAnalyzer.analyzeInstalled(applicationContext, pkg, enabled) ?: continue
            val notable = report.verdict == ApkAnalyzer.Verdict.KNOWN_BAD ||
                report.findings.any {
                    it.severity == RiskRules.Severity.CRITICAL ||
                        it.severity == RiskRules.Severity.HIGH
                }
            if (notable) flagged += report
        }

        saveSnapshot(current)

        if (flagged.isNotEmpty() && PeriodicScan.alertsAllowed(applicationContext)) {
            ScanNotifier.postPeriodic(applicationContext, flagged)
        }
        Diagnostics.log("antivirus.PeriodicScan", "diff done: ${flagged.size} notable of ${current.size} pkgs")
        return Result.success()
    }

    private data class PkgStamp(val versionCode: Long, val lastUpdateTime: Long)

    private fun stampFor(pkg: String): PkgStamp? = runCatching {
        val info = applicationContext.packageManager.getPackageInfo(pkg, 0)
        @Suppress("DEPRECATION")
        val vc = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P)
            info.longVersionCode else info.versionCode.toLong()
        PkgStamp(vc, info.lastUpdateTime)
    }.getOrNull()

    private fun snapshotFile(): File =
        File(File(applicationContext.filesDir, "scan").apply { mkdirs() }, "known-packages.json")

    private fun loadSnapshot(): Map<String, PkgStamp> = runCatching {
        val f = snapshotFile()
        if (!f.exists()) return emptyMap()
        val obj = JSONObject(f.readText())
        val out = mutableMapOf<String, PkgStamp>()
        val keys = obj.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            val o = obj.getJSONObject(k)
            out[k] = PkgStamp(o.getLong("versionCode"), o.getLong("lastUpdateTime"))
        }
        out
    }.getOrDefault(emptyMap())

    private fun saveSnapshot(map: Map<String, PkgStamp>) {
        runCatching {
            val obj = JSONObject()
            for ((k, v) in map) {
                obj.put(k, JSONObject().put("versionCode", v.versionCode).put("lastUpdateTime", v.lastUpdateTime))
            }
            snapshotFile().writeText(obj.toString())
        }
    }

}
