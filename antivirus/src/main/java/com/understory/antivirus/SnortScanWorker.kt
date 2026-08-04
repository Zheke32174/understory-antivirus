package com.understory.antivirus

import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.understory.security.Diagnostics
import com.understory.security.ui.Bg
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Periodic PASSIVE Snort-signature scan (opt-in, default off — see
 * [ScanSchedules]). Walks user-visible installed apps and streams each app's
 * base APK through the active Snort-format ruleset ([SnortRuleStore]).
 * Incremental like [PeriodicScanWorker]: an app whose version/update stamp is
 * unchanged since the last pass is skipped, so steady-state runs cost almost
 * nothing.
 *
 * Honest scope (same as [SnortRules]): content signatures over bytes already
 * on disk — never packet capture, never network.
 */
class SnortScanWorker(
    ctx: Context,
    params: WorkerParameters,
) : CoroutineWorker(ctx, params) {

    /** Per-APK read budget. Matches ApkAnalyzer's whole-file cap. */
    private val maxBytesPerApk = 200L * 1024 * 1024

    override suspend fun doWork(): Result = withContext(Bg.io) {
        runCatching { scan() }.getOrElse {
            Diagnostics.error("antivirus.SnortScan", "worker threw: ${it.javaClass.simpleName}: ${it.message}")
            Result.success() // never a retry storm; next period tries again
        }
    }

    private fun scan(): Result {
        SnortRuleStore.ensureLoaded(applicationContext)
        val rules = SnortRuleStore.rules()
        if (rules.isEmpty()) {
            Diagnostics.log("antivirus.SnortScan", "no rules loaded; nothing to do")
            return Result.success()
        }

        val pm = applicationContext.packageManager
        val previous = loadStamps()
        val previousHits = SnortScanLog.load(applicationContext)?.hits ?: emptyList()
        val current = mutableMapOf<String, Long>()
        val hits = mutableListOf<SnortScanLog.Hit>()
        var scanned = 0

        for (app in pm.getInstalledApplications(0)) {
            val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val isUpdatedSystem = (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            if (isSystem && !isUpdatedSystem) continue
            if (app.packageName == applicationContext.packageName) continue

            val apk = app.sourceDir?.let(::File) ?: continue
            if (!apk.exists()) continue
            val stamp = runCatching {
                pm.getPackageInfo(app.packageName, 0).lastUpdateTime
            }.getOrNull() ?: continue
            current[app.packageName] = stamp

            // Incremental: unchanged since the last pass → keep old hits, skip.
            if (previous[app.packageName] == stamp) {
                hits += previousHits.filter { it.packageName == app.packageName }
                continue
            }

            scanned++
            val fired = runCatching {
                apk.inputStream().use { SnortRules.scanStream(it, rules, maxBytesPerApk) }
            }.getOrDefault(emptyList())
            for (h in fired) {
                hits += SnortScanLog.Hit(
                    packageName = app.packageName,
                    sid = h.rule.sid,
                    msg = h.rule.msg,
                    severity = h.rule.severity,
                )
            }
        }

        saveStamps(current)
        SnortScanLog.save(applicationContext, hits)

        val notable = hits.filter { it.severity == RiskRules.Severity.HIGH }
        if (notable.isNotEmpty() && PeriodicScan.alertsAllowed(applicationContext)) {
            ScanNotifier.postSnort(applicationContext, notable.map { it.packageName }.distinct())
        }
        Diagnostics.log(
            "antivirus.SnortScan",
            "pass done: $scanned rescanned of ${current.size}, ${hits.size} rule hits",
        )
        return Result.success()
    }

    private fun stampFile(): File =
        File(File(applicationContext.filesDir, "snort").apply { mkdirs() }, "scan-stamps.json")

    private fun loadStamps(): Map<String, Long> = runCatching {
        val f = stampFile()
        if (!f.exists()) return emptyMap()
        val obj = JSONObject(f.readText())
        val out = mutableMapOf<String, Long>()
        val keys = obj.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            out[k] = obj.getLong(k)
        }
        out
    }.getOrDefault(emptyMap())

    private fun saveStamps(map: Map<String, Long>) {
        runCatching {
            val obj = JSONObject()
            for ((k, v) in map) obj.put(k, v)
            stampFile().writeText(obj.toString())
        }
    }
}

/**
 * Persisted results of the last Snort pass, for the Definitions-tab status
 * card ("last pass: N hits") and for carrying forward hits on apps the
 * incremental pass skipped.
 */
internal object SnortScanLog {

    data class Hit(
        val packageName: String,
        val sid: Long,
        val msg: String,
        val severity: RiskRules.Severity,
    )

    data class Snapshot(val atMillis: Long, val hits: List<Hit>)

    private fun file(ctx: Context): File =
        File(File(ctx.filesDir, "snort").apply { mkdirs() }, "last-scan.json")

    fun save(ctx: Context, hits: List<Hit>) {
        runCatching {
            val arr = JSONArray()
            for (h in hits) {
                arr.put(
                    JSONObject()
                        .put("pkg", h.packageName)
                        .put("sid", h.sid)
                        .put("msg", h.msg)
                        .put("sev", h.severity.name),
                )
            }
            file(ctx).writeText(
                JSONObject().put("at", System.currentTimeMillis()).put("hits", arr).toString(),
            )
        }
    }

    fun load(ctx: Context): Snapshot? = runCatching {
        val f = file(ctx)
        if (!f.exists()) return null
        val obj = JSONObject(f.readText())
        val arr = obj.getJSONArray("hits")
        val hits = buildList {
            for (i in 0 until arr.length()) {
                val h = arr.getJSONObject(i)
                add(
                    Hit(
                        packageName = h.getString("pkg"),
                        sid = h.getLong("sid"),
                        msg = h.getString("msg"),
                        severity = RiskRules.Severity.valueOf(h.getString("sev")),
                    ),
                )
            }
        }
        Snapshot(obj.getLong("at"), hits)
    }.getOrNull()

}
