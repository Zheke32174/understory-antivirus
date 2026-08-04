package com.understory.antivirus

import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.understory.security.Diagnostics
import com.understory.security.ui.Bg
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest

/**
 * Periodic VirusTotal hash-lookup check (opt-in twice over: the VT feature
 * itself must be enabled with a user key, AND this periodic check has its own
 * toggle — see [ScanSchedules]).
 *
 * Scope is deliberately narrow: only SIDELOADED user apps are looked up (a
 * store-installed app's hash tells VT little and burns quota; sideloads are
 * the actual threat surface this app exists for). Hash-only, never an upload.
 * Cached verdicts are skipped, lookups are throttled to respect the free-tier
 * 4 req/min, and a run is capped at [MAX_LOOKUPS_PER_RUN] so the worker's
 * budget stays bounded no matter how many sideloads a device carries.
 */
class VtScanWorker(
    ctx: Context,
    params: WorkerParameters,
) : CoroutineWorker(ctx, params) {

    private companion object {
        /** Free-tier VT is 4 req/min — 16s spacing keeps safely under it. */
        const val THROTTLE_MS = 16_000L

        /** Per-run lookup cap; the rest wait for the next period. */
        const val MAX_LOOKUPS_PER_RUN = 12
    }

    override suspend fun doWork(): Result = withContext(Bg.io) {
        runCatching { scan() }.getOrElse {
            Diagnostics.error("antivirus.VtScan", "worker threw: ${it.javaClass.simpleName}: ${it.message}")
            Result.success()
        }
    }

    private suspend fun scan(): Result {
        val ctx = applicationContext
        if (!VirusTotal.isEnabled(ctx)) {
            Diagnostics.log("antivirus.VtScan", "VT disabled; nothing to do")
            return Result.success()
        }

        val pm = ctx.packageManager
        val flagged = mutableListOf<VirusTotal.Verdict>()
        var lookups = 0

        for (app in pm.getInstalledApplications(0)) {
            if (lookups >= MAX_LOOKUPS_PER_RUN) break
            val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val isUpdatedSystem = (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            if (isSystem && !isUpdatedSystem) continue
            if (app.packageName == ctx.packageName) continue
            if (!isSideloaded(ctx, app.packageName)) continue

            val apk = app.sourceDir?.let(::File) ?: continue
            if (!apk.exists()) continue
            val sha = sha256(apk) ?: continue

            // Cached (hit or known-miss) → free; only real network calls count
            // against the throttle and the per-run cap.
            val cachedBefore = VirusTotal.cached(ctx, sha)
            val result = VirusTotal.lookup(ctx, sha)
            if (cachedBefore == null) {
                lookups++
                delay(THROTTLE_MS)
            }
            when (result) {
                is VirusTotal.LookupResult.Found ->
                    if (result.verdict.flagged) flagged += result.verdict
                is VirusTotal.LookupResult.BadApiKey -> {
                    Diagnostics.error("antivirus.VtScan", "API key rejected; stopping run")
                    return Result.success()
                }
                is VirusTotal.LookupResult.RateLimited -> {
                    Diagnostics.log("antivirus.VtScan", "rate limited; stopping run")
                    return Result.success()
                }
                else -> Unit
            }
        }

        if (flagged.isNotEmpty() && PeriodicScan.alertsAllowed(ctx)) {
            ScanNotifier.postVt(ctx, flagged.size)
        }
        Diagnostics.log("antivirus.VtScan", "run done: $lookups lookups, ${flagged.size} flagged")
        return Result.success()
    }

    /** Same trusted-installer read as [ApkAnalyzer]: null/unknown → sideload. */
    private fun isSideloaded(ctx: Context, pkg: String): Boolean = runCatching {
        val installer = ctx.packageManager.getInstallSourceInfo(pkg).installingPackageName
        installer == null || installer !in ApkAnalyzer.TRUSTED_INSTALLERS
    }.getOrDefault(false)

    private fun sha256(file: File): String? = runCatching {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(8192)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        md.digest().joinToString("") { "%02x".format(it) }
    }.getOrNull()
}
