package com.understory.antivirus

import android.content.Context
import com.understory.security.Diagnostics
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * VirusTotal v3 integration — the suite's ONLY network feature in this app,
 * and strictly opt-in ("zero network unless explicitly opted in", the suite
 * constitution). The network path is dead until the user pastes their own
 * API key AND flips the enable toggle; there is no default key, no telemetry,
 * no background sync beyond the periodic lookup the user turns on.
 *
 * Privacy shape: HASH LOOKUP ONLY (`GET /api/v3/files/{sha256}`). We never
 * upload an APK — uploading would hand the file (and anything personal inside
 * it) to a third party. A hash lookup discloses only "this device asked about
 * this hash", which the opt-in text says plainly.
 *
 * Results are cached on disk ([filesDir]/vt/cache.json) so repeat scans are
 * free and the periodic worker respects the free-tier budget (4 req/min) —
 * see [VtScanWorker] for the throttle.
 */
internal object VirusTotal {

    private const val PREFS = "antivirus_vt"
    private const val KEY_API = "vt_api_key"
    private const val KEY_ENABLED = "vt_enabled"
    private const val DIR = "vt"
    private const val CACHE = "cache.json"

    /** A lookup's cached verdict for one file hash. */
    data class Verdict(
        val sha256: String,
        /** Engines flagging the hash malicious. */
        val malicious: Int,
        /** Engines flagging it suspicious. */
        val suspicious: Int,
        /** Total engines that returned a result. */
        val total: Int,
        /** VT's meaningful name for the file, when present. */
        val name: String?,
        val checkedAtMillis: Long,
    ) {
        val flagged: Boolean get() = malicious > 0
    }

    sealed interface LookupResult {
        data class Found(val verdict: Verdict) : LookupResult
        /** VT has never seen this hash — a common, honest outcome. */
        data object NotKnown : LookupResult
        data object BadApiKey : LookupResult
        data object RateLimited : LookupResult
        data class Error(val detail: String) : LookupResult
    }

    // --- opt-in state ---

    fun isConfigured(ctx: Context): Boolean = apiKey(ctx).isNotEmpty()

    fun isEnabled(ctx: Context): Boolean =
        prefs(ctx).getBoolean(KEY_ENABLED, false) && isConfigured(ctx)

    fun setEnabled(ctx: Context, enabled: Boolean) {
        prefs(ctx).edit().putBoolean(KEY_ENABLED, enabled).apply()
        Diagnostics.log("antivirus.VT", "setEnabled=$enabled")
    }

    fun apiKey(ctx: Context): String = prefs(ctx).getString(KEY_API, "") ?: ""

    fun setApiKey(ctx: Context, key: String) {
        prefs(ctx).edit().putString(KEY_API, key.trim()).apply()
        if (key.isBlank()) setEnabled(ctx, false)
        Diagnostics.log("antivirus.VT", "api key ${if (key.isBlank()) "cleared" else "set"}")
    }

    // --- lookup ---

    /**
     * Look up [sha256] on VirusTotal. MUST run off the main thread. Checks the
     * cache first unless [forceNetwork]; caches every Found/NotKnown outcome.
     * No-ops to [LookupResult.Error] when the feature is disabled — callers
     * gate on [isEnabled], this is the belt-and-braces second gate.
     */
    fun lookup(ctx: Context, sha256: String, forceNetwork: Boolean = false): LookupResult {
        if (!isEnabled(ctx)) return LookupResult.Error("VirusTotal is not enabled")
        val key = sha256.lowercase()
        if (!forceNetwork) {
            cached(ctx, key)?.let { return LookupResult.Found(it) }
        }
        return when (val fetched = fetch(ctx, key)) {
            is LookupResult.Found -> {
                cachePut(ctx, fetched.verdict)
                fetched
            }
            is LookupResult.NotKnown -> {
                // Cache the miss too (as a 0/0 verdict) so the periodic worker
                // doesn't burn budget re-asking about the same unknown hash.
                cachePut(
                    ctx,
                    Verdict(key, 0, 0, 0, null, System.currentTimeMillis()),
                )
                fetched
            }
            else -> fetched
        }
    }

    /** The cached verdict for [sha256], if any. Never touches the network. */
    fun cached(ctx: Context, sha256: String): Verdict? {
        val obj = readCache(ctx).optJSONObject(sha256.lowercase()) ?: return null
        return runCatching { verdictFromCacheEntry(sha256.lowercase(), obj) }.getOrNull()
    }

    /**
     * Parse a VT v3 `files/{hash}` response body into a [Verdict]. Pure
     * function, unit-tested. Throws on a body that isn't a VT file object.
     */
    fun parseResponse(sha256: String, body: String, nowMillis: Long): Verdict {
        val attrs = JSONObject(body)
            .getJSONObject("data")
            .getJSONObject("attributes")
        val stats = attrs.getJSONObject("last_analysis_stats")
        val malicious = stats.optInt("malicious", 0)
        val suspicious = stats.optInt("suspicious", 0)
        val total = malicious + suspicious +
            stats.optInt("harmless", 0) + stats.optInt("undetected", 0)
        return Verdict(
            sha256 = sha256.lowercase(),
            malicious = malicious,
            suspicious = suspicious,
            total = total,
            name = attrs.optString("meaningful_name").takeIf { it.isNotEmpty() },
            checkedAtMillis = nowMillis,
        )
    }

    /**
     * A short advisory note for a report when the cache already knows this
     * hash is flagged. Advisory by design: VT engine counts are third-party
     * opinion, not the suite deny-list — so this feeds notes, not KNOWN_BAD.
     */
    fun cachedVerdictNote(ctx: Context, sha256: String?): String? {
        if (sha256 == null || !isEnabled(ctx)) return null
        val v = cached(ctx, sha256) ?: return null
        if (!v.flagged) return null
        val named = v.name?.let { " ($it)" } ?: ""
        return "VirusTotal: ${v.malicious} of ${v.total} engines flag this file$named. " +
            "Third-party opinion, not a suite verdict — but treat a multi-engine " +
            "hit seriously."
    }

    // --- internals ---

    private fun fetch(ctx: Context, sha256: String): LookupResult {
        val conn = runCatching {
            URL("https://www.virustotal.com/api/v3/files/$sha256")
                .openConnection() as HttpURLConnection
        }.getOrElse { return LookupResult.Error("connection failed: ${it.message}") }
        return try {
            conn.requestMethod = "GET"
            conn.connectTimeout = 15_000
            conn.readTimeout = 15_000
            conn.setRequestProperty("x-apikey", apiKey(ctx))
            conn.setRequestProperty("Accept", "application/json")
            when (val code = conn.responseCode) {
                200 -> {
                    val body = conn.inputStream.bufferedReader().use { it.readText() }
                    runCatching {
                        LookupResult.Found(parseResponse(sha256, body, System.currentTimeMillis()))
                    }.getOrElse { LookupResult.Error("unparseable response") }
                }
                404 -> LookupResult.NotKnown
                401, 403 -> LookupResult.BadApiKey
                429 -> LookupResult.RateLimited
                else -> LookupResult.Error("HTTP $code")
            }
        } catch (t: Throwable) {
            LookupResult.Error("${t.javaClass.simpleName}: ${t.message}")
        } finally {
            conn.disconnect()
        }
    }

    private fun cacheFile(ctx: Context): File =
        File(File(ctx.filesDir, DIR).apply { mkdirs() }, CACHE)

    private fun readCache(ctx: Context): JSONObject = runCatching {
        val f = cacheFile(ctx)
        if (f.exists()) JSONObject(f.readText()) else JSONObject()
    }.getOrDefault(JSONObject())

    @Synchronized
    private fun cachePut(ctx: Context, v: Verdict) {
        runCatching {
            val cache = readCache(ctx)
            cache.put(
                v.sha256,
                JSONObject()
                    .put("malicious", v.malicious)
                    .put("suspicious", v.suspicious)
                    .put("total", v.total)
                    .put("name", v.name ?: "")
                    .put("at", v.checkedAtMillis),
            )
            cacheFile(ctx).writeText(cache.toString())
        }
    }

    private fun verdictFromCacheEntry(sha256: String, obj: JSONObject): Verdict =
        Verdict(
            sha256 = sha256,
            malicious = obj.getInt("malicious"),
            suspicious = obj.getInt("suspicious"),
            total = obj.getInt("total"),
            name = obj.optString("name").takeIf { it.isNotEmpty() },
            checkedAtMillis = obj.getLong("at"),
        )

    private fun prefs(ctx: Context) =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
