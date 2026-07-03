package com.understory.antivirus

import android.content.Context
import com.understory.security.Diagnostics
import org.json.JSONObject
import java.io.File

/**
 * Persists and caches the active signed blocklist. On first run, if no
 * imported file exists, the built-in seed (`res/raw/blocklist_seed.ubl`) is
 * loaded. Every load RE-VERIFIES the stored bytes through [BlocklistCodec] so
 * a file tampered-at-rest is caught, not trusted.
 *
 * Layout under `filesDir/blocklist/`:
 *   active.ubl   — the raw signed bytes currently in force
 *   meta.json    — {serial, issued, apkCount, certCount} for the UI status line
 *
 * The two hash sets are cached in memory after load so [KnownBad]'s per-app
 * lookups are O(1) and the audit path only pays SHA-256 when the sets are
 * non-empty (see [ApkAnalyzer]). Atomic replace (write tmp, rename) mirrors
 * the vault engines' pattern.
 */
internal object BlocklistStore {

    private const val DIR = "blocklist"
    private const val ACTIVE = "active.ubl"
    private const val META = "meta.json"

    /** Snapshot the UI reads for its status line. */
    data class Meta(
        val serial: Int,
        val issued: String,
        val apkCount: Int,
        val certCount: Int,
        /** True when the active file is the shipped seed, not a user import. */
        val isSeed: Boolean,
    )

    @Volatile private var loaded = false
    @Volatile private var apkSet: Set<String> = emptySet()
    @Volatile private var certSet: Set<String> = emptySet()
    @Volatile private var labels: Map<String, String> = emptyMap()
    @Volatile private var meta: Meta? = null

    /** Cached APK-hash deny-list (lowercase hex). */
    fun apkHashes(): Set<String> = apkSet

    /** Cached signing-cert deny-list (lowercase hex). */
    fun certHashes(): Set<String> = certSet

    /** Human-readable name for a matched hash, if the definitions carried one. */
    fun label(sha256: String): String? = labels[sha256.lowercase()]

    /** Status snapshot for the home-screen definitions line; null before load. */
    fun meta(): Meta? = meta

    /**
     * Ensure the store is loaded. Idempotent and cheap after the first call.
     * MUST run off the main thread (reads files + re-verifies a signature) —
     * callers use [com.understory.security.ui.Bg.io].
     */
    @Synchronized
    fun ensureLoaded(ctx: Context) {
        if (loaded) return
        val dir = File(ctx.filesDir, DIR)
        val active = File(dir, ACTIVE)
        if (active.exists()) {
            if (applyBytes(active.readBytes(), isSeed = !hasUserMeta(dir))) {
                loaded = true
                return
            }
            // Stored file failed re-verification (tampered at rest) — drop it
            // and fall back to the seed, never trust a bad file.
            Diagnostics.error("antivirus.Blocklist", "active.ubl failed re-verify; falling back to seed")
            runCatching { active.delete() }
            runCatching { File(dir, META).delete() }
        }
        loadSeed(ctx)
        loaded = true
    }

    /**
     * Import a user-supplied definitions file. Returns the outcome so the UI
     * can render the honest result card. The bytes are verified before any
     * on-disk state changes; a failure leaves the previous definitions intact.
     *
     * @param allowOlder when false (default), a serial ≤ the installed serial
     *   is refused (anti-rollback) and reported as [ImportResult.OlderSerial].
     */
    @Synchronized
    fun importFrom(ctx: Context, bytes: ByteArray, allowOlder: Boolean = false): ImportResult {
        ensureLoaded(ctx)
        val parsed = BlocklistCodec.verifyAndParse(bytes)
        val payload = parsed.payload
            ?: return ImportResult.Rejected(parsed.failure ?: BlocklistCodec.Failure.MALFORMED)

        val currentSerial = meta?.serial ?: -1
        if (!allowOlder && payload.serial <= currentSerial) {
            return ImportResult.OlderSerial(payload.serial, currentSerial)
        }

        val dir = File(ctx.filesDir, DIR).apply { mkdirs() }
        val ok = writeAtomic(File(dir, ACTIVE), bytes) &&
            writeAtomic(File(dir, META), metaJson(payload, userImport = true).toByteArray())
        if (!ok) return ImportResult.Rejected(BlocklistCodec.Failure.MALFORMED)

        apply(payload, isSeed = false)
        Diagnostics.log("antivirus.Blocklist", "imported serial=${payload.serial} apks=${payload.apkSha256.size} certs=${payload.certSha256.size}")
        return ImportResult.Imported(meta!!)
    }

    /** Outcome of an [importFrom] call — one honest UI state each. */
    sealed interface ImportResult {
        data class Imported(val meta: Meta) : ImportResult
        data class OlderSerial(val incoming: Int, val installed: Int) : ImportResult
        data class Rejected(val reason: BlocklistCodec.Failure) : ImportResult
    }

    // --- internals ---

    private fun loadSeed(ctx: Context) {
        val seed = runCatching {
            ctx.resources.openRawResource(R.raw.blocklist_seed).use { it.readBytes() }
        }.getOrNull()
        if (seed == null) {
            Diagnostics.error("antivirus.Blocklist", "seed resource unreadable")
            apply(emptyPayload(), isSeed = true)
            return
        }
        if (!applyBytes(seed, isSeed = true)) {
            Diagnostics.error("antivirus.Blocklist", "seed failed verification")
            apply(emptyPayload(), isSeed = true)
        }
    }

    /** Verify+apply raw bytes; returns false if verification failed. */
    private fun applyBytes(bytes: ByteArray, isSeed: Boolean): Boolean {
        val parsed = BlocklistCodec.verifyAndParse(bytes)
        val payload = parsed.payload ?: return false
        apply(payload, isSeed)
        return true
    }

    private fun apply(payload: BlocklistCodec.BlocklistPayload, isSeed: Boolean) {
        apkSet = payload.apkSha256
        certSet = payload.certSha256
        labels = payload.labels
        meta = Meta(
            serial = payload.serial,
            issued = payload.issued,
            apkCount = payload.apkSha256.size,
            certCount = payload.certSha256.size,
            isSeed = isSeed,
        )
    }

    private fun hasUserMeta(dir: File): Boolean = runCatching {
        val m = File(dir, META)
        m.exists() && JSONObject(m.readText()).optBoolean("userImport", false)
    }.getOrDefault(false)

    private fun metaJson(p: BlocklistCodec.BlocklistPayload, userImport: Boolean): String =
        JSONObject().apply {
            put("serial", p.serial)
            put("issued", p.issued)
            put("apkCount", p.apkSha256.size)
            put("certCount", p.certSha256.size)
            put("userImport", userImport)
        }.toString()

    private fun writeAtomic(target: File, bytes: ByteArray): Boolean = runCatching {
        val tmp = File(target.parentFile, target.name + ".tmp")
        tmp.writeBytes(bytes)
        if (target.exists()) target.delete()
        tmp.renameTo(target)
    }.getOrDefault(false)

    private fun emptyPayload() = BlocklistCodec.BlocklistPayload(
        schema = 1, issued = "unknown", serial = 0,
        apkSha256 = emptySet(), certSha256 = emptySet(), labels = emptyMap(),
    )
}
