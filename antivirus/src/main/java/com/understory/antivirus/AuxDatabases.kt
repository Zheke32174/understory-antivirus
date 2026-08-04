package com.understory.antivirus

import android.content.Context
import com.understory.security.Diagnostics
import org.json.JSONObject
import java.io.File

/**
 * Auxiliary virus databases — additional hash deny-lists layered on top of the
 * signed `.ubl` blocklist ([BlocklistStore]). Where the .ubl file is the
 * curated, Ed25519-signed suite list, aux databases let the user import
 * third-party hash feeds (MalwareBazaar full dumps, abuse.ch exports, ClamAV
 * hash sets) as SEPARATE named databases, each with its own provenance line in
 * the UI and its own remove control.
 *
 * Imported files are NOT signed, so an aux match is surfaced with the database
 * name it came from and never silently merged into the signed list's identity.
 * The verdict weight is the same (KNOWN_BAD) — a user who imports a feed is
 * trusting that feed — but the provenance is always visible.
 *
 * Accepted line formats, auto-detected per line (mixable within one file):
 *   - `<sha256>`                      plain hash list (MalwareBazaar dump)
 *   - `<sha256>,<label>`              CSV hash,label
 *   - `<sha256>:<size>:<name>`        ClamAV .hsb style (size ignored)
 *   - `# comment` / blank             skipped
 * A line that is none of these is counted as skipped; a file where EVERY
 * non-comment line is malformed is rejected (probably not a hash list at all).
 *
 * Layout under `filesDir/auxdb/`: one `<id>.json` per database:
 *   {name, importedAt, hashes: {sha256: label|""}}
 *
 * All hashes are lowercase hex, 64 chars, all-zero sentinel rejected — same
 * discipline as [BlocklistCodec].
 */
internal object AuxDatabases {

    private const val DIR = "auxdb"

    /** Cap per database — a full MalwareBazaar dump is ~1M lines; cap above it. */
    const val MAX_ENTRIES = 2_000_000

    /** Cap on an import file's size (a 2M-line sha256 CSV is < 200 MiB). */
    const val MAX_IMPORT_BYTES = 256L * 1024 * 1024

    private const val ALL_ZERO_HASH =
        "0000000000000000000000000000000000000000000000000000000000000000"

    /** One database's status snapshot for the UI list. */
    data class Meta(
        val id: String,
        val name: String,
        val importedAt: String,
        val count: Int,
    )

    /** A deny-list hit: which database matched and its label (if any). */
    data class Match(val dbName: String, val label: String?)

    sealed interface ImportResult {
        /** [skipped] = malformed lines dropped (shown honestly in the UI). */
        data class Imported(val meta: Meta, val skipped: Int) : ImportResult
        data object NotAHashList : ImportResult
        data object TooLarge : ImportResult
    }

    @Volatile private var loaded = false
    @Volatile private var databases: Map<String, LoadedDb> = emptyMap()
    /** Monotonic suffix so two imports in the same millisecond never collide. */
    private var importSeq = 0

    private class LoadedDb(val meta: Meta, val hashes: Map<String, String>)

    /** Databases for the UI list, import-order stable. */
    fun list(): List<Meta> = databases.values.map { it.meta }

    /** Total entries across all aux databases (cheap pre-hash gate). */
    fun totalEntries(): Int = databases.values.sumOf { it.hashes.size }

    /**
     * Look up an APK SHA-256 across every aux database. First match wins;
     * the match names its source database so provenance is never lost.
     */
    fun matchApk(sha256: String): Match? {
        val key = sha256.lowercase()
        for (db in databases.values) {
            val label = db.hashes[key] ?: continue
            return Match(db.meta.name, label.ifEmpty { null })
        }
        return null
    }

    /**
     * Load every stored database into memory. Idempotent and cheap after the
     * first call. MUST run off the main thread (reads files) — callers use
     * [com.understory.security.ui.Bg.io]. A file that fails to parse is
     * dropped (logged), never trusted.
     */
    @Synchronized
    fun ensureLoaded(ctx: Context) {
        if (loaded) return
        val dir = File(ctx.filesDir, DIR)
        val out = LinkedHashMap<String, LoadedDb>()
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(".json") }
            ?.sortedBy { it.name } ?: emptyList()
        for (f in files) {
            val db = runCatching { readDb(f) }.getOrNull()
            if (db == null) {
                Diagnostics.error("antivirus.AuxDb", "unreadable aux db ${f.name}; dropping")
                runCatching { f.delete() }
                continue
            }
            out[db.meta.id] = db
        }
        databases = out
        loaded = true
    }

    /**
     * Import [bytes] as a new named database. Parsing is line-based and
     * fail-soft per line (a feed with a header row still imports) but
     * fail-closed per file (all-malformed → [ImportResult.NotAHashList]).
     * The previous databases are untouched on any failure.
     */
    @Synchronized
    fun import(ctx: Context, displayName: String, bytes: ByteArray, nowIso: String): ImportResult {
        ensureLoaded(ctx)
        if (bytes.size > MAX_IMPORT_BYTES) return ImportResult.TooLarge

        val hashes = LinkedHashMap<String, String>()
        var skipped = 0
        var sawContent = false
        bytes.inputStream().bufferedReader().forEachLine { raw ->
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) return@forEachLine
            sawContent = true
            val entry = parseLine(line)
            if (entry == null) {
                skipped++
            } else if (hashes.size < MAX_ENTRIES) {
                hashes.putIfAbsent(entry.first, entry.second)
            }
        }
        if (!sawContent || hashes.isEmpty()) return ImportResult.NotAHashList

        val id = "db-" + System.currentTimeMillis() + "-" + importSeq++
        val meta = Meta(id = id, name = displayName, importedAt = nowIso, count = hashes.size)
        val dir = File(ctx.filesDir, DIR).apply { mkdirs() }
        val ok = runCatching {
            val tmp = File(dir, "$id.json.tmp")
            tmp.writeText(dbJson(meta, hashes))
            tmp.renameTo(File(dir, "$id.json"))
        }.getOrDefault(false)
        if (!ok) return ImportResult.NotAHashList

        databases = databases + (id to LoadedDb(meta, hashes))
        Diagnostics.log("antivirus.AuxDb", "imported '$displayName' entries=${hashes.size} skipped=$skipped")
        return ImportResult.Imported(meta, skipped)
    }

    /** Remove one database by id. */
    @Synchronized
    fun remove(ctx: Context, id: String) {
        ensureLoaded(ctx)
        runCatching { File(File(ctx.filesDir, DIR), "$id.json").delete() }
        databases = databases - id
        Diagnostics.log("antivirus.AuxDb", "removed $id")
    }

    /**
     * Parse one line into (hash, label). Returns null on a malformed line.
     * Exposed internally for the unit tests.
     */
    fun parseLine(line: String): Pair<String, String>? {
        // ClamAV .hsb: sha256:size:name — check before CSV (colons, no comma).
        val colon = line.split(':')
        if (colon.size == 3) {
            val h = colon[0].lowercase()
            if (isHash64(h) && h != ALL_ZERO_HASH) return h to colon[2].trim()
            return null
        }
        val comma = line.indexOf(',')
        if (comma >= 0) {
            val h = line.substring(0, comma).trim().lowercase()
            if (isHash64(h) && h != ALL_ZERO_HASH) return h to line.substring(comma + 1).trim()
            return null
        }
        val h = line.lowercase()
        if (isHash64(h) && h != ALL_ZERO_HASH) return h to ""
        return null
    }

    // --- internals ---

    private fun readDb(f: File): LoadedDb {
        val obj = JSONObject(f.readText())
        val hashesObj = obj.getJSONObject("hashes")
        val hashes = LinkedHashMap<String, String>(hashesObj.length())
        val keys = hashesObj.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            val norm = k.lowercase()
            require(isHash64(norm)) { "malformed stored hash" }
            hashes[norm] = hashesObj.getString(k)
        }
        val id = f.name.removeSuffix(".json")
        return LoadedDb(
            Meta(
                id = id,
                name = obj.getString("name"),
                importedAt = obj.getString("importedAt"),
                count = hashes.size,
            ),
            hashes,
        )
    }

    private fun dbJson(meta: Meta, hashes: Map<String, String>): String =
        JSONObject().apply {
            put("name", meta.name)
            put("importedAt", meta.importedAt)
            put("hashes", JSONObject().apply { for ((h, l) in hashes) put(h, l) })
        }.toString()

    private fun isHash64(s: String): Boolean =
        s.length == 64 && s.all { it in '0'..'9' || it in 'a'..'f' }

    /** Test hook: reset in-memory state so Robolectric tests get a fresh load. */
    @Synchronized
    internal fun resetForTest() {
        loaded = false
        databases = emptyMap()
    }
}
