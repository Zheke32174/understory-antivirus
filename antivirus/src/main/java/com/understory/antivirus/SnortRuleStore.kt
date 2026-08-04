package com.understory.antivirus

import android.content.Context
import com.understory.security.Diagnostics
import java.io.File

/**
 * Holds the active Snort-format ruleset: the shipped seed
 * (`res/raw/snort_seed.rules`) plus an optional user-imported rules file.
 * Mirrors [BlocklistStore]'s shape (ensureLoaded / import / meta) but WITHOUT
 * a signature: community .rules feeds aren't signed, so — like
 * [AuxDatabases] — an import is trusted only as far as the user trusts the
 * feed, and the UI always shows how many rules came from where.
 *
 * Layout under `filesDir/snort/`:
 *   user.rules — the raw imported text (re-parsed on every load; a rule that
 *                no longer parses is skipped, never trusted)
 */
internal object SnortRuleStore {

    private const val DIR = "snort"
    private const val USER_FILE = "user.rules"

    /** Cap on an imported rules file. Community feeds are well under this. */
    const val MAX_IMPORT_BYTES = 8L * 1024 * 1024

    data class Meta(val seedCount: Int, val userCount: Int, val skipped: Int)

    sealed interface ImportResult {
        data class Imported(val meta: Meta) : ImportResult
        data object NoValidRules : ImportResult
        data object TooLarge : ImportResult
    }

    @Volatile private var loaded = false
    @Volatile private var rules: List<SnortRules.Rule> = emptyList()
    @Volatile private var meta: Meta? = null

    /** The combined active ruleset (seed + user), sid-deduped (user wins). */
    fun rules(): List<SnortRules.Rule> = rules

    fun meta(): Meta? = meta

    /**
     * Load seed + any stored user rules. Idempotent, cheap after first call.
     * MUST run off the main thread (reads resources + files).
     */
    @Synchronized
    fun ensureLoaded(ctx: Context) {
        if (loaded) return
        val seedText = runCatching {
            ctx.resources.openRawResource(R.raw.snort_seed).use { it.readBytes() }
                .toString(Charsets.UTF_8)
        }.getOrDefault("")
        val seed = SnortRules.parse(seedText)
        if (seed.rules.isEmpty()) {
            Diagnostics.error("antivirus.Snort", "seed ruleset unreadable or empty")
        }
        val userText = runCatching {
            File(File(ctx.filesDir, DIR), USER_FILE).takeIf { it.exists() }?.readText()
        }.getOrNull()
        val user = userText?.let { SnortRules.parse(it) }
        apply(seed, user)
        loaded = true
    }

    /**
     * Import a user rules file (raw Snort .rules text). Verified by parsing
     * BEFORE any on-disk change; zero valid rules → refused, previous state
     * intact. Replaces (not appends) the previous user ruleset — one clear
     * provenance line beats an unbounded pile of merged feeds.
     */
    @Synchronized
    fun importFrom(ctx: Context, bytes: ByteArray): ImportResult {
        ensureLoaded(ctx)
        if (bytes.size > MAX_IMPORT_BYTES) return ImportResult.TooLarge
        val text = bytes.toString(Charsets.UTF_8)
        val parsed = SnortRules.parse(text)
        if (parsed.rules.isEmpty()) return ImportResult.NoValidRules

        val dir = File(ctx.filesDir, DIR).apply { mkdirs() }
        val ok = runCatching {
            val tmp = File(dir, "$USER_FILE.tmp")
            tmp.writeText(text)
            if (File(dir, USER_FILE).exists()) File(dir, USER_FILE).delete()
            tmp.renameTo(File(dir, USER_FILE))
        }.getOrDefault(false)
        if (!ok) return ImportResult.NoValidRules

        val seedText = runCatching {
            ctx.resources.openRawResource(R.raw.snort_seed).use { it.readBytes() }
                .toString(Charsets.UTF_8)
        }.getOrDefault("")
        apply(SnortRules.parse(seedText), parsed)
        Diagnostics.log("antivirus.Snort", "imported user rules: ${parsed.rules.size} ok, ${parsed.skipped} skipped")
        return ImportResult.Imported(meta!!)
    }

    /** Drop the user ruleset, back to seed-only. */
    @Synchronized
    fun removeUserRules(ctx: Context) {
        ensureLoaded(ctx)
        runCatching { File(File(ctx.filesDir, DIR), USER_FILE).delete() }
        val seedText = runCatching {
            ctx.resources.openRawResource(R.raw.snort_seed).use { it.readBytes() }
                .toString(Charsets.UTF_8)
        }.getOrDefault("")
        apply(SnortRules.parse(seedText), null)
        Diagnostics.log("antivirus.Snort", "user rules removed")
    }

    private fun apply(seed: SnortRules.ParseOutcome, user: SnortRules.ParseOutcome?) {
        // sid-dedup, user rules win (they can supersede a seed rule's rev).
        val bySid = LinkedHashMap<Long, SnortRules.Rule>()
        for (r in seed.rules) bySid[r.sid] = r
        for (r in user?.rules.orEmpty()) bySid[r.sid] = r
        rules = bySid.values.toList()
        meta = Meta(
            seedCount = seed.rules.size,
            userCount = user?.rules?.size ?: 0,
            skipped = seed.skipped + (user?.skipped ?: 0),
        )
    }

    /** Test hook: reset in-memory state so tests get a fresh load. */
    @Synchronized
    internal fun resetForTest() {
        loaded = false
        rules = emptyList()
        meta = null
    }
}
