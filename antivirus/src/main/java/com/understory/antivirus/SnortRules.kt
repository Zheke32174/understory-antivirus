package com.understory.antivirus

import java.io.InputStream

/**
 * Snort-rule-subset engine for PASSIVE content scanning.
 *
 * Honesty first: a rootless Android app cannot capture packets, so this is NOT
 * a network IDS. What it is: a signature scanner that understands the Snort
 * rule *format* — the de-facto lingua franca for community threat signatures —
 * and applies each rule's content matchers passively (read-only) to bytes
 * already on the device (installed APK files). That lets users carry
 * Android-relevant signatures from Snort-format community feeds without a new
 * bespoke format, and lets the suite ship a seed ruleset in a format security
 * people already know how to audit.
 *
 * Supported subset (everything else in a rule body is ignored, header fields
 * are parsed for shape but carry no meaning off-wire):
 *   - `msg:"..."`             the finding title
 *   - `content:"..."`         literal matcher; `|de ad be ef|` hex segments;
 *                             multiple contents AND together
 *   - `nocase`                case-insensitive ASCII for the preceding content
 *   - `pcre:"/re/flags"`      Java-regex compiled; flags i/s/m honored
 *   - `classtype:<name>`      mapped to a severity via Snort's priority table
 *   - `sid:<n>` / `rev:<n>`   identity for dedup and display
 *
 * Parsing is fail-soft per rule (a malformed rule is skipped and counted) and
 * bounded everywhere: content patterns cap at [MAX_PATTERN_BYTES], a rule
 * without sid or msg is refused, comment/blank lines skipped.
 */
object SnortRules {

    /** Longest content pattern accepted — also the stream-scan overlap size. */
    const val MAX_PATTERN_BYTES = 1024

    /** Cap on rules loaded at once (seed + user imports). */
    const val MAX_RULES = 20_000

    /** One compiled content matcher. */
    data class Content(val bytes: ByteArray, val noCase: Boolean) {
        override fun equals(other: Any?): Boolean =
            other is Content && noCase == other.noCase && bytes.contentEquals(other.bytes)
        override fun hashCode(): Int = 31 * bytes.contentHashCode() + noCase.hashCode()
    }

    /** One parsed rule. [pcre] patterns are pre-compiled Java regexes. */
    data class Rule(
        val sid: Long,
        val rev: Int,
        val msg: String,
        val classtype: String?,
        val severity: RiskRules.Severity,
        val contents: List<Content>,
        val pcre: List<Regex>,
    )

    data class ParseOutcome(val rules: List<Rule>, val skipped: Int)

    /**
     * Snort classtype → severity. Snort assigns classtypes priority 1..4;
     * priority-1 attack classes read as HIGH (advisory heuristics never claim
     * CRITICAL — that band is reserved for deny-list certainty), priority-2 as
     * MED, everything else LOW. Unknown/absent classtype defaults MED — the
     * rule author bothered to write a signature, but we can't rank it.
     */
    private val CLASSTYPE_SEVERITY = mapOf(
        // priority 1
        "trojan-activity" to RiskRules.Severity.HIGH,
        "malware-cnc" to RiskRules.Severity.HIGH,
        "command-and-control" to RiskRules.Severity.HIGH,
        "attempted-admin" to RiskRules.Severity.HIGH,
        "attempted-user" to RiskRules.Severity.HIGH,
        "shellcode-detect" to RiskRules.Severity.HIGH,
        "successful-admin" to RiskRules.Severity.HIGH,
        "successful-user" to RiskRules.Severity.HIGH,
        "credential-theft" to RiskRules.Severity.HIGH,
        // priority 2
        "policy-violation" to RiskRules.Severity.MED,
        "misc-attack" to RiskRules.Severity.MED,
        "suspicious-filename-detect" to RiskRules.Severity.MED,
        "suspicious-login" to RiskRules.Severity.MED,
        "bad-unknown" to RiskRules.Severity.MED,
        // priority 3+
        "misc-activity" to RiskRules.Severity.LOW,
        "not-suspicious" to RiskRules.Severity.LOW,
        "network-scan" to RiskRules.Severity.LOW,
        "protocol-command-decode" to RiskRules.Severity.LOW,
    )

    /**
     * Parse a Snort rules file. Rules may wrap lines with a trailing `\`
     * (Snort continuation syntax). Fail-soft per rule; the outcome reports how
     * many were skipped so the UI can be honest about partial imports.
     */
    fun parse(text: String): ParseOutcome {
        val rules = mutableListOf<Rule>()
        var skipped = 0
        val logical = StringBuilder()
        val lines = text.lineSequence().iterator()
        while (lines.hasNext()) {
            var line = lines.next().trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            // Continuation: join `\`-terminated lines into one logical rule.
            logical.setLength(0)
            while (line.endsWith("\\")) {
                logical.append(line.dropLast(1)).append(' ')
                line = if (lines.hasNext()) lines.next().trim() else ""
            }
            logical.append(line)
            val rule = runCatching { parseRule(logical.toString()) }.getOrNull()
            if (rule == null) skipped++
            else if (rules.size < MAX_RULES) rules += rule
        }
        return ParseOutcome(rules, skipped)
    }

    /** Parse one logical rule line; throws on any violation (caller counts it). */
    private fun parseRule(line: String): Rule {
        val open = line.indexOf('(')
        val close = line.lastIndexOf(')')
        require(open > 0 && close > open) { "no rule body" }
        val header = line.substring(0, open).trim()
        // Header shape check only — action + at least protocol. Off-wire, the
        // address/port/direction fields carry no meaning here.
        val headerParts = header.split(Regex("\\s+"))
        require(headerParts.size >= 2) { "malformed header" }
        require(headerParts[0] == "alert") { "only alert rules are used" }

        val body = line.substring(open + 1, close)
        var msg: String? = null
        var sid: Long? = null
        var rev = 1
        var classtype: String? = null
        val contents = mutableListOf<Content>()
        val pcre = mutableListOf<Regex>()

        for (opt in splitOptions(body)) {
            val colon = opt.indexOf(':')
            val key = (if (colon >= 0) opt.substring(0, colon) else opt).trim()
            val value = if (colon >= 0) opt.substring(colon + 1).trim() else ""
            when (key) {
                "msg" -> msg = unquote(value)
                "sid" -> sid = value.toLong()
                "rev" -> rev = value.toInt()
                "classtype" -> classtype = value
                "content" -> contents += Content(contentBytes(unquote(value)), noCase = false)
                "nocase" -> {
                    require(contents.isNotEmpty()) { "nocase before any content" }
                    val last = contents.removeAt(contents.size - 1)
                    contents += Content(last.bytes, noCase = true)
                }
                "pcre" -> pcre += compilePcre(unquote(value))
                else -> Unit // unsupported option — ignored, not an error
            }
        }
        require(!msg.isNullOrBlank()) { "rule without msg" }
        require(sid != null) { "rule without sid" }
        require(contents.isNotEmpty() || pcre.isNotEmpty()) { "rule with no matcher" }
        contents.forEach {
            require(it.bytes.isNotEmpty() && it.bytes.size <= MAX_PATTERN_BYTES) { "content size" }
        }
        return Rule(
            sid = sid,
            rev = rev,
            msg = msg,
            classtype = classtype,
            severity = CLASSTYPE_SEVERITY[classtype] ?: RiskRules.Severity.MED,
            contents = contents,
            pcre = pcre,
        )
    }

    /**
     * Split a rule body on `;` — but not inside a quoted string, where Snort
     * allows `\;` escapes and literal semicolons never occur unescaped.
     */
    private fun splitOptions(body: String): List<String> {
        val out = mutableListOf<String>()
        val cur = StringBuilder()
        var inQuote = false
        var escaped = false
        for (c in body) {
            when {
                escaped -> { cur.append(c); escaped = false }
                c == '\\' && inQuote -> { cur.append(c); escaped = true }
                c == '"' -> { cur.append(c); inQuote = !inQuote }
                c == ';' && !inQuote -> { out += cur.toString().trim(); cur.setLength(0) }
                else -> cur.append(c)
            }
        }
        if (cur.isNotBlank()) out += cur.toString().trim()
        return out.filter { it.isNotEmpty() }
    }

    private fun unquote(s: String): String {
        val t = s.trim()
        require(t.length >= 2 && t.first() == '"' && t.last() == '"') { "expected quoted value" }
        // Unescape \" \\ \; (the escapes Snort defines inside quoted strings).
        val inner = t.substring(1, t.length - 1)
        val out = StringBuilder(inner.length)
        var i = 0
        while (i < inner.length) {
            val c = inner[i]
            if (c == '\\' && i + 1 < inner.length) {
                out.append(inner[i + 1]); i += 2
            } else {
                out.append(c); i++
            }
        }
        return out.toString()
    }

    /**
     * A Snort content string with optional `|hex hex|` segments →
     * the literal byte pattern. Text outside pipes is Latin-1 bytes.
     */
    fun contentBytes(content: String): ByteArray {
        val out = ArrayList<Byte>(content.length)
        var i = 0
        var inHex = false
        val hexBuf = StringBuilder()
        while (i < content.length) {
            val c = content[i]
            if (c == '|') {
                if (inHex) {
                    val cleaned = hexBuf.toString().replace(" ", "")
                    require(cleaned.length % 2 == 0) { "odd hex segment" }
                    var j = 0
                    while (j < cleaned.length) {
                        out += cleaned.substring(j, j + 2).toInt(16).toByte()
                        j += 2
                    }
                    hexBuf.setLength(0)
                }
                inHex = !inHex
            } else if (inHex) {
                require(c.isDigit() || c in 'a'..'f' || c in 'A'..'F' || c == ' ') { "bad hex char" }
                hexBuf.append(c)
            } else {
                out += c.code.toByte()
            }
            i++
        }
        require(!inHex) { "unterminated hex segment" }
        return out.toByteArray()
    }

    /** `/regex/flags` → compiled Java [Regex]; i/s/m honored, others ignored. */
    private fun compilePcre(v: String): Regex {
        require(v.length >= 2 && v.first() == '/') { "pcre must be /re/flags" }
        val lastSlash = v.lastIndexOf('/')
        require(lastSlash > 0) { "pcre must be /re/flags" }
        val pattern = v.substring(1, lastSlash)
        val flags = v.substring(lastSlash + 1)
        val opts = mutableSetOf<RegexOption>()
        if ('i' in flags) opts += RegexOption.IGNORE_CASE
        if ('s' in flags) opts += RegexOption.DOT_MATCHES_ALL
        if ('m' in flags) opts += RegexOption.MULTILINE
        return Regex(pattern, opts)
    }

    // ------------------------------------------------------------------
    // Matching
    // ------------------------------------------------------------------

    /** One rule that fired against a scanned byte source. */
    data class Hit(val rule: Rule)

    /**
     * Scan a stream against [rules] in bounded chunks. A rule fires when ALL
     * of its content patterns and pcres have matched somewhere in the stream
     * (whole-stream AND, no proximity semantics — honest simplification of
     * Snort's within/distance, which we don't parse). Chunks overlap by
     * [MAX_PATTERN_BYTES] so no literal pattern is lost on a chunk boundary;
     * pcre matches are per-chunk (a regex spanning a boundary can be missed —
     * bounded memory is worth that documented miss).
     *
     * Reads at most [maxBytes]; the caller decides the budget per file.
     */
    fun scanStream(
        input: InputStream,
        rules: List<Rule>,
        maxBytes: Long = 64L * 1024 * 1024,
        chunkSize: Int = 1 shl 20,
    ): List<Hit> {
        if (rules.isEmpty()) return emptyList()
        // matchedContents[r] tracks which of rule r's matchers hit so far.
        val contentDone = Array(rules.size) { BooleanArray(rules[it].contents.size) }
        val pcreDone = Array(rules.size) { BooleanArray(rules[it].pcre.size) }

        val buf = ByteArray(chunkSize + MAX_PATTERN_BYTES)
        var carry = 0 // bytes retained from the previous chunk (overlap)
        var total = 0L
        while (total < maxBytes) {
            val want = minOf(chunkSize.toLong(), maxBytes - total).toInt()
            val n = readFully(input, buf, carry, want)
            if (n <= 0) break
            total += n
            val window = carry + n

            // Latin-1 keeps a 1:1 byte→char map, so byte-oriented patterns
            // behave predictably. Decoded at most once per chunk, only when
            // some rule actually carries a pcre.
            var text: String? = null
            for ((ri, rule) in rules.withIndex()) {
                for ((ci, c) in rule.contents.withIndex()) {
                    if (!contentDone[ri][ci] && indexOf(buf, window, c) >= 0) {
                        contentDone[ri][ci] = true
                    }
                }
                if (rule.pcre.isNotEmpty()) {
                    val t = text ?: String(buf, 0, window, Charsets.ISO_8859_1).also { text = it }
                    for ((pi, re) in rule.pcre.withIndex()) {
                        if (!pcreDone[ri][pi] && re.containsMatchIn(t)) {
                            pcreDone[ri][pi] = true
                        }
                    }
                }
            }

            // Retain the tail as overlap for boundary-straddling patterns.
            carry = minOf(MAX_PATTERN_BYTES, window)
            System.arraycopy(buf, window - carry, buf, 0, carry)
        }

        val hits = mutableListOf<Hit>()
        for ((ri, rule) in rules.withIndex()) {
            if (contentDone[ri].all { it } && pcreDone[ri].all { it }) hits += Hit(rule)
        }
        return hits
    }

    private fun readFully(input: InputStream, buf: ByteArray, offset: Int, want: Int): Int {
        var got = 0
        while (got < want) {
            val n = input.read(buf, offset + got, want - got)
            if (n < 0) break
            got += n
        }
        return got
    }

    /** Naive search of [c] in buf[0, len) — patterns are short, files chunked. */
    private fun indexOf(buf: ByteArray, len: Int, c: Content): Int {
        val pat = c.bytes
        if (pat.isEmpty() || pat.size > len) return -1
        val last = len - pat.size
        outer@ for (i in 0..last) {
            for (j in pat.indices) {
                val a = buf[i + j]
                val b = pat[j]
                if (a == b) continue
                if (c.noCase && asciiLower(a) == asciiLower(b)) continue
                continue@outer
            }
            return i
        }
        return -1
    }

    private fun asciiLower(b: Byte): Byte =
        if (b >= 'A'.code.toByte() && b <= 'Z'.code.toByte()) (b + 32).toByte() else b
}
