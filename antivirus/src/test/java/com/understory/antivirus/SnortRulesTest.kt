package com.understory.antivirus

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

/**
 * Snort-subset parser + passive matcher: rule parsing (msg/sid/content/
 * nocase/hex/pcre/classtype), fail-soft skipping, and stream matching
 * including chunk-boundary overlap.
 */
class SnortRulesTest {

    private fun rule(body: String): SnortRules.Rule {
        val out = SnortRules.parse("alert tcp any any -> any any ($body)")
        assertEquals("expected 1 rule from: $body", 1, out.rules.size)
        return out.rules.first()
    }

    private fun scan(data: ByteArray, vararg rules: SnortRules.Rule): List<SnortRules.Hit> =
        SnortRules.scanStream(ByteArrayInputStream(data), rules.toList())

    // --- parsing ---

    @Test
    fun parse_basicRule() {
        val r = rule("""msg:"Evil marker"; content:"evil-string"; classtype:trojan-activity; sid:9100001; rev:2;""")
        assertEquals("Evil marker", r.msg)
        assertEquals(9100001L, r.sid)
        assertEquals(2, r.rev)
        assertEquals("trojan-activity", r.classtype)
        assertEquals(RiskRules.Severity.HIGH, r.severity)
        assertEquals(1, r.contents.size)
        assertArrayEquals("evil-string".toByteArray(), r.contents[0].bytes)
    }

    @Test
    fun parse_hexContent() {
        assertArrayEquals(
            byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte()),
            SnortRules.contentBytes("|de ad be ef|"),
        )
        assertArrayEquals(
            "AB".toByteArray() + byteArrayOf(0x00) + "CD".toByteArray(),
            SnortRules.contentBytes("AB|00|CD"),
        )
    }

    @Test
    fun parse_nocaseAppliesToPrecedingContent() {
        val r = rule("""msg:"m"; content:"MiXeD"; nocase; sid:1;""")
        assertTrue(r.contents[0].noCase)
    }

    @Test
    fun parse_classtypeSeverityMapping() {
        assertEquals(RiskRules.Severity.MED, rule("""msg:"m"; content:"x"; classtype:policy-violation; sid:2;""").severity)
        assertEquals(RiskRules.Severity.LOW, rule("""msg:"m"; content:"x"; classtype:misc-activity; sid:3;""").severity)
        // No classtype → MED default.
        assertEquals(RiskRules.Severity.MED, rule("""msg:"m"; content:"x"; sid:4;""").severity)
    }

    @Test
    fun parse_failSoftSkipsBadRules() {
        val text = """
            # comment
            alert tcp any any -> any any (msg:"good"; content:"ok"; sid:10;)
            not a rule at all
            alert tcp any any -> any any (content:"no msg or sid";)
            drop tcp any any -> any any (msg:"wrong action"; content:"x"; sid:11;)
        """.trimIndent()
        val out = SnortRules.parse(text)
        assertEquals(1, out.rules.size)
        assertEquals(3, out.skipped)
        assertEquals(10L, out.rules[0].sid)
    }

    @Test
    fun parse_escapedSemicolonInsideMsg() {
        val r = rule("""msg:"has \; semicolon"; content:"x"; sid:12;""")
        assertEquals("has ; semicolon", r.msg)
    }

    @Test
    fun parse_lineContinuation() {
        val text = "alert tcp any any -> any any (msg:\"wrapped\"; \\\n content:\"abc\"; sid:13;)"
        val out = SnortRules.parse(text)
        assertEquals(1, out.rules.size)
        assertEquals("wrapped", out.rules[0].msg)
    }

    @Test
    fun parse_ruleWithoutMatcherRefused() {
        val out = SnortRules.parse("""alert tcp any any -> any any (msg:"no matcher"; sid:14;)""")
        assertEquals(0, out.rules.size)
        assertEquals(1, out.skipped)
    }

    // --- matching ---

    @Test
    fun match_simpleContent() {
        val r = rule("""msg:"m"; content:"needle"; sid:20;""")
        assertEquals(1, scan("hay needle stack".toByteArray(), r).size)
        assertEquals(0, scan("no match here".toByteArray(), r).size)
    }

    @Test
    fun match_nocase() {
        val sensitive = rule("""msg:"m"; content:"Needle"; sid:21;""")
        val insensitive = rule("""msg:"m"; content:"Needle"; nocase; sid:22;""")
        val data = "find the NEEDLE now".toByteArray()
        assertEquals(0, scan(data, sensitive).size)
        assertEquals(1, scan(data, insensitive).size)
    }

    @Test
    fun match_multipleContentsAnd() {
        val r = rule("""msg:"m"; content:"alpha"; content:"omega"; sid:23;""")
        assertEquals(1, scan("alpha ... omega".toByteArray(), r).size)
        assertEquals(0, scan("alpha only".toByteArray(), r).size)
    }

    @Test
    fun match_hexBytes() {
        val r = rule("""msg:"m"; content:"|50 4b 03 04|"; sid:24;""")
        assertEquals(1, scan(byteArrayOf(0x00, 0x50, 0x4B, 0x03, 0x04, 0x7F), r).size)
    }

    @Test
    fun match_pcre() {
        val r = rule("""msg:"m"; pcre:"/exfil[0-9]{3}/i"; sid:25;""")
        assertEquals(1, scan("data EXFIL123 marker".toByteArray(), r).size)
        assertEquals(0, scan("exfil marker".toByteArray(), r).size)
    }

    @Test
    fun match_acrossChunkBoundary() {
        // Pattern straddles the 1 MiB chunk boundary — overlap must catch it.
        val chunk = 1 shl 20
        val data = ByteArray(chunk + 64) { 'a'.code.toByte() }
        val pat = "boundary-marker".toByteArray()
        System.arraycopy(pat, 0, data, chunk - 7, pat.size) // straddles
        val r = rule("""msg:"m"; content:"boundary-marker"; sid:26;""")
        assertEquals(1, scan(data, r).size)
    }

    @Test
    fun match_respectsMaxBytes() {
        val r = rule("""msg:"m"; content:"tail-secret"; sid:27;""")
        val data = ByteArray(4096) { 'x'.code.toByte() } + "tail-secret".toByteArray()
        val hits = SnortRules.scanStream(ByteArrayInputStream(data), listOf(r), maxBytes = 1024)
        assertEquals(0, hits.size)
    }

    @Test
    fun seedRuleset_parsesClean() {
        // Keep the shipped seed honest: every rule in it must parse.
        val seed = javaClass.classLoader!!
            .getResourceAsStream("res/raw/snort_seed.rules")
        // Robolectric resource path handling differs across setups; if the raw
        // resource isn't visible on this classpath the store-level test in
        // SnortRuleStoreTest covers it instead.
        if (seed != null) {
            val out = SnortRules.parse(seed.readBytes().toString(Charsets.UTF_8))
            assertTrue(out.rules.isNotEmpty())
            assertEquals(0, out.skipped)
        }
    }
}
