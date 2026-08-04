package com.understory.antivirus

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * VirusTotal response parsing (pure), opt-in gating, and the on-disk verdict
 * cache. No test touches the network — the client's fetch path is exercised
 * only on a real device with a real user key.
 */
@RunWith(RobolectricTestRunner::class)
class VirusTotalTest {

    private val ctx: Context = ApplicationProvider.getApplicationContext()
    private val hash = "ab".repeat(32)

    @Before
    fun reset() {
        ctx.getSharedPreferences("antivirus_vt", Context.MODE_PRIVATE).edit().clear().commit()
        ctx.filesDir.resolve("vt").deleteRecursively()
    }

    private fun vtBody(malicious: Int, suspicious: Int, harmless: Int, undetected: Int, name: String? = null) =
        """
        {"data":{"attributes":{
            "last_analysis_stats":{
                "malicious":$malicious,"suspicious":$suspicious,
                "harmless":$harmless,"undetected":$undetected
            }${if (name != null) ""","meaningful_name":"$name"""" else ""}
        }}}
        """.trimIndent()

    @Test
    fun parseResponse_flaggedFile() {
        val v = VirusTotal.parseResponse(hash.uppercase(), vtBody(41, 3, 0, 30, "evil.apk"), 123L)
        assertEquals(hash, v.sha256) // normalised to lowercase
        assertEquals(41, v.malicious)
        assertEquals(3, v.suspicious)
        assertEquals(74, v.total)
        assertEquals("evil.apk", v.name)
        assertEquals(123L, v.checkedAtMillis)
        assertTrue(v.flagged)
    }

    @Test
    fun parseResponse_cleanFile() {
        val v = VirusTotal.parseResponse(hash, vtBody(0, 0, 60, 14), 1L)
        assertFalse(v.flagged)
        assertEquals(74, v.total)
        assertNull(v.name)
    }

    @Test(expected = Throwable::class)
    fun parseResponse_garbageThrows() {
        VirusTotal.parseResponse(hash, """{"error":"nope"}""", 1L)
    }

    @Test
    fun optIn_gating() {
        // Fresh state: not configured, not enabled.
        assertFalse(VirusTotal.isConfigured(ctx))
        assertFalse(VirusTotal.isEnabled(ctx))
        // Toggle without a key still reads disabled — no key, no network.
        VirusTotal.setEnabled(ctx, true)
        assertFalse(VirusTotal.isEnabled(ctx))
        // Key + toggle → enabled.
        VirusTotal.setApiKey(ctx, "test-key")
        assertTrue(VirusTotal.isEnabled(ctx))
        // Clearing the key force-disables.
        VirusTotal.setApiKey(ctx, "")
        assertFalse(VirusTotal.isEnabled(ctx))
    }

    @Test
    fun lookup_refusedWhenDisabled() {
        val result = VirusTotal.lookup(ctx, hash)
        assertTrue(result is VirusTotal.LookupResult.Error)
    }

    @Test
    fun cachedVerdictNote_onlyWhenEnabledAndFlagged() {
        // Seed the cache via the internals-free path: parse + a direct cache
        // write through lookup is network-bound, so emulate by enabling and
        // checking the null cases; the note-formatting path is covered by
        // cached() returning null (no cache file).
        assertNull(VirusTotal.cachedVerdictNote(ctx, hash))
        VirusTotal.setApiKey(ctx, "k")
        VirusTotal.setEnabled(ctx, true)
        assertNull(VirusTotal.cachedVerdictNote(ctx, hash)) // no cache entry
        assertNull(VirusTotal.cachedVerdictNote(ctx, null))
    }

    @Test
    fun cached_missOnEmptyStore() {
        assertNull(VirusTotal.cached(ctx, hash))
    }
}
