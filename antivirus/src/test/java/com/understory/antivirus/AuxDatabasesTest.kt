package com.understory.antivirus

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Aux-database import/parse/lookup behaviour: line-format auto-detection,
 * per-line fail-soft vs per-file fail-closed, multi-database union lookup with
 * provenance, and removal.
 */
@RunWith(RobolectricTestRunner::class)
class AuxDatabasesTest {

    private val ctx: Context = ApplicationProvider.getApplicationContext()

    private val hashA = "a".repeat(64)
    private val hashB = "b".repeat(64)
    private val hashC = "c".repeat(64)

    @Before
    fun reset() {
        AuxDatabases.resetForTest()
        ctx.filesDir.resolve("auxdb").deleteRecursively()
    }

    @Test
    fun parseLine_plainHash() {
        assertEquals(hashA to "", AuxDatabases.parseLine(hashA))
        // Uppercase normalises to lowercase.
        assertEquals(hashA to "", AuxDatabases.parseLine(hashA.uppercase()))
    }

    @Test
    fun parseLine_csvWithLabel() {
        assertEquals(hashA to "Evil.apk", AuxDatabases.parseLine("$hashA,Evil.apk"))
    }

    @Test
    fun parseLine_clamavHsb() {
        assertEquals(hashA to "Andr.Trojan.Agent", AuxDatabases.parseLine("$hashA:12345:Andr.Trojan.Agent"))
    }

    @Test
    fun parseLine_rejectsMalformed() {
        assertNull(AuxDatabases.parseLine("not-a-hash"))
        assertNull(AuxDatabases.parseLine("deadbeef")) // too short
        assertNull(AuxDatabases.parseLine("0".repeat(64))) // all-zero sentinel
        assertNull(AuxDatabases.parseLine("g".repeat(64))) // non-hex
    }

    @Test
    fun import_mixedFormats_skipsBadLines() {
        val body = """
            # a comment header
            $hashA
            $hashB,Banker.B
            junk line that is not a hash
            $hashC:999:Andr.Dropper.C
        """.trimIndent()
        val result = AuxDatabases.import(ctx, "feed-one", body.toByteArray(), "2026-08-04")
        val imported = result as AuxDatabases.ImportResult.Imported
        assertEquals(3, imported.meta.count)
        assertEquals(1, imported.skipped)
        assertEquals("feed-one", imported.meta.name)

        assertNotNull(AuxDatabases.matchApk(hashA))
        assertEquals("Banker.B", AuxDatabases.matchApk(hashB)!!.label)
        assertEquals("feed-one", AuxDatabases.matchApk(hashC)!!.dbName)
    }

    @Test
    fun import_allMalformed_rejected() {
        val result = AuxDatabases.import(ctx, "junk", "hello\nworld\n".toByteArray(), "2026-08-04")
        assertTrue(result is AuxDatabases.ImportResult.NotAHashList)
        assertEquals(0, AuxDatabases.list().size)
    }

    @Test
    fun import_emptyFile_rejected() {
        val result = AuxDatabases.import(ctx, "empty", "# only a comment\n".toByteArray(), "2026-08-04")
        assertTrue(result is AuxDatabases.ImportResult.NotAHashList)
    }

    @Test
    fun multipleDatabases_unionLookup_withProvenance() {
        AuxDatabases.import(ctx, "feed-one", hashA.toByteArray(), "2026-08-04")
        AuxDatabases.import(ctx, "feed-two", "$hashB,FromTwo".toByteArray(), "2026-08-04")

        assertEquals(2, AuxDatabases.list().size)
        assertEquals("feed-one", AuxDatabases.matchApk(hashA)!!.dbName)
        assertEquals("feed-two", AuxDatabases.matchApk(hashB)!!.dbName)
        assertNull(AuxDatabases.matchApk(hashC))
        assertEquals(2, AuxDatabases.totalEntries())
    }

    @Test
    fun remove_dropsDatabaseAndLookups() {
        val meta = (AuxDatabases.import(ctx, "gone", hashA.toByteArray(), "2026-08-04")
            as AuxDatabases.ImportResult.Imported).meta
        AuxDatabases.remove(ctx, meta.id)
        assertNull(AuxDatabases.matchApk(hashA))
        assertEquals(0, AuxDatabases.list().size)
    }

    @Test
    fun persistence_survivesReload() {
        AuxDatabases.import(ctx, "persist", "$hashA,Sticky".toByteArray(), "2026-08-04")
        AuxDatabases.resetForTest()
        AuxDatabases.ensureLoaded(ctx)
        val match = AuxDatabases.matchApk(hashA)
        assertNotNull(match)
        assertEquals("Sticky", match!!.label)
        assertEquals("persist", match.dbName)
    }

    @Test
    fun knownBad_facadeSeesAuxEntries() {
        AuxDatabases.import(ctx, "facade", hashA.toByteArray(), "2026-08-04")
        assertTrue(KnownBad.isKnownBadApk(hashA))
        assertTrue(KnownBad.hasApkHashDefinitions())
        assertEquals("facade", KnownBad.auxMatchApk(hashA)!!.dbName)
    }
}
