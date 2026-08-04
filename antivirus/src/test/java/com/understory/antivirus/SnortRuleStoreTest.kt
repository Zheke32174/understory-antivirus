package com.understory.antivirus

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** Seed load, user import (replace semantics, sid dedup), and removal. */
@RunWith(RobolectricTestRunner::class)
class SnortRuleStoreTest {

    private val ctx: Context = ApplicationProvider.getApplicationContext()

    @Before
    fun reset() {
        SnortRuleStore.resetForTest()
        ctx.filesDir.resolve("snort").deleteRecursively()
    }

    @Test
    fun seedLoads() {
        SnortRuleStore.ensureLoaded(ctx)
        val meta = SnortRuleStore.meta()!!
        assertTrue("seed must carry rules", meta.seedCount > 0)
        assertEquals("seed must parse clean", 0, meta.skipped)
        assertEquals(0, meta.userCount)
        assertEquals(meta.seedCount, SnortRuleStore.rules().size)
    }

    @Test
    fun importAddsUserRules() {
        SnortRuleStore.ensureLoaded(ctx)
        val body = """alert tcp any any -> any any (msg:"user rule"; content:"userpattern"; sid:9990001;)"""
        val result = SnortRuleStore.importFrom(ctx, body.toByteArray())
        assertTrue(result is SnortRuleStore.ImportResult.Imported)
        val meta = (result as SnortRuleStore.ImportResult.Imported).meta
        assertEquals(1, meta.userCount)
        assertTrue(SnortRuleStore.rules().any { it.sid == 9990001L })
    }

    @Test
    fun importGarbageRefused_previousStateIntact() {
        SnortRuleStore.ensureLoaded(ctx)
        val before = SnortRuleStore.rules().size
        val result = SnortRuleStore.importFrom(ctx, "this is not a rules file".toByteArray())
        assertTrue(result is SnortRuleStore.ImportResult.NoValidRules)
        assertEquals(before, SnortRuleStore.rules().size)
    }

    @Test
    fun userRuleSupersedesSeedSid() {
        SnortRuleStore.ensureLoaded(ctx)
        val seedSid = SnortRuleStore.rules().first().sid
        val body = """alert tcp any any -> any any (msg:"superseded"; content:"x"; sid:$seedSid; rev:9;)"""
        SnortRuleStore.importFrom(ctx, body.toByteArray())
        val winner = SnortRuleStore.rules().first { it.sid == seedSid }
        assertEquals("superseded", winner.msg)
        assertEquals(9, winner.rev)
    }

    @Test
    fun removeUserRules_backToSeedOnly() {
        SnortRuleStore.ensureLoaded(ctx)
        val seedCount = SnortRuleStore.meta()!!.seedCount
        SnortRuleStore.importFrom(
            ctx,
            """alert tcp any any -> any any (msg:"u"; content:"y"; sid:9990002;)""".toByteArray(),
        )
        SnortRuleStore.removeUserRules(ctx)
        val meta = SnortRuleStore.meta()!!
        assertEquals(0, meta.userCount)
        assertEquals(seedCount, SnortRuleStore.rules().size)
    }

    @Test
    fun persistence_userRulesSurviveReload() {
        SnortRuleStore.ensureLoaded(ctx)
        SnortRuleStore.importFrom(
            ctx,
            """alert tcp any any -> any any (msg:"sticky"; content:"z"; sid:9990003;)""".toByteArray(),
        )
        SnortRuleStore.resetForTest()
        SnortRuleStore.ensureLoaded(ctx)
        assertTrue(SnortRuleStore.rules().any { it.sid == 9990003L })
    }
}
