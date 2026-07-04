package com.understory.antivirus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the READ-ONLY ground-truth [DeepFacts.parse]. The parser must
 * be DEFENSIVE: it extracts what it can from a real-ish `dumpsys package` /
 * `appops get` dump and degrades to empty (never throws, never fabricates) on a
 * format it doesn't recognise. These tests pin both the happy path and the
 * fail-open behaviour on drift/garbage/null.
 */
class DeepFactsTest {

    private val realisticDumpsys = """
        Packages:
          Package [com.example.tracker] (a1b2c3):
            userId=10234
            pkg=Package{...}
            versionName=3.2.1
            firstInstallTime=2024-11-02 14:07:33
            lastUpdateTime=2025-01-08 09:12:00
            installerPackageName=com.android.vending
            installInitiator=com.android.vending
            requested permissions:
              android.permission.INTERNET
              android.permission.CAMERA
              android.permission.ACCESS_FINE_LOCATION
              android.permission.RECORD_AUDIO
            runtime permissions:
              android.permission.CAMERA: granted=true, flags=[ USER_SENSITIVE_WHEN_GRANTED ]
              android.permission.ACCESS_FINE_LOCATION: granted=false, flags=[ USER_SENSITIVE_WHEN_DENIED ]
              android.permission.RECORD_AUDIO: granted=true, flags=[ ]
    """.trimIndent()

    private val realisticAppops = """
        Uid mode: MODE_ALLOWED
        Package com.example.tracker:
          SYSTEM_ALERT_WINDOW: allow; time=+2h1m ago
          GET_USAGE_STATS: allow
          COARSE_LOCATION: ignore
          FINE_LOCATION: default
    """.trimIndent()

    @Test fun parsesGrantedAndDeniedRuntimePermissions() {
        val f = DeepFacts.parse(realisticDumpsys, realisticAppops)
        // CAMERA + RECORD_AUDIO are granted dangerous; short-named + sorted.
        assertEquals(listOf("CAMERA", "RECORD_AUDIO"), f.grantedRuntimePermissions)
        // ACCESS_FINE_LOCATION requested but granted=false → denied bucket.
        assertEquals(listOf("ACCESS_FINE_LOCATION"), f.deniedRuntimePermissions)
    }

    @Test fun ignoresNormalInstallTimePermissions() {
        // INTERNET is a normal permission and must never appear in either bucket,
        // even though it's listed under requested permissions.
        val f = DeepFacts.parse(realisticDumpsys, null)
        assertFalse("INTERNET" in f.grantedRuntimePermissions)
        assertFalse("INTERNET" in f.deniedRuntimePermissions)
    }

    @Test fun parsesProvenance() {
        val f = DeepFacts.parse(realisticDumpsys, null)
        assertEquals("2024-11-02 14:07:33", f.firstInstallTime)
        assertEquals("com.android.vending", f.installerPackage)
    }

    @Test fun parsesOnlyNonDefaultAppops() {
        val f = DeepFacts.parse(null, realisticAppops)
        val ops = f.activeAppOps.associate { it.op to it.mode }
        assertEquals("allow", ops["SYSTEM_ALERT_WINDOW"])
        assertEquals("allow", ops["GET_USAGE_STATS"])
        // ignore + default are benign defaults → not surfaced.
        assertFalse("COARSE_LOCATION" in ops.keys)
        assertFalse("FINE_LOCATION" in ops.keys)
    }

    @Test fun grantedWinsOverDeniedAcrossMultiUserRows() {
        // Some dumps print the same permission per-user; a granted row anywhere
        // must win and must not be double-listed as denied.
        val dump = """
            runtime permissions:
              android.permission.CAMERA: granted=false, flags=[ ]
            User 10 runtime permissions:
              android.permission.CAMERA: granted=true, flags=[ ]
        """.trimIndent()
        val f = DeepFacts.parse(dump, null)
        assertEquals(listOf("CAMERA"), f.grantedRuntimePermissions)
        assertTrue(f.deniedRuntimePermissions.isEmpty())
    }

    @Test fun degradesToEmptyOnGarbage() {
        val f = DeepFacts.parse("total nonsense\nno colon lines here", "also nonsense")
        assertTrue(f.grantedRuntimePermissions.isEmpty())
        assertTrue(f.deniedRuntimePermissions.isEmpty())
        assertTrue(f.activeAppOps.isEmpty())
        assertNull(f.firstInstallTime)
        assertNull(f.installerPackage)
        assertFalse("garbage must not be treated as ground truth", f.hasAnything())
    }

    @Test fun bothNullDumpsYieldNothing() {
        val f = DeepFacts.parse(null, null)
        assertFalse(f.hasAnything())
    }

    @Test fun installerNullTokenIsIgnored() {
        // A sideloaded app often prints installerPackageName=null — treat as unknown.
        val dump = "installerPackageName=null"
        assertNull(DeepFacts.parse(dump, null).installerPackage)
    }

    @Test fun handlesInstallInitiatorFallback() {
        // When installerPackageName is absent, installInitiator supplies the value.
        val dump = "installInitiator=org.fdroid.fdroid"
        assertEquals("org.fdroid.fdroid", DeepFacts.parse(dump, null).installerPackage)
    }

    @Test fun appopsPreambleLinesAreSkipped() {
        // "Uid mode: MODE_ALLOWED" and "Package pkg:" lines must not be mistaken
        // for ops (they contain spaces / aren't UPPER_SNAKE ops at non-default).
        val f = DeepFacts.parse(null, "Uid mode: MODE_ALLOWED\nPackage com.x:")
        assertTrue(f.activeAppOps.isEmpty())
    }
}
