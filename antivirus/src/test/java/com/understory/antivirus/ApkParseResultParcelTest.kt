package com.understory.antivirus

import android.os.Parcel
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Round-trips [ApkParseResult] through a Parcel to prove the v2 appended
 * fields (servicePermissions / receiverPermissions) survive the wire and stay
 * aligned — the append-only invariant the isolated-parser boundary depends on.
 *
 * Robolectric 4.13 supports Android API 34. Production still compiles and
 * targets API 35; this fixture is pinned only to the supported emulation level
 * because it tests parcel structure rather than Android 15-specific behavior.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ApkParseResultParcelTest {

    @Test fun v2FieldsRoundTrip() {
        val original = ApkParseResult(
            packageName = "com.example",
            versionName = "1.2",
            versionCode = 42,
            certSha256s = listOf("aa", "bb"),
            permissions = listOf("android.permission.INTERNET"),
            flags = listOf(ApkParseResult.FLAG_NO_CERT),
            servicePermissions = listOf(RiskRules.PERM_ACCESSIBILITY),
            receiverPermissions = listOf(RiskRules.PERM_DEVICE_ADMIN),
        )
        val parcel = Parcel.obtain()
        try {
            original.writeToParcel(parcel, 0)
            parcel.setDataPosition(0)
            val restored = ApkParseResult.CREATOR.createFromParcel(parcel)
            assertEquals("com.example", restored.packageName)
            assertEquals(42L, restored.versionCode)
            assertEquals(listOf("android.permission.INTERNET"), restored.permissions)
            assertEquals(listOf(RiskRules.PERM_ACCESSIBILITY), restored.servicePermissions)
            assertEquals(listOf(RiskRules.PERM_DEVICE_ADMIN), restored.receiverPermissions)
        } finally {
            parcel.recycle()
        }
    }

    @Test fun v3StructuralFieldsRoundTrip() {
        val original = ApkParseResult(
            packageName = "com.example",
            versionName = "1.2",
            versionCode = 42,
            certSha256s = listOf("aa"),
            permissions = emptyList(),
            flags = emptyList(),
            servicePermissions = emptyList(),
            receiverPermissions = emptyList(),
            debuggable = true,
            allowBackup = false,
            usesCleartextTraffic = true,
            testOnly = true,
            minSdk = 19,
            targetSdk = 21,
            exportedUnprotectedComponents = 4,
        )
        val parcel = Parcel.obtain()
        try {
            original.writeToParcel(parcel, 0)
            parcel.setDataPosition(0)
            val restored = ApkParseResult.CREATOR.createFromParcel(parcel)
            assertEquals(true, restored.debuggable)
            assertEquals(false, restored.allowBackup)
            assertEquals(true, restored.usesCleartextTraffic)
            assertEquals(true, restored.testOnly)
            assertEquals(19, restored.minSdk)
            assertEquals(21, restored.targetSdk)
            assertEquals(4, restored.exportedUnprotectedComponents)
        } finally {
            parcel.recycle()
        }
    }

    @Test fun v3DefaultsRoundTrip() {
        // The positional constructor the isolated service uses (6 args) must
        // still parcel/unparcel with the v3 defaults intact.
        val original = ApkParseResult(
            "x", null, 0L, emptyList(), emptyList(), listOf(ApkParseResult.FLAG_BAD_ZIP),
        )
        val parcel = Parcel.obtain()
        try {
            original.writeToParcel(parcel, 0)
            parcel.setDataPosition(0)
            val restored = ApkParseResult.CREATOR.createFromParcel(parcel)
            assertEquals(false, restored.debuggable)
            assertEquals(true, restored.allowBackup)
            assertEquals(ApkParseResult.SDK_UNKNOWN, restored.minSdk)
            assertEquals(ApkParseResult.SDK_UNKNOWN, restored.targetSdk)
            assertEquals(0, restored.exportedUnprotectedComponents)
        } finally {
            parcel.recycle()
        }
    }

    @Test fun defaultV2FieldsAreEmpty() {
        val original = ApkParseResult(
            packageName = "x",
            versionName = null,
            versionCode = 0,
            certSha256s = emptyList(),
            permissions = emptyList(),
            flags = emptyList(),
        )
        val parcel = Parcel.obtain()
        try {
            original.writeToParcel(parcel, 0)
            parcel.setDataPosition(0)
            val restored = ApkParseResult.CREATOR.createFromParcel(parcel)
            assertEquals(emptyList<String>(), restored.servicePermissions)
            assertEquals(emptyList<String>(), restored.receiverPermissions)
        } finally {
            parcel.recycle()
        }
    }
}
