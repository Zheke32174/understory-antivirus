package com.understory.antivirus

import android.os.Parcel
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Round-trips [ApkParseResult] through a Parcel to prove the v2 appended
 * fields (servicePermissions / receiverPermissions) survive the wire and stay
 * aligned — the append-only invariant the isolated-parser boundary depends on.
 */
@RunWith(RobolectricTestRunner::class)
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
