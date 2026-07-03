package com.understory.antivirus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure-JVM tests for the detail-screen permission tiering. */
class PermissionGroupsTest {

    @Test fun runtimePermissionsAreDangerous() {
        assertEquals(
            PermissionGroups.Tier.DANGEROUS,
            PermissionGroups.tierOf("android.permission.READ_SMS"),
        )
        assertEquals(
            PermissionGroups.Tier.DANGEROUS,
            PermissionGroups.tierOf("android.permission.RECORD_AUDIO"),
        )
    }

    @Test fun specialAccessCountsAsDangerous() {
        assertEquals(
            PermissionGroups.Tier.DANGEROUS,
            PermissionGroups.tierOf("android.permission.SYSTEM_ALERT_WINDOW"),
        )
    }

    @Test fun bindPermissionsAreSignature() {
        assertEquals(
            PermissionGroups.Tier.SIGNATURE,
            PermissionGroups.tierOf("android.permission.BIND_ACCESSIBILITY_SERVICE"),
        )
    }

    @Test fun internetIsNormal() {
        assertEquals(
            PermissionGroups.Tier.NORMAL,
            PermissionGroups.tierOf("android.permission.INTERNET"),
        )
    }

    @Test fun groupedIsWorstFirstAndDeduped() {
        val groups = PermissionGroups.grouped(
            listOf(
                "android.permission.INTERNET",
                "android.permission.READ_SMS",
                "android.permission.READ_SMS", // dup
                "android.permission.BIND_DEVICE_ADMIN",
            ),
        )
        // Dangerous tier first.
        assertEquals(PermissionGroups.Tier.DANGEROUS, groups.first().first)
        // Dedup: READ_SMS appears once.
        val dangerous = groups.first { it.first == PermissionGroups.Tier.DANGEROUS }.second
        assertEquals(1, dangerous.count { it == "android.permission.READ_SMS" })
        // Tiers are ordinal-sorted.
        val ordinals = groups.map { it.first.ordinal }
        assertEquals(ordinals.sorted(), ordinals)
    }

    @Test fun shortNameIsLastSegment() {
        assertTrue(PermissionGroups.shortName("android.permission.READ_SMS") == "READ_SMS")
    }
}
