package com.understory.antivirus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the permission-combination + declared-component rules.
 * Locks the corrected severity ordering (D#1), the corrected abuser input
 * (D#2), and the new call-log / SEND_SMS rules (D#12).
 */
class RiskRulesTest {

    private fun titles(fs: List<RiskRules.Finding>) = fs.map { it.title }

    @Test fun smsStealerProfileIsCritical() {
        val f = RiskRules.analyze(
            setOf(
                "android.permission.INTERNET",
                "android.permission.READ_SMS",
                "android.permission.READ_CONTACTS",
            ),
        )
        assertTrue("SMS-stealer profile" in titles(f))
        assertEquals(RiskRules.Severity.CRITICAL, f.first { it.title == "SMS-stealer profile" }.severity)
    }

    @Test fun surveillanceProfileIsCritical() {
        val f = RiskRules.analyze(
            setOf(
                "android.permission.INTERNET",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_BACKGROUND_LOCATION",
            ),
        )
        assertTrue("Surveillance profile" in titles(f))
    }

    @Test fun sendSmsRuleFires() {
        val f = RiskRules.analyze(setOf("android.permission.SEND_SMS"))
        assertTrue("Can send SMS" in titles(f))
        assertEquals(RiskRules.Severity.MED, f.first().severity)
    }

    @Test fun callLogPlusInternetFires() {
        val f = RiskRules.analyze(
            setOf("android.permission.READ_CALL_LOG", "android.permission.INTERNET"),
        )
        assertTrue("Call log + internet" in titles(f))
    }

    @Test fun callLogWithoutInternetDoesNotFire() {
        val f = RiskRules.analyze(setOf("android.permission.READ_CALL_LOG"))
        assertFalse("Call log + internet" in titles(f))
    }

    /** D#1: findings come out most-severe first (CRITICAL ordinal 0). */
    @Test fun findingsAreMostSevereFirst() {
        val f = RiskRules.analyze(
            setOf(
                "android.permission.INTERNET",
                "android.permission.READ_SMS",
                "android.permission.READ_CONTACTS", // CRITICAL
                "android.permission.QUERY_ALL_PACKAGES", // LOW
                "android.permission.READ_PHONE_STATE", // LOW
            ),
        )
        // Non-increasing severity ordinal across the whole list.
        val ordinals = f.map { it.severity.ordinal }
        assertEquals(ordinals.sorted(), ordinals)
        assertEquals(RiskRules.Severity.CRITICAL, f.first().severity)
    }

    /**
     * D#2: the a11y/device-admin/notif signals key on DECLARED COMPONENTS, not
     * on uses-permission. A cargo-culted BIND_* in the requested-perm set must
     * NOT fire the abuser rules.
     */
    @Test fun bindPermissionInRequestedSetDoesNotFireAbuserRules() {
        val f = RiskRules.analyze(
            setOf(
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.BIND_DEVICE_ADMIN",
                "android.permission.INTERNET",
            ),
        )
        assertFalse(titles(f).any { it.contains("accessibility", ignoreCase = true) })
        assertFalse(titles(f).any { it.contains("device-admin", ignoreCase = true) })
    }

    @Test fun declaredAccessibilityServiceFiresHigh() {
        val f = RiskRules.analyzeComponents(
            servicePermissions = listOf(RiskRules.PERM_ACCESSIBILITY),
            receiverPermissions = emptyList(),
            requestedPermissions = emptySet(),
        )
        assertTrue("Declares an accessibility service" in titles(f))
    }

    @Test fun declaredAccessibilityPlusInternetIsCritical() {
        val f = RiskRules.analyzeComponents(
            servicePermissions = listOf(RiskRules.PERM_ACCESSIBILITY),
            receiverPermissions = emptyList(),
            requestedPermissions = setOf("android.permission.INTERNET"),
        )
        assertEquals(RiskRules.Severity.CRITICAL, f.first().severity)
        assertTrue("Accessibility + internet exfiltration profile" in titles(f))
    }

    @Test fun declaredDeviceAdminAndNotifListenerFire() {
        val f = RiskRules.analyzeComponents(
            servicePermissions = listOf(RiskRules.PERM_NOTIFICATION_LISTENER),
            receiverPermissions = listOf(RiskRules.PERM_DEVICE_ADMIN),
            requestedPermissions = emptySet(),
        )
        assertTrue("Declares a device-admin receiver" in titles(f))
        assertTrue("Declares a notification listener" in titles(f))
    }

    // ---- New permission-combination rules ----

    @Test fun smsPlusInternetWithoutContactsFiresHigh() {
        val f = RiskRules.analyze(
            setOf("android.permission.INTERNET", "android.permission.RECEIVE_SMS"),
        )
        assertTrue("SMS + internet" in titles(f))
        assertEquals(RiskRules.Severity.HIGH, f.first { it.title == "SMS + internet" }.severity)
    }

    @Test fun smsStealerTakesPrecedenceOverPlainSmsInternet() {
        // When contacts is ALSO present the CRITICAL stealer rule fires; the
        // plain SMS+internet HIGH rule must NOT also fire (it's gated on
        // !readContacts) so the same fact isn't double-counted.
        val f = RiskRules.analyze(
            setOf(
                "android.permission.INTERNET",
                "android.permission.READ_SMS",
                "android.permission.READ_CONTACTS",
            ),
        )
        assertTrue("SMS-stealer profile" in titles(f))
        assertFalse("SMS + internet" in titles(f))
    }

    @Test fun installPlusDeleteFiresDropperRule() {
        val f = RiskRules.analyze(
            setOf(
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.REQUEST_DELETE_PACKAGES",
            ),
        )
        assertTrue("Installs and removes other apps" in titles(f))
    }

    @Test fun bootPlusInternetFiresPersistenceRule() {
        val f = RiskRules.analyze(
            setOf("android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.INTERNET"),
        )
        assertTrue("Auto-starts on boot + internet" in titles(f))
    }

    @Test fun accessibilityPlusOverlayIsCritical() {
        val f = RiskRules.analyzeComponents(
            servicePermissions = listOf(RiskRules.PERM_ACCESSIBILITY),
            receiverPermissions = emptyList(),
            requestedPermissions = setOf("android.permission.SYSTEM_ALERT_WINDOW"),
        )
        assertTrue("Accessibility + screen overlay profile" in titles(f))
        assertEquals(RiskRules.Severity.CRITICAL, f.first().severity)
    }

    @Test fun deviceAdminPlusBootIsCritical() {
        val f = RiskRules.analyzeComponents(
            servicePermissions = emptyList(),
            receiverPermissions = listOf(RiskRules.PERM_DEVICE_ADMIN),
            requestedPermissions = setOf("android.permission.RECEIVE_BOOT_COMPLETED"),
        )
        assertTrue("Device-admin + auto-start on boot" in titles(f))
    }

    // ---- Structural rules ----

    private fun structural(
        debuggable: Boolean = false,
        allowBackup: Boolean = false,
        cleartext: Boolean = false,
        testOnly: Boolean = false,
        minSdk: Int = ApkParseResult.SDK_UNKNOWN,
        targetSdk: Int = ApkParseResult.SDK_UNKNOWN,
        exported: Int = 0,
        installer: RiskRules.InstallerTrust = RiskRules.InstallerTrust.UNKNOWN,
        signing: RiskRules.SigningPosture = RiskRules.SigningPosture.OK,
    ) = RiskRules.analyzeStructural(
        debuggable, allowBackup, cleartext, testOnly, minSdk, targetSdk,
        exported, installer, signing,
    )

    @Test fun debuggableFiresHigh() {
        val f = structural(debuggable = true)
        assertTrue("Ships as debuggable" in titles(f))
        assertEquals(RiskRules.Severity.HIGH, f.first { it.title == "Ships as debuggable" }.severity)
    }

    @Test fun testOnlyFiresHigh() {
        assertTrue("Test-only build" in titles(structural(testOnly = true)))
    }

    @Test fun exportedUnprotectedFiresWhenNonZeroOnly() {
        assertTrue("Exported components with no permission guard" in titles(structural(exported = 3)))
        assertFalse("Exported components with no permission guard" in titles(structural(exported = 0)))
    }

    @Test fun cleartextFiresMed() {
        assertTrue("Allows cleartext (unencrypted) traffic" in titles(structural(cleartext = true)))
    }

    @Test fun lowMinSdkFiresButUnknownDoesNot() {
        assertTrue(titles(structural(minSdk = 19)).any { it.startsWith("Targets very old Android") })
        // SDK_UNKNOWN (-1) is "no signal", never treated as below the floor.
        assertFalse(
            titles(structural(minSdk = ApkParseResult.SDK_UNKNOWN))
                .any { it.startsWith("Targets very old Android") },
        )
        // A modern minSdk doesn't fire.
        assertFalse(titles(structural(minSdk = 33)).any { it.startsWith("Targets very old Android") })
    }

    @Test fun lowTargetSdkFiresLow() {
        assertTrue(titles(structural(targetSdk = 21)).any { it.startsWith("Old target SDK") })
        assertFalse(
            titles(structural(targetSdk = ApkParseResult.SDK_UNKNOWN))
                .any { it.startsWith("Old target SDK") },
        )
    }

    @Test fun allowBackupFiresLow() {
        assertTrue("Backup allowed" in titles(structural(allowBackup = true)))
        assertFalse("Backup allowed" in titles(structural(allowBackup = false)))
    }

    @Test fun sideloadFiresButTrustedDoesNot() {
        assertTrue("Sideloaded (not from a store)" in titles(structural(installer = RiskRules.InstallerTrust.SIDELOAD)))
        assertFalse("Sideloaded (not from a store)" in titles(structural(installer = RiskRules.InstallerTrust.TRUSTED)))
        assertFalse("Sideloaded (not from a store)" in titles(structural(installer = RiskRules.InstallerTrust.UNKNOWN)))
    }

    @Test fun unsignedFiresMedSelfSignedFiresLow() {
        assertTrue("No signing certificate" in titles(structural(signing = RiskRules.SigningPosture.UNSIGNED)))
        assertTrue("Self-signed certificate" in titles(structural(signing = RiskRules.SigningPosture.SELF_SIGNED)))
        assertFalse(
            titles(structural(signing = RiskRules.SigningPosture.OK))
                .any { it.contains("certificate", ignoreCase = true) },
        )
    }

    @Test fun structuralFindingsAreMostSevereFirst() {
        val f = structural(
            debuggable = true, // HIGH
            allowBackup = true, // LOW
            targetSdk = 21, // LOW
            installer = RiskRules.InstallerTrust.SIDELOAD, // LOW
        )
        val ordinals = f.map { it.severity.ordinal }
        assertEquals(ordinals.sorted(), ordinals)
    }

    // ---- Numeric scoring ----

    @Test fun emptyFindingsScoreZeroLow() {
        val s = RiskRules.score(emptyList())
        assertEquals(0, s.score)
        assertEquals(RiskRules.Rating.LOW, s.rating)
    }

    @Test fun singleCriticalIsAtLeastHigh() {
        val s = RiskRules.score(
            listOf(RiskRules.Finding(RiskRules.Severity.CRITICAL, "c", "e")),
        )
        assertTrue(s.rating.ordinal >= RiskRules.Rating.HIGH.ordinal)
    }

    @Test fun twoCriticalsAreCritical() {
        val s = RiskRules.score(
            listOf(
                RiskRules.Finding(RiskRules.Severity.CRITICAL, "c1", "e"),
                RiskRules.Finding(RiskRules.Severity.CRITICAL, "c2", "e"),
            ),
        )
        assertEquals(RiskRules.Rating.CRITICAL, s.rating)
    }

    @Test fun scoreIsCappedAt100() {
        val many = (1..20).map { RiskRules.Finding(RiskRules.Severity.CRITICAL, "c$it", "e") }
        assertEquals(100, RiskRules.score(many).score)
    }

    @Test fun knownBadPinsToCritical100() {
        val s = RiskRules.score(
            listOf(RiskRules.Finding(RiskRules.Severity.LOW, "l", "e")),
            knownBad = true,
        )
        assertEquals(100, s.score)
        assertEquals(RiskRules.Rating.CRITICAL, s.rating)
    }

    @Test fun lowOnlyFindingsStayLow() {
        val s = RiskRules.score(
            listOf(
                RiskRules.Finding(RiskRules.Severity.LOW, "l1", "e"),
                RiskRules.Finding(RiskRules.Severity.LOW, "l2", "e"),
            ),
        )
        assertEquals(RiskRules.Rating.LOW, s.rating)
    }

    @Test fun reasonsListedMostSevereFirst() {
        val s = RiskRules.score(
            listOf(
                RiskRules.Finding(RiskRules.Severity.LOW, "low", "e"),
                RiskRules.Finding(RiskRules.Severity.CRITICAL, "crit", "e"),
            ),
        )
        assertEquals(listOf("crit", "low"), s.reasons)
    }
}
