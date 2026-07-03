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
}
