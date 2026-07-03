package com.understory.antivirus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the [ApkFacts] rule-input: that [ApkFacts.findings]
 * composes the permission, component, and structural rule families into one
 * most-severe-first list, and that [ApkFactsBuilder.fromParsed] derives the
 * installer/signing posture from an [ApkParseResult].
 */
class ApkFactsTest {

    private fun titles(fs: List<RiskRules.Finding>) = fs.map { it.title }

    @Test fun findingsComposeAllThreeFamilies() {
        val facts = ApkFacts(
            permissions = setOf(
                "android.permission.INTERNET",
                "android.permission.RECEIVE_SMS", // HIGH: SMS + internet
            ),
            servicePermissions = listOf(RiskRules.PERM_ACCESSIBILITY), // HIGH component
            receiverPermissions = emptyList(),
            debuggable = true, // HIGH structural
            allowBackup = false,
            usesCleartextTraffic = false,
            testOnly = false,
            minSdk = ApkParseResult.SDK_UNKNOWN,
            targetSdk = ApkParseResult.SDK_UNKNOWN,
            exportedUnprotectedComponents = 0,
            installer = RiskRules.InstallerTrust.UNKNOWN,
            signing = RiskRules.SigningPosture.OK,
        )
        val f = facts.findings()
        // One from each family present.
        assertTrue("SMS + internet" in titles(f)) // permission
        assertTrue("Declares an accessibility service" in titles(f)) // component
        assertTrue("Ships as debuggable" in titles(f)) // structural
        // Merged list is most-severe first.
        val ordinals = f.map { it.severity.ordinal }
        assertEquals(ordinals.sorted(), ordinals)
    }

    @Test fun fromParsedUnknownInstallerAndOkSigningWhenCertPresent() {
        val parsed = ApkParseResult(
            packageName = "com.example",
            versionName = "1",
            versionCode = 1,
            certSha256s = listOf("aa"),
            permissions = listOf("android.permission.INTERNET"),
            flags = emptyList(),
        )
        val facts = ApkFactsBuilder.fromParsed(parsed)
        assertEquals(RiskRules.InstallerTrust.UNKNOWN, facts.installer)
        assertEquals(RiskRules.SigningPosture.OK, facts.signing)
        // UNKNOWN installer must NOT emit a sideload finding.
        assertFalse("Sideloaded (not from a store)" in titles(facts.findings()))
    }

    @Test fun fromParsedNoCertIsUnsigned() {
        val parsed = ApkParseResult(
            packageName = "com.example",
            versionName = "1",
            versionCode = 1,
            certSha256s = emptyList(),
            permissions = emptyList(),
            flags = listOf(ApkParseResult.FLAG_NO_CERT),
        )
        val facts = ApkFactsBuilder.fromParsed(parsed)
        assertEquals(RiskRules.SigningPosture.UNSIGNED, facts.signing)
        assertTrue("No signing certificate" in titles(facts.findings()))
    }

    @Test fun structuralFactsCarryThroughFromParsed() {
        val parsed = ApkParseResult(
            packageName = "com.example",
            versionName = "1",
            versionCode = 1,
            certSha256s = listOf("aa"),
            permissions = emptyList(),
            flags = emptyList(),
            debuggable = true,
            testOnly = true,
            minSdk = 19,
        )
        val f = ApkFactsBuilder.fromParsed(parsed).findings()
        assertTrue("Ships as debuggable" in titles(f))
        assertTrue("Test-only build" in titles(f))
        assertTrue(titles(f).any { it.startsWith("Targets very old Android") })
    }
}
