package com.understory.antivirus

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Locks D#1 in the audit-list path: KNOWN_BAD pinned top, then most-severe
 * first, alphabetical within a tier. Pure JVM — [ApkAnalyzer.rankReports]
 * touches no Android API.
 */
class RankingTest {

    private fun report(
        pkg: String,
        verdict: ApkAnalyzer.Verdict,
        top: RiskRules.Severity?,
    ) = ApkAnalyzer.Report(
        verdict = verdict,
        packageName = pkg,
        versionName = "1",
        versionCode = 1,
        apkSha256 = null,
        certSha256 = null,
        findings = top?.let { listOf(RiskRules.Finding(it, "t", "e")) } ?: emptyList(),
        notes = emptyList(),
    )

    @Test fun knownBadPinnedTopThenMostSevereFirst() {
        val input = listOf(
            report("z.low", ApkAnalyzer.Verdict.CLEAN, RiskRules.Severity.LOW),
            report("a.critical", ApkAnalyzer.Verdict.SUSPICIOUS, RiskRules.Severity.CRITICAL),
            report("b.high", ApkAnalyzer.Verdict.SUSPICIOUS, RiskRules.Severity.HIGH),
            report("k.knownbad", ApkAnalyzer.Verdict.KNOWN_BAD, null),
        )
        val ranked = ApkAnalyzer.rankReports(input).map { it.packageName }
        assertEquals(listOf("k.knownbad", "a.critical", "b.high", "z.low"), ranked)
    }

    @Test fun alphabeticalWithinSameSeverityTier() {
        val input = listOf(
            report("beta", ApkAnalyzer.Verdict.SUSPICIOUS, RiskRules.Severity.HIGH),
            report("alpha", ApkAnalyzer.Verdict.SUSPICIOUS, RiskRules.Severity.HIGH),
        )
        val ranked = ApkAnalyzer.rankReports(input).map { it.packageName }
        assertEquals(listOf("alpha", "beta"), ranked)
    }
}
