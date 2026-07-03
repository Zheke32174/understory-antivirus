package com.understory.antivirus

/**
 * Normalized rule-input: the union of everything [RiskRules] needs to score one
 * app, produced identically from BOTH scan paths so the heuristics run on one
 * shape regardless of where the facts came from.
 *
 *   - SAF-scanned APK  → built from the isolated parser's [ApkParseResult]
 *     ([ApkFactsBuilder.fromParsed]). Install source is UNKNOWN (a raw file has
 *     no installer yet); cert facts come from the parsed cert digests.
 *   - Installed app    → built from PackageManager metadata
 *     ([ApkFactsBuilder.fromInstalled], in [ApkAnalyzer]), which supplies the
 *     real install source and application-flag bits the system already parsed.
 *
 * Keeping the rules keyed on ApkFacts (not on two different Android/parse types)
 * is what makes the scoring path unit-testable and the two scan paths honest
 * about producing the same findings from the same facts.
 */
data class ApkFacts(
    val permissions: Set<String>,
    val servicePermissions: List<String>,
    val receiverPermissions: List<String>,
    val debuggable: Boolean,
    val allowBackup: Boolean,
    val usesCleartextTraffic: Boolean,
    val testOnly: Boolean,
    val minSdk: Int,
    val targetSdk: Int,
    val exportedUnprotectedComponents: Int,
    val installer: RiskRules.InstallerTrust,
    val signing: RiskRules.SigningPosture,
) {
    /**
     * The full finding list for this app: permission combos + declared-component
     * abuse + structural posture, merged and re-sorted most-severe-first. This
     * is the single place the three rule families are composed, so both scan
     * paths and the tests agree on the merge.
     */
    fun findings(): List<RiskRules.Finding> =
        (
            RiskRules.analyze(permissions) +
                RiskRules.analyzeComponents(servicePermissions, receiverPermissions, permissions) +
                RiskRules.analyzeStructural(
                    debuggable = debuggable,
                    allowBackup = allowBackup,
                    usesCleartextTraffic = usesCleartextTraffic,
                    testOnly = testOnly,
                    minSdk = minSdk,
                    targetSdk = targetSdk,
                    exportedUnprotectedComponents = exportedUnprotectedComponents,
                    installer = installer,
                    signing = signing,
                )
            ).sortedBy { it.severity.ordinal }
}

object ApkFactsBuilder {

    /**
     * Build facts from a successful isolated parse. Install source is UNKNOWN
     * (a SAF-picked file carries no installer). Signing posture is derived from
     * the parsed cert digest count: none → UNSIGNED; the parser can't cheaply
     * prove subject==issuer, so a present cert reads as OK here (the self-signed
     * distinction is only made on the installed-app path, which has the parsed
     * X.509 subject/issuer available).
     */
    fun fromParsed(parsed: ApkParseResult): ApkFacts = ApkFacts(
        permissions = parsed.permissions.toSet(),
        servicePermissions = parsed.servicePermissions,
        receiverPermissions = parsed.receiverPermissions,
        debuggable = parsed.debuggable,
        allowBackup = parsed.allowBackup,
        usesCleartextTraffic = parsed.usesCleartextTraffic,
        testOnly = parsed.testOnly,
        minSdk = parsed.minSdk,
        targetSdk = parsed.targetSdk,
        exportedUnprotectedComponents = parsed.exportedUnprotectedComponents,
        installer = RiskRules.InstallerTrust.UNKNOWN,
        signing = if (parsed.certSha256s.isEmpty()) RiskRules.SigningPosture.UNSIGNED
        else RiskRules.SigningPosture.OK,
    )
}
