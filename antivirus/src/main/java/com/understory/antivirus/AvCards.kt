package com.understory.antivirus

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Dangerous
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.ReportProblem
import androidx.compose.material.icons.filled.Launch
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * New, token-native home-screen surfaces (positioning banner, Play Protect
 * card, definitions status, Tamper card, periodic-scan toggle, full-screen
 * tamper block). Authored against the shared components + [UnderstoryTheme] per
 * the wave-2 rule that NEW screens are token-native and honest.
 *
 * Severity → semantic-color mapping lives here so both the new cards and the
 * (still-legacy) report views agree on the palette.
 */

@Composable
internal fun severityAccent(s: RiskRules.Severity): Color = when (s) {
    RiskRules.Severity.CRITICAL -> MaterialTheme.colorScheme.error
    RiskRules.Severity.HIGH -> UnderstoryTheme.semantic.warning
    RiskRules.Severity.MED -> UnderstoryTheme.semantic.warning
    RiskRules.Severity.LOW -> UnderstoryTheme.semantic.dim
}

@Composable
internal fun ratingAccent(r: RiskRules.Rating): Color = when (r) {
    RiskRules.Rating.CRITICAL -> MaterialTheme.colorScheme.error
    RiskRules.Rating.HIGH -> UnderstoryTheme.semantic.warning
    RiskRules.Rating.MEDIUM -> UnderstoryTheme.semantic.warning
    RiskRules.Rating.LOW -> UnderstoryTheme.semantic.success
}

@Composable
internal fun ratingLabel(r: RiskRules.Rating): String = when (r) {
    RiskRules.Rating.CRITICAL -> stringResource(R.string.av_rating_critical)
    RiskRules.Rating.HIGH -> stringResource(R.string.av_rating_high)
    RiskRules.Rating.MEDIUM -> stringResource(R.string.av_rating_medium)
    RiskRules.Rating.LOW -> stringResource(R.string.av_rating_low)
}

/**
 * A compact, inline error card sized to its content — safe to place inside a
 * scrolling column (unlike the shared full-screen [com.understory.security.ui.components.ErrorState],
 * which fills its parent and would clash with a verticalScroll constraint). An
 * optional Retry uses the tap-jacking-hardened [SecureOutlinedButton].
 */
@Composable
internal fun InlineErrorCard(message: String, onRetry: (() -> Unit)? = null) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            Text(message, style = MaterialTheme.typography.bodyMedium)
            if (onRetry != null) {
                SecureOutlinedButton(onClick = onRetry) {
                    Text(stringResource(R.string.av_scan_hero_action))
                }
            }
        }
    }
}

/** Human, localized severity name for the finding-card badge. */
@Composable
internal fun severityLabel(s: RiskRules.Severity): String = when (s) {
    RiskRules.Severity.CRITICAL -> stringResource(R.string.av_sev_critical)
    RiskRules.Severity.HIGH -> stringResource(R.string.av_sev_high)
    RiskRules.Severity.MED -> stringResource(R.string.av_sev_medium)
    RiskRules.Severity.LOW -> stringResource(R.string.av_sev_low)
}

/** Icon that reads the finding severity at a glance. */
internal fun severityIcon(s: RiskRules.Severity): ImageVector = when (s) {
    RiskRules.Severity.CRITICAL -> Icons.Filled.Dangerous
    RiskRules.Severity.HIGH -> Icons.Filled.ReportProblem
    RiskRules.Severity.MED -> Icons.Filled.ErrorOutline
    RiskRules.Severity.LOW -> Icons.Filled.Info
}

/** Localized verdict name. */
@Composable
internal fun verdictLabel(v: ApkAnalyzer.Verdict): String = when (v) {
    ApkAnalyzer.Verdict.CLEAN -> stringResource(R.string.av_verdict_clean)
    ApkAnalyzer.Verdict.SUSPICIOUS -> stringResource(R.string.av_verdict_suspicious)
    ApkAnalyzer.Verdict.KNOWN_BAD -> stringResource(R.string.av_verdict_known_bad)
    ApkAnalyzer.Verdict.UNKNOWN -> stringResource(R.string.av_verdict_unknown)
}

@Composable
internal fun verdictAccent(v: ApkAnalyzer.Verdict): Color = when (v) {
    ApkAnalyzer.Verdict.CLEAN -> UnderstoryTheme.semantic.success
    ApkAnalyzer.Verdict.SUSPICIOUS -> UnderstoryTheme.semantic.warning
    ApkAnalyzer.Verdict.KNOWN_BAD -> MaterialTheme.colorScheme.error
    ApkAnalyzer.Verdict.UNKNOWN -> UnderstoryTheme.semantic.dim
}

internal fun verdictIcon(v: ApkAnalyzer.Verdict): ImageVector = when (v) {
    ApkAnalyzer.Verdict.CLEAN -> Icons.Filled.Info
    ApkAnalyzer.Verdict.SUSPICIOUS -> Icons.Filled.ReportProblem
    ApkAnalyzer.Verdict.KNOWN_BAD -> Icons.Filled.Block
    ApkAnalyzer.Verdict.UNKNOWN -> Icons.Filled.ErrorOutline
}

/**
 * A round severity chip: a tinted disc with the severity icon, used as the
 * leading element of a finding card so the row's risk level is legible before
 * any text is read.
 */
@Composable
internal fun SeverityBadge(severity: RiskRules.Severity, modifier: Modifier = Modifier) {
    val accent = severityAccent(severity)
    Box(
        modifier = modifier
            .size(40.dp)
            .background(accent.copy(alpha = 0.16f), CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = severityIcon(severity),
            contentDescription = stringResource(R.string.cd_severity) + ": " + severityLabel(severity),
            tint = accent,
            modifier = Modifier.size(22.dp),
        )
    }
}

/**
 * A single finding rendered as a card: leading severity badge, title, the
 * localized severity name, the plain-English explanation, and (for
 * enabled-abuser findings) a "Fix in Settings" deep-link. Findings arrive
 * CRITICAL-first, so a column of these reads worst-first.
 */
@Composable
internal fun FindingCard(finding: RiskRules.Finding) {
    val ctx = LocalContext.current
    val accent = severityAccent(finding.severity)
    SuiteCard {
        Row(verticalAlignment = Alignment.Top) {
            SeverityBadge(finding.severity)
            Spacer(Modifier.width(UnderstoryTheme.spacing.md))
            Column(Modifier.weight(1f)) {
                Text(
                    finding.title,
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.Medium,
                )
                Text(
                    severityLabel(finding.severity),
                    style = MaterialTheme.typography.labelMedium,
                    color = accent,
                )
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                Text(
                    finding.explain,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                finding.deepLink?.let { target ->
                    val canOpen = SettingsDeepLinks.canOpen(ctx, target)
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    SecureOutlinedButton(
                        onClick = { SettingsDeepLinks.open(ctx, target) },
                        enabled = canOpen,
                    ) {
                        Text(stringResource(R.string.av_fix_in_settings))
                    }
                }
            }
        }
    }
}

/**
 * The verdict header card for a scan/audit report: package name, a verdict
 * chip (icon + localized verdict, severity-tinted), version, and the evidence
 * hashes. THREAT-MODEL: these are the APK's own public digests (never a stored
 * secret), shown truncated as scan evidence — unchanged from wave-2/3.
 */
@Composable
internal fun ReportHeaderCard(r: ApkAnalyzer.Report) {
    val accent = verdictAccent(r.verdict)
    SuiteCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    r.packageName,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Text(
                    stringResource(R.string.av_report_version, r.versionName ?: "?", r.versionCode),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
            VerdictChip(r.verdict)
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        RiskScoreRow(r.risk)
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        val apkSha = r.apkSha256
        Text(
            if (apkSha != null) stringResource(R.string.av_report_apk_sha, apkSha.take(16))
            else stringResource(R.string.av_apk_not_hashed),
            style = MaterialTheme.typography.bodySmall,
            color = UnderstoryTheme.semantic.dim,
        )
        r.certSha256?.let {
            Text(
                stringResource(R.string.av_report_cert_sha, it.take(16)),
                style = MaterialTheme.typography.bodySmall,
                color = UnderstoryTheme.semantic.dim,
            )
        }
        r.notes.forEach { note ->
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                note,
                style = MaterialTheme.typography.bodyMedium,
                color = UnderstoryTheme.semantic.warning,
            )
        }
    }
}

/** Verdict pill: severity-tinted icon + localized verdict text. */
@Composable
internal fun VerdictChip(verdict: ApkAnalyzer.Verdict) {
    val accent = verdictAccent(verdict)
    Surface(
        color = accent.copy(alpha = 0.16f),
        contentColor = accent,
        shape = MaterialTheme.shapes.small,
    ) {
        Row(
            modifier = Modifier.padding(
                horizontal = UnderstoryTheme.spacing.sm,
                vertical = UnderstoryTheme.spacing.xs,
            ),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = verdictIcon(verdict),
                contentDescription = null,
                tint = accent,
                modifier = Modifier.size(18.dp),
            )
            Spacer(Modifier.width(UnderstoryTheme.spacing.xs))
            Text(
                verdictLabel(verdict),
                style = MaterialTheme.typography.labelLarge,
            )
        }
    }
}

/**
 * The aggregate risk-score row: a rating chip, the numeric score out of 100, a
 * progress bar, and an HONEST caption. The score is a heuristic ranking dial,
 * NOT a probability — the caption says so, keeping copy truthful (the vault /
 * honest-copy invariant applies to security claims too).
 */
@Composable
internal fun RiskScoreRow(risk: RiskRules.RiskScore) {
    val accent = ratingAccent(risk.rating)
    Column(Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Surface(
                color = accent.copy(alpha = 0.16f),
                contentColor = accent,
                shape = MaterialTheme.shapes.small,
            ) {
                Text(
                    stringResource(R.string.av_rating_chip, ratingLabel(risk.rating)),
                    style = MaterialTheme.typography.labelLarge,
                    modifier = Modifier.padding(
                        horizontal = UnderstoryTheme.spacing.sm,
                        vertical = UnderstoryTheme.spacing.xs,
                    ),
                )
            }
            Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
            Text(
                stringResource(R.string.av_score_out_of, risk.score),
                style = MaterialTheme.typography.titleMedium,
                color = accent,
                fontWeight = FontWeight.Medium,
            )
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        LinearProgressIndicator(
            progress = { risk.score / 100f },
            color = accent,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            stringResource(R.string.av_score_caption),
            style = MaterialTheme.typography.bodySmall,
            color = UnderstoryTheme.semantic.dim,
        )
    }
}

/**
 * A tappable row for the audit list: leading severity badge (from the top
 * finding, or the verdict when there is none), package name, the top finding's
 * title as supporting text, a verdict chip, and a trailing chevron. The whole
 * card is [SuiteCard]'s secure-clickable surface.
 */
@Composable
internal fun AuditRowCard(r: ApkAnalyzer.Report, onClick: () -> Unit) {
    SuiteCard(onClick = onClick) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            val top = r.findings.firstOrNull()
            if (top != null) {
                SeverityBadge(top.severity)
                Spacer(Modifier.width(UnderstoryTheme.spacing.md))
            }
            Column(Modifier.weight(1f)) {
                Text(
                    r.packageName,
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                top?.let { f ->
                    Text(
                        f.title,
                        style = MaterialTheme.typography.bodyMedium,
                        color = severityAccent(f.severity),
                    )
                }
            }
            Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
            VerdictChip(r.verdict)
            Icon(
                imageVector = Icons.Filled.ChevronRight,
                contentDescription = stringResource(R.string.av_audit_details),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** Top-of-home positioning banner (§0). */
@Composable
internal fun PositioningBanner() {
    Surface(
        color = MaterialTheme.colorScheme.primaryContainer,
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            text = stringResource(R.string.av_positioning),
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(UnderstoryTheme.spacing.md),
        )
    }
}

/** Honest Play Protect card (§3) — UNKNOWN-amber + "Open Play Protect" deep-link. */
@Composable
internal fun PlayProtectCard(status: PlayProtectStatus.Status) {
    val ctx = LocalContext.current
    val accent = when (status.state) {
        PlayProtectStatus.State.ENABLED -> UnderstoryTheme.semantic.success
        PlayProtectStatus.State.DISABLED -> MaterialTheme.colorScheme.error
        PlayProtectStatus.State.NOT_APPLICABLE -> UnderstoryTheme.semantic.dim
        PlayProtectStatus.State.UNKNOWN -> UnderstoryTheme.semantic.warning
    }
    val label = when (status.state) {
        PlayProtectStatus.State.ENABLED -> stringResource(R.string.av_pp_on)
        PlayProtectStatus.State.DISABLED -> stringResource(R.string.av_pp_off)
        PlayProtectStatus.State.NOT_APPLICABLE -> stringResource(R.string.av_pp_na)
        PlayProtectStatus.State.UNKNOWN -> stringResource(R.string.av_pp_unknown)
    }
    // Offer the deep-link on every state except NOT_APPLICABLE (no GMS present).
    val showOpen = status.state != PlayProtectStatus.State.NOT_APPLICABLE
    val canOpen = showOpen && SettingsDeepLinks.canOpenPlayProtect(ctx)

    SuiteCard {
        Text(label, style = MaterialTheme.typography.titleMedium, color = accent)
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            status.explain,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (showOpen) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            SecureOutlinedButton(
                onClick = { SettingsDeepLinks.openPlayProtect(ctx) },
                enabled = canOpen,
            ) {
                Text(
                    if (canOpen) stringResource(R.string.av_pp_open)
                    else stringResource(R.string.av_pp_unreachable),
                )
            }
        }
    }
}

/** Definitions status line + Import action (§1.5). */
@Composable
internal fun DefinitionsCard(
    meta: BlocklistStore.Meta?,
    onImport: () -> Unit,
    transientResult: String?,
    isError: Boolean,
    onImportOlder: (() -> Unit)? = null,
) {
    SuiteCard {
        val line = when {
            meta == null -> stringResource(R.string.av_defs_loading)
            meta.isSeed -> stringResource(R.string.av_defs_seed, meta.serial)
            else -> stringResource(R.string.av_defs_imported, meta.serial, meta.issued)
        }
        Text(line, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface)
        if (meta != null) {
            Text(
                stringResource(R.string.av_defs_counts, meta.apkCount, meta.certCount),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (transientResult != null) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                transientResult,
                style = MaterialTheme.typography.bodyMedium,
                color = if (isError) MaterialTheme.colorScheme.error else UnderstoryTheme.semantic.success,
            )
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        SecureOutlinedButton(onClick = onImport) {
            Text(stringResource(R.string.av_import_defs))
        }
        if (onImportOlder != null) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            SecureOutlinedButton(onClick = onImportOlder) {
                Text(stringResource(R.string.av_defs_import_anyway))
            }
        }
    }
}

/** Root/patcher/hooking-tooling informational card (§6/§7). Hidden when empty. */
@Composable
internal fun TamperCard(info: TamperFindings.TamperInfo) {
    if (info.lines.isEmpty()) return
    val topSeverity = info.lines.first().severity
    SuiteCard {
        Text(
            stringResource(R.string.av_tamper_title),
            style = MaterialTheme.typography.titleMedium,
            color = severityAccent(topSeverity),
            fontWeight = FontWeight.Medium,
        )
        for (line in info.lines) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Row(Modifier.fillMaxWidth()) {
                Text(
                    line.severity.name + ": ",
                    style = MaterialTheme.typography.bodyMedium,
                    color = severityAccent(line.severity),
                )
                Text(
                    line.text,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/**
 * Device-wide audit summary shown above the flagged list: "N of M scanned
 * flagged" plus a per-rating breakdown. Honest denominator — [scanned] is every
 * user app audited, not just the flagged ones.
 */
@Composable
internal fun AuditSummaryCard(summary: ApkAnalyzer.AuditSummary) {
    SuiteCard {
        Text(
            stringResource(R.string.av_audit_summary, summary.flagged, summary.scanned),
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface,
            fontWeight = FontWeight.Medium,
        )
        val order = listOf(
            RiskRules.Rating.CRITICAL,
            RiskRules.Rating.HIGH,
            RiskRules.Rating.MEDIUM,
            RiskRules.Rating.LOW,
        )
        val parts = order.mapNotNull { rating ->
            summary.byRating[rating]?.takeIf { it > 0 }?.let { n -> ratingLabel(rating) to n }
        }
        if (parts.isNotEmpty()) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Row(Modifier.fillMaxWidth()) {
                parts.forEachIndexed { i, (label, n) ->
                    if (i > 0) Spacer(Modifier.width(UnderstoryTheme.spacing.md))
                    Text(
                        "$n $label",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
        if (summary.knownBad > 0) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                stringResource(R.string.av_audit_summary_known_bad, summary.knownBad),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
            )
        }
    }
}

/** Install-source line for the detail screen (installed apps only). */
@Composable
internal fun InstallSourceCard(source: ApkAnalyzer.InstallSource) {
    val accent = when (source.trust) {
        RiskRules.InstallerTrust.TRUSTED -> UnderstoryTheme.semantic.success
        RiskRules.InstallerTrust.SIDELOAD -> UnderstoryTheme.semantic.warning
        RiskRules.InstallerTrust.UNKNOWN -> UnderstoryTheme.semantic.dim
    }
    SuiteCard {
        Text(
            stringResource(R.string.av_install_source_title),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
            fontWeight = FontWeight.Medium,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            source.label,
            style = MaterialTheme.typography.bodyMedium,
            color = accent,
        )
        val note = when (source.trust) {
            RiskRules.InstallerTrust.TRUSTED -> stringResource(R.string.av_install_trusted)
            RiskRules.InstallerTrust.SIDELOAD -> stringResource(R.string.av_install_sideload)
            RiskRules.InstallerTrust.UNKNOWN -> stringResource(R.string.av_install_unknown)
        }
        Text(
            note,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/**
 * The app's declared permissions, grouped by danger tier (Dangerous → Signature
 * → Normal). Honest framing: "requests", not "has" — this is the declared set,
 * not the granted set.
 */
@Composable
internal fun PermissionGroupsCard(permissions: List<String>) {
    if (permissions.isEmpty()) return
    val groups = remember(permissions) { PermissionGroups.grouped(permissions) }
    SuiteCard {
        Text(
            stringResource(R.string.av_perms_title, permissions.distinct().size),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
            fontWeight = FontWeight.Medium,
        )
        for ((tier, perms) in groups) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            val (tierLabel, tierColor) = when (tier) {
                PermissionGroups.Tier.DANGEROUS ->
                    stringResource(R.string.av_perm_tier_dangerous) to MaterialTheme.colorScheme.error
                PermissionGroups.Tier.SIGNATURE ->
                    stringResource(R.string.av_perm_tier_signature) to UnderstoryTheme.semantic.warning
                PermissionGroups.Tier.NORMAL ->
                    stringResource(R.string.av_perm_tier_normal) to UnderstoryTheme.semantic.dim
            }
            Text(
                "$tierLabel (${perms.size})",
                style = MaterialTheme.typography.labelMedium,
                color = tierColor,
            )
            for (p in perms) {
                Text(
                    PermissionGroups.shortName(p),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/**
 * The "take action" card for an installed app: deep-links to the OS App-Info
 * screen, the uninstall confirmation, and Play Protect. We never uninstall or
 * revoke on the user's behalf — every control hands off to the system screen
 * where the user decides. [pkg] is the target package.
 */
@Composable
internal fun AppActionsCard(pkg: String) {
    val ctx = LocalContext.current
    val canDetails = remember(pkg) { SettingsDeepLinks.canOpenAppDetails(ctx, pkg) }
    val canPlayProtect = remember { SettingsDeepLinks.canOpenPlayProtect(ctx) }
    SuiteCard {
        Text(
            stringResource(R.string.av_actions_title),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
            fontWeight = FontWeight.Medium,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        SecureOutlinedButton(
            onClick = { SettingsDeepLinks.openAppDetails(ctx, pkg) },
            enabled = canDetails,
        ) {
            Icon(
                imageVector = Icons.Filled.Launch,
                contentDescription = null,
                modifier = Modifier.size(18.dp),
            )
            Spacer(Modifier.width(UnderstoryTheme.spacing.xs))
            Text(stringResource(R.string.av_action_app_info))
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        SecureOutlinedButton(onClick = { SettingsDeepLinks.requestUninstall(ctx, pkg) }) {
            Text(stringResource(R.string.av_action_uninstall))
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        SecureOutlinedButton(
            onClick = { SettingsDeepLinks.openPlayProtect(ctx) },
            enabled = canPlayProtect,
        ) {
            Icon(
                imageVector = Icons.Filled.OpenInNew,
                contentDescription = null,
                modifier = Modifier.size(18.dp),
            )
            Spacer(Modifier.width(UnderstoryTheme.spacing.xs))
            Text(stringResource(R.string.av_action_play_protect))
        }
    }
}

/** Periodic-scan opt-in toggle (§5.2). Default off; honest alerts-off sub-line. */
@Composable
internal fun PeriodicScanToggle(
    enabled: Boolean,
    alertsGranted: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    val sub = when {
        !enabled -> stringResource(R.string.av_periodic_sub_off)
        !alertsGranted -> stringResource(R.string.av_periodic_alerts_off)
        else -> stringResource(R.string.av_periodic_sub_on)
    }
    SuiteCard {
        SwitchRow(
            label = stringResource(R.string.av_periodic_label),
            checked = enabled,
            onCheckedChange = onToggle,
            supporting = sub,
        )
    }
}

/**
 * On-install alert opt-in (§5.1). Default off. When on, a freshly installed /
 * updated app that scores High/Critical (while APK Check is open) fires a
 * notification. Honest sub-line: the in-app banner shows regardless; this only
 * governs the out-of-app alert, which needs the notification permission.
 */
@Composable
internal fun InstallAlertToggle(
    enabled: Boolean,
    alertsGranted: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    val sub = when {
        !enabled -> stringResource(R.string.av_install_alert_sub_off)
        !alertsGranted -> stringResource(R.string.av_periodic_alerts_off)
        else -> stringResource(R.string.av_install_alert_sub_on)
    }
    SuiteCard {
        SwitchRow(
            label = stringResource(R.string.av_install_alert_label),
            checked = enabled,
            onCheckedChange = onToggle,
            supporting = sub,
        )
    }
}
