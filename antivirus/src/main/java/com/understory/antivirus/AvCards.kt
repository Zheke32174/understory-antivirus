package com.understory.antivirus

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
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
