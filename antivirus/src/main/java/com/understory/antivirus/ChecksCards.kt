package com.understory.antivirus

import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme

// ------------------------------------------------------------------
// Definitions-tab cards for the additional check layers: aux databases,
// Snort-format passive rules, VirusTotal, and the periodic-check toggles.
// ------------------------------------------------------------------

/**
 * Auxiliary virus databases: the imported third-party hash feeds layered on
 * top of the signed .ubl list, each with provenance and a remove control.
 */
@Composable
internal fun AuxDatabasesCard(
    databases: List<AuxDatabases.Meta>,
    onImport: () -> Unit,
    onRemove: (AuxDatabases.Meta) -> Unit,
    transientResult: String?,
    isError: Boolean,
) {
    SuiteCard {
        Text(
            stringResource(R.string.av_auxdb_title),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
            fontWeight = FontWeight.Medium,
        )
        Text(
            if (databases.isEmpty()) stringResource(R.string.av_auxdb_none)
            else stringResource(R.string.av_auxdb_count, databases.size, databases.sumOf { it.count }),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        for (db in databases) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(
                stringResource(R.string.av_auxdb_row, db.name, db.count, db.importedAt),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            SecureOutlinedButton(onClick = { onRemove(db) }) {
                Text(stringResource(R.string.av_auxdb_remove, db.name))
            }
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
            Text(stringResource(R.string.av_auxdb_import))
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            stringResource(R.string.av_auxdb_formats),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/**
 * Snort-format passive ruleset status: seed/user rule counts, last-pass
 * summary, import/remove controls. The supporting text says plainly what
 * "passive" means here (content signatures, not packet capture).
 */
@Composable
internal fun SnortRulesCard(
    meta: SnortRuleStore.Meta?,
    lastScan: SnortScanLog.Snapshot?,
    onImport: () -> Unit,
    onRemoveUser: (() -> Unit)?,
    transientResult: String?,
    isError: Boolean,
) {
    SuiteCard {
        Text(
            stringResource(R.string.av_snort_title),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
            fontWeight = FontWeight.Medium,
        )
        Text(
            if (meta == null) stringResource(R.string.av_defs_loading)
            else stringResource(R.string.av_snort_counts, meta.seedCount, meta.userCount),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (lastScan != null) {
            Text(
                if (lastScan.hits.isEmpty()) stringResource(R.string.av_snort_last_clean)
                else stringResource(R.string.av_snort_last_hits, lastScan.hits.size),
                style = MaterialTheme.typography.bodyMedium,
                color = if (lastScan.hits.isEmpty()) UnderstoryTheme.semantic.success
                else UnderstoryTheme.semantic.warning,
            )
            for (hit in lastScan.hits.take(5)) {
                Text(
                    stringResource(R.string.av_snort_hit_row, hit.packageName, hit.msg, hit.sid),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
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
            Text(stringResource(R.string.av_snort_import))
        }
        if (onRemoveUser != null) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            SecureOutlinedButton(onClick = onRemoveUser) {
                Text(stringResource(R.string.av_snort_remove_user))
            }
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
        Text(
            stringResource(R.string.av_snort_honest),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/**
 * VirusTotal opt-in: API-key entry + master enable toggle. The card's copy is
 * the consent screen — it says exactly what leaves the device (a file hash,
 * never the file) and that the feature is dead without the user's own key.
 */
@Composable
internal fun VirusTotalCard(
    configured: Boolean,
    enabled: Boolean,
    onSaveKey: (String) -> Unit,
    onClearKey: () -> Unit,
    onToggle: (Boolean) -> Unit,
) {
    var keyInput by rememberSaveable { mutableStateOf("") }
    SuiteCard {
        Text(
            stringResource(R.string.av_vt_title),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
            fontWeight = FontWeight.Medium,
        )
        Text(
            stringResource(R.string.av_vt_explain),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        if (!configured) {
            OutlinedTextField(
                value = keyInput,
                onValueChange = { keyInput = it },
                label = { Text(stringResource(R.string.av_vt_key_label)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            SecureOutlinedButton(
                onClick = {
                    if (keyInput.isNotBlank()) {
                        onSaveKey(keyInput)
                        keyInput = ""
                    }
                },
            ) {
                Text(stringResource(R.string.av_vt_key_save))
            }
        } else {
            Text(
                stringResource(R.string.av_vt_key_set),
                style = MaterialTheme.typography.bodyMedium,
                color = UnderstoryTheme.semantic.success,
            )
            SwitchRow(
                label = stringResource(R.string.av_vt_toggle_label),
                checked = enabled,
                onCheckedChange = onToggle,
                supporting = if (enabled) stringResource(R.string.av_vt_toggle_on)
                else stringResource(R.string.av_vt_toggle_off),
            )
            SecureOutlinedButton(onClick = onClearKey) {
                Text(stringResource(R.string.av_vt_key_clear))
            }
        }
    }
}

/**
 * The app's own periodic checks — one independent toggle per check, all
 * default off ([ScanSchedules]). The VT row is additionally gated on the
 * feature being configured+enabled above; it renders disabled until then.
 */
@Composable
internal fun PeriodicChecksCard(
    fullAuditOn: Boolean,
    snortOn: Boolean,
    vtOn: Boolean,
    vtAvailable: Boolean,
    onToggle: (ScanSchedules.Check, Boolean) -> Unit,
) {
    SuiteCard {
        Text(
            stringResource(R.string.av_checks_title),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
            fontWeight = FontWeight.Medium,
        )
        SwitchRow(
            label = stringResource(R.string.av_check_full_audit),
            checked = fullAuditOn,
            onCheckedChange = { onToggle(ScanSchedules.Check.FULL_AUDIT, it) },
            supporting = stringResource(R.string.av_check_full_audit_sub),
        )
        SwitchRow(
            label = stringResource(R.string.av_check_snort),
            checked = snortOn,
            onCheckedChange = { onToggle(ScanSchedules.Check.SNORT, it) },
            supporting = stringResource(R.string.av_check_snort_sub),
        )
        SwitchRow(
            label = stringResource(R.string.av_check_vt),
            checked = vtOn && vtAvailable,
            onCheckedChange = { onToggle(ScanSchedules.Check.VIRUSTOTAL, it) },
            supporting = if (vtAvailable) stringResource(R.string.av_check_vt_sub)
            else stringResource(R.string.av_check_vt_unavailable),
            enabled = vtAvailable,
        )
    }
}
