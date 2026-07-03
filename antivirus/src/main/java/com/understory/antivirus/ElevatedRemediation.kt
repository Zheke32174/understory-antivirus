package com.understory.antivirus

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.RemoveModerator
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.understory.elevation.Elevation
import com.understory.elevation.Outcome
import com.understory.elevation.ui.ElevationCard
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.Bg
import com.understory.security.ui.components.ConfirmDestructiveDialog
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * OPTIONAL-elevation remediation for a flagged app's detail screen.
 *
 * The suite is rootless by default. This section renders REAL remediation
 * controls (uninstall / force-stop / suspend / revoke-dangerous-permissions)
 * ONLY when an elevation tier the user explicitly granted can actually perform
 * them — asked capability-first ([Elevation.canManageApps] /
 * [Elevation.canWriteSecureSettings]-style predicates), never "is Shizuku
 * present?". When no tier is granted the section renders nothing and the plain
 * rootless deep-links in [AppActionsCard] stand alone — no dead/disabled
 * elevated controls, no elevation ever required.
 *
 * Destructive controls (uninstall, suspend) go through the tap-jacking-hardened
 * [ConfirmDestructiveDialog]; results are shown honestly inline (Success /
 * Unsupported / Failed) rather than silently. The vault threat-model invariant
 * is untouched — nothing here renders or types a recovery secret.
 */
@Composable
internal fun ElevatedActionsSection(report: ApkAnalyzer.Report) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val pkg = report.packageName

    // Recomputed capability snapshot. Bumping [refreshKey] (after a grant made
    // elsewhere, or after an action that changes install state) re-derives it off
    // the main thread. Capability-first: we ask what we CAN do, not which tier.
    var refreshKey by remember { mutableIntStateOf(0) }
    val caps by produceState(
        initialValue = ElevCaps(manageApps = false, revokePerms = false),
        key1 = refreshKey,
        key2 = pkg,
    ) {
        value = withContext(Bg.io) {
            ElevCaps(
                manageApps = Elevation.canManageApps(ctx),
                revokePerms = Elevation.canWriteSecureSettings(ctx),
            )
        }
    }

    // The runtime dangerous permissions this app declares that an elevated tier
    // could actually revoke (special-access perms are excluded — see
    // PermissionGroups.revocableDangerous).
    val revocable = remember(report.permissions) {
        PermissionGroups.revocableDangerous(report.permissions)
    }

    // Nothing granted → render nothing. The rootless deep-links in AppActionsCard
    // remain the honest path; we never show a dead elevated control.
    if (!caps.manageApps && !(caps.revokePerms && revocable.isNotEmpty())) return

    // Transient, honest result line for the last elevated action.
    var result by remember { mutableStateOf<String?>(null) }
    var resultIsError by remember { mutableStateOf(false) }

    // Confirm state for the destructive controls.
    var confirmUninstall by remember { mutableStateOf(false) }
    var confirmSuspend by remember { mutableStateOf(false) }

    fun runAction(work: suspend () -> Outcome) {
        scope.launch {
            val outcome = withContext(Bg.io) { runCatching { work() }.getOrElse { Outcome.Failed(it.message ?: "error") } }
            when (outcome) {
                is Outcome.Success -> {
                    result = ctx.getString(R.string.av_elev_result_ok)
                    resultIsError = false
                }
                is Outcome.Unsupported -> {
                    result = ctx.getString(R.string.av_elev_result_unsupported, outcome.reason)
                    resultIsError = true
                }
                is Outcome.Failed -> {
                    result = ctx.getString(R.string.av_elev_result_failed, outcome.message)
                    resultIsError = true
                }
            }
            // The install/permission state may have changed; re-derive capability.
            refreshKey++
        }
    }

    SuiteCard {
        Text(
            stringResource(R.string.av_elev_actions_title),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
            fontWeight = FontWeight.Medium,
        )
        Text(
            stringResource(R.string.av_elev_actions_sub),
            style = MaterialTheme.typography.bodySmall,
            color = UnderstoryTheme.semantic.dim,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))

        Column(verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs)) {
            if (caps.manageApps) {
                // Uninstall — destructive, confirm first.
                SecureOutlinedButton(
                    onClick = { confirmUninstall = true },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Filled.DeleteForever, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(UnderstoryTheme.spacing.xs))
                    Text(stringResource(R.string.av_elev_uninstall))
                }
                // Force stop — kills the running processes now. Not destructive to
                // installed state, so no confirm.
                SecureOutlinedButton(
                    onClick = { runAction { Elevation.forceStop(ctx, pkg) } },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Filled.Stop, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(UnderstoryTheme.spacing.xs))
                    Text(stringResource(R.string.av_elev_force_stop))
                }
                // Suspend — greys the app out and stops it launching. Reversible,
                // but surprising to the user, so confirm it.
                SecureOutlinedButton(
                    onClick = { confirmSuspend = true },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Filled.Block, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(UnderstoryTheme.spacing.xs))
                    Text(stringResource(R.string.av_elev_suspend))
                }
            }

            if (caps.revokePerms && revocable.isNotEmpty()) {
                // Revoke the specific dangerous runtime permissions the risk rules
                // surfaced. No confirm dialog: revoking a permission is safe and
                // reversible from Settings, and the button label names exactly
                // what it will revoke count-wise.
                SecureOutlinedButton(
                    onClick = {
                        runAction {
                            var lastFailure: Outcome? = null
                            var anyOk = false
                            for (perm in revocable) {
                                when (val r = Elevation.revokePermission(ctx, pkg, perm)) {
                                    is Outcome.Success -> anyOk = true
                                    is Outcome.Unsupported -> return@runAction r
                                    is Outcome.Failed -> lastFailure = r
                                }
                            }
                            lastFailure?.takeIf { !anyOk } ?: Outcome.Success()
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Filled.RemoveModerator, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(UnderstoryTheme.spacing.xs))
                    Text(stringResource(R.string.av_elev_revoke_perms, revocable.size))
                }
            }
        }

        result?.let { line ->
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(
                line,
                style = MaterialTheme.typography.bodyMedium,
                color = if (resultIsError) MaterialTheme.colorScheme.error else UnderstoryTheme.semantic.success,
            )
        }
    }

    ConfirmDestructiveDialog(
        visible = confirmUninstall,
        title = stringResource(R.string.av_elev_uninstall_confirm_title),
        body = stringResource(R.string.av_elev_uninstall_confirm_body, pkg),
        confirmLabel = stringResource(R.string.av_elev_uninstall),
        requireHold = true,
        onConfirm = {
            confirmUninstall = false
            runAction { Elevation.uninstall(ctx, pkg) }
        },
        onDismiss = { confirmUninstall = false },
    )

    ConfirmDestructiveDialog(
        visible = confirmSuspend,
        title = stringResource(R.string.av_elev_suspend_confirm_title),
        body = stringResource(R.string.av_elev_suspend_confirm_body, pkg),
        confirmLabel = stringResource(R.string.av_elev_suspend),
        onConfirm = {
            confirmSuspend = false
            runAction { Elevation.setAppSuspended(ctx, pkg, suspended = true) }
        },
        onDismiss = { confirmSuspend = false },
    )
}

/** Capability snapshot for [ElevatedActionsSection]. Capability-first, not tier-first. */
private data class ElevCaps(val manageApps: Boolean, val revokePerms: Boolean)

/**
 * The settings-screen elevation section: a header plus the shared
 * [com.understory.elevation.ui.ElevationCard]. Lets the user OPTIONALLY enable
 * Shizuku or Dhizuku to unlock in-app remediation on flagged apps. The card is
 * honest by construction — it shows the current tier, a grant button ONLY when a
 * tier is actually reachable-but-ungranted (never a dead button), and otherwise
 * the rootless fallback ("Open Settings", pointing at the OS all-apps list).
 * Enabling elevation is never required; APK Check is 100% functional without it.
 */
@Composable
internal fun AntivirusElevationSection() {
    val ctx = LocalContext.current
    SuiteSectionHeader(stringResource(R.string.av_section_elevation))
    ElevationCard(
        unlocks = listOf(
            stringResource(R.string.av_elev_unlock_manage),
            stringResource(R.string.av_elev_unlock_revoke),
        ),
        rootlessFallback = stringResource(R.string.av_elev_rootless_fallback),
        onRootlessFallback = { SettingsDeepLinks.openApplicationSettings(ctx) },
    )
}
