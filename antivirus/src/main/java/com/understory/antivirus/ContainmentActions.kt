package com.understory.antivirus

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.LayersClear
import androidx.compose.material.icons.filled.LockReset
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.RemoveModerator
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.filled.Shield
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.understory.elevation.Elevation
import com.understory.elevation.Outcome
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.Bg
import com.understory.security.ui.components.ConfirmDestructiveDialog
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Elevated CONTAINMENT controls for a flagged installed app — the reversible-first
 * "make this app safe right now" surface that sits above the rootless deep-links
 * in [AppActionsCard], alongside the existing [ElevatedActionsSection].
 *
 * DOCTRINE (enforced here, not just documented):
 *   - OPT-IN + FAIL-CLOSED. Every control is gated on [Elevation.canRunShell].
 *     When elevation is not granted this section renders a single honest note
 *     that routes to the app's Shizuku grant surface (the Definitions tab) — never
 *     a dead/disabled control.
 *   - REVERSIBLE-FIRST. Quarantine (suspend + appops-ignore + pm-revoke) has a
 *     one-tap RELEASE inverse; appops revoke has an "undo to default"; disabling a
 *     component is undone by re-enabling. Only WIPE DATA and (via the existing
 *     section) uninstall are destructive, and those go behind
 *     [ConfirmDestructiveDialog(requireHold = true)].
 *   - HONEST REPORTING. Every step's [Outcome] is shown (succeeded / failed /
 *     unsupported) with no fabricated success. Multi-step ops render a per-step
 *     result list.
 *   - HARD EXCLUSIONS. Protected packages ([ContainmentFacts.suiteSibling]) get an
 *     "excluded" note and no actions — we never act on the launcher, system
 *     settings, Tailscale, the Shizuku manager, or a suite sibling.
 *   - NETWORK stays with the firewall. Quarantine routes network restriction to
 *     the firewall app via a launch deep-link; we do NOT run netpolicy here.
 */
@Composable
internal fun ContainmentSection(report: ApkAnalyzer.Report) {
    val facts = report.containment ?: return
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val pkg = facts.packageName

    // Fail-closed capability snapshot, re-derived off the main thread. Bumping
    // [refreshKey] after a grant (or an action that changes state) recomputes it.
    var refreshKey by remember { mutableIntStateOf(0) }
    val canRun by produceState(initialValue = false, key1 = refreshKey, key2 = pkg) {
        value = withContext(Bg.io) { Elevation.canRunShell(ctx) }
    }

    // Protected package → never any containment action; say so and stop.
    if (facts.suiteSibling) {
        SuiteCard {
            SectionTitle(stringResource(R.string.av_contain_title))
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                stringResource(R.string.av_contain_excluded, pkg),
                style = MaterialTheme.typography.bodyMedium,
                color = UnderstoryTheme.semantic.dim,
            )
        }
        return
    }

    // Nothing to contain on this app → render nothing (no empty card).
    if (!facts.hasAnyControl()) return

    // Not elevated → one honest note routing to the grant surface; NO dead control.
    if (!canRun) {
        SuiteCard {
            SectionTitle(stringResource(R.string.av_contain_title))
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                stringResource(R.string.av_contain_locked),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        return
    }

    // Per-step result lines from the last multi-step op (quarantine/release).
    var steps by remember { mutableStateOf<List<StepResult>>(emptyList()) }
    // Single transient result for the single-shot ops.
    var single by remember { mutableStateOf<StepResult?>(null) }
    var busy by remember { mutableStateOf(false) }

    // Destructive-confirm state.
    var confirmWipe by remember { mutableStateOf(false) }
    var confirmDisable by remember { mutableStateOf<ContainmentFacts.DisableTarget?>(null) }

    fun runSteps(work: suspend () -> List<StepResult>) {
        if (busy) return
        busy = true
        single = null
        scope.launch {
            val result = withContext(Bg.io) {
                runCatching { work() }.getOrElse {
                    listOf(StepResult(it.message ?: "error", ok = false))
                }
            }
            steps = result
            refreshKey++
            busy = false
        }
    }

    fun runSingle(label: String, work: suspend () -> Outcome) {
        if (busy) return
        busy = true
        steps = emptyList()
        scope.launch {
            val outcome = withContext(Bg.io) {
                runCatching { work() }.getOrElse { Outcome.Failed(it.message ?: "error") }
            }
            single = StepResult.of(ctx, label, outcome)
            refreshKey++
            busy = false
        }
    }

    SuiteCard {
        SectionTitle(stringResource(R.string.av_contain_title))
        Text(
            stringResource(R.string.av_contain_sub),
            style = MaterialTheme.typography.bodySmall,
            color = UnderstoryTheme.semantic.dim,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))

        Column(verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs)) {
            // --- Feature 1: one-tap quarantine + its inverse release. ---
            ContainButton(
                icon = Icons.Filled.Shield,
                label = stringResource(R.string.av_contain_quarantine),
                enabled = !busy,
                onClick = { runSteps { quarantine(ctx, facts) } },
            )
            ContainButton(
                icon = Icons.Filled.LockReset,
                label = stringResource(R.string.av_contain_release),
                enabled = !busy,
                onClick = { runSteps { release(ctx, facts) } },
            )

            // Network restriction is the firewall's slot — route there, never run
            // netpolicy here. Shown only when the firewall app is installed.
            val canFirewall = remember(refreshKey) { ContainmentDeepLinks.canRouteToFirewall(ctx) }
            if (canFirewall) {
                ContainButton(
                    icon = Icons.Filled.Block,
                    label = stringResource(R.string.av_contain_network),
                    enabled = !busy,
                    onClick = { ContainmentDeepLinks.routeToFirewall(ctx) },
                )
            }

            // --- Feature 2: special-access appops revoke (overlay / usage) + undo. ---
            if (facts.hasOverlayPermission || facts.hasUsageStatsPermission) {
                ContainButton(
                    icon = Icons.Filled.LayersClear,
                    label = stringResource(R.string.av_contain_appops_ignore),
                    enabled = !busy,
                    onClick = { runSteps { setSpecialAccess(ctx, facts, "ignore") } },
                )
                ContainButton(
                    icon = Icons.Filled.Restore,
                    label = stringResource(R.string.av_contain_appops_default),
                    enabled = !busy,
                    onClick = { runSteps { setSpecialAccess(ctx, facts, "default") } },
                )
            }

            // --- Feature 3: neutralise device admin (unblocks uninstall). ---
            if (facts.activeDeviceAdminComponents.isNotEmpty()) {
                ContainButton(
                    icon = Icons.Filled.RemoveModerator,
                    label = stringResource(R.string.av_contain_deadmin),
                    enabled = !busy,
                    onClick = { runSteps { neutraliseDeviceAdmin(ctx, facts) } },
                )
            }

            // --- Feature 5: disable a specific flagged abuser component (reversible). ---
            facts.disableTargets.forEach { target ->
                ContainButton(
                    icon = Icons.Filled.PowerSettingsNew,
                    label = stringResource(R.string.av_contain_disable_component, disableKindLabel(target.kind)),
                    enabled = !busy,
                    onClick = { confirmDisable = target },
                )
            }

            // --- Feature 4: wipe app data (destructive → hold-to-confirm). ---
            ContainButton(
                icon = Icons.Filled.CleaningServices,
                label = stringResource(R.string.av_contain_wipe),
                enabled = !busy,
                onClick = { confirmWipe = true },
            )
        }

        // Per-step result list (quarantine / release / appops / de-admin).
        if (steps.isNotEmpty()) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            steps.forEach { StepLine(it) }
        }
        // Single-op result line.
        single?.let {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            StepLine(it)
        }
    }

    // Wipe data — destructive, press-and-hold.
    ConfirmDestructiveDialog(
        visible = confirmWipe,
        title = stringResource(R.string.av_contain_wipe_confirm_title),
        body = stringResource(R.string.av_contain_wipe_confirm_body, pkg),
        confirmLabel = stringResource(R.string.av_contain_wipe),
        requireHold = true,
        onConfirm = {
            confirmWipe = false
            runSingle(ctx.getString(R.string.av_contain_step_wipe)) { Elevation.clearAppData(ctx, pkg) }
        },
        onDismiss = { confirmWipe = false },
    )

    // Disable a specific component — reversible, but a normal confirm so it isn't
    // a stray tap (copy warns an update/reboot can re-enable it).
    confirmDisable?.let { target ->
        ConfirmDestructiveDialog(
            visible = true,
            title = stringResource(R.string.av_contain_disable_confirm_title),
            body = stringResource(
                R.string.av_contain_disable_confirm_body,
                disableKindLabel(target.kind),
                target.component,
            ),
            confirmLabel = stringResource(R.string.av_contain_disable_confirm_action),
            onConfirm = {
                confirmDisable = null
                runSingle(ctx.getString(R.string.av_contain_step_disable)) {
                    Elevation.setComponentEnabled(ctx, pkg, target.component, enabled = false)
                }
            },
            onDismiss = { confirmDisable = null },
        )
    }
}

// ---------------------------------------------------------------------------
// Multi-step containment compositions. Each returns a per-step [StepResult] list
// so the UI reports honestly what succeeded and what didn't. None throw.
// ---------------------------------------------------------------------------

/**
 * Feature 1 — one-tap quarantine. Composes the vetted primitives in order, each
 * reported honestly:
 *   force-stop → suspend → revoke each dangerous granted perm →
 *   appops-ignore SYSTEM_ALERT_WINDOW + GET_USAGE_STATS.
 * Network restriction is intentionally NOT done here — it's routed to the
 * firewall app (see the UI's network row / [ContainmentDeepLinks]).
 */
private suspend fun quarantine(
    ctx: android.content.Context,
    facts: ContainmentFacts,
): List<StepResult> {
    val pkg = facts.packageName
    val out = mutableListOf<StepResult>()
    out += StepResult.of(ctx, ctx.getString(R.string.av_contain_step_forcestop), Elevation.forceStop(ctx, pkg))
    out += StepResult.of(ctx, ctx.getString(R.string.av_contain_step_suspend), Elevation.setAppSuspended(ctx, pkg, suspended = true))
    for (perm in facts.revocableDangerousPerms) {
        out += StepResult.of(
            ctx,
            ctx.getString(R.string.av_contain_step_revoke, PermissionGroups.shortName(perm)),
            Elevation.revokePermission(ctx, pkg, perm),
        )
    }
    // The overlay / usage appops abuse surface pm-revoke can't touch — always
    // ignore both as part of quarantine (harmless if the app never held them).
    out += StepResult.of(
        ctx,
        ctx.getString(R.string.av_contain_step_appop, "SYSTEM_ALERT_WINDOW"),
        Elevation.setAppOpMode(ctx, pkg, "SYSTEM_ALERT_WINDOW", "ignore"),
    )
    out += StepResult.of(
        ctx,
        ctx.getString(R.string.av_contain_step_appop, "GET_USAGE_STATS"),
        Elevation.setAppOpMode(ctx, pkg, "GET_USAGE_STATS", "ignore"),
    )
    return out
}

/**
 * Feature 1 inverse — release from quarantine: un-suspend + restore both appops
 * to "default". Runtime permissions are NOT re-granted (the user re-grants those
 * through the OS if the app legitimately needs them).
 */
private suspend fun release(
    ctx: android.content.Context,
    facts: ContainmentFacts,
): List<StepResult> {
    val pkg = facts.packageName
    val out = mutableListOf<StepResult>()
    out += StepResult.of(ctx, ctx.getString(R.string.av_contain_step_unsuspend), Elevation.setAppSuspended(ctx, pkg, suspended = false))
    out += StepResult.of(
        ctx,
        ctx.getString(R.string.av_contain_step_appop_default, "SYSTEM_ALERT_WINDOW"),
        Elevation.setAppOpMode(ctx, pkg, "SYSTEM_ALERT_WINDOW", "default"),
    )
    out += StepResult.of(
        ctx,
        ctx.getString(R.string.av_contain_step_appop_default, "GET_USAGE_STATS"),
        Elevation.setAppOpMode(ctx, pkg, "GET_USAGE_STATS", "default"),
    )
    return out
}

/**
 * Feature 2 — set the special-access appops (overlay / usage) to [mode], only for
 * the ones this app actually holds. [mode] is "ignore" (revoke) or "default" (undo).
 */
private suspend fun setSpecialAccess(
    ctx: android.content.Context,
    facts: ContainmentFacts,
    mode: String,
): List<StepResult> {
    val pkg = facts.packageName
    val out = mutableListOf<StepResult>()
    if (facts.hasOverlayPermission) {
        out += StepResult.of(
            ctx,
            ctx.getString(R.string.av_contain_step_appop, "SYSTEM_ALERT_WINDOW"),
            Elevation.setAppOpMode(ctx, pkg, "SYSTEM_ALERT_WINDOW", mode),
        )
    }
    if (facts.hasUsageStatsPermission) {
        out += StepResult.of(
            ctx,
            ctx.getString(R.string.av_contain_step_appop, "GET_USAGE_STATS"),
            Elevation.setAppOpMode(ctx, pkg, "GET_USAGE_STATS", mode),
        )
    }
    return out
}

/**
 * Feature 3 — neutralise every active device-admin component for this app, so a
 * device-admin-pinned app can then be uninstalled. A true Device Owner cannot be
 * removed this way; that surfaces honestly as a failed step (the shared helper
 * translates the nonzero exit to [Outcome.Failed]).
 */
private suspend fun neutraliseDeviceAdmin(
    ctx: android.content.Context,
    facts: ContainmentFacts,
): List<StepResult> {
    val out = mutableListOf<StepResult>()
    for (component in facts.activeDeviceAdminComponents) {
        out += StepResult.of(
            ctx,
            ctx.getString(R.string.av_contain_step_deadmin, component),
            Elevation.removeActiveDeviceAdmin(ctx, component),
        )
    }
    return out
}

// ---------------------------------------------------------------------------
// Small UI helpers.
// ---------------------------------------------------------------------------

@Composable
private fun SectionTitle(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.onSurface,
        fontWeight = FontWeight.Medium,
    )
}

@Composable
private fun ContainButton(
    icon: ImageVector,
    label: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    SecureOutlinedButton(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(UnderstoryTheme.spacing.xs))
        Text(label)
    }
}

/** A single honest result line: green on success, error-tinted otherwise. */
@Composable
private fun StepLine(step: StepResult) {
    val color = if (step.ok) UnderstoryTheme.semantic.success else MaterialTheme.colorScheme.error
    Row(Modifier.fillMaxWidth()) {
        Icon(
            imageVector = if (step.ok) Icons.Filled.CheckCircle else Icons.Filled.ErrorOutline,
            contentDescription = null,
            tint = color,
            modifier = Modifier.size(16.dp),
        )
        Spacer(Modifier.width(UnderstoryTheme.spacing.xs))
        Text(
            step.text,
            style = MaterialTheme.typography.bodySmall,
            color = color,
        )
    }
}

@Composable
private fun disableKindLabel(kind: ContainmentFacts.DisableTarget.Kind): String = when (kind) {
    ContainmentFacts.DisableTarget.Kind.ACCESSIBILITY -> stringResource(R.string.av_contain_kind_a11y)
    ContainmentFacts.DisableTarget.Kind.NOTIFICATION_LISTENER -> stringResource(R.string.av_contain_kind_notif)
    ContainmentFacts.DisableTarget.Kind.DEVICE_ADMIN -> stringResource(R.string.av_contain_kind_admin)
}

/**
 * One honest step outcome for the result list. [ok] drives the color/icon; [text]
 * is the already-localized line (label + honest Success/Unsupported/Failed tail).
 */
internal data class StepResult(val text: String, val ok: Boolean) {
    companion object {
        fun of(ctx: android.content.Context, label: String, outcome: Outcome): StepResult = when (outcome) {
            is Outcome.Success -> StepResult(ctx.getString(R.string.av_contain_step_ok, label), ok = true)
            is Outcome.Unsupported -> StepResult(
                ctx.getString(R.string.av_contain_step_unsupported, label, outcome.reason),
                ok = false,
            )
            is Outcome.Failed -> StepResult(
                ctx.getString(R.string.av_contain_step_failed, label, outcome.message),
                ok = false,
            )
        }
    }
}
