package com.understory.antivirus

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.RemoveCircleOutline
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.understory.security.ui.Bg
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.withContext

/**
 * "Verified (elevated)" ground-truth section for a flagged installed app's detail
 * screen. Renders the actually-granted runtime permissions, live appop modes,
 * firstInstallTime, and installer package that only an elevated READ can see —
 * upgrading the static, manifest-derived "requests" list above it from "what the
 * app asks for" to "what it actually has".
 *
 * FAIL-OPEN by construction. This composable renders NOTHING unless
 * [DeepFacts.read] returned real ground truth. That covers every degrade case:
 * elevation not granted, the read returning null, or a dump-format drift the
 * parser couldn't make sense of. In all of those the static
 * [PermissionGroupsCard] above stands alone as the honest fallback — there is no
 * dead control, no spinner-forever, no alarm, and no fabricated "verified" value.
 *
 * READ-ONLY: no confirm, no action; nothing here mutates device state or touches
 * the containment/remediation controls.
 *
 * The read is keyed on the package, runs off the main thread, and re-runs if the
 * detail screen is recomposed for a different app. Its initial value is null, so
 * before the read settles the section is simply absent (the static view carries
 * the screen), then it appears if — and only if — there was something to verify.
 */
@Composable
internal fun VerifiedFactsSection(report: ApkAnalyzer.Report) {
    val ctx = LocalContext.current
    val pkg = report.packageName

    val facts by produceState<DeepFacts?>(initialValue = null, key1 = pkg) {
        value = withContext(Bg.io) { DeepFacts.read(ctx, pkg) }
    }

    // Nothing verified (unelevated / read null / parse-miss) → render nothing and
    // let the static "requests" section be the honest posture. FAIL-OPEN.
    val f = facts ?: return

    SuiteCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = Icons.Filled.VerifiedUser,
                contentDescription = null,
                tint = UnderstoryTheme.semantic.success,
                modifier = Modifier.size(20.dp),
            )
            Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
            Text(
                stringResource(R.string.av_deep_title),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurface,
                fontWeight = FontWeight.Medium,
            )
        }
        Text(
            stringResource(R.string.av_deep_sub),
            style = MaterialTheme.typography.bodySmall,
            color = UnderstoryTheme.semantic.dim,
        )

        // Provenance: when + from where the app actually arrived.
        f.firstInstallTime?.let { time ->
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            LabeledFact(
                label = stringResource(R.string.av_deep_first_install),
                value = time,
            )
        }
        f.installerPackage?.let { installer ->
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            LabeledFact(
                label = stringResource(R.string.av_deep_installer),
                value = installer,
            )
        }

        // Granted dangerous runtime permissions — the ground-truth "has".
        if (f.grantedRuntimePermissions.isNotEmpty()) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(
                stringResource(R.string.av_deep_granted, f.grantedRuntimePermissions.size),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.error,
            )
            f.grantedRuntimePermissions.forEach { perm ->
                PermRow(name = perm, granted = true)
            }
        }

        // Declared-but-not-granted dangerous permissions — the distinction the
        // static "requests" view can't draw.
        if (f.deniedRuntimePermissions.isNotEmpty()) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(
                stringResource(R.string.av_deep_denied, f.deniedRuntimePermissions.size),
                style = MaterialTheme.typography.labelMedium,
                color = UnderstoryTheme.semantic.dim,
            )
            f.deniedRuntimePermissions.forEach { perm ->
                PermRow(name = perm, granted = false)
            }
        }

        // Live appop modes (overlay / usage-access / etc.) at a non-default mode.
        if (f.activeAppOps.isNotEmpty()) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(
                stringResource(R.string.av_deep_appops, f.activeAppOps.size),
                style = MaterialTheme.typography.labelMedium,
                color = UnderstoryTheme.semantic.warning,
            )
            f.activeAppOps.forEach { op ->
                Text(
                    stringResource(R.string.av_deep_appop_row, op.op, op.mode),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** A "label: value" line for a single verified provenance fact. */
@Composable
private fun LabeledFact(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.width(UnderstoryTheme.spacing.xs))
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

/**
 * One verified runtime-permission row: a granted/denied glyph + the short
 * permission name. Granted dangerous perms read error-tinted (they are active
 * power); denied ones read dim (declared but off).
 */
@Composable
private fun PermRow(name: String, granted: Boolean) {
    val color = if (granted) MaterialTheme.colorScheme.error else UnderstoryTheme.semantic.dim
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            imageVector = if (granted) Icons.Filled.CheckCircle else Icons.Filled.RemoveCircleOutline,
            contentDescription = null,
            tint = color,
            modifier = Modifier.size(16.dp),
        )
        Spacer(Modifier.width(UnderstoryTheme.spacing.xs))
        Text(
            name,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
