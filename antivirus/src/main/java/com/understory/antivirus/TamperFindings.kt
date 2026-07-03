package com.understory.antivirus

import android.content.Context
import android.content.pm.PackageManager
import com.understory.security.Tamper

/**
 * Builds the content for the home-screen Tamper card (§6/§7): the "report,
 * don't block" surface for patching/root/hooking tooling present on the
 * device. This is informational, not a verdict — root and hooking tools have
 * legitimate power-user uses; they also let malware do more, so the card lists
 * what's present so the user knows.
 *
 * Uses the manifest `<queries>` rows (Magisk / SuperSU / Kingo / ROM manager /
 * Xposed managers) — otherwise-dead package-visibility declarations — as the
 * root/hooking-tooling probe, which is exactly what keeps those rows *used*.
 */
internal object TamperFindings {

    /** One line on the Tamper card, most-severe first. */
    data class Line(
        val severity: RiskRules.Severity,
        val text: String,
    )

    /** Card content; [lines] empty means "nothing to report" (card hidden). */
    data class TamperInfo(val lines: List<Line>)

    /**
     * Root / hooking manager packages, from the manifest `<queries>` block.
     * Presence is informational only.
     */
    private val ROOT_HOOK_MANAGERS: List<Pair<String, String>> = listOf(
        "de.robv.android.xposed.installer" to "Xposed Installer",
        "org.meowcat.edxposed.manager" to "EdXposed Manager",
        "org.lsposed.manager" to "LSPosed Manager",
        "io.github.lsposed.manager" to "LSPosed Manager",
        "com.topjohnwu.magisk" to "Magisk",
        "io.github.huskydg.magisk" to "Magisk (Delta)",
        "com.kingoapp.apk" to "KingoRoot",
        "com.koushikdutta.rommanager" to "ROM Manager",
        "eu.chainfire.supersu" to "SuperSU",
    )

    fun build(ctx: Context, report: Tamper.Report): TamperInfo {
        val lines = mutableListOf<Line>()

        if (report.luckyPatcherInstalled) {
            lines += Line(
                RiskRules.Severity.CRITICAL,
                "A Lucky-Patcher-family tool is installed on this device — a " +
                    "repackaging / in-app-purchase patching tool commonly used to " +
                    "trojanize apps. If you didn't install it, treat it as hostile.",
            )
        }
        if (report.installedByPatcher) {
            lines += Line(
                RiskRules.Severity.CRITICAL,
                "This app reports it was installed by a known patcher. Reinstall " +
                    "APK Check from a trusted source to be sure it wasn't modified.",
            )
        }
        for (w in report.warnings) {
            lines += Line(RiskRules.Severity.HIGH, w)
        }

        val managers = presentRootHookManagers(ctx)
        if (managers.isNotEmpty()) {
            lines += Line(
                RiskRules.Severity.MED,
                "Root / hooking tooling detected: ${managers.joinToString(", ")}. " +
                    "These have legitimate power-user uses; they also let malware do " +
                    "more, so they're listed here so you know what's on the device — " +
                    "not flagged as a verdict.",
            )
        }

        // Severity order: CRITICAL(0) < HIGH(1) < MED(2) — most-severe first.
        return TamperInfo(lines.sortedBy { it.severity.ordinal })
    }

    private fun presentRootHookManagers(ctx: Context): List<String> {
        val pm = ctx.packageManager
        val seen = LinkedHashSet<String>()
        for ((pkg, label) in ROOT_HOOK_MANAGERS) {
            val present = try {
                pm.getPackageInfo(pkg, 0); true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            } catch (_: Throwable) {
                false
            }
            if (present) seen += label
        }
        return seen.toList()
    }
}
