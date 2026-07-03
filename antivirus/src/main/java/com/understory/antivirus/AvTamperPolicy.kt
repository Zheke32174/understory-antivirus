package com.understory.antivirus

import com.understory.security.Tamper

/**
 * Antivirus-specific interpretation of a shared [Tamper.Report].
 *
 * The suite-wide [Tamper.Report.hardFail] treats a Lucky-Patcher-family
 * install (or being installed *by* a patcher) as a refuse-to-run condition —
 * correct for an IME/autofill app on a hot path. But for THIS app that is
 * self-defeating: an antivirus whose whole job is telling the user "you have a
 * patching tool on this device" must not refuse to launch precisely when one
 * is present. So the policy lives at the call site, not in the shared type
 * (which other apps consume on hot paths and must not change).
 *
 * Split:
 *   - **Hard-fail** (refuse — OUR OWN binary is compromised, so any finding we
 *     show is untrustworthy): signature mismatch, Xposed/LSPosed loaded, Frida
 *     mapped in.
 *   - **Report** (surface as a finding, keep running): a patcher installed on
 *     the device, we were installed by a patcher, root markers, test-keys.
 */
internal object AvTamperPolicy {

    /**
     * @property hardFail true when the scanner itself may be tampered with and
     *   results can't be trusted → refuse (with an explanation screen, never a
     *   silent exit).
     * @property reason short human-readable cause for the block screen.
     */
    data class AvGate(
        val hardFail: Boolean,
        val reason: String,
    )

    fun evaluate(report: Tamper.Report): AvGate {
        val causes = buildList {
            if (!report.signatureMatches) add("this build's signing certificate doesn't match")
            if (report.xposed) add("an Xposed/LSPosed hooking framework is active")
            if (report.frida) add("a Frida instrumentation agent is mapped into this app")
        }
        return AvGate(hardFail = causes.isNotEmpty(), reason = causes.joinToString("; "))
    }

    /**
     * True when there's a patcher / root / test-keys signal worth surfacing as
     * a first-class finding (drives the home-screen Tamper card). These are NOT
     * hard-fails for this app — they are exactly what it exists to report.
     */
    fun hasReportableTooling(report: Tamper.Report): Boolean =
        report.luckyPatcherInstalled ||
            report.installedByPatcher ||
            report.warnings.isNotEmpty()
}
