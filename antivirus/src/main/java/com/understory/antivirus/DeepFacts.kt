package com.understory.antivirus

import android.content.Context
import com.understory.elevation.Elevation

/**
 * READ-ONLY, ELEVATED ground-truth enrichment for a flagged app's detail screen.
 *
 * The static detail view frames permissions as "requests" — the manifest's
 * declared set, which is honest but coarse: it can't tell a granted-and-active
 * dangerous permission from one the user denied, and it can't show WHEN the app
 * arrived or WHO installed it. When (and only when) the user has granted the
 * optional Shizuku elevation, we run two READ-ONLY shell reads to upgrade that
 * section to actual ground truth:
 *
 *   - `dumpsys package <pkg>`  → the runtime permissions actually GRANTED, the
 *     firstInstallTime, and the installer/initiating package.
 *   - `appops get <pkg>`       → the current appop modes (overlay / usage-access
 *     / etc.), which `pm`-style grant state can't express.
 *
 * DOCTRINE:
 *   - READ-ONLY. Nothing here mutates device state; there is no confirm, and this
 *     never touches the elevated CONTAINMENT/remediation controls (those live in
 *     ContainmentActions.kt / ElevatedRemediation.kt and are unchanged).
 *   - FAIL-OPEN on a parse miss. Every read can return null ([Elevation.readShell]
 *     returns null when unelevated or on any error) and every parse can come back
 *     empty on a dump-format drift. In BOTH cases the caller keeps the existing
 *     static "requests" posture — we never block, never alarm, never fabricate a
 *     "verified" value we didn't actually read.
 *   - HARD EXCLUSIONS are not needed here: this is a pure read of the app the user
 *     is already looking at, with no action taken against any package.
 *
 * The parsing is deliberately loose (line-oriented, prefix/keyword based) so a
 * cosmetic reordering or an added field in a future Android release degrades to
 * "couldn't read that one field" rather than crashing or mislabelling.
 */
data class DeepFacts(
    /**
     * Runtime permissions dumpsys reports as granted=true for this app, short-named
     * (last dotted segment) and sorted. Empty ⇒ either the app holds none or the
     * runtime-permission block wasn't parseable — the UI degrades either way.
     */
    val grantedRuntimePermissions: List<String>,
    /**
     * Runtime permissions dumpsys reports as granted=false (declared but not
     * granted / denied). Short-named + sorted. This is the value the static
     * "requests" view can't distinguish; showing it is the whole point.
     */
    val deniedRuntimePermissions: List<String>,
    /**
     * Appops whose current mode is NOT the benign default — each an
     * [AppOpMode] with the op's short name and the reported mode string
     * (e.g. "SYSTEM_ALERT_WINDOW = allow"). Empty ⇒ none set or unparseable.
     */
    val activeAppOps: List<AppOpMode>,
    /** firstInstallTime as dumpsys prints it (already human-readable), or null. */
    val firstInstallTime: String?,
    /** The installer package dumpsys attributes the install to, or null. */
    val installerPackage: String?,
) {
    /**
     * True when at least one field actually parsed to something. When false the
     * caller renders nothing (keeps the static section) — an all-empty DeepFacts
     * carries no ground truth worth a "Verified" heading.
     */
    fun hasAnything(): Boolean =
        grantedRuntimePermissions.isNotEmpty() ||
            deniedRuntimePermissions.isNotEmpty() ||
            activeAppOps.isNotEmpty() ||
            firstInstallTime != null ||
            installerPackage != null

    /** One appop and the non-default mode it currently sits at. */
    data class AppOpMode(val op: String, val mode: String)

    companion object {

        /**
         * Read ground-truth facts for [pkg] via two READ-ONLY elevated shell reads.
         * Returns null when elevation isn't granted, when both reads come back null,
         * or when nothing parsed — every one of which means "degrade to the static
         * requests view". Must be called off the main thread. NEVER throws.
         */
        suspend fun read(ctx: Context, pkg: String): DeepFacts? {
            // Fail-closed on the ACTION side: no elevated read attempted unless a
            // privileged shell is actually granted. (readShell also guards this,
            // but checking first keeps the intent explicit and avoids the bind.)
            if (!Elevation.canRunShell(ctx)) return null

            val dump = runCatching { Elevation.readShell(ctx, listOf("dumpsys", "package", pkg)) }.getOrNull()
            val appops = runCatching { Elevation.readShell(ctx, listOf("appops", "get", pkg)) }.getOrNull()

            // Both reads unavailable ⇒ nothing to show; degrade.
            if (dump == null && appops == null) return null

            val facts = parse(dump, appops)
            return if (facts.hasAnything()) facts else null
        }

        /**
         * Pure, defensive parse of the two dumps into [DeepFacts]. Package-visible
         * (not private) so it is unit-testable without a device. Either argument
         * may be null (that read failed); each parses independently and contributes
         * only what it can. A malformed or unexpected dump yields empty fields, not
         * an exception.
         */
        fun parse(dumpsysPackage: String?, appopsGet: String?): DeepFacts {
            val granted = sortedSetOf<String>()
            val denied = sortedSetOf<String>()
            var firstInstall: String? = null
            var installer: String? = null

            if (dumpsysPackage != null) {
                parseRuntimePermissions(dumpsysPackage, granted, denied)
                firstInstall = parseFirstInstallTime(dumpsysPackage)
                installer = parseInstaller(dumpsysPackage)
            }

            val ops = if (appopsGet != null) parseAppOps(appopsGet) else emptyList()

            // A permission that shows up as both granted and denied across the two
            // user/runtime blocks dumpsys prints (e.g. per-user rows) is treated as
            // granted — the stronger, safety-relevant signal wins and we don't
            // double-list it.
            denied.removeAll(granted)

            return DeepFacts(
                grantedRuntimePermissions = granted.toList(),
                deniedRuntimePermissions = denied.toList(),
                activeAppOps = ops,
                firstInstallTime = firstInstall,
                installerPackage = installer,
            )
        }

        /**
         * Parse the `runtime permissions:` block(s) of a `dumpsys package` dump.
         * Lines look like:
         *   `android.permission.CAMERA: granted=true, flags=[ ... ]`
         * We key off the `android.permission.` (or vendor-dotted) name and the
         * `granted=true` / `granted=false` token. Only genuine dangerous/runtime
         * permissions (per [PermissionGroups]) are surfaced, so install-time normal
         * permissions don't flood the list. Robust to leading whitespace and to the
         * name appearing with or without a trailing colon.
         */
        private fun parseRuntimePermissions(
            dump: String,
            granted: MutableSet<String>,
            denied: MutableSet<String>,
        ) {
            for (raw in dump.lineSequence()) {
                val line = raw.trim()
                // A runtime-permission row always mentions granted=…; skip anything
                // else cheaply before the more expensive name extraction.
                val grantedTrue = line.contains("granted=true")
                val grantedFalse = line.contains("granted=false")
                if (!grantedTrue && !grantedFalse) continue

                val perm = line.substringBefore(':').trim()
                // Guard: must look like a permission name, and one we classify as a
                // real runtime/dangerous permission (not a normal install-time one).
                if (!perm.contains('.') || perm.contains(' ')) continue
                if (PermissionGroups.tierOf(perm) != PermissionGroups.Tier.DANGEROUS) continue

                val short = PermissionGroups.shortName(perm)
                if (grantedTrue) granted.add(short) else denied.add(short)
            }
        }

        /**
         * Extract firstInstallTime from a `dumpsys package` dump. The line is:
         *   `firstInstallTime=2024-01-15 09:30:12`
         * We return the value verbatim (already human-readable). Null when absent.
         */
        private fun parseFirstInstallTime(dump: String): String? {
            for (raw in dump.lineSequence()) {
                val line = raw.trim()
                val idx = line.indexOf("firstInstallTime=")
                if (idx >= 0) {
                    val value = line.substring(idx + "firstInstallTime=".length).trim()
                    if (value.isNotBlank()) return value
                }
            }
            return null
        }

        /**
         * Extract the installer/initiating package from a `dumpsys package` dump.
         * Recent Android prints an `installerPackageName=…` line; some builds print
         * `installInitiator=…`. We accept the first of either that yields a real
         * package (not "null"/"?"). Null when neither is present or usable.
         */
        private fun parseInstaller(dump: String): String? {
            val keys = listOf("installerPackageName=", "installInitiator=")
            for (raw in dump.lineSequence()) {
                val line = raw.trim()
                for (key in keys) {
                    val idx = line.indexOf(key)
                    if (idx >= 0) {
                        // The value is the token after '=' up to the first space (the
                        // line can carry trailing fields on some builds).
                        val value = line.substring(idx + key.length).substringBefore(' ').trim()
                        if (value.isNotBlank() && value != "null" && value != "?") return value
                    }
                }
            }
            return null
        }

        /**
         * Modes we treat as "benign default" — an op sitting at one of these is not
         * surfaced (it isn't an active grant worth flagging). Everything else
         * (allow, foreground, and any vendor mode string we don't recognise) is
         * reported verbatim so we never hide a real grant behind an assumption.
         */
        private val BENIGN_APPOP_MODES = setOf("default", "ignore", "deny")

        /**
         * Parse `appops get <pkg>` output. Lines look like:
         *   `SYSTEM_ALERT_WINDOW: allow`
         *   `COARSE_LOCATION: allow; time=+1h2m3s ago ...`
         * We take the op name before the first ':' and the mode as the first token
         * after it (up to ';' or whitespace). Non-op preamble lines (they lack the
         * `OP: mode` shape) are skipped. Only non-default modes are returned.
         */
        private fun parseAppOps(dump: String): List<DeepFacts.AppOpMode> {
            val out = LinkedHashMap<String, String>() // op → mode, de-duped, order-stable
            for (raw in dump.lineSequence()) {
                val line = raw.trim()
                if (line.isEmpty()) continue
                val colon = line.indexOf(':')
                if (colon <= 0 || colon >= line.length - 1) continue
                val op = line.substring(0, colon).trim()
                // An op name is a single UPPER_SNAKE token; reject anything with a
                // space (preamble like "Uid mode:" or package headers).
                if (op.isEmpty() || op.contains(' ')) continue
                val rest = line.substring(colon + 1).trim()
                // Mode is the first token, before any '; time=…' detail or space.
                val mode = rest.substringBefore(';').substringBefore(' ').trim()
                if (mode.isEmpty()) continue
                if (mode.lowercase() in BENIGN_APPOP_MODES) continue
                out[op] = mode
            }
            return out.map { (op, mode) -> DeepFacts.AppOpMode(op, mode) }
        }
    }
}
