package com.understory.antivirus

import android.content.Context
import android.content.pm.PackageManager
import android.provider.Settings

/**
 * Surfaces whether Google Play Protect is active on this device.
 *
 * Why this matters: a common stalkerware install tactic is to disable
 * Play Protect during setup so the OS-level scanner doesn't block the
 * payload. Surfacing the current state lets the user notice if Play
 * Protect has been silently turned off — a meaningful signal even when
 * our own heuristics see nothing wrong with any specific app.
 *
 * Four states:
 *   ENABLED         — GMS present + the legacy verifier key is present AND = 1.
 *                     Only reachable on older / de-Googled devices that still
 *                     write the key; a valid signal *there*.
 *   DISABLED        — GMS present + the legacy verifier key is present AND = 0.
 *   NOT_APPLICABLE  — GMS isn't on this device (de-Googled / GrapheneOS /
 *                     LineageOS without GApps). Play Protect doesn't exist as a
 *                     concept here; surface that, don't alarm.
 *   UNKNOWN         — GMS present but the key is absent / unreadable. This is
 *                     the MODERN-DEVICE DEFAULT (Play Protect's real toggle
 *                     lives in Play services and does not write this key), and
 *                     it is the *correct* honest answer: we don't claim a green
 *                     we can't verify. The card deep-links the user to Play
 *                     Protect to check.
 *
 * The v1 3-arg `getInt(cr, key, default=1)` was a false-green: a missing key
 * (the normal modern-Samsung case) read back as "enabled." We use the 2-arg
 * form so a missing key throws [SettingNotFoundException] → UNKNOWN, never a
 * fabricated ENABLED.
 */
object PlayProtectStatus {

    enum class State { ENABLED, DISABLED, NOT_APPLICABLE, UNKNOWN }

    data class Status(val state: State, val explain: String)

    private const val GMS_PACKAGE = "com.google.android.gms"
    // Legacy pre-Oreo verifier key. Absent on modern GMS devices — its absence
    // must read as UNKNOWN, not ENABLED.
    private const val K_VERIFIER_ENABLE = "package_verifier_enable"

    fun check(ctx: Context): Status {
        val hasGms = try {
            ctx.packageManager.getPackageInfo(GMS_PACKAGE, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }

        if (!hasGms) {
            return Status(
                State.NOT_APPLICABLE,
                "This device has no Google Play Services. Play Protect — Google's " +
                    "OS-level app scanner — doesn't exist on this device. Normal for " +
                    "de-Googled installs (GrapheneOS, LineageOS without GApps, etc.).",
            )
        }

        // 2-arg getInt: a missing key throws SettingNotFoundException → UNKNOWN.
        // We NEVER default a missing key to enabled.
        val raw = try {
            Settings.Global.getInt(ctx.contentResolver, K_VERIFIER_ENABLE)
        } catch (_: Settings.SettingNotFoundException) {
            return unknown()
        } catch (_: Throwable) {
            return unknown()
        }

        return when (raw) {
            0 -> Status(
                State.DISABLED,
                "Play Protect is DISABLED on this device. Disabling Play Protect is a " +
                    "common stalkerware install tactic — it's the OS-level scanner that " +
                    "would otherwise block the spying app. If you didn't disable it " +
                    "yourself, scrutinize what was installed around then. Keep it on.",
            )
            1 -> Status(
                State.ENABLED,
                "Play Protect's app verifier is enabled. Keep Play Protect on — APK " +
                    "Check works alongside it, it doesn't replace it.",
            )
            else -> unknown()
        }
    }

    private fun unknown(): Status = Status(
        State.UNKNOWN,
        "We can't read Play Protect's state on this Android version — its setting " +
            "isn't exposed to apps. Open Play Protect to verify it's on, and keep it " +
            "on. APK Check works alongside Play Protect; it doesn't replace it.",
    )
}
