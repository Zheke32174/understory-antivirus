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
 *   ENABLED         — GMS present + verifier setting = 1. Standard healthy.
 *   DISABLED        — GMS present + verifier setting = 0. Worth surfacing.
 *   NOT_APPLICABLE  — GMS isn't on this device (de-Googled / GrapheneOS /
 *                     LineageOS without GApps). Play Protect doesn't exist
 *                     as a concept here; surface that, don't alarm.
 *   UNKNOWN         — couldn't read the setting (non-standard Android build,
 *                     setting key moved, etc.).
 *
 * Implementation is best-effort. Setting key names have varied across
 * Android versions and OEMs; we read the conventional one and any read
 * failure becomes UNKNOWN rather than a false signal in either direction.
 */
object PlayProtectStatus {

    enum class State { ENABLED, DISABLED, NOT_APPLICABLE, UNKNOWN }

    data class Status(val state: State, val explain: String)

    private const val GMS_PACKAGE = "com.google.android.gms"
    // Settings.Global.PACKAGE_VERIFIER_ENABLE is @hide; the underlying
    // string key has been stable since pre-API-21.
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

        val enabled = try {
            Settings.Global.getInt(ctx.contentResolver, K_VERIFIER_ENABLE, 1) == 1
        } catch (_: Throwable) {
            return Status(
                State.UNKNOWN,
                "Couldn't read the Play Protect verifier state. Usually means a " +
                    "non-standard Android build that doesn't expose the setting.",
            )
        }

        return if (enabled) Status(
            State.ENABLED,
            "Play Protect's app verifier is enabled. Google's OS-level scanner is " +
                "active in the background.",
        ) else Status(
            State.DISABLED,
            "Play Protect is currently DISABLED on this device. Disabling Play Protect " +
                "is a common stalkerware install tactic — it's the OS-level scanner that " +
                "would otherwise block the spying app from being installed. If you " +
                "didn't disable it yourself, scrutinize what was installed around the " +
                "time it was turned off.",
        )
    }
}
