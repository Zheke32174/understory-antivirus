package com.understory.antivirus

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.provider.Settings
import com.understory.security.Diagnostics

/**
 * Shared helper for the "Fix in Settings" / "Open Play Protect" deep-links.
 * We only *revoke*-guide — never add-admin or grant — so each action fires a
 * public settings Intent. Every launch is try/catch with an ordered fallback,
 * and the final signal is whether *anything* opened, so a caller can
 * disable-with-reason rather than leave a dead control.
 */
object SettingsDeepLinks {

    /**
     * A revoke destination for one abuser class. [primary] is tried first,
     * [fallbacks] in order after an [ActivityNotFoundException].
     */
    enum class Target(val primary: String, val fallbacks: List<String>) {
        ACCESSIBILITY(
            Settings.ACTION_ACCESSIBILITY_SETTINGS,
            listOf(Settings.ACTION_SETTINGS),
        ),
        DEVICE_ADMIN(
            // No public constant opens the device-admin list directly on all
            // OEMs; ACTION_SECURITY_SETTINGS is the reachable revoke surface.
            Settings.ACTION_SECURITY_SETTINGS,
            listOf(Settings.ACTION_SETTINGS),
        ),
        NOTIFICATION_LISTENER(
            Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS,
            listOf(Settings.ACTION_SETTINGS),
        ),
        ;

        /** All candidate actions in order. */
        fun actions(): List<String> = listOf(primary) + fallbacks
    }

    /** Play Protect's public settings deep-link, with security-settings fallback. */
    private const val PLAY_PROTECT_ACTION = "com.google.android.gms.settings.VERIFY_APPS_SETTINGS"

    /**
     * Fire the first Intent in [target] that resolves. Returns true if an
     * activity was launched. Callers that get false disable the button with a
     * reason instead of leaving it dead.
     */
    fun open(ctx: Context, target: Target): Boolean =
        launchFirst(ctx, target.actions())

    /** Open Play Protect, falling back to security settings. */
    fun openPlayProtect(ctx: Context): Boolean =
        launchFirst(ctx, listOf(PLAY_PROTECT_ACTION, Settings.ACTION_SECURITY_SETTINGS))

    private fun launchFirst(ctx: Context, actions: List<String>): Boolean {
        for (action in actions) {
            val intent = Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            try {
                ctx.startActivity(intent)
                return true
            } catch (_: ActivityNotFoundException) {
                // try the next fallback
            } catch (t: Throwable) {
                Diagnostics.error("antivirus.DeepLink", "launch $action threw: ${t.javaClass.simpleName}")
            }
        }
        Diagnostics.error("antivirus.DeepLink", "no reachable settings target for $actions")
        return false
    }

    /**
     * Whether at least one action for [target] resolves on this device, so a
     * button can render enabled/disabled without launching. Pure query.
     */
    fun canOpen(ctx: Context, target: Target): Boolean =
        target.actions().any { resolves(ctx, it) }

    fun canOpenPlayProtect(ctx: Context): Boolean =
        resolves(ctx, PLAY_PROTECT_ACTION) || resolves(ctx, Settings.ACTION_SECURITY_SETTINGS)

    private fun resolves(ctx: Context, action: String): Boolean = runCatching {
        Intent(action).resolveActivity(ctx.packageManager) != null
    }.getOrDefault(false)
}
