package com.understory.antivirus

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
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

    /**
     * Open the system App-Info screen for [pkg] (permissions, storage, the
     * "Uninstall" and "Force stop" controls live here). This is the honest
     * "take action on this app" destination for the detail screen: we don't
     * uninstall or revoke on the user's behalf — we take them to the exact OS
     * screen where they decide. Falls back to the all-apps settings list.
     */
    fun openAppDetails(ctx: Context, pkg: String): Boolean {
        val details = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
            .setData(Uri.fromParts("package", pkg, null))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return try {
            ctx.startActivity(details)
            true
        } catch (_: Throwable) {
            launchFirst(ctx, listOf(Settings.ACTION_APPLICATION_SETTINGS))
        }
    }

    /**
     * Launch the system uninstall confirmation for [pkg]. Uses the public
     * ACTION_DELETE Intent — the OS shows its own confirm dialog; we never
     * remove an app silently (and hold no delete permission). Returns false if
     * nothing handled it, so the caller can fall back to [openAppDetails].
     */
    fun requestUninstall(ctx: Context, pkg: String): Boolean {
        val intent = Intent(Intent.ACTION_DELETE)
            .setData(Uri.fromParts("package", pkg, null))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return try {
            ctx.startActivity(intent)
            true
        } catch (_: Throwable) {
            openAppDetails(ctx, pkg)
        }
    }

    /**
     * Open the device's all-apps settings list. The honest rootless fallback for
     * the optional-elevation settings card: when the user hasn't installed
     * Shizuku/Dhizuku there is no in-app elevated remediation, so we point them at
     * the OS surface where every app's uninstall / permissions live. Falls back to
     * the top-level Settings screen.
     */
    fun openApplicationSettings(ctx: Context): Boolean =
        launchFirst(ctx, listOf(Settings.ACTION_APPLICATION_SETTINGS, Settings.ACTION_SETTINGS))

    fun canOpenAppDetails(ctx: Context, pkg: String): Boolean = runCatching {
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
            .setData(Uri.fromParts("package", pkg, null))
            .resolveActivity(ctx.packageManager) != null
    }.getOrDefault(false)

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
