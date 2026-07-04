package com.understory.antivirus

import android.content.Context
import android.content.Intent
import com.understory.security.Diagnostics

/**
 * Network restriction for a quarantined app is the firewall's job, not the
 * antivirus's — the antivirus never runs `cmd netpolicy` here (that would
 * duplicate the firewall's slot and fight it). This helper routes the user to the
 * firewall app when it's installed, so they can block the flagged app's network
 * there. When the firewall isn't installed there is no honest in-app network
 * action, so the caller hides the row (never a dead control).
 */
object ContainmentDeepLinks {

    /** The suite firewall package that owns network control. */
    const val FIREWALL_PACKAGE = "com.understory.firewall"

    /** Whether the firewall app is installed and has a launchable entry. */
    fun canRouteToFirewall(ctx: Context): Boolean =
        ctx.packageManager.getLaunchIntentForPackage(FIREWALL_PACKAGE) != null

    /**
     * Launch the firewall app so the user can restrict the flagged app's network
     * there. Returns true if it opened. We pass no package extra: the firewall
     * owns its own targeting UI; we only bring it to the foreground.
     */
    fun routeToFirewall(ctx: Context): Boolean {
        val intent = ctx.packageManager.getLaunchIntentForPackage(FIREWALL_PACKAGE)
            ?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            ?: return false
        return try {
            ctx.startActivity(intent)
            true
        } catch (t: Throwable) {
            Diagnostics.error("antivirus.Contain", "route to firewall threw: ${t.javaClass.simpleName}")
            false
        }
    }
}
