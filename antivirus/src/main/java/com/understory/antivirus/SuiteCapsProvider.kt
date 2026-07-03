package com.understory.antivirus

import com.understory.security.BaseCapabilityProvider

/**
 * antivirus's capability beacon. Consumers translate
 * `(com.understory.antivirus, version=1)` into [SuiteCapability.APK_AUDITOR]
 * via their KNOWN_PEERS table.
 *
 * Note on naming: the capability is APK_AUDITOR — an on-demand static APK /
 * installed-app auditor (SAF APK scan, installed-app posture review, signed
 * offline deny-list). There is no real-time watcher, receiver, or worker
 * cadence claimed: rootless real-time process scanning is impossible and the
 * name never implies it. Periodic re-scan is an in-app opt-in convenience, not
 * a peer-facing capability.
 */
class SuiteCapsProvider : BaseCapabilityProvider() {
    override val providedVersion: Int = 1
}
