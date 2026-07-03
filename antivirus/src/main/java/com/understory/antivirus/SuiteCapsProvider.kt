package com.understory.antivirus

import com.understory.security.BaseCapabilityProvider

/**
 * antivirus's capability beacon. Consumers translate
 * `(com.understory.antivirus, version=1)` into [SuiteCapability.REALTIME_SCANNER]
 * via their KNOWN_PEERS table.
 *
 * Note on naming: the capability is REALTIME_SCANNER but the MVP is a
 * static / on-demand scanner — APK analysis at install time, file
 * hash check via SAF, installed-app permission audit. Real-time
 * process scanning would require accessibility-service-shape APIs the
 * suite explicitly refuses. The capability name reflects the *role*
 * in the suite, not the literal scanning cadence.
 */
class SuiteCapsProvider : BaseCapabilityProvider() {
    override val providedVersion: Int = 1
}
