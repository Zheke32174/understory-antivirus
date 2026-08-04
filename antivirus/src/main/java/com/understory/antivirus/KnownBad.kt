package com.understory.antivirus

/**
 * Thin facade over [BlocklistStore] — the real signed deny-list. Kept as a
 * separate type so the call sites in [ApkAnalyzer] read unchanged.
 *
 * Storage shape (unchanged): SHA-256 of either the APK file itself or the
 * signing certificate, lowercase hex, no separators. Both surfaces exist
 * because:
 *   - APK-hash matches catch a specific malicious build.
 *   - Cert-hash matches catch every APK signed by a known-bad keystore (a
 *     repackager that mass-resigns clean APKs).
 *
 * The all-zero hash is the reserved "not a real entry" sentinel and is
 * rejected on import (see [BlocklistCodec]).
 *
 * The definitions themselves come from [BlocklistStore], which loads the
 * signed built-in seed (`res/raw/blocklist_seed.ubl`) on first run and any
 * user-imported signed `.ubl` file after that. Callers must have invoked
 * [BlocklistStore.ensureLoaded] first (ApkAnalyzer does, off the main thread).
 */
object KnownBad {

    /**
     * True if [sha256] is in the APK deny-list — the signed .ubl list OR any
     * user-imported auxiliary database ([AuxDatabases]). Aux provenance is
     * recovered via [auxMatchApk] so findings can name the source database.
     */
    fun isKnownBadApk(sha256: String): Boolean =
        BlocklistStore.apkHashes().contains(sha256.lowercase()) ||
            AuxDatabases.matchApk(sha256) != null

    /** The aux-database match for [sha256], if the hit came from an aux DB. */
    internal fun auxMatchApk(sha256: String): AuxDatabases.Match? =
        AuxDatabases.matchApk(sha256)

    /** True when ANY loaded database carries APK-hash entries (hash gate). */
    fun hasApkHashDefinitions(): Boolean =
        BlocklistStore.apkHashes().isNotEmpty() || AuxDatabases.totalEntries() > 0

    /** True if [sha256] is in the cert deny-list. */
    fun isKnownBadCert(sha256: String): Boolean =
        BlocklistStore.certHashes().contains(sha256.lowercase())

    /** Human-readable name for a matched hash, if the definitions carried one. */
    fun labelFor(sha256: String): String? =
        BlocklistStore.label(sha256.lowercase())
}
