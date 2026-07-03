package com.understory.antivirus

/**
 * Tiny built-in deny-list. The MVP ships with a hand-curated seed of
 * known-bad APK signatures — Lucky Patcher, common repackager certs,
 * popular adware/spyware family signatures. Phase 2 adds an opt-in
 * SAF-tree-based signed-blob update mechanism (NOT a background
 * sync — definitions arrive as a file the user explicitly imports,
 * keeping the no-INTERNET posture).
 *
 * Storage shape: SHA-256 of either the APK file itself, or the
 * signing certificate. We keep both surfaces because:
 *   - APK-hash matches catch a specific malicious build.
 *   - Cert-hash matches catch every APK signed by a known-bad
 *     keystore (e.g. a repackager that mass-resigns clean APKs).
 *
 * Format: lowercase hex, no separators. All-zero hash is reserved as
 * "not a real entry" sentinel so we don't accidentally match an
 * empty-byte ByteArray.
 */
object KnownBad {

    /**
     * SHA-256 hashes of complete APK files known to be malicious or
     * unwanted (Lucky Patcher, common adware/spyware builds, etc.).
     * Hand-curated seed; expand as observations accumulate.
     */
    val apkHashes: Set<String> = setOf(
        // Empty for now — populated as we build out the deny-list.
        // Sample format: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".
    )

    /**
     * SHA-256 of signing certificates known to belong to bad actors.
     * Cert-hash matches are stronger than APK-hash matches because
     * one cert may sign many malicious APKs.
     */
    val certHashes: Set<String> = setOf(
        // Empty for now — populated as we build out the deny-list.
    )

    /** True if [sha256] is in the apk deny-list. */
    fun isKnownBadApk(sha256: String): Boolean =
        sha256.lowercase() in apkHashes

    /** True if [sha256] is in the cert deny-list. */
    fun isKnownBadCert(sha256: String): Boolean =
        sha256.lowercase() in certHashes
}
