package com.understory.antivirus

/**
 * The compiled-in Ed25519 public key that verifies signed blocklist
 * definition files (`.ubl`). Mirrors how [com.understory.security.SuitePins]
 * pins the app's own signing cert: the trust anchor is baked into the APK,
 * never derived from anything on device and never fetched over the network
 * (this app has no INTERNET permission).
 *
 * Definitions are signed OFF-DEVICE by the maintainer's Ed25519 private key,
 * which lives in the operator vault and is out of this repo. The public key
 * below is the only half that ships. See `docs/BLOCKLIST_SEED.md` for key
 * custody and the seed-provenance record.
 *
 * The bytes are the 32-byte raw Ed25519 public key (RFC 8032). We build a
 * [java.security.PublicKey] from them by wrapping the raw key in the standard
 * X.509 SubjectPublicKeyInfo DER prefix for id-Ed25519 (OID 1.3.101.112), so
 * platform `KeyFactory.getInstance("Ed25519")` accepts it without any external
 * crypto dependency (API 33+, minSdk 33).
 */
internal object BlocklistKeys {

    /**
     * Raw 32-byte Ed25519 public key (lowercase hex). Paired with the seed
     * file `res/raw/blocklist_seed.ubl`, which is signed by the matching
     * private key. This placeholder-shaped constant is the real shipped key
     * for the seed; rotating it requires re-signing every definitions file.
     *
     * NOTE: the seed .ubl shipped in this repo is signed by THIS key. If the
     * key is rotated, regenerate the seed (see docs/BLOCKLIST_SEED.md).
     */
    const val PUBLIC_KEY_HEX =
        "a309883d6e5f946948dff7bed6881b8bc3cbeb15518faeed2583c72ac7a02173"

    /**
     * The 12-byte X.509 SubjectPublicKeyInfo DER prefix for a raw Ed25519
     * public key: SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING }.
     * Prepended to the 32 raw key bytes to yield the 44-byte DER encoding
     * that `KeyFactory("Ed25519").generatePublic(X509EncodedKeySpec(..))`
     * consumes. Fixed by the algorithm; never varies per key.
     */
    val SPKI_PREFIX: ByteArray = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
        0x70, 0x03, 0x21, 0x00,
    )

    /** The 32 raw key bytes decoded from [PUBLIC_KEY_HEX]. */
    fun rawPublicKey(): ByteArray {
        val hex = PUBLIC_KEY_HEX
        require(hex.length == 64) { "Ed25519 public key must be 32 bytes (64 hex chars)" }
        return ByteArray(32) { i ->
            ((hexDigit(hex[i * 2]) shl 4) or hexDigit(hex[i * 2 + 1])).toByte()
        }
    }

    /** X.509 SubjectPublicKeyInfo DER encoding of the raw key (44 bytes). */
    fun spkiPublicKey(): ByteArray = SPKI_PREFIX + rawPublicKey()

    private fun hexDigit(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw IllegalArgumentException("non-hex char in public key: $c")
    }
}
