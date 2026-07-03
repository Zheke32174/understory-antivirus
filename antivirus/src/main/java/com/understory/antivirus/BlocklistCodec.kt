package com.understory.antivirus

import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Parser + verifier for the signed offline blocklist file format
 * (`understory-blocklist.ubl`). Definitions arrive as a file the user
 * explicitly imports through SAF — never a network sync (this app has no
 * INTERNET permission). Every byte is bounds-checked with the same
 * defensive-parsing discipline as [RawApkParser]: hard caps, explicit offset
 * checks, fail-closed on any violation.
 *
 * On-disk envelope (all multi-byte integers big-endian):
 *   magic:      "UBL1"                         (4 ASCII bytes)
 *   payloadLen: uint32                         (4 bytes; cap 4 MiB)
 *   payload:    <payloadLen> bytes canonical JSON (UTF-8)
 *   sigLen:     uint16                         (2 bytes; == 64 for Ed25519)
 *   signature:  <sigLen> bytes                 (Ed25519 over the payload bytes)
 *
 * The signature covers exactly the payload byte range, so a re-serialization
 * of the parsed JSON is never needed to re-verify — we verify the raw bytes.
 */
internal object BlocklistCodec {

    private val MAGIC = byteArrayOf('U'.code.toByte(), 'B'.code.toByte(), 'L'.code.toByte(), '1'.code.toByte())

    /** Payload cap — a real definitions file is kilobytes; 4 MiB is absurd. */
    const val MAX_PAYLOAD_BYTES = 4 * 1024 * 1024

    /** Ed25519 signatures are exactly 64 bytes. */
    private const val ED25519_SIG_LEN = 64

    /** Reserved all-zero sentinel hash — never a real entry (KnownBad doc). */
    private const val ALL_ZERO_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    /**
     * The verified, parsed definitions. Hashes are lowercase hex, exactly 64
     * chars each. [labels] maps a hash to a human-readable name for legible
     * findings ("matches: Lucky Patcher 10.x").
     */
    data class BlocklistPayload(
        val schema: Int,
        val issued: String,
        val serial: Int,
        val apkSha256: Set<String>,
        val certSha256: Set<String>,
        val labels: Map<String, String>,
    )

    /** Failure reason, so the UI can render the right honest message. */
    enum class Failure { BAD_MAGIC, BAD_LENGTH, BAD_SIGNATURE, MALFORMED }

    /**
     * The raw signed bytes plus the verified payload, so [BlocklistStore] can
     * persist the exact bytes it verified (re-verified on every load).
     */
    class ParseResult private constructor(
        val payload: BlocklistPayload?,
        val failure: Failure?,
    ) {
        val isOk: Boolean get() = payload != null
        companion object {
            fun ok(p: BlocklistPayload) = ParseResult(p, null)
            fun fail(f: Failure) = ParseResult(null, f)
        }
    }

    /**
     * Verify the Ed25519 signature over the payload and parse the JSON.
     * Any structural violation, a bad signature, or a malformed entry
     * rejects the WHOLE file (fail closed) — never partial trust.
     *
     * Runs on the caller's thread; callers invoke it on [com.understory.security.ui.Bg.io].
     */
    fun verifyAndParse(bytes: ByteArray): ParseResult {
        // --- envelope bounds ---
        if (bytes.size < 4 + 4 + 2) return ParseResult.fail(Failure.BAD_LENGTH)
        for (i in MAGIC.indices) {
            if (bytes[i] != MAGIC[i]) return ParseResult.fail(Failure.BAD_MAGIC)
        }
        val bb = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
        bb.position(4)
        val payloadLen = bb.int.toLong() and 0xFFFFFFFFL
        if (payloadLen <= 0 || payloadLen > MAX_PAYLOAD_BYTES) {
            return ParseResult.fail(Failure.BAD_LENGTH)
        }
        // 4 magic + 4 len + payload + 2 sigLen must fit.
        if (8L + payloadLen + 2L > bytes.size) return ParseResult.fail(Failure.BAD_LENGTH)
        val payloadStart = 8
        val payloadEnd = (payloadStart + payloadLen).toInt()
        bb.position(payloadEnd)
        val sigLen = bb.short.toInt() and 0xFFFF
        if (sigLen != ED25519_SIG_LEN) return ParseResult.fail(Failure.BAD_LENGTH)
        val sigStart = payloadEnd + 2
        if (sigStart + sigLen != bytes.size) return ParseResult.fail(Failure.BAD_LENGTH)

        val payloadBytes = bytes.copyOfRange(payloadStart, payloadEnd)
        val sigBytes = bytes.copyOfRange(sigStart, sigStart + sigLen)

        // --- signature ---
        val verified = try {
            val keySpec = X509EncodedKeySpec(BlocklistKeys.spkiPublicKey())
            val publicKey = KeyFactory.getInstance("Ed25519").generatePublic(keySpec)
            val sig = Signature.getInstance("Ed25519")
            sig.initVerify(publicKey)
            sig.update(payloadBytes)
            sig.verify(sigBytes)
        } catch (_: Throwable) {
            false
        }
        if (!verified) return ParseResult.fail(Failure.BAD_SIGNATURE)

        // --- payload JSON ---
        return try {
            ParseResult.ok(parsePayload(payloadBytes))
        } catch (_: Throwable) {
            ParseResult.fail(Failure.MALFORMED)
        }
    }

    /**
     * Parse and validate the canonical JSON. Throws on any violation so the
     * caller maps it to [Failure.MALFORMED] and drops the whole file.
     */
    private fun parsePayload(payloadBytes: ByteArray): BlocklistPayload {
        val json = JSONObject(String(payloadBytes, StandardCharsets.UTF_8))
        val schema = json.getInt("schema")
        require(schema == 1) { "unsupported schema: $schema" }
        val issued = json.getString("issued")
        val serial = json.getInt("serial")
        require(serial >= 0) { "negative serial" }

        val apk = hashSet(json, "apkSha256")
        val cert = hashSet(json, "certSha256")

        val labels = mutableMapOf<String, String>()
        json.optJSONObject("labels")?.let { obj ->
            val keys = obj.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                val norm = k.lowercase()
                require(isHash64(norm)) { "malformed label key: $k" }
                labels[norm] = obj.getString(k)
            }
        }

        return BlocklistPayload(
            schema = schema,
            issued = issued,
            serial = serial,
            apkSha256 = apk,
            certSha256 = cert,
            labels = labels,
        )
    }

    /** Read a JSON array of 64-hex hashes; reject the file on any bad entry. */
    private fun hashSet(json: JSONObject, key: String): Set<String> {
        val arr = json.optJSONArray(key) ?: return emptySet()
        val out = LinkedHashSet<String>(arr.length())
        for (i in 0 until arr.length()) {
            val raw = arr.getString(i).lowercase()
            require(isHash64(raw)) { "malformed hash entry in $key: $raw" }
            require(raw != ALL_ZERO_HASH) { "reserved all-zero sentinel in $key" }
            out += raw
        }
        return out
    }

    /** Exactly 64 lowercase-hex characters. */
    private fun isHash64(s: String): Boolean =
        s.length == 64 && s.all { it in '0'..'9' || it in 'a'..'f' }
}
