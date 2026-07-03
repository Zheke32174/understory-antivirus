package com.understory.antivirus

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * Envelope-level rejection tests for [BlocklistCodec]. These paths all return
 * BEFORE any JSON parsing, so they run on the plain JVM with no Android stubs.
 * They exercise the fail-closed discipline: any structural violation drops the
 * whole file.
 */
class BlocklistCodecRejectTest {

    private fun envelope(magic: ByteArray, payload: ByteArray, sig: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(magic)
        out.write(byteArrayOf(
            (payload.size ushr 24).toByte(), (payload.size ushr 16).toByte(),
            (payload.size ushr 8).toByte(), payload.size.toByte(),
        ))
        out.write(payload)
        out.write(byteArrayOf((sig.size ushr 8).toByte(), sig.size.toByte()))
        out.write(sig)
        return out.toByteArray()
    }

    @Test fun badMagicRejected() {
        val blob = envelope("XXXX".toByteArray(), ByteArray(10), ByteArray(64))
        val r = BlocklistCodec.verifyAndParse(blob)
        assertFalse(r.isOk)
        assertEquals(BlocklistCodec.Failure.BAD_MAGIC, r.failure)
    }

    @Test fun tooShortRejected() {
        val r = BlocklistCodec.verifyAndParse(byteArrayOf(1, 2, 3))
        assertFalse(r.isOk)
        assertEquals(BlocklistCodec.Failure.BAD_LENGTH, r.failure)
    }

    @Test fun wrongSigLengthRejected() {
        // 32-byte "signature" (not the required 64) → BAD_LENGTH before verify.
        val blob = envelope("UBL1".toByteArray(), ByteArray(20), ByteArray(32))
        val r = BlocklistCodec.verifyAndParse(blob)
        assertFalse(r.isOk)
        assertEquals(BlocklistCodec.Failure.BAD_LENGTH, r.failure)
    }

    @Test fun declaredPayloadLenBeyondBufferRejected() {
        val out = java.io.ByteArrayOutputStream()
        out.write("UBL1".toByteArray())
        // payloadLen says 1000 but buffer has far fewer bytes.
        out.write(byteArrayOf(0, 0, 0x03, (0xE8).toByte()))
        out.write(ByteArray(10))
        val r = BlocklistCodec.verifyAndParse(out.toByteArray())
        assertFalse(r.isOk)
        assertEquals(BlocklistCodec.Failure.BAD_LENGTH, r.failure)
    }

    @Test fun validMagicButGarbageSignatureRejected() {
        // Correct envelope shape (64-byte sig) but random signature bytes over
        // a random payload → Ed25519 verify fails → BAD_SIGNATURE.
        val payload = "{\"schema\":1,\"serial\":1,\"issued\":\"x\"}".toByteArray()
        val blob = envelope("UBL1".toByteArray(), payload, ByteArray(64) { 0x7 })
        val r = BlocklistCodec.verifyAndParse(blob)
        assertFalse(r.isOk)
        assertEquals(BlocklistCodec.Failure.BAD_SIGNATURE, r.failure)
    }
}
