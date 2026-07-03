package com.understory.antivirus

import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Verifies the shipped seed (`res/raw/blocklist_seed.ubl`) is a valid signed
 * blob under the compiled-in [BlocklistKeys] public key, and that a single
 * flipped byte in the signature is rejected. Robolectric supplies the resource
 * loader and Android's org.json.
 */
@RunWith(RobolectricTestRunner::class)
class BlocklistSeedTest {

    private fun seedBytes(): ByteArray {
        val ctx = ApplicationProvider.getApplicationContext<android.content.Context>()
        return ctx.resources.openRawResource(R.raw.blocklist_seed).use { it.readBytes() }
    }

    @Test fun shippedSeedVerifiesAndParses() {
        val r = BlocklistCodec.verifyAndParse(seedBytes())
        assertTrue("seed must verify under the compiled-in key", r.isOk)
        val p = r.payload!!
        assertEquals(1, p.schema)
        assertEquals(1, p.serial)
        // Seed ships cert-hash entries for the Lucky-Patcher family.
        assertTrue(p.certSha256.isNotEmpty())
        // Every cert hash is 64-hex.
        assertTrue(p.certSha256.all { it.length == 64 && it.all { c -> c in '0'..'9' || c in 'a'..'f' } })
        // Labels are present and keyed by a hash in the set.
        assertTrue(p.labels.keys.all { it in p.certSha256 })
    }

    @Test fun flippedSignatureByteRejected() {
        val bytes = seedBytes()
        // Flip the last byte (inside the signature region).
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xFF).toByte()
        val r = BlocklistCodec.verifyAndParse(bytes)
        assertFalse(r.isOk)
        assertEquals(BlocklistCodec.Failure.BAD_SIGNATURE, r.failure)
    }

    @Test fun flippedPayloadByteRejected() {
        val bytes = seedBytes()
        // Flip a byte inside the payload (offset 8 = first payload byte).
        bytes[8] = (bytes[8].toInt() xor 0x01).toByte()
        val r = BlocklistCodec.verifyAndParse(bytes)
        assertFalse(r.isOk)
        assertEquals(BlocklistCodec.Failure.BAD_SIGNATURE, r.failure)
    }
}
