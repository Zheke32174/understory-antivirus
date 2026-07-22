package com.understory.antivirus

import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Verifies the shipped seed (`res/raw/blocklist_seed.ubl`) is a valid signed
 * blob under the compiled-in [BlocklistKeys] public key, and that modified
 * payload/signature bytes are rejected.
 *
 * Robolectric 4.13 supports through API 34. This resource/cryptographic fixture
 * is pinned to that emulation level while production remains targetSdk 35.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
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
        assertTrue(p.certSha256.isNotEmpty())
        assertTrue(p.certSha256.all { it.length == 64 && it.all { c -> c in '0'..'9' || c in 'a'..'f' } })
        assertTrue(p.labels.keys.all { it in p.certSha256 })
    }

    @Test fun flippedSignatureByteRejected() {
        val bytes = seedBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xFF).toByte()
        val r = BlocklistCodec.verifyAndParse(bytes)
        assertFalse(r.isOk)
        assertEquals(BlocklistCodec.Failure.BAD_SIGNATURE, r.failure)
    }

    @Test fun flippedPayloadByteRejected() {
        val bytes = seedBytes()
        bytes[8] = (bytes[8].toInt() xor 0x01).toByte()
        val r = BlocklistCodec.verifyAndParse(bytes)
        assertFalse(r.isOk)
        assertEquals(BlocklistCodec.Failure.BAD_SIGNATURE, r.failure)
    }
}
