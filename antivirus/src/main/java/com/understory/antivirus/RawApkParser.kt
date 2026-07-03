package com.understory.antivirus

import android.os.ParcelFileDescriptor
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.FileInputStream
import java.io.FilterInputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.zip.ZipInputStream

/**
 * Raw APK parser that operates on nothing but an already-open, seekable
 * file descriptor. It runs inside ApkParserService (isolatedProcess),
 * which has no filesystem, no network, and no PackageManager — so this
 * deliberately re-implements the three extractions we need (ZIP walk,
 * binary AndroidManifest.xml, signing certs) instead of calling
 * PackageManager.getPackageArchiveInfo: the framework parser needs a
 * file *path* and can't run under an isolated uid, and keeping it in
 * the main process is exactly the ACE surface the isolation exists to
 * remove (see RELEASE_BLOCKERS.md).
 *
 * Every read is bounds-checked and size-capped; a structural violation
 * throws and surfaces as a bad-zip / bad-manifest flag rather than a
 * crash. If something DOES crash hard (OOM from a decompression bomb,
 * stack overflow), it kills only the throwaway isolated process and the
 * client reports "parser crashed" — that containment is the point.
 *
 * Signing certs are extracted, not verified — the digest is only
 * matched against the KnownBad deny-list, and an attacker gains nothing
 * from forging a cert *toward* a deny-list hit.
 */
internal object RawApkParser {

    /** Binary AndroidManifest.xml over this size is not a real manifest. */
    private const val MAX_MANIFEST_BYTES = 8 * 1024 * 1024

    /** Cap per META-INF PKCS#7 blob (v1 signatures: .RSA, .DSA, .EC). */
    private const val MAX_V1_CERT_BYTES = 1024 * 1024

    /** Entry-count cap so a crafted central directory can't spin us. */
    private const val MAX_ZIP_ENTRIES = 100_000

    /** Real APK Signing Blocks are a few KiB; 4 MiB is already absurd. */
    private const val MAX_SIG_BLOCK_BYTES = 4L * 1024 * 1024

    fun parse(pfd: ParcelFileDescriptor): ApkParseResult {
        val flags = mutableListOf<String>()
        val certDigests = LinkedHashSet<String>()

        // Single stream over the shared fd, alive for the whole parse.
        // Phase 1 uses positional channel reads (they don't move the fd
        // offset), so phase 2's sequential zip walk still starts at 0.
        val fis = FileInputStream(pfd.fileDescriptor)

        // Phase 1: APK Signing Block (v2/v3). Absence is normal
        // (v1-only APKs); malformed blocks are simply skipped — cert
        // digests are best-effort input to a deny-list.
        runCatching { certDigests += signingBlockCertDigests(fis.channel) }

        // Phase 2: sequential zip walk for the manifest bytes and any
        // v1 (JAR) signature blocks.
        var manifestBytes: ByteArray? = null
        var manifestEntries = 0
        try {
            ZipInputStream(BufferedInputStream(NonClosingInputStream(fis))).use { zis ->
                var entries = 0
                while (true) {
                    val entry = zis.nextEntry ?: break
                    require(++entries <= MAX_ZIP_ENTRIES) { "too many zip entries" }
                    val name = entry.name
                    if (name == "AndroidManifest.xml") {
                        manifestEntries++
                        if (manifestBytes == null) {
                            manifestBytes = readCapped(zis, MAX_MANIFEST_BYTES)
                        }
                    } else if (name.startsWith("META-INF/") &&
                        (name.endsWith(".RSA", ignoreCase = true) ||
                            name.endsWith(".DSA", ignoreCase = true) ||
                            name.endsWith(".EC", ignoreCase = true))
                    ) {
                        readCapped(zis, MAX_V1_CERT_BYTES)?.let { block ->
                            // X.509 CertificateFactory understands PKCS#7.
                            runCatching {
                                CertificateFactory.getInstance("X.509")
                                    .generateCertificates(ByteArrayInputStream(block))
                                    .forEach { certDigests += sha256Hex(it.encoded) }
                            }
                        }
                    }
                    zis.closeEntry()
                }
            }
        } catch (_: Exception) {
            flags += ApkParseResult.FLAG_BAD_ZIP
        }
        if (manifestEntries > 1) flags += ApkParseResult.FLAG_DUPLICATE_MANIFEST

        // Phase 3: binary-XML manifest decode.
        var manifest: AxmlManifest? = null
        val bytes = manifestBytes
        if (bytes != null) {
            try {
                manifest = parseBinaryManifest(bytes)
            } catch (_: Exception) {
                flags += ApkParseResult.FLAG_BAD_MANIFEST
            }
        } else if (ApkParseResult.FLAG_BAD_ZIP !in flags) {
            flags += ApkParseResult.FLAG_BAD_MANIFEST
        }
        if (certDigests.isEmpty()) flags += ApkParseResult.FLAG_NO_CERT

        return ApkParseResult(
            packageName = manifest?.packageName,
            versionName = manifest?.versionName,
            versionCode = manifest?.versionCode ?: 0L,
            certSha256s = certDigests.toList(),
            permissions = manifest?.permissions ?: emptyList(),
            flags = flags,
            servicePermissions = manifest?.servicePermissions ?: emptyList(),
            receiverPermissions = manifest?.receiverPermissions ?: emptyList(),
        )
    }

    // ---------------------------------------------------------------
    // APK Signing Block (v2 = 0x7109871a, v3 = 0xf05368c0)
    // ---------------------------------------------------------------

    // "APK Sig Block 42"
    private val SIG_BLOCK_MAGIC = byteArrayOf(
        0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
        0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32,
    )
    private const val SCHEME_V2_ID = 0x7109871aL
    private const val SCHEME_V3_ID = 0xf05368c0L

    /**
     * Locate the signing block just before the zip central directory
     * and pull the DER cert bytes out of any v2/v3 signer sequences.
     * Layout: [size u64][id/value pairs][size u64][magic 16B], sitting
     * immediately before the central directory. All little-endian.
     */
    private fun signingBlockCertDigests(channel: FileChannel): List<String> {
        val fileSize = channel.size()
        if (fileSize < 22) return emptyList()
        // End-of-central-directory: last 22 bytes + up to 64 KiB comment.
        val tailLen = minOf(fileSize, (22 + 0xFFFF).toLong()).toInt()
        val tail = ByteArray(tailLen)
        readFully(channel, fileSize - tailLen, tail)
        var eocd = -1
        for (i in tailLen - 22 downTo 0) {
            if (u32(tail, i) == 0x06054b50L && i + 22 + u16(tail, i + 20) == tailLen) {
                eocd = i
                break
            }
        }
        if (eocd < 0) return emptyList()
        val cdOffset = u32(tail, eocd + 16)
        if (cdOffset < 32 || cdOffset >= fileSize) return emptyList()

        val footer = ByteArray(24)
        readFully(channel, cdOffset - 24, footer)
        if (!footer.copyOfRange(8, 24).contentEquals(SIG_BLOCK_MAGIC)) return emptyList()
        // Trailing size field counts everything after the leading one:
        // pairs + trailing size + magic.
        val blockSize = u64(footer, 0)
        if (blockSize < 24 || blockSize > MAX_SIG_BLOCK_BYTES || blockSize + 8 > cdOffset) {
            return emptyList()
        }
        val pairs = ByteArray((blockSize - 24).toInt())
        readFully(channel, cdOffset - blockSize, pairs)

        val out = mutableListOf<String>()
        var p = 0
        while (p + 12 <= pairs.size) {
            val len = u64(pairs, p)
            if (len < 4 || len > (pairs.size - p - 8).toLong()) break
            val id = u32(pairs, p + 8)
            if (id == SCHEME_V2_ID || id == SCHEME_V3_ID) {
                out += schemeBlockCertDigests(pairs, p + 12, (len - 4).toInt())
            }
            p += 8 + len.toInt()
        }
        return out
    }

    /**
     * v2/v3 share the prefix that matters: signers → signer →
     * signed-data → (digests, certificates). Every element is a u32
     * length-prefixed blob; certs are raw X.509 DER, the same bytes
     * Signature.toByteArray() yields, so digests line up with
     * KnownBad.certHashes and Tamper.kt.
     */
    private fun schemeBlockCertDigests(b: ByteArray, at: Int, len: Int): List<String> {
        val out = mutableListOf<String>()
        var q = at
        val end = at + len
        if (q + 4 > end) return out
        val signersEnd = minOf(end.toLong(), q + 4L + i32(b, q)).toInt()
        q += 4
        while (q + 4 <= signersEnd) {
            val signerLen = i32(b, q)
            q += 4
            if (signerLen < 4 || signerLen > signersEnd - q) break
            val signerEnd = q + signerLen
            val signedDataLen = i32(b, q)
            if (signedDataLen >= 4 && signedDataLen <= signerEnd - q - 4) {
                val sdEnd = q + 4 + signedDataLen
                var d = q + 4
                val digestsLen = i32(b, d)
                d += 4
                if (digestsLen in 0..(sdEnd - d - 4)) {
                    d += digestsLen
                    val certsEnd = minOf(sdEnd.toLong(), d + 4L + i32(b, d)).toInt()
                    d += 4
                    while (d + 4 <= certsEnd) {
                        val certLen = i32(b, d)
                        d += 4
                        if (certLen <= 0 || certLen > certsEnd - d) break
                        out += sha256Hex(b.copyOfRange(d, d + certLen))
                        d += certLen
                    }
                }
            }
            q = signerEnd
        }
        return out
    }

    // ---------------------------------------------------------------
    // Binary AndroidManifest.xml (AXML)
    // ---------------------------------------------------------------

    private class AxmlManifest(
        val packageName: String,
        val versionName: String?,
        val versionCode: Long,
        val permissions: List<String>,
        /** `android:permission` of each `<service>` element. */
        val servicePermissions: List<String>,
        /** `android:permission` of each `<receiver>` element. */
        val receiverPermissions: List<String>,
    )

    private const val CHUNK_STRING_POOL = 0x0001
    private const val CHUNK_XML = 0x0003
    private const val CHUNK_START_ELEMENT = 0x0102
    private const val CHUNK_RESOURCE_MAP = 0x0180

    // Framework attribute resource ids — stable public values. Matching
    // by id (with a string-name fallback) survives manifests whose
    // attribute-name strings were stripped by obfuscators.
    private const val RES_ID_NAME = 0x01010003
    private const val RES_ID_PERMISSION = 0x01010006
    private const val RES_ID_VERSION_CODE = 0x0101021b
    private const val RES_ID_VERSION_NAME = 0x0101021c

    private const val TYPE_STRING = 0x03

    /** Defensive cap on collected component-permission strings. */
    private const val MAX_COMPONENT_PERMS = 256

    private fun parseBinaryManifest(m: ByteArray): AxmlManifest {
        require(m.size >= 8 && u16(m, 0) == CHUNK_XML) { "not binary XML" }
        var pos = 8
        var strings: List<String> = emptyList()
        var resIds = IntArray(0)
        var pkg: String? = null
        var versionName: String? = null
        var versionCode = 0L
        val permissions = mutableListOf<String>()
        val servicePermissions = mutableListOf<String>()
        val receiverPermissions = mutableListOf<String>()

        while (pos + 8 <= m.size) {
            val chunkType = u16(m, pos)
            val headerSize = u16(m, pos + 2)
            val chunkSize = i32(m, pos + 4)
            require(chunkSize >= 8 && headerSize >= 8 && chunkSize <= m.size - pos) { "bad chunk" }
            when (chunkType) {
                CHUNK_STRING_POOL -> if (strings.isEmpty()) {
                    strings = parseStringPool(m, pos, chunkSize)
                }
                CHUNK_RESOURCE_MAP -> {
                    val n = (chunkSize - headerSize) / 4
                    resIds = IntArray(n) { i32(m, pos + headerSize + it * 4) }
                }
                CHUNK_START_ELEMENT -> {
                    // ResXMLTree_node header is 16 bytes (chunk header +
                    // line number + comment); the attrExt follows.
                    val ext = pos + 16
                    require(ext + 16 <= pos + chunkSize) { "truncated element" }
                    val elemName = strings.getOrNull(i32(m, ext + 4))
                    val attrStart = u16(m, ext + 8)
                    val attrSize = u16(m, ext + 10)
                    val attrCount = u16(m, ext + 12)
                    val isManifest = elemName == "manifest"
                    val isPermission = elemName == "uses-permission" ||
                        elemName == "uses-permission-sdk-23"
                    val isService = elemName == "service"
                    val isReceiver = elemName == "receiver"
                    if (isManifest || isPermission || isService || isReceiver) {
                        require(attrSize >= 20) { "bad attribute size" }
                        for (i in 0 until attrCount) {
                            val a = ext + attrStart + i * attrSize
                            require(a + 20 <= pos + chunkSize) { "attr out of chunk" }
                            val nameIdx = i32(m, a + 4)
                            val rawValueIdx = i32(m, a + 8)
                            val dataType = u8(m, a + 15)
                            val data = i32(m, a + 16)
                            val resId = if (nameIdx in resIds.indices) resIds[nameIdx] else 0
                            val attrName = strings.getOrNull(nameIdx)
                            val stringValue = when {
                                rawValueIdx != -1 -> strings.getOrNull(rawValueIdx)
                                dataType == TYPE_STRING -> strings.getOrNull(data)
                                else -> null
                            }
                            when {
                                isManifest && attrName == "package" ->
                                    pkg = stringValue
                                isManifest && (resId == RES_ID_VERSION_CODE || attrName == "versionCode") ->
                                    versionCode = data.toLong() and 0xFFFFFFFFL
                                isManifest && (resId == RES_ID_VERSION_NAME || attrName == "versionName") ->
                                    versionName = stringValue
                                isPermission && (resId == RES_ID_NAME || attrName == "name") ->
                                    stringValue?.let { permissions += it }
                                isService && (resId == RES_ID_PERMISSION || attrName == "permission") ->
                                    stringValue?.let {
                                        if (servicePermissions.size < MAX_COMPONENT_PERMS) {
                                            servicePermissions += it
                                        }
                                    }
                                isReceiver && (resId == RES_ID_PERMISSION || attrName == "permission") ->
                                    stringValue?.let {
                                        if (receiverPermissions.size < MAX_COMPONENT_PERMS) {
                                            receiverPermissions += it
                                        }
                                    }
                            }
                        }
                    }
                }
            }
            pos += chunkSize
        }
        return AxmlManifest(
            packageName = requireNotNull(pkg) { "no package attribute" },
            versionName = versionName,
            versionCode = versionCode,
            permissions = permissions,
            servicePermissions = servicePermissions,
            receiverPermissions = receiverPermissions,
        )
    }

    private fun parseStringPool(m: ByteArray, start: Int, size: Int): List<String> {
        val stringCount = i32(m, start + 8)
        val poolFlags = i32(m, start + 16)
        val stringsStart = i32(m, start + 20)
        require(stringCount >= 0 && 28 + stringCount.toLong() * 4 <= size) { "bad string pool" }
        require(stringsStart in 0..size) { "bad strings start" }
        val utf8 = (poolFlags and 0x100) != 0
        val poolEnd = start + size
        val out = ArrayList<String>(stringCount)
        for (i in 0 until stringCount) {
            var p = start + stringsStart + i32(m, start + 28 + i * 4)
            require(p >= start && p < poolEnd) { "string offset out of pool" }
            if (utf8) {
                // Two lengths (chars, then bytes), each 1 or 2 bytes.
                val skip = u8(m, p)
                p += if (skip and 0x80 != 0) 2 else 1
                var byteLen = u8(m, p)
                p += 1
                if (byteLen and 0x80 != 0) {
                    byteLen = ((byteLen and 0x7F) shl 8) or u8(m, p)
                    p += 1
                }
                require(p + byteLen.toLong() <= poolEnd) { "utf8 string out of pool" }
                out += String(m, p, byteLen, Charsets.UTF_8)
            } else {
                var charLen = u16(m, p)
                p += 2
                if (charLen and 0x8000 != 0) {
                    charLen = ((charLen and 0x7FFF) shl 16) or u16(m, p)
                    p += 2
                }
                require(p + charLen.toLong() * 2 <= poolEnd) { "utf16 string out of pool" }
                out += String(m, p, charLen * 2, Charsets.UTF_16LE)
            }
        }
        return out
    }

    // ---------------------------------------------------------------
    // Plumbing
    // ---------------------------------------------------------------

    /**
     * close() suppressed: the fd belongs to the ParcelFileDescriptor the
     * service owns, but ZipInputStream.close() must still run to free
     * its native Inflater.
     */
    private class NonClosingInputStream(wrapped: InputStream) : FilterInputStream(wrapped) {
        override fun close() { /* fd owned by the caller */ }
    }

    /** Read a whole zip entry, or null if it exceeds [cap] (bomb guard). */
    private fun readCapped(zis: ZipInputStream, cap: Int): ByteArray? {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (true) {
            val n = zis.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > cap) return null
        }
        return out.toByteArray()
    }

    /** Positional read: fills [dst] from [position] without moving the fd offset. */
    private fun readFully(channel: FileChannel, position: Long, dst: ByteArray) {
        val buf = ByteBuffer.wrap(dst)
        while (buf.hasRemaining()) {
            val n = channel.read(buf, position + buf.position())
            if (n <= 0) throw EOFException("truncated positional read")
        }
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }

    // Little-endian primitive readers; array indexing bounds-checks for us.
    private fun u8(b: ByteArray, at: Int): Int = b[at].toInt() and 0xFF
    private fun u16(b: ByteArray, at: Int): Int = u8(b, at) or (u8(b, at + 1) shl 8)
    private fun i32(b: ByteArray, at: Int): Int = u16(b, at) or (u16(b, at + 2) shl 16)
    private fun u32(b: ByteArray, at: Int): Long = i32(b, at).toLong() and 0xFFFFFFFFL
    private fun u64(b: ByteArray, at: Int): Long = u32(b, at) or (u32(b, at + 4) shl 32)
}
