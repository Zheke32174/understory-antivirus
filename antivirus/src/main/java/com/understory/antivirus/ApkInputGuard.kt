package com.understory.antivirus

import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.nio.ByteBuffer

/**
 * Minimal structural admission check before untrusted input reaches the raw APK
 * parser. APK files are ZIP archives and must begin with a local-file header.
 *
 * The descriptor is duplicated so the check cannot consume or close the
 * descriptor later handed to [RawApkParser].
 */
internal object ApkInputGuard {
    private val ZIP_LOCAL_FILE_HEADER = byteArrayOf(0x50, 0x4b, 0x03, 0x04)

    fun hasZipLocalFileHeader(pfd: ParcelFileDescriptor): Boolean = runCatching {
        ParcelFileDescriptor.dup(pfd.fileDescriptor).use { duplicate ->
            FileInputStream(duplicate.fileDescriptor).channel.use { channel ->
                val header = ByteArray(ZIP_LOCAL_FILE_HEADER.size)
                val read = channel.read(ByteBuffer.wrap(header), 0)
                read == header.size && header.contentEquals(ZIP_LOCAL_FILE_HEADER)
            }
        }
    }.getOrDefault(false)
}
