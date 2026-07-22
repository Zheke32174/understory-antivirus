package com.understory.antivirus

import android.os.ParcelFileDescriptor
import android.system.Os

/**
 * Minimal structural admission check before untrusted input reaches the raw APK
 * parser. APK files are ZIP archives and must begin with a local-file header.
 *
 * `pread` is positional: it does not advance or take ownership of the descriptor
 * later handed to [RawApkParser].
 */
internal object ApkInputGuard {
    private val ZIP_LOCAL_FILE_HEADER = byteArrayOf(0x50, 0x4b, 0x03, 0x04)

    fun hasZipLocalFileHeader(pfd: ParcelFileDescriptor): Boolean = runCatching {
        val header = ByteArray(ZIP_LOCAL_FILE_HEADER.size)
        val read = Os.pread(
            pfd.fileDescriptor,
            header,
            0,
            header.size,
            0L,
        )
        read == header.size && header.contentEquals(ZIP_LOCAL_FILE_HEADER)
    }.getOrDefault(false)
}
