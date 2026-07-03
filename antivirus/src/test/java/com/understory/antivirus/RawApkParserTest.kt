package com.understory.antivirus

import android.os.ParcelFileDescriptor
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Structural tests for [RawApkParser] over real ZIP inputs (the fd is a real
 * temp file — Robolectric provides ParcelFileDescriptor). We exercise the ZIP
 * walk's fail-closed flags without hand-crafting binary AXML: the binary-XML
 * decode path is covered by the [RiskRules.analyzeComponents] rules that
 * consume its output.
 */
@RunWith(RobolectricTestRunner::class)
class RawApkParserTest {

    private fun tempApk(build: (ZipOutputStream) -> Unit): File {
        val dir = ApplicationProvider.getApplicationContext<android.content.Context>().cacheDir
        val f = File.createTempFile("test", ".apk", dir)
        ZipOutputStream(f.outputStream()).use(build)
        return f
    }

    private fun parse(f: File): ApkParseResult {
        val pfd = ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY)
        return pfd.use { RawApkParser.parse(it) }
    }

    @Test fun nonZipFileFlagsBadZip() {
        val dir = ApplicationProvider.getApplicationContext<android.content.Context>().cacheDir
        val f = File.createTempFile("notzip", ".apk", dir)
        f.writeText("this is not a zip file at all")
        val result = parse(f)
        assertTrue(ApkParseResult.FLAG_BAD_ZIP in result.flags)
    }

    @Test fun missingManifestFlagged() {
        val f = tempApk { zos ->
            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write(ByteArray(16))
            zos.closeEntry()
        }
        val result = parse(f)
        assertTrue(ApkParseResult.FLAG_BAD_MANIFEST in result.flags)
        // No cert entries → NO_CERT flag.
        assertTrue(ApkParseResult.FLAG_NO_CERT in result.flags)
    }

    @Test fun malformedManifestBytesFlagBadManifest() {
        val f = tempApk { zos ->
            zos.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zos.write("definitely not binary xml".toByteArray())
            zos.closeEntry()
        }
        val result = parse(f)
        assertTrue(ApkParseResult.FLAG_BAD_MANIFEST in result.flags)
        // v2 component-permission fields default empty on an unparsed manifest.
        assertTrue(result.servicePermissions.isEmpty())
        assertFalse(result.flags.isEmpty())
    }
}
