package com.understory.antivirus

import android.os.ParcelFileDescriptor
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Structural tests for [RawApkParser] over real ZIP inputs. Robolectric supplies
 * ParcelFileDescriptor and the application cache directory.
 *
 * Robolectric 4.13 supports through API 34. This ZIP/parser fixture is pinned to
 * that emulation level while production remains targetSdk 35.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
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
        assertTrue(result.servicePermissions.isEmpty())
        assertFalse(result.flags.isEmpty())
    }
}
