package com.understory.antivirus

import android.os.Parcel
import android.os.Parcelable

/**
 * Wire format between ApkParserService (isolated process) and the main
 * process. Deliberately dumb: raw facts extracted from the APK, zero
 * interpretation. KnownBad / RiskRules run in the main process, so the
 * isolated parser holds no policy and the policy code never touches
 * attacker-controlled bytes directly.
 *
 * Manual Parcelable (no kotlin-parcelize) — keeps the wire shape explicit and
 * auditable, which matters for a cross-process boundary whose other side is
 * parsing hostile input.
 *
 * WIRE VERSION (manual, append-only): fields are written/read in a fixed
 * order; NEW fields are APPENDED to both [writeToParcel] and [CREATOR] so an
 * older reader never mis-aligns. v1 = packageName..flags. v2 appended
 * [servicePermissions] and [receiverPermissions] (the `android:permission`
 * values of declared `<service>`/`<receiver>` components, for declared-abuse
 * detection on SAF-scanned APKs). Both sides here are the same build, so v2 is
 * always symmetric; the append-only rule is the invariant to preserve on any
 * future change.
 */
class ApkParseResult(
    val packageName: String?,
    val versionName: String?,
    val versionCode: Long,
    /** SHA-256 (lowercase hex) of every signing cert found, v1 + v2/v3. */
    val certSha256s: List<String>,
    /** Permission strings from `<uses-permission>` entries. */
    val permissions: List<String>,
    /** Structural [FLAG_BAD_ZIP]-style observations, not verdicts. */
    val flags: List<String>,
    /** `android:permission` of every `<service>` (v2). Empty for old-style. */
    val servicePermissions: List<String> = emptyList(),
    /** `android:permission` of every `<receiver>` (v2). */
    val receiverPermissions: List<String> = emptyList(),
) : Parcelable {

    override fun describeContents(): Int = 0

    override fun writeToParcel(dest: Parcel, parcelableFlags: Int) {
        dest.writeString(packageName)
        dest.writeString(versionName)
        dest.writeLong(versionCode)
        dest.writeStringList(certSha256s)
        dest.writeStringList(permissions)
        dest.writeStringList(flags)
        // --- v2 appended fields ---
        dest.writeStringList(servicePermissions)
        dest.writeStringList(receiverPermissions)
    }

    companion object {
        /** ZIP walk failed outright (not a zip, truncated, entry bomb). */
        const val FLAG_BAD_ZIP = "bad_zip"

        /** AndroidManifest.xml missing or its binary XML didn't parse. */
        const val FLAG_BAD_MANIFEST = "bad_manifest"

        /**
         * More than one AndroidManifest.xml entry in the zip — the classic
         * parser-confusion shape (different parsers pick different entries).
         * Legitimate build tools never emit this.
         */
        const val FLAG_DUPLICATE_MANIFEST = "duplicate_manifest"

        /** No signing certificate found via v1, v2, or v3 surfaces. */
        const val FLAG_NO_CERT = "no_cert"

        @JvmField
        val CREATOR = object : Parcelable.Creator<ApkParseResult> {
            override fun createFromParcel(source: Parcel) = ApkParseResult(
                packageName = source.readString(),
                versionName = source.readString(),
                versionCode = source.readLong(),
                certSha256s = source.createStringArrayList() ?: emptyList(),
                permissions = source.createStringArrayList() ?: emptyList(),
                flags = source.createStringArrayList() ?: emptyList(),
                // --- v2 appended fields ---
                servicePermissions = source.createStringArrayList() ?: emptyList(),
                receiverPermissions = source.createStringArrayList() ?: emptyList(),
            )

            override fun newArray(size: Int) = arrayOfNulls<ApkParseResult>(size)
        }
    }
}
