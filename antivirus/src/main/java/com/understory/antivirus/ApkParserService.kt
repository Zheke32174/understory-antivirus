package com.understory.antivirus

import android.app.Service
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.ParcelFileDescriptor

/**
 * Isolated-process host for RawApkParser (`android:isolatedProcess=
 * "true"`, `android:exported="false"` in the manifest). An isolated
 * process runs under a throwaway uid with no permissions, no
 * PackageManager, no filesystem, and no network — arbitrary code
 * execution inside the APK parser gets an attacker nothing but the fd
 * it was handed. See RELEASE_BLOCKERS.md (per-app hardening).
 *
 * Protocol (Messenger — deliberately narrow, no AIDL surface):
 *   in:  MSG_PARSE, data[KEY_APK] = read-only ParcelFileDescriptor,
 *        replyTo = client Messenger
 *   out: MSG_RESULT, data[KEY_RESULT] = ApkParseResult
 *
 * A hard parser crash (native, OOM) kills only this process; the
 * client's binder-death / timeout path turns that into a "suspicious
 * file, parser crashed" scan result instead of an app crash.
 */
class ApkParserService : Service() {

    private val handler = object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(msg: Message) {
            if (msg.what != MSG_PARSE) return
            val reply = msg.replyTo ?: return
            val pfd = msg.data.getParcelable(KEY_APK, ParcelFileDescriptor::class.java)
            val result = if (pfd == null) {
                ApkParseResult(null, null, 0L, emptyList(), emptyList(), listOf(ApkParseResult.FLAG_BAD_ZIP))
            } else {
                try {
                    RawApkParser.parse(pfd)
                } catch (_: Exception) {
                    // Structured failure. Errors (OOM, stack overflow)
                    // intentionally fall through and kill this process —
                    // the client's death path covers those.
                    ApkParseResult(null, null, 0L, emptyList(), emptyList(), listOf(ApkParseResult.FLAG_BAD_ZIP))
                } finally {
                    runCatching { pfd.close() }
                }
            }
            val out = Message.obtain(null, MSG_RESULT)
            out.data = Bundle().apply { putParcelable(KEY_RESULT, result) }
            runCatching { reply.send(out) }
        }
    }

    override fun onBind(intent: Intent?): IBinder = Messenger(handler).binder

    companion object {
        const val MSG_PARSE = 1
        const val MSG_RESULT = 2
        const val KEY_APK = "apk"
        const val KEY_RESULT = "result"
    }
}
