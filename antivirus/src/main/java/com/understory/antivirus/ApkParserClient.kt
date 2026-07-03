package com.understory.antivirus

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.ParcelFileDescriptor
import com.understory.security.Diagnostics
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Main-process client for ApkParserService. Synchronous facade over the
 * Messenger round-trip so ApkAnalyzer stays a plain blocking call on
 * Dispatchers.IO. Must NOT be called from the main thread — the reply
 * and the ServiceConnection callbacks are delivered on the main looper,
 * so blocking it here would deadlock (the check() below enforces this).
 *
 * Returns null when the isolated parser died or never answered — a
 * malformed APK crashed it, or the reply budget ran out. Callers treat
 * null as "suspicious file, parser crashed": a scan RESULT, not an app
 * error.
 */
internal object ApkParserClient {

    /** Generous — parsing is fast, but cold-starting an isolated process
     *  on a loaded low-end device is not. */
    private const val REPLY_TIMEOUT_MS = 30_000L

    fun parse(ctx: Context, apk: File): ApkParseResult? {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "ApkParserClient.parse must not run on the main thread"
        }
        val appCtx = ctx.applicationContext
        // Open the fd here, before binding: the isolated process can't
        // open files itself, and MODE_READ_ONLY is the entire capability
        // it receives.
        val pfd = ParcelFileDescriptor.open(apk, ParcelFileDescriptor.MODE_READ_ONLY)
        val latch = CountDownLatch(1)
        val result = AtomicReference<ApkParseResult?>(null)
        val replyMessenger = Messenger(Handler(Looper.getMainLooper()) { msg ->
            if (msg.what == ApkParserService.MSG_RESULT) {
                msg.data.classLoader = ApkParseResult::class.java.classLoader
                result.set(
                    msg.data.getParcelable(ApkParserService.KEY_RESULT, ApkParseResult::class.java),
                )
                latch.countDown()
            }
            true
        })
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                if (binder == null) {
                    latch.countDown(); return
                }
                val msg = Message.obtain(null, ApkParserService.MSG_PARSE)
                msg.replyTo = replyMessenger
                // Messenger.send parcels (and dups the fd) synchronously,
                // so closing our side in the finally below is safe.
                msg.data = Bundle().apply { putParcelable(ApkParserService.KEY_APK, pfd) }
                runCatching { Messenger(binder).send(msg) }
                    .onFailure { latch.countDown() }
            }

            // Fires when the isolated process dies while bound — i.e. the
            // parser crashed on this APK. That's a scan signal, not an
            // error; the latch releases with no result set.
            override fun onServiceDisconnected(name: ComponentName?) = latch.countDown()
            override fun onBindingDied(name: ComponentName?) = latch.countDown()
            override fun onNullBinding(name: ComponentName?) = latch.countDown()
        }
        try {
            val bound = appCtx.bindService(
                Intent(appCtx, ApkParserService::class.java), conn, Context.BIND_AUTO_CREATE,
            )
            if (!bound) {
                Diagnostics.error("antivirus.ParserClient", "bindService returned false")
                return null
            }
            if (!latch.await(REPLY_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                Diagnostics.error("antivirus.ParserClient", "isolated parser timed out")
                return null
            }
            return result.get()
        } finally {
            runCatching { appCtx.unbindService(conn) }
            runCatching { pfd.close() }
        }
    }
}
