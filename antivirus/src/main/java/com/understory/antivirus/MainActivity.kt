package com.understory.antivirus

import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.view.View
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import com.understory.security.Diagnostics
import com.understory.security.DiagnosticsDump
import com.understory.security.DiagnosticsScreen
import com.understory.security.KeepAliveBackHandler
import com.understory.security.SuiteStatusFooter
import com.understory.security.TransientFlight
import com.understory.security.Tamper
import com.understory.security.TestingMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    private fun initialize() {
        val debuggerAttached = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        if (debuggerAttached ||
            Tamper.check(applicationContext).hardFail ||
            com.understory.security.SuiteAttestation.verify(applicationContext).hardFail
        ) {
            finishAndRemoveTask(); return
        }

        if (!TestingMode.ALLOW_SCREENSHOTS) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                window.setHideOverlayWindows(true)
            }
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                setRecentsScreenshotEnabled(false)
            }
        }
        runCatching { WindowCompat.setDecorFitsSystemWindows(window, false) }

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFF0A0A0A)) {
                    AntivirusRoot()
                }
            }
        }

        // Note: we deliberately do NOT set
        // `window.decorView.filterTouchesWhenObscured = true` here. Per
        // SAMSUNG_QUIRKS.md, Samsung One UI's Edge Panel and various
        // system gesture overlays trigger FLAG_WINDOW_IS_OBSCURED on
        // legitimate touches, and a global decor filter silently drops
        // every tap underneath. This antivirus is read-only static
        // analysis with no destructive actions, so per-control tap-
        // jacking guards aren't needed; FLAG_SECURE on the window still
        // prevents screenshot / overlay capture of scan results.
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        DiagnosticsDump.activateIfEng(this)
        Diagnostics.log("antivirus.MainActivity", "onCreate (savedInstanceState=${savedInstanceState != null})")
        super.onCreate(savedInstanceState)
        try {
            initialize()
        } catch (t: Throwable) {
            Diagnostics.error("antivirus.MainActivity", "onCreate threw: ${t.javaClass.simpleName}: ${t.message}")
            setContent {
                Surface(modifier = Modifier.fillMaxSize(), color = Color.Black) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Text("antivirus crash", color = Color(0xFFEF5350), fontSize = 18.sp)
                        Text(t.toString(), color = Color(0xFFE0E0E0), fontSize = 11.sp)
                    }
                }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        Diagnostics.log("antivirus.MainActivity", "onPause")
        DiagnosticsDump.snapshotState(this, "onPause")
    }

    override fun onStop() {
        super.onStop()
        Diagnostics.log("antivirus.MainActivity", "onStop (changingConfigs=$isChangingConfigurations)")
        DiagnosticsDump.snapshotState(this, "onStop")
    }

    override fun onResume() {
        super.onResume()
        Diagnostics.log("antivirus.MainActivity", "onResume (transientFlight=${TransientFlight.isActive()})")
        // Skip the hardFail re-check while we're round-tripping through a
        // SAF picker. The onCreate check is the authoritative gate; running
        // it on every resume turns into a self-inflicted denial-of-service
        // because either probe (Tamper / SuiteAttestation) can transiently
        // misreport during the foreground transition — most commonly when
        // a peer suite app was recently sideloaded with a mismatched
        // signing cert (mid-keystore-rotation), making the app close
        // mid-scan with no visible error. The scan worker still calls
        // Tamper.check on hot paths if needed.
        if (TransientFlight.isActive()) return
        Tamper.invalidate()
        if (Tamper.check(applicationContext).hardFail) {
            Diagnostics.error("antivirus.MainActivity", "Tamper.check hardFail on resume — finishing")
            finishAndRemoveTask()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Diagnostics.log("antivirus.MainActivity", "onDestroy")
    }
}

private enum class Mode { Initial, ScanApk, AuditInstalled, Diagnostics }

@Composable
private fun AntivirusRoot() {
    // Save the mode *as a String* across activity recreation — earlier
    // attempt used the Kotlin enum directly via rememberSaveable's
    // AutoSaver, but the shipped APK contained the "cannot be saved"
    // error which suggests AutoSaver was rejecting it. String is safe.
    var modeName by rememberSaveable { mutableStateOf(Mode.Initial.name) }
    val mode = remember(modeName) { Mode.valueOf(modeName) }
    val setMode: (Mode) -> Unit = {
        Diagnostics.log("antivirus.Root", "mode transition: $modeName → ${it.name}")
        modeName = it.name
    }
    val backToInitial: () -> Unit = { setMode(Mode.Initial) }
    when (mode) {
        Mode.Initial -> {
            KeepAliveBackHandler("antivirus.Root.Initial")
            InitialScreen(
                onScanApk = { setMode(Mode.ScanApk) },
                onAuditInstalled = { setMode(Mode.AuditInstalled) },
                onDiagnostics = { setMode(Mode.Diagnostics) },
            )
        }
        Mode.ScanApk -> {
            BackHandler { backToInitial() }
            ScanApkScreen(onBack = backToInitial)
        }
        Mode.AuditInstalled -> {
            BackHandler { backToInitial() }
            AuditInstalledScreen(onBack = backToInitial)
        }
        Mode.Diagnostics -> {
            BackHandler { backToInitial() }
            DiagnosticsScreen(onBack = backToInitial)
        }
    }
}

@Composable
private fun InitialScreen(
    onScanApk: () -> Unit,
    onAuditInstalled: () -> Unit,
    onDiagnostics: () -> Unit,
) {
    val ctx = LocalContext.current
    val playProtect = remember { PlayProtectStatus.check(ctx) }
    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("antivirus", color = Color(0xFFE0E0E0), fontSize = 28.sp)
        Text(
            "Static APK + installed-app analysis. Hash check, signing-cert check, " +
                "permission-combination heuristics. No internet. No accessibility " +
                "service. No real-time process monitoring (those would need root or " +
                "privileged APIs the suite refuses).",
            color = Color(0xFF9E9E9E),
            fontSize = 13.sp,
        )
        PlayProtectCard(playProtect)
        Box(
            modifier = Modifier.fillMaxWidth()
                .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
                .padding(12.dp),
        ) {
            Text(
                "What this catches: known-bad APK hashes, repackager signing certs, " +
                    "permission combinations that match malware shapes (SMS-stealer, " +
                    "surveillance-suite, RAT), apps hidden from the launcher. What it " +
                    "doesn't: novel zero-days, running-process behavior. Treat findings " +
                    "as advisory, not verdicts.",
                color = Color(0xFF9E9E9E),
                fontSize = 11.sp,
            )
        }
        Spacer(Modifier.height(8.dp))
        // Plain Button — antivirus is read-only static analysis, no
        // destructive paths, no secret exposure. SecureButton is overkill
        // here and trips the Samsung Edge Panel false-positive (see
        // SAMSUNG_QUIRKS.md).
        Button(onClick = onScanApk, modifier = Modifier.fillMaxWidth()) {
            Text("Scan an APK file")
        }
        OutlinedButton(onClick = onAuditInstalled, modifier = Modifier.fillMaxWidth()) {
            Text("Audit installed apps")
        }
        Spacer(Modifier.weight(1f))
        OutlinedButton(onClick = onDiagnostics, modifier = Modifier.fillMaxWidth()) {
            Text("Diagnostics")
        }
        SuiteStatusFooter()
    }
}

@Composable
private fun PlayProtectCard(status: PlayProtectStatus.Status) {
    val (label, accent) = when (status.state) {
        PlayProtectStatus.State.ENABLED -> "Play Protect: ON" to Color(0xFF81C784)
        PlayProtectStatus.State.DISABLED -> "Play Protect: OFF" to Color(0xFFEF5350)
        PlayProtectStatus.State.NOT_APPLICABLE -> "Play Protect: not applicable" to Color(0xFF9E9E9E)
        PlayProtectStatus.State.UNKNOWN -> "Play Protect: unknown" to Color(0xFFFFB74D)
    }
    Box(
        modifier = Modifier.fillMaxWidth()
            .background(accent.copy(alpha = 0.10f), RoundedCornerShape(6.dp))
            .padding(12.dp),
    ) {
        Column {
            Text(label, color = accent, fontSize = 12.sp)
            Text(status.explain, color = Color(0xFF9E9E9E), fontSize = 10.sp)
        }
    }
}

@Composable
private fun ScanApkScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var report by remember { mutableStateOf<ApkAnalyzer.Report?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }

    val pickApk = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        // Always close the transient-flight guard FIRST, even on null/cancel
        // so we don't leave the on-resume hardFail check suppressed forever
        // if the user backs out of the picker.
        TransientFlight.end()
        Diagnostics.log("antivirus.ScanApk", "pickApk result: uri=${if (uri != null) "non-null" else "null"}")
        if (uri == null) return@rememberLauncherForActivityResult
        working = true
        // Move scan off main thread — APK SHA-256 of a 50MB file
        // freezes the UI noticeably otherwise.
        scope.launch {
            Diagnostics.log("antivirus.ScanApk", "scan starting on Dispatchers.IO")
            val result = withContext(Dispatchers.IO) {
                runCatching { ApkAnalyzer.analyzeUri(ctx, uri) }
            }
            result
                .onSuccess {
                    Diagnostics.log("antivirus.ScanApk", "scan ok: ${it.packageName} verdict=${it.verdict.name}")
                    report = it; error = null
                }
                .onFailure {
                    Diagnostics.error("antivirus.ScanApk",
                        "scan failed: ${it.javaClass.simpleName}: ${it.message}")
                    error = "Scan failed: ${it.message ?: it.javaClass.simpleName}"
                }
            working = false
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("scan APK", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Button(
            onClick = {
                Diagnostics.log("antivirus.ScanApk", "Pick APK file: tap")
                // Open the transient-flight guard BEFORE the picker fires.
                // The launcher callback closes it. If launch itself throws,
                // we close it here so the on-resume hardFail check isn't
                // suppressed forever.
                TransientFlight.begin()
                runCatching {
                    // Drop the strict APK MIME hint — Drive / Files / Samsung
                    // My Files often expose APKs as application/octet-stream,
                    // and a strict filter hides them entirely. We validate by
                    // parsing in ApkAnalyzer; an unparseable file produces a
                    // clear "(unparseable)" report.
                    pickApk.launch(arrayOf("*/*"))
                }.onFailure {
                    TransientFlight.end()
                    Diagnostics.error("antivirus.ScanApk",
                        "pickApk.launch threw: ${it.javaClass.simpleName}: ${it.message}")
                    error = "Couldn't open file picker: ${it.message}"
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (working) "Scanning…" else "Pick APK file")
        }
        error?.let { Text(it, color = Color(0xFFEF5350), fontSize = 12.sp) }
        report?.let { ReportView(it) }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("Back") }
    }
}

@Composable
private fun AuditInstalledScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var reports by remember { mutableStateOf<List<ApkAnalyzer.Report>?>(null) }
    var working by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var selected by remember { mutableStateOf<ApkAnalyzer.Report?>(null) }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("audit installed apps", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        if (reports == null) {
            Text(
                "Scans your installed user apps for risky permission combinations. " +
                    "System apps you can't uninstall are skipped (no actionable result). " +
                    "Slow on devices with many apps — give it a moment.",
                color = Color(0xFF9E9E9E), fontSize = 12.sp,
            )
            Button(
                onClick = {
                    if (working) return@Button
                    working = true
                    // Move audit off main thread. SHA-256 of every
                    // installed APK on a Dispatchers.IO coroutine; UI
                    // updates back on main when done.
                    scope.launch {
                        val result = withContext(Dispatchers.IO) {
                            runCatching { ApkAnalyzer.auditInstalled(ctx) }
                        }
                        result
                            .onSuccess { reports = it; error = null }
                            .onFailure { error = "Audit failed: ${it.message ?: it.javaClass.simpleName}" }
                        working = false
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (working) "Auditing…" else "Run audit")
            }
            error?.let { Text(it, color = Color(0xFFEF5350), fontSize = 12.sp) }
        } else if (selected != null) {
            ReportView(selected!!)
            OutlinedButton(
                onClick = { selected = null },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Back to list") }
        } else {
            val list = reports!!
            Text(
                "${list.size} app(s) flagged. Tap an entry for details.",
                color = Color(0xFF9E9E9E), fontSize = 12.sp,
            )
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(4.dp),
                modifier = Modifier.fillMaxWidth().weight(1f),
            ) {
                items(list, key = { it.packageName }) { r ->
                    Box(
                        modifier = Modifier.fillMaxWidth()
                            .background(verdictColor(r.verdict).copy(alpha = 0.15f), RoundedCornerShape(6.dp))
                            .padding(10.dp),
                    ) {
                        Column {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Text(r.packageName, color = Color(0xFFE0E0E0), fontSize = 12.sp)
                                Text(r.verdict.name, color = verdictColor(r.verdict), fontSize = 11.sp)
                            }
                            r.findings.firstOrNull()?.let { f ->
                                Text(
                                    "${f.severity.name}: ${f.title}",
                                    color = severityColor(f.severity), fontSize = 10.sp,
                                )
                            }
                        }
                        Box(
                            modifier = Modifier.fillMaxSize()
                                .padding(0.dp),
                        ) {
                            // Whole-row clickable overlay handled by an invisible button.
                            OutlinedButton(
                                onClick = { selected = r },
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Text("Details", color = Color(0xFFE0E0E0))
                            }
                        }
                    }
                }
            }
        }
        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("Back") }
    }
}

@Composable
private fun ReportView(r: ApkAnalyzer.Report) {
    Column(
        modifier = Modifier.fillMaxWidth()
            .background(verdictColor(r.verdict).copy(alpha = 0.10f), RoundedCornerShape(8.dp))
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(r.packageName, color = Color(0xFFE0E0E0), fontSize = 14.sp)
            Text(r.verdict.name, color = verdictColor(r.verdict), fontSize = 12.sp)
        }
        Text(
            "${r.versionName ?: "?"} (${r.versionCode})",
            color = Color(0xFF9E9E9E), fontSize = 11.sp,
        )
        Text(
            "apk sha256: ${r.apkSha256.take(16)}…",
            color = Color(0xFF707070), fontSize = 10.sp,
        )
        r.certSha256?.let {
            Text(
                "cert sha256: ${it.take(16)}…",
                color = Color(0xFF707070), fontSize = 10.sp,
            )
        }
        r.notes.forEach {
            Text(it, color = Color(0xFFFFB74D), fontSize = 11.sp)
        }
        if (r.findings.isEmpty()) {
            Text(
                "No risky permission patterns detected.",
                color = Color(0xFF81C784), fontSize = 11.sp,
            )
        } else {
            Text(
                "Findings:",
                color = Color(0xFFE0E0E0), fontSize = 12.sp,
            )
            r.findings.forEach { f ->
                Box(
                    modifier = Modifier.fillMaxWidth()
                        .background(severityColor(f.severity).copy(alpha = 0.10f), RoundedCornerShape(4.dp))
                        .padding(8.dp),
                ) {
                    Column {
                        Text(
                            "${f.severity.name}: ${f.title}",
                            color = severityColor(f.severity), fontSize = 11.sp,
                        )
                        Text(f.explain, color = Color(0xFF9E9E9E), fontSize = 10.sp)
                    }
                }
            }
        }
    }
}

private fun verdictColor(v: ApkAnalyzer.Verdict): Color = when (v) {
    ApkAnalyzer.Verdict.CLEAN -> Color(0xFF81C784)
    ApkAnalyzer.Verdict.SUSPICIOUS -> Color(0xFFFFB74D)
    ApkAnalyzer.Verdict.KNOWN_BAD -> Color(0xFFEF5350)
    ApkAnalyzer.Verdict.UNKNOWN -> Color(0xFF9E9E9E)
}

private fun severityColor(s: RiskRules.Severity): Color = when (s) {
    RiskRules.Severity.CRITICAL -> Color(0xFFEF5350)
    RiskRules.Severity.HIGH -> Color(0xFFFFB74D)
    RiskRules.Severity.MED -> Color(0xFFE6C26B)
    RiskRules.Severity.LOW -> Color(0xFF9E9E9E)
}
