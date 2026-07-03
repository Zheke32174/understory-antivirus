package com.understory.antivirus

import android.Manifest
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.core.view.WindowCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewmodel.compose.viewModel
import com.understory.security.Diagnostics
import com.understory.security.DiagnosticsDump
import com.understory.security.DiagnosticsScreen
import com.understory.security.KeepAliveBackHandler
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.SuiteStatusFooter
import com.understory.security.Tamper
import com.understory.security.TestingMode
import com.understory.security.TransientFlight
import com.understory.security.ui.Bg
import com.understory.security.ui.components.EmptyState
import com.understory.security.ui.components.FatalScreen
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.theme.UnderstoryAccent
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    /** Result of the antivirus-specific tamper gate, held for the block screen. */
    private var tamperBlockReason: String? = null

    private fun initialize() {
        val debuggerAttached = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        val tamper = Tamper.check(applicationContext)
        val avGate = AvTamperPolicy.evaluate(tamper)
        val attestation = com.understory.security.SuiteAttestation.verify(applicationContext)

        // For THIS app, a patcher merely INSTALLED is not a hard-fail — it's a
        // finding (the app's whole job). Only signature-mismatch / Frida /
        // Xposed (our own binary compromised) hard-fail, plus attestation and a
        // live debugger. And we NEVER exit silently: on a hard-fail we render a
        // full-screen explanation, then finish on the user's Close.
        val hardBlockReason = when {
            debuggerAttached -> "a debugger is attached to this build"
            avGate.hardFail -> avGate.reason
            attestation.hardFail -> "the suite attestation check failed"
            else -> null
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

        tamperBlockReason = hardBlockReason

        setContent {
            UnderstoryTheme(accent = UnderstoryAccent.ANTIVIRUS) {
                val reason = tamperBlockReason
                if (reason != null) {
                    TamperBlockScreen(reason = reason, onClose = { finishAndRemoveTask() })
                } else {
                    Surface(
                        modifier = Modifier.fillMaxSize(),
                        color = MaterialTheme.colorScheme.background,
                    ) {
                        AntivirusRoot()
                    }
                }
            }
        }
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
                UnderstoryTheme(accent = UnderstoryAccent.ANTIVIRUS) {
                    FatalScreen(
                        title = "APK Check crash",
                        reason = "Something went wrong starting the app.",
                        details = t.toString(),
                    )
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
        // Skip the re-check while round-tripping a SAF picker (the onCreate
        // check is authoritative). Otherwise a transient probe misread during
        // the foreground transition would DoS the app mid-scan.
        if (TransientFlight.isActive()) return
        Tamper.invalidate()
        val avGate = AvTamperPolicy.evaluate(Tamper.check(applicationContext))
        if (avGate.hardFail) {
            Diagnostics.error("antivirus.MainActivity", "AvTamperPolicy hardFail on resume — finishing")
            finishAndRemoveTask()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Diagnostics.log("antivirus.MainActivity", "onDestroy")
    }
}

/** Full-screen honest tamper explanation (§6). Never a bare silent finish. */
@Composable
private fun TamperBlockScreen(reason: String, onClose: () -> Unit) {
    Column(modifier = Modifier.fillMaxSize()) {
        FatalScreen(
            title = stringResource(R.string.av_tamper_block_title),
            reason = stringResource(R.string.av_tamper_block_reason, reason),
            modifier = Modifier.weight(1f),
        )
        SecureButton(
            onClick = onClose,
            modifier = Modifier
                .fillMaxWidth()
                .padding(UnderstoryTheme.spacing.lg),
        ) {
            Text(stringResource(R.string.av_tamper_block_close))
        }
    }
}

private enum class Mode { Initial, ScanApk, AuditInstalled, Diagnostics }

@Composable
private fun AntivirusRoot() {
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
    val scope = rememberCoroutineScope()

    val playProtect = remember { PlayProtectStatus.check(ctx) }
    var defsMeta by remember { mutableStateOf<BlocklistStore.Meta?>(null) }
    var tamperInfo by remember { mutableStateOf<TamperFindings.TamperInfo?>(null) }
    var importResult by remember { mutableStateOf<String?>(null) }
    var importIsError by remember { mutableStateOf(false) }
    // When an import is refused for being an older serial, we hold the picked
    // URI so the user can confirm an explicit "import older anyway".
    var pendingOlderUri by remember { mutableStateOf<Uri?>(null) }
    var periodicOn by remember { mutableStateOf(PeriodicScan.isEnabled(ctx)) }
    var alertsGranted by remember { mutableStateOf(PeriodicScan.alertsAllowed(ctx)) }
    // Freshness-while-open (§5.1): a context-registered PACKAGE_ADDED receiver,
    // alive only while this screen is composed (foreground). This is the only
    // rootless place a PACKAGE_ADDED receiver still fires. NOT background
    // real-time — the banner copy says so.
    var freshInstall by remember { mutableStateOf<ApkAnalyzer.Report?>(null) }
    OnNewInstall { report -> freshInstall = report }

    // Load definitions meta + tamper info off the main thread on first show.
    LaunchedEffect(Unit) {
        withContext(Bg.io) { BlocklistStore.ensureLoaded(ctx) }
        defsMeta = BlocklistStore.meta()
        val report = withContext(Bg.io) { Tamper.check(ctx.applicationContext) }
        tamperInfo = withContext(Bg.io) { TamperFindings.build(ctx, report) }
    }

    val requestNotif = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        alertsGranted = granted
        // Whether granted or denied, periodic scanning proceeds; alerts just
        // degrade if denied. Enable the worker now.
        PeriodicScan.setEnabled(ctx, true)
        periodicOn = true
    }

    // Shared import runner: reads the URI off-main, imports, and maps the
    // outcome to an honest card state. allowOlder=true is the explicit
    // "import older anyway" confirm path.
    val runImport: (Uri, Boolean) -> Unit = { uri, allowOlder ->
        scope.launch {
            val outcome = withContext(Bg.io) {
                runCatching {
                    ctx.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?.let { BlocklistStore.importFrom(ctx, it, allowOlder = allowOlder) }
                }.getOrNull()
            }
            when (outcome) {
                is BlocklistStore.ImportResult.Imported -> {
                    defsMeta = outcome.meta
                    importIsError = false
                    pendingOlderUri = null
                    importResult = ctx.getString(
                        R.string.av_defs_updated,
                        outcome.meta.serial, outcome.meta.issued,
                        ctx.getString(R.string.av_defs_counts, outcome.meta.apkCount, outcome.meta.certCount),
                    )
                }
                is BlocklistStore.ImportResult.OlderSerial -> {
                    importIsError = true
                    pendingOlderUri = uri
                    importResult = ctx.getString(R.string.av_defs_older, outcome.incoming, outcome.installed)
                }
                is BlocklistStore.ImportResult.Rejected, null -> {
                    importIsError = true
                    pendingOlderUri = null
                    importResult = ctx.getString(R.string.av_defs_bad)
                }
            }
        }
    }

    val importDefs = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        TransientFlight.end()
        if (uri == null) return@rememberLauncherForActivityResult
        runImport(uri, false)
    }

    Column(
        modifier = Modifier.fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(UnderstoryTheme.spacing.lg),
        verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
    ) {
        Text(
            stringResource(R.string.app_name),
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onBackground,
        )
        PositioningBanner()
        freshInstall?.let { report ->
            SuiteCard {
                Text(
                    "Just installed / updated: ${report.packageName} — ${report.verdict.name}. " +
                        "Checked while APK Check is open (not background real-time).",
                    style = MaterialTheme.typography.bodyMedium,
                    color = verdictAccent(report.verdict),
                )
                report.findings.firstOrNull()?.let { f ->
                    Text(
                        "${f.severity.name}: ${f.title}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = severityAccent(f.severity),
                    )
                }
            }
        }
        PlayProtectCard(playProtect)
        tamperInfo?.let { TamperCard(it) }
        DefinitionsCard(
            meta = defsMeta,
            onImport = {
                TransientFlight.begin()
                runCatching { importDefs.launch(arrayOf("*/*")) }
                    .onFailure { TransientFlight.end() }
            },
            transientResult = importResult,
            isError = importIsError,
            onImportOlder = pendingOlderUri?.let { uri -> { runImport(uri, true) } },
        )
        PeriodicScanToggle(
            enabled = periodicOn,
            alertsGranted = alertsGranted,
            onToggle = { on ->
                if (on) {
                    // Request POST_NOTIFICATIONS (opt-in); the worker is enabled
                    // in the permission callback regardless of grant.
                    if (PeriodicScan.alertsAllowed(ctx)) {
                        PeriodicScan.setEnabled(ctx, true); periodicOn = true; alertsGranted = true
                    } else {
                        requestNotif.launch(Manifest.permission.POST_NOTIFICATIONS)
                    }
                } else {
                    PeriodicScan.setEnabled(ctx, false); periodicOn = false
                }
            },
        )
        SuiteCard {
            Text(
                stringResource(R.string.av_home_catches),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        SecureButton(onClick = onScanApk, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.av_scan_apk))
        }
        SecureOutlinedButton(onClick = onAuditInstalled, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.av_audit_installed))
        }
        SecureOutlinedButton(onClick = onDiagnostics, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.av_diagnostics))
        }
        SuiteStatusFooter()
    }
}

/**
 * Holds scan/audit results across configuration change AND process death is
 * mitigated by re-derivable state; the Report list is transient (recomputed by
 * re-running) but the in-flight results survive recreation here.
 */
class ScanViewModel : ViewModel() {
    var scanReport by mutableStateOf<ApkAnalyzer.Report?>(null)
    var scanError by mutableStateOf<String?>(null)
    var auditReports by mutableStateOf<List<ApkAnalyzer.Report>?>(null)
    var auditError by mutableStateOf<String?>(null)
    var auditSelected by mutableStateOf<ApkAnalyzer.Report?>(null)
}

@Composable
private fun ScanApkScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val vm: ScanViewModel = viewModel()
    var working by remember { mutableStateOf(false) }

    val pickApk = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        TransientFlight.end()
        Diagnostics.log("antivirus.ScanApk", "pickApk result: uri=${if (uri != null) "non-null" else "null"}")
        if (uri == null) return@rememberLauncherForActivityResult
        working = true
        scope.launch {
            val result = withContext(Bg.io) { runCatching { ApkAnalyzer.analyzeUri(ctx, uri) } }
            result
                .onSuccess { vm.scanReport = it; vm.scanError = null }
                .onFailure {
                    Diagnostics.error("antivirus.ScanApk", "scan failed: ${it.javaClass.simpleName}: ${it.message}")
                    vm.scanError = "Scan failed: ${it.message ?: it.javaClass.simpleName}"
                }
            working = false
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(UnderstoryTheme.spacing.lg),
        verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
    ) {
        Text(
            stringResource(R.string.av_scan_title),
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onBackground,
        )
        SecureButton(
            onClick = {
                if (working) return@SecureButton
                Diagnostics.log("antivirus.ScanApk", "Pick APK file: tap")
                TransientFlight.begin()
                runCatching { pickApk.launch(arrayOf("*/*")) }
                    .onFailure {
                        TransientFlight.end()
                        vm.scanError = "Couldn't open file picker: ${it.message}"
                    }
            },
            enabled = !working,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (working) stringResource(R.string.av_scanning) else stringResource(R.string.av_scan_pick))
        }
        if (working) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        }
        vm.scanError?.let {
            Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
        }
        vm.scanReport?.let { ReportView(it) }
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        SecureOutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.av_back))
        }
    }
}

@Composable
private fun AuditInstalledScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val vm: ScanViewModel = viewModel()
    var working by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0 to 0) }

    val runAudit: () -> Unit = {
        if (!working) {
            working = true
            vm.auditSelected = null
            scope.launch {
                val result = withContext(Bg.io) {
                    runCatching {
                        ApkAnalyzer.auditInstalled(ctx) { done, total -> progress = done to total }
                    }
                }
                result
                    .onSuccess { vm.auditReports = it; vm.auditError = null }
                    .onFailure { vm.auditError = "Audit failed: ${it.message ?: it.javaClass.simpleName}" }
                working = false
            }
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(UnderstoryTheme.spacing.lg),
        verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
    ) {
        Text(
            stringResource(R.string.av_audit_title),
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onBackground,
        )
        val reports = vm.auditReports
        val selected = vm.auditSelected
        when {
            reports == null -> {
                Text(
                    stringResource(R.string.av_audit_intro),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                SecureButton(onClick = runAudit, enabled = !working, modifier = Modifier.fillMaxWidth()) {
                    Text(if (working) stringResource(R.string.av_auditing_progress, progress.first, progress.second)
                    else stringResource(R.string.av_audit_run))
                }
                if (working && progress.second > 0) {
                    LinearProgressIndicator(
                        progress = { progress.first.toFloat() / progress.second },
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                vm.auditError?.let {
                    Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
                }
            }
            selected != null -> {
                Column(
                    modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
                ) {
                    ReportView(selected)
                    SecureOutlinedButton(
                        onClick = { vm.auditSelected = null },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(stringResource(R.string.av_audit_back_to_list)) }
                }
            }
            reports.isEmpty() -> {
                Column(Modifier.weight(1f)) {
                    EmptyState(
                        title = stringResource(R.string.av_audit_clean_title),
                        body = stringResource(R.string.av_audit_clean_body),
                    )
                }
                SecureOutlinedButton(onClick = runAudit, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.av_audit_rerun))
                }
            }
            else -> {
                Text(
                    stringResource(R.string.av_audit_flagged_count, reports.size),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
                    modifier = Modifier.fillMaxWidth().weight(1f),
                ) {
                    items(reports, key = { it.packageName }) { r ->
                        AuditRow(r, onClick = { vm.auditSelected = r })
                    }
                }
                SecureOutlinedButton(onClick = runAudit, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.av_audit_rerun))
                }
            }
        }
        SecureOutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.av_back))
        }
    }
}

/** D#5 fix: whole-row clickable card + trailing chevron, no overlaid button. */
@Composable
private fun AuditRow(r: ApkAnalyzer.Report, onClick: () -> Unit) {
    SuiteCard(onClick = onClick) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    r.packageName,
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                r.findings.firstOrNull()?.let { f ->
                    Text(
                        "${f.severity.name}: ${f.title}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = severityAccent(f.severity),
                    )
                }
            }
            Text(
                r.verdict.name,
                style = MaterialTheme.typography.bodyMedium,
                color = verdictAccent(r.verdict),
            )
            Icon(
                imageVector = Icons.Filled.ChevronRight,
                contentDescription = stringResource(R.string.av_audit_details),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ReportView(r: ApkAnalyzer.Report) {
    val ctx = LocalContext.current
    SuiteCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                r.packageName,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                r.verdict.name,
                style = MaterialTheme.typography.titleMedium,
                color = verdictAccent(r.verdict),
            )
        }
        Text(
            "${r.versionName ?: "?"} (${r.versionCode})",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            "apk sha256: " + (r.apkSha256?.take(16)?.plus("…") ?: stringResource(R.string.av_apk_not_hashed)),
            style = MaterialTheme.typography.bodyMedium,
            color = UnderstoryTheme.semantic.dim,
        )
        r.certSha256?.let {
            Text(
                "cert sha256: ${it.take(16)}…",
                style = MaterialTheme.typography.bodyMedium,
                color = UnderstoryTheme.semantic.dim,
            )
        }
        r.notes.forEach {
            Text(it, style = MaterialTheme.typography.bodyMedium, color = UnderstoryTheme.semantic.warning)
        }
        if (r.findings.isEmpty()) {
            Text(
                stringResource(R.string.av_no_findings),
                style = MaterialTheme.typography.bodyMedium,
                color = UnderstoryTheme.semantic.success,
            )
        } else {
            Text(
                stringResource(R.string.av_findings),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            r.findings.forEach { f ->
                Surface(
                    color = MaterialTheme.colorScheme.surface,
                    shape = MaterialTheme.shapes.small,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(Modifier.padding(UnderstoryTheme.spacing.sm)) {
                        Text(
                            "${f.severity.name}: ${f.title}",
                            style = MaterialTheme.typography.bodyMedium,
                            color = severityAccent(f.severity),
                            fontWeight = FontWeight.Medium,
                        )
                        Text(
                            f.explain,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        f.deepLink?.let { target ->
                            val canOpen = SettingsDeepLinks.canOpen(ctx, target)
                            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                            SecureOutlinedButton(
                                onClick = { SettingsDeepLinks.open(ctx, target) },
                                enabled = canOpen,
                            ) {
                                Text(stringResource(R.string.av_fix_in_settings))
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun verdictAccent(v: ApkAnalyzer.Verdict): Color = when (v) {
    ApkAnalyzer.Verdict.CLEAN -> UnderstoryTheme.semantic.success
    ApkAnalyzer.Verdict.SUSPICIOUS -> UnderstoryTheme.semantic.warning
    ApkAnalyzer.Verdict.KNOWN_BAD -> MaterialTheme.colorScheme.error
    ApkAnalyzer.Verdict.UNKNOWN -> UnderstoryTheme.semantic.dim
}

/**
 * Freshness-while-open (§5.1): registers a context-registered
 * [android.content.BroadcastReceiver] for PACKAGE_ADDED / PACKAGE_REPLACED that
 * lives only while this composable is in the STARTED lifecycle state (i.e. the
 * app is foreground) — the only rootless place such a receiver still fires.
 * When a package is added while the app is open, it runs an on-demand analyze
 * of just that package and hands the report back for a top-of-screen banner.
 * Explicitly NOT background real-time.
 */
@Composable
private fun OnNewInstall(onResult: (ApkAnalyzer.Report) -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val lifecycleOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current
    androidx.compose.runtime.DisposableEffect(lifecycleOwner) {
        val receiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(c: android.content.Context?, intent: android.content.Intent?) {
                val pkg = intent?.data?.schemeSpecificPart ?: return
                if (pkg == ctx.packageName) return
                scope.launch {
                    val report = withContext(Bg.io) {
                        runCatching {
                            val enabled = EnabledAbusers.snapshot(ctx)
                            ApkAnalyzer.analyzeInstalled(ctx, pkg, enabled)
                        }.getOrNull()
                    }
                    if (report != null) onResult(report)
                }
            }
        }
        val filter = android.content.IntentFilter().apply {
            addAction(android.content.Intent.ACTION_PACKAGE_ADDED)
            addAction(android.content.Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        val observer = androidx.lifecycle.LifecycleEventObserver { _, event ->
            when (event) {
                androidx.lifecycle.Lifecycle.Event.ON_RESUME ->
                    runCatching {
                        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                            ctx.registerReceiver(receiver, filter, android.content.Context.RECEIVER_NOT_EXPORTED)
                        } else {
                            @Suppress("UnspecifiedRegisterReceiverFlag")
                            ctx.registerReceiver(receiver, filter)
                        }
                    }
                androidx.lifecycle.Lifecycle.Event.ON_PAUSE ->
                    runCatching { ctx.unregisterReceiver(receiver) }
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            runCatching { ctx.unregisterReceiver(receiver) }
        }
    }
}
