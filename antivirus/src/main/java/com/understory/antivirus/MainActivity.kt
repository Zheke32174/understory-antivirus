package com.understory.antivirus

import android.Manifest
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
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.core.view.WindowCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewmodel.compose.viewModel
import com.understory.security.Diagnostics
import com.understory.security.DiagnosticsDump
import com.understory.security.DiagnosticsScreen
import com.understory.security.KeepAliveBackHandler
import com.understory.security.SecureButton
import com.understory.security.Tamper
import com.understory.security.TestingMode
import com.understory.security.TransientFlight
import com.understory.security.ui.Bg
import com.understory.security.ui.components.EmptyState
import com.understory.security.ui.components.ErrorState
import com.understory.security.ui.components.FatalScreen
import com.understory.security.ui.components.LoadingState
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteSectionHeader
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
                    AntivirusApp()
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
                        title = getString(R.string.av_crash_title),
                        reason = getString(R.string.av_crash_reason),
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

/** Top-level destinations shown in the NavigationBar. */
private enum class Dest(
    val labelRes: Int,
    val cdRes: Int,
    val icon: ImageVector,
) {
    Scan(R.string.av_nav_scan, R.string.cd_nav_scan, Icons.Filled.Shield),
    Apps(R.string.av_nav_apps, R.string.cd_nav_apps, Icons.Filled.Apps),
    Definitions(R.string.av_nav_defs, R.string.cd_nav_defs, Icons.Filled.FolderOpen),
}

/**
 * The shipping app shell. A Material3 [Scaffold] with a per-destination
 * [TopAppBar], a bottom [NavigationBar] over three top-level sections, and a
 * scan [FloatingActionButton] on the Scan tab.
 *
 * Diagnostics is an ENGINEERING-BUILD-ONLY affordance: the top-bar bug-report
 * action and the DiagnosticsScreen route only exist when
 * `BuildConfig.FLAVOR == "eng"`. The shipped prod app exposes no diagnostics
 * entry point and no diagnostics dump.
 *
 * The dev-looking SuiteStatusFooter (tier/peer/caps smoke-test strip) is
 * deliberately NOT part of this chrome: this shell owns its own bottom bar (the
 * NavigationBar) and never composes SuiteStatusFooter, so it appears on no
 * screen in any build. The shipping face carries only user-facing security
 * content.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AntivirusApp() {
    var destName by rememberSaveable { mutableStateOf(Dest.Scan.name) }
    val dest = remember(destName) { Dest.valueOf(destName) }
    // Eng-only: whether the diagnostics sub-screen is currently shown.
    var showDiagnostics by rememberSaveable { mutableStateOf(false) }
    val isEng = BuildConfig.FLAVOR == "eng"

    // Keep this composable alive on back at the top level; children override.
    KeepAliveBackHandler("antivirus.App")

    if (isEng && showDiagnostics) {
        BackHandler { showDiagnostics = false }
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background,
        ) {
            DiagnosticsScreen(onBack = { showDiagnostics = false })
        }
        return
    }

    val titleRes = when (dest) {
        Dest.Scan -> R.string.app_name
        Dest.Apps -> R.string.av_apps_title
        Dest.Definitions -> R.string.av_defs_title
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(titleRes), style = MaterialTheme.typography.titleLarge) },
                actions = {
                    // Diagnostics affordance — ENG BUILDS ONLY. In prod this
                    // block is compiled but the guard is false, so no
                    // diagnostics icon is ever shown.
                    if (isEng) {
                        IconButton(onClick = { showDiagnostics = true }) {
                            Icon(
                                imageVector = Icons.Filled.BugReport,
                                contentDescription = stringResource(R.string.cd_diagnostics),
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                    actionIconContentColor = MaterialTheme.colorScheme.onSurface,
                ),
            )
        },
        bottomBar = {
            NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                for (d in Dest.entries) {
                    val selected = d == dest
                    NavigationBarItem(
                        selected = selected,
                        onClick = {
                            if (d != dest) {
                                Diagnostics.log("antivirus.App", "nav ${dest.name} → ${d.name}")
                                destName = d.name
                            }
                        },
                        icon = {
                            Icon(
                                imageVector = d.icon,
                                contentDescription = stringResource(d.cdRes),
                            )
                        },
                        label = { Text(stringResource(d.labelRes)) },
                    )
                }
            }
        },
    ) { pad ->
        when (dest) {
            Dest.Scan -> ScanSection(pad)
            Dest.Apps -> AppsSection(pad)
            Dest.Definitions -> DefinitionsSection(pad)
        }
    }
}

/**
 * Holds scan/audit results across configuration change. Process death is
 * mitigated by re-derivable state (results are recomputed by re-running).
 */
class ScanViewModel : ViewModel() {
    var scanReport by mutableStateOf<ApkAnalyzer.Report?>(null)
    var scanError by mutableStateOf<String?>(null)
    var scanning by mutableStateOf(false)
    var auditReports by mutableStateOf<List<ApkAnalyzer.Report>?>(null)
    var auditSummary by mutableStateOf<ApkAnalyzer.AuditSummary?>(null)
    var auditError by mutableStateOf<String?>(null)
    var auditSelected by mutableStateOf<ApkAnalyzer.Report?>(null)
    var auditWorking by mutableStateOf(false)
    var auditProgress by mutableStateOf(0 to 0)
}

// ------------------------------------------------------------------
// Scan (home) — the scanner face.
// ------------------------------------------------------------------

@Composable
private fun ScanSection(pad: PaddingValues) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val vm: ScanViewModel = viewModel()

    val playProtect = remember { PlayProtectStatus.check(ctx) }
    var tamperInfo by remember { mutableStateOf<TamperFindings.TamperInfo?>(null) }
    var freshInstall by remember { mutableStateOf<ApkAnalyzer.Report?>(null) }
    OnNewInstall { report -> freshInstall = report }

    LaunchedEffect(Unit) {
        val report = withContext(Bg.io) { Tamper.check(ctx.applicationContext) }
        tamperInfo = withContext(Bg.io) { TamperFindings.build(ctx, report) }
    }

    val pickApk = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        TransientFlight.end()
        Diagnostics.log("antivirus.Scan", "pickApk result: uri=${if (uri != null) "non-null" else "null"}")
        if (uri == null) return@rememberLauncherForActivityResult
        vm.scanning = true
        scope.launch {
            val result = withContext(Bg.io) { runCatching { ApkAnalyzer.analyzeUri(ctx, uri) } }
            result
                .onSuccess { vm.scanReport = it; vm.scanError = null }
                .onFailure {
                    Diagnostics.error("antivirus.Scan", "scan failed: ${it.javaClass.simpleName}: ${it.message}")
                    vm.scanError = "Scan failed: ${it.message ?: it.javaClass.simpleName}"
                }
            vm.scanning = false
        }
    }

    val launchPicker: () -> Unit = {
        if (!vm.scanning) {
            Diagnostics.log("antivirus.Scan", "Pick APK file: tap")
            TransientFlight.begin()
            runCatching { pickApk.launch(arrayOf("*/*")) }
                .onFailure {
                    TransientFlight.end()
                    vm.scanError = "Couldn't open file picker: ${it.message}"
                }
        }
    }

    Scaffold(
        modifier = Modifier.padding(pad),
        containerColor = MaterialTheme.colorScheme.background,
        floatingActionButton = {
            if (!vm.scanning) {
                FloatingActionButton(onClick = launchPicker) {
                    Icon(
                        imageVector = Icons.Filled.FolderOpen,
                        contentDescription = stringResource(R.string.cd_scan_apk_fab),
                    )
                }
            }
        },
    ) { inner ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(inner)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            PositioningBanner()

            // Scan hero: the prominent scan action + progress while scanning.
            ScanHeroCard(
                scanning = vm.scanning,
                onScan = launchPicker,
            )

            freshInstall?.let { FreshInstallCard(it) }

            // Scan result (findings ranked CRITICAL-first).
            vm.scanError?.let { err ->
                InlineErrorCard(message = err, onRetry = launchPicker)
            }
            vm.scanReport?.let { report ->
                SuiteSectionHeader(stringResource(R.string.av_section_result))
                ReportHeaderCard(report)
                if (report.findings.isEmpty()) {
                    SuiteCard {
                        Text(
                            stringResource(R.string.av_no_findings),
                            style = MaterialTheme.typography.bodyMedium,
                            color = UnderstoryTheme.semantic.success,
                        )
                    }
                } else {
                    SuiteSectionHeader(stringResource(R.string.av_section_findings))
                    report.findings.forEach { FindingCard(it) }
                }
            }

            // Device posture: Play Protect + tamper/root tooling.
            SuiteSectionHeader(stringResource(R.string.av_section_posture))
            PlayProtectCard(playProtect)
            tamperInfo?.let { TamperCard(it) }

            SuiteCard {
                Text(
                    stringResource(R.string.av_home_catches),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            // Bottom breathing room so the FAB never covers the last card.
            Spacer(Modifier.height(UnderstoryTheme.spacing.xxl))
        }
    }
}

/**
 * The prominent scan call-to-action. Shows a determinate-feeling progress bar
 * with a label while a scan is in flight, and a big primary button otherwise.
 * (The isolated parse has no byte-progress signal, so the in-flight bar is the
 * indeterminate [LinearProgressIndicator] with an honest "inspecting" label.)
 */
@Composable
private fun ScanHeroCard(scanning: Boolean, onScan: () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.primaryContainer,
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            Text(
                stringResource(R.string.av_scan_hero_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                stringResource(R.string.av_scan_hero_body),
                style = MaterialTheme.typography.bodyMedium,
            )
            if (scanning) {
                Text(
                    stringResource(R.string.av_scan_progress_indeterminate),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            } else {
                SecureButton(onClick = onScan, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.av_scan_hero_action))
                }
            }
        }
    }
}

/** Fresh-install banner (§5.1 freshness-while-open) as a token-native card. */
@Composable
private fun FreshInstallCard(report: ApkAnalyzer.Report) {
    SuiteCard {
        Text(
            stringResource(R.string.av_fresh_install, report.packageName, report.verdict.name),
            style = MaterialTheme.typography.bodyMedium,
            color = verdictAccent(report.verdict),
        )
        report.findings.firstOrNull()?.let { f ->
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                f.title,
                style = MaterialTheme.typography.bodyMedium,
                color = severityAccent(f.severity),
            )
        }
    }
}

// ------------------------------------------------------------------
// Apps — audit installed apps.
// ------------------------------------------------------------------

@Composable
private fun AppsSection(pad: PaddingValues) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val vm: ScanViewModel = viewModel()

    val runAudit: () -> Unit = {
        if (!vm.auditWorking) {
            vm.auditWorking = true
            vm.auditSelected = null
            scope.launch {
                val result = withContext(Bg.io) {
                    runCatching {
                        ApkAnalyzer.auditInstalledWithSummary(ctx) { done, total ->
                            vm.auditProgress = done to total
                        }
                    }
                }
                result
                    .onSuccess {
                        vm.auditReports = it.flagged
                        vm.auditSummary = it.summary
                        vm.auditError = null
                    }
                    .onFailure { vm.auditError = "Audit failed: ${it.message ?: it.javaClass.simpleName}" }
                vm.auditWorking = false
            }
        }
    }

    val selected = vm.auditSelected
    if (selected != null) {
        BackHandler { vm.auditSelected = null }
        AuditDetail(
            report = selected,
            modifier = Modifier.padding(pad),
            onBack = { vm.auditSelected = null },
        )
        return
    }

    val reports = vm.auditReports
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(pad)
            .padding(horizontal = UnderstoryTheme.spacing.lg),
    ) {
        when {
            vm.auditWorking -> {
                val (done, total) = vm.auditProgress
                Column(Modifier.fillMaxSize()) {
                    LoadingState(
                        label = if (total > 0) stringResource(R.string.av_auditing_progress, done, total)
                        else stringResource(R.string.av_scanning),
                        modifier = Modifier.weight(1f),
                    )
                    if (total > 0) {
                        LinearProgressIndicator(
                            progress = { done.toFloat() / total },
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(bottom = UnderstoryTheme.spacing.lg),
                        )
                    }
                }
            }
            vm.auditError != null -> {
                Column(Modifier.fillMaxSize()) {
                    ErrorState(
                        message = vm.auditError!!,
                        onRetry = runAudit,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
            reports == null -> {
                Column(Modifier.fillMaxSize()) {
                    EmptyState(
                        title = stringResource(R.string.av_audit_title),
                        body = stringResource(R.string.av_audit_intro),
                        icon = Icons.Filled.Apps,
                        modifier = Modifier.weight(1f),
                        action = {
                            SecureButton(onClick = runAudit, modifier = Modifier.fillMaxWidth()) {
                                Text(stringResource(R.string.av_audit_run))
                            }
                        },
                    )
                }
            }
            reports.isEmpty() -> {
                Column(Modifier.fillMaxSize()) {
                    EmptyState(
                        title = stringResource(R.string.av_audit_clean_title),
                        body = stringResource(R.string.av_audit_clean_body),
                        icon = Icons.Filled.Shield,
                        modifier = Modifier.weight(1f),
                        action = {
                            SecureButton(onClick = runAudit, modifier = Modifier.fillMaxWidth()) {
                                Text(stringResource(R.string.av_audit_rerun))
                            }
                        },
                    )
                }
            }
            else -> {
                vm.auditSummary?.let { summary ->
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    AuditSummaryCard(summary)
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                }
                SuiteSectionHeader(stringResource(R.string.av_audit_flagged_count, reports.size))
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
                    modifier = Modifier.fillMaxWidth().weight(1f),
                ) {
                    items(reports, key = { it.packageName }) { r ->
                        AuditRowCard(r, onClick = { vm.auditSelected = r })
                    }
                }
                SecureButton(
                    onClick = runAudit,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = UnderstoryTheme.spacing.md),
                ) {
                    Text(stringResource(R.string.av_audit_rerun))
                }
            }
        }
    }
}

/** Detail view for one flagged installed app: header + ranked finding cards. */
@Composable
private fun AuditDetail(
    report: ApkAnalyzer.Report,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = UnderstoryTheme.spacing.lg),
        verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
    ) {
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        ReportHeaderCard(report)
        report.installSource?.let { InstallSourceCard(it) }
        if (report.findings.isEmpty()) {
            SuiteCard {
                Text(
                    stringResource(R.string.av_no_findings),
                    style = MaterialTheme.typography.bodyMedium,
                    color = UnderstoryTheme.semantic.success,
                )
            }
        } else {
            SuiteSectionHeader(stringResource(R.string.av_section_findings))
            report.findings.forEach { FindingCard(it) }
        }
        if (report.permissions.isNotEmpty()) {
            SuiteSectionHeader(stringResource(R.string.av_section_permissions))
            PermissionGroupsCard(report.permissions)
        }
        // Ground-truth enrichment (READ-ONLY): when the user granted elevation,
        // upgrade the static "requests" view above with what the app ACTUALLY has
        // (granted runtime perms, live appops, install provenance). Installed apps
        // only — a SAF-scanned raw APK isn't installed, so there's nothing to read.
        // Fails OPEN: renders nothing on no-elevation / read-null / parse-miss.
        if (report.installSource != null && report.packageName.contains('.')) {
            VerifiedFactsSection(report)
        }
        // "Take action" deep-links — installed apps only (a SAF-scanned raw APK
        // isn't installed, so there's no App-Info screen to open).
        if (report.installSource != null && report.packageName.contains('.')) {
            SuiteSectionHeader(stringResource(R.string.av_section_actions))
            AppActionsCard(report)
        }
        SecureButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.av_audit_back_to_list))
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
    }
}

// ------------------------------------------------------------------
// Definitions — deny-list status, import, periodic scanning.
// ------------------------------------------------------------------

@Composable
private fun DefinitionsSection(pad: PaddingValues) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    var defsMeta by remember { mutableStateOf<BlocklistStore.Meta?>(null) }
    var importResult by remember { mutableStateOf<String?>(null) }
    var importIsError by remember { mutableStateOf(false) }
    var pendingOlderUri by remember { mutableStateOf<Uri?>(null) }
    var periodicOn by remember { mutableStateOf(PeriodicScan.isEnabled(ctx)) }
    var alertsGranted by remember { mutableStateOf(PeriodicScan.alertsAllowed(ctx)) }
    var installAlertsOn by remember { mutableStateOf(PeriodicScan.installAlertsEnabled(ctx)) }

    LaunchedEffect(Unit) {
        withContext(Bg.io) { BlocklistStore.ensureLoaded(ctx) }
        defsMeta = BlocklistStore.meta()
    }

    val requestNotif = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        alertsGranted = granted
        PeriodicScan.setEnabled(ctx, true)
        periodicOn = true
    }

    val requestInstallNotif = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        alertsGranted = granted
        // Enable the opt-in regardless — the in-app banner still works if the
        // user declines the notification permission; only the out-of-app alert
        // needs it. Honest degradation, no dead control.
        PeriodicScan.setInstallAlertsEnabled(ctx, true)
        installAlertsOn = true
    }

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
        modifier = Modifier
            .fillMaxSize()
            .padding(pad)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = UnderstoryTheme.spacing.lg),
        verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
    ) {
        SuiteSectionHeader(stringResource(R.string.av_section_defs))
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

        SuiteSectionHeader(stringResource(R.string.av_section_scanning))
        PeriodicScanToggle(
            enabled = periodicOn,
            alertsGranted = alertsGranted,
            onToggle = { on ->
                if (on) {
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
        InstallAlertToggle(
            enabled = installAlertsOn,
            alertsGranted = alertsGranted,
            onToggle = { on ->
                if (on) {
                    if (PeriodicScan.alertsAllowed(ctx)) {
                        PeriodicScan.setInstallAlertsEnabled(ctx, true)
                        installAlertsOn = true; alertsGranted = true
                    } else {
                        requestInstallNotif.launch(Manifest.permission.POST_NOTIFICATIONS)
                    }
                } else {
                    PeriodicScan.setInstallAlertsEnabled(ctx, false); installAlertsOn = false
                }
            },
        )

        // Optional-elevation opt-in (Shizuku / Dhizuku). Rootless by default; this
        // only lets the user unlock in-app remediation on flagged apps. Honest
        // grant flow lives in the shared ElevationCard.
        AntivirusElevationSection()

        SuiteSectionHeader(stringResource(R.string.av_section_about))
        SuiteCard {
            Text(
                stringResource(R.string.av_home_catches),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.lg))
    }
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
                    if (report != null) {
                        onResult(report)
                        // §5.1 on-install surfacing: opt-in notification when a
                        // freshly installed/updated app scores High/Critical.
                        // The in-app banner (onResult) always shows; this only
                        // adds the out-of-app alert the user opted into.
                        val notable = report.risk.rating == RiskRules.Rating.HIGH ||
                            report.risk.rating == RiskRules.Rating.CRITICAL
                        if (notable && PeriodicScan.installAlertsEnabled(ctx)) {
                            withContext(Bg.io) {
                                runCatching { ScanNotifier.postInstallAlert(ctx, report) }
                            }
                        }
                    }
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
