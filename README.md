# understory-antivirus

**Understory APK Check** — a local-first, on-demand APK auditor that complements Google Play Protect (it does not replace it). It inspects sideloaded APKs and reviews what your installed apps *can* do: a signed offline deny-list (Lucky-Patcher-family and known repackager signing certs, extensible via a signed import file), permission-shape heuristics, hidden-launcher detection, and enumeration of declared and currently-enabled accessibility / device-admin / notification-listener abusers. Userspace-honest: structural, not behavioral — no real-time process/memory scanning (rootless-impossible). Findings are advisory, not verdicts.

On top of the base auditor sit four opt-in check layers (all default off):

- **Multiple virus databases** — import third-party SHA-256 hash feeds (MalwareBazaar dumps, `hash,label` CSV, ClamAV-style `hash:size:name`) as separate named databases alongside the signed deny-list. Every scan checks all of them; a hit always names its source database. Imports are unsigned — trust the feed you import.
- **Passive Snort-format signature rules** — a Snort-rule-subset engine (`content`/`nocase`/hex/`pcre`/`classtype`/`sid`) applied *passively* to installed APK bytes, with a built-in Android-malware seed ruleset and `.rules` import. Honest scope: this is a content-signature scanner speaking the Snort format, **not** a network IDS — a rootless app cannot capture packets and this one never claims to.
- **VirusTotal lookups** — hash-only lookups (`GET /files/{sha256}`, never an upload) against the user's own free API key. This is the app's sole network feature and the reason `INTERNET` is now declared: the network path is dead code until a key is pasted and the toggle flipped; results are cached on-device.
- **Independent periodic checks** — each layer has its own WorkManager schedule and toggle: the original ~6h new/changed-app diff, a daily full-device audit (so newly imported definitions retroactively catch existing apps), a 12h incremental Snort pass, and a daily rate-limit-respecting VirusTotal pass over sideloaded apps.

Status: **alpha** (functional; working the release-blockers list in understory-common).

## Build

Requires JDK 17+ and the Android SDK with platform 35 + build-tools 35.0.0.

```bash
# Copy local.properties.example to local.properties, set sdk.dir
gradle :antivirus:assembleDebug
# APK: antivirus/build/outputs/apk/debug/antivirus-debug.apk
```

CI (GitHub Actions) builds the debug APK + runs unit tests on every push; the APK is attached as a workflow artifact. Debug builds are signed with the committed suite debug keystore so the signing-cert digest matches the suite pin (Tamper.EXPECTED_CERT_SHA256) — installs update-in-place over other suite-pin builds.

## Provenance & suite

Split 2026-07-02 from `Zheke32174/underward` `android/` (commit `f867493`) into per-app repos — one repo per suite app.

Part of the **Understory Suite** — rootless, in-bounds, local-first Android security apps (design constraints: no root, no Shizuku, public APIs only, zero network unless explicitly opted in).

Shared modules vendored here for a self-contained build: `common-security/` (+ `common-backup/`, `overlay-*/` where used) and `keystore/` (pinned suite debug keystore — cert digest is the Tamper/SuiteAttestation pin). **Do not edit shared modules in this repo.** Their canonical home is [`understory-common`](https://github.com/Zheke32174/understory-common); propagate changes with its `tools/sync-common.sh`.

Suite-level docs (SUITE_DESIGN, SUITE_ROADMAP, RELEASE_BLOCKERS, SAMSUNG_QUIRKS, BlackArch defense matrix + runbooks) live in `understory-common`.

## Verify your install

Before trusting the app, confirm the APK you are about to install (or did install) is signed by the suite key. With Android build-tools on any machine:

```bash
apksigner verify --print-certs the-downloaded.apk | grep -i 'SHA-256'
```

The signer certificate SHA-256 digest must be exactly one of the two suite pins (single source of truth: `common-security/.../SuitePins.kt`):

- **Debug** builds (CI artifacts; committed suite debug keystore): `aba68a81a0d63b5549794e586875a4f04e6dba3a6fe25d363e04eb75f46df69e`
- **Release** builds (offline release keystore): `59a3dee7feb8262170e4dcabb3dbe7bc323abe8715ab49f5bed5133046a45c4a`

Any other digest means the APK was not signed by the suite keys — do not install it. The apps also enforce these pins at runtime (Tamper self-check + SuiteAttestation cross-check of installed siblings), but verifying before install is the stronger position. Signing doctrine: `docs/SIGNING.md` in understory-common.
