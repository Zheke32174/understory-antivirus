# Blocklist seed provenance & signing-key custody

`res/raw/blocklist_seed.ubl` is the built-in signed deny-list loaded on first
run when no user-imported definitions file exists. This document records where
every seed entry comes from and how the seed is signed, so the honest-UI
requirement holds: **no hash the app flags ships without a documented source.**

## File format

See `BlocklistCodec.kt` for the authoritative envelope spec. Summary:

```
"UBL1" | uint32 payloadLen (BE) | canonical-JSON payload | uint16 sigLen (BE) | Ed25519 sig
```

The signature covers exactly the payload bytes. Payload JSON is canonical
(keys sorted, compact separators, UTF-8) so the signed byte range is
deterministic and re-verifiable without re-serialization.

## Signing key

- **Algorithm:** Ed25519 (RFC 8032), verified on-device via the platform
  `KeyFactory`/`Signature` "Ed25519" providers (API 33+, minSdk 33). No
  BouncyCastle, no external crypto dependency.
- **Public key (compiled in):** `BlocklistKeys.PUBLIC_KEY_HEX` — the 32-byte
  raw Ed25519 public key. It is the only half that ships in the APK. It is
  never fetched (this app has no INTERNET permission).
- **Private key:**
  - The **seed-signing** private key used to sign the committed
    `blocklist_seed.ubl` is derived deterministically in
    `tools`/generator (`gen_seed.py`) from a fixed byte string, purely so the
    committed artifact is reproducible from the repo. It signs ONLY the
    built-in seed.
  - The **ongoing definitions** private key — used to sign the `.ubl` files
    users import for updates — lives in the **operator vault**, out of every
    repo (custody per the suite's key-custody doctrine). Rotating it requires
    re-signing every distributed definitions file and bumping
    `BlocklistKeys.PUBLIC_KEY_HEX`.

To regenerate the seed after a key rotation or a content change, re-run the
generator, then paste the printed `PUBLIC_KEY_HEX` into `BlocklistKeys.kt`.

## Seed contents (serial 1)

The seed carries **cert-SHA-256 deny entries for the Lucky-Patcher family**,
the same packages `Tamper.luckyPatcherInstalled` and the manifest `<queries>`
enumerate. Cert-hash (rather than APK-hash) entries are used so repackaged
variants re-signed under the same keystore also match.

| Package | Label | Source |
|---|---|---|
| `com.chelpus.lackypatch` | Lucky Patcher (chelpus) | Tamper.kt patcher list |
| `com.dimonvideo.luckypatcher` | Lucky Patcher (dimonvideo) | Tamper.kt patcher list |
| `com.forpda.lp` | Lucky Patcher (forpda) | Tamper.kt patcher list |
| `ru.aaaaaaac.luckypatcher` | Lucky Patcher (ru.aaaaaaac) | Tamper.kt patcher list |
| `uret.jasi2169.patcher` | URET Patcher (jasi2169) | Tamper.kt patcher list |
| `zone.jasi2169.uretpatcher` | URET Patcher (jasi2169 zone) | Tamper.kt patcher list |
| `ru.luckypatchers.luckypatcherinstaller` | Lucky Patcher Installer | Tamper.kt patcher list |

### Capture status — IMPORTANT (honesty)

The digests in the committed seed are **provenance-tracked starter values**
derived deterministically from each package identity (see `gen_seed.py`), NOT
yet the real signing-cert SHA-256 of a sandbox-captured build. They exist so
the seed is a self-consistent, signature-valid, non-empty file with a stable
schema — the plumbing is exercised end to end.

**Before store release**, each entry MUST be replaced with the real captured
digest, obtained as follows and re-recorded here with its capture date:

1. Install the target build in an isolated sandbox / emulator.
2. Read `PackageManager.getPackageInfo(pkg, GET_SIGNING_CERTIFICATES)
   .signingInfo.apkContentsSigners[0]` and SHA-256 the encoded cert bytes
   (the exact bytes `ApkAnalyzer.signingCertSha256` and `Tamper` hash).
3. Record the digest, the build's version, and the capture date in this table.
4. Re-run `gen_seed.py` with the real digests and commit the new
   `blocklist_seed.ubl` + `PUBLIC_KEY_HEX`.

Additional curated repackager/stalkerware signing certs (StopStalkerware
coalition IOCs, MVT `appid` lists) are added the same way — one row per entry
with a citation — and **no entry ships without a source row here.**

## Anti-rollback

`serial` is monotonic. Import refuses a file whose `serial` ≤ the installed
serial unless the user explicitly checks "allow older definitions". The seed is
`serial = 1`.
