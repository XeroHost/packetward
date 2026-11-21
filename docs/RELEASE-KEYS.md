# PacketWard — Release keys

Two keys are needed before the first public release. Every feature that depends on a key fails *closed* (disabled)
until the key exists.

* **Updater key — generated on 2026-11-21 (decision changed by the owner, see DECISIONS "Updater key").** It was
  generated on the development VPS under strict rules, its public half is committed, its private half and password
  are repository secrets, and the VPS copy is **deleted after the owner has backed it up** (section 1.4).
* **Blocklist minisign key — still to do, on the owner's own PC** (section 2): the XeroHost blocklist stays
  disabled until its public key is pinned.

| Key | Used for | Public part lives in | Private part lives in |
|---|---|---|---|
| Tauri updater key | Signing update artifacts (`latest.json` + installers) so installed apps trust updates | `apps/desktop/src-tauri/tauri.conf.json` → `plugins.updater.pubkey` | GitHub Actions secret `TAURI_SIGNING_PRIVATE_KEY` (+ `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`) |
| Blocklist minisign key | Signing the shared XeroHost blocklist (`blocklist.txt.minisig`) | Pinned in the app: `crates/pw-intel/src/blocklist/pinned_key.rs` (`PINNED_PUBLIC_KEY`) | A secret of the repo `XeroHost/packetward-blocklist` |

> **If you lose the updater private key you can never ship another update to installed apps** (they only accept
> artifacts signed by it). Back it up before using it (step 3).

## 1. Tauri updater key

Public key id: `86363F430AEB7F72` (the first line of the decoded public key says so; it is not a secret).

### 1.1 What was done (2026-11-21)

1. A random 40-letter/digit password (about 238 bits) and the key were created in `%USERPROFILE%\.tauri\`:
   `packetward.key` (private), `packetward.key.pub`, `packetward.key.password.txt`. The Tauri CLI was started directly
   (`node apps\desktop\node_modules\@tauri-apps\cli\tauri.js signer generate -w … -p …`) with its output discarded.
   **Why not `pnpm tauri …`:** pnpm echoes the whole command line, password included, into its error output. That happened
   once, in the first attempt: that password was thrown away and **a new password and key were generated before anything
   used them**. Never pass a password to pnpm.
2. The files were restricted to the owner account and SYSTEM (`icacls /inheritance:r`).
3. Both secrets were loaded with `gh` from the files by redirection (nothing printed, no value on a command line):
   `cmd /c "gh secret set TAURI_SIGNING_PRIVATE_KEY --repo XeroHost/packetward < packetward.key"` and the same for
   `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` with the password file (written without a trailing newline).
   `gh secret list` shows both names.
4. The public key (the whole `.pub` file, base64) is in `apps/desktop/src-tauri/tauri.conf.json` → `plugins.updater.pubkey`.
   `bundle.createUpdaterArtifacts` is `true` in `tauri.release.conf.json` (the release workflow stamps it `true` only when the
   secret and a real public key exist).

### 1.2 How the signature is checked

* `.github/scripts/verify-sig.mjs` verifies a `.sig` against the public key of `tauri.conf.json` (minisign, algorithm "ED":
  BLAKE2b-512 of the file, plus the trusted-comment signature), the same checks the installed app makes. The release
  workflow runs it on every build **before anything is published**. Its tests use throwaway fixtures (only public halves).
* A local signed build was made and verified with the real public key (section 1.5).

### 1.3 Channels

| Channel | Endpoint the app reads | What puts a file there |
|---|---|---|
| stable | `https://github.com/XeroHost/packetward/releases/latest/download/latest.json` | the workflow, **only for a normal release** (tag `vX.Y.Z`); GitHub's "latest" ignores pre-releases |
| beta | `https://github.com/XeroHost/packetward/releases/download/updater-beta/latest.json` | the workflow, for every beta **and** every stable release (so beta users also get a stable that supersedes their beta) |

A beta can never reach somebody on stable, on four independent layers: a pre-release release never carries a `latest.json`
for the stable endpoint; `release.mjs manifest` refuses a stable manifest with a pre-release version (`assertChannel`);
the app's stable channel ignores any offered version that contains `-` (`UpdateChannel::accepts`); and semver ranks
`0.1.0-beta.1` below `0.1.0`, so nobody on a newer version is offered an older beta. The app checks at start and every 24 hours
(Settings switch, on by default) and **never installs without the user pressing the button**.

> The endpoints are on github.com: the repository must be **public** before an installed app can read them (a private repo
> answers 404 to anonymous requests).

### 1.4 Hand-over and deletion of the VPS copy

1. Copy `packetward.key` and `packetward.key.password.txt` from `%USERPROFILE%\.tauri\` of the VPS to your PC and store them in
   your password manager (**two separate entries**: the key, and its password). `packetward.key.pub` is public.
2. Tell the assistant you have them. Only then the VPS files are deleted (overwritten, then removed) and the deletion verified.
3. If you lose both the key and the password you can **never ship another update to installed apps**; if the key leaks,
   generate a new one, ship an app version with the new public key by hand (a normal installer), and replace the secrets.

### 1.5 Generate a new key (rotation), safely

```powershell
# From a checkout, in PowerShell. The password is generated, stored in a file and never shown.
$dir = "$HOME\.tauri"; New-Item -ItemType Directory -Force $dir | Out-Null
$rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $pw = ''
while ($pw.Length -lt 40) { $b = New-Object byte[] 64; $rng.GetBytes($b); $pw += ([Convert]::ToBase64String($b) -replace '[^A-Za-z0-9]', '') }
$pw = $pw.Substring(0, 40); [IO.File]::WriteAllText("$dir\packetward.key.password.txt", $pw, [Text.Encoding]::ASCII)
node apps\desktop\node_modules\@tauri-apps\cli\tauri.js signer generate -w "$dir\packetward.key" -p $pw *> $null; $pw = $null
cmd /c "gh secret set TAURI_SIGNING_PRIVATE_KEY --repo XeroHost/packetward < $dir\packetward.key"
cmd /c "gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD --repo XeroHost/packetward < $dir\packetward.key.password.txt"
```

Then put the content of `packetward.key.pub` in `tauri.conf.json` and back both files up.

### 1.6 Testing a release without publishing

Push a branch named `release-dryrun/<anything>`: the release workflow builds the installer, signs it with the secrets, verifies the
signature and writes `latest.json`, then keeps the files **for one day as a workflow artifact** (`release-dry-run`) and publishes
nothing (no release, no tag). Only a pushed `vX.Y.Z` / `vX.Y.Z-beta.N` tag publishes.

The release workflow (`.github/workflows/release.yml`, M12) reads the two secrets. Without them it builds **unsigned** artifacts and skips
publishing `latest.json`, so no update channel is advertised by accident.

## 2. Blocklist minisign key (on your own PC)

Install [minisign](https://jedisct1.github.io/minisign/) (`scoop install minisign` or the release binary).

```powershell
minisign -G -p "$HOME\.minisign\packetward-blocklist.pub" -s "$HOME\.minisign\packetward-blocklist.key"
```

1. Public key: copy the second line of `packetward-blocklist.pub` (starts with `RW`) into
   `crates/pw-intel/src/blocklist/pinned_key.rs`, constant `PINNED_PUBLIC_KEY` (currently `None`, which keeps the
   XeroHost list **disabled**). Commit it to this repository; it is public by design.
2. Private key: store it as a secret of the **blocklist repo** (the repo that publishes the list), used by its
   workflow to sign each new `blocklist.txt`:

```powershell
gh secret set MINISIGN_SECRET_KEY --repo XeroHost/packetward-blocklist < "$HOME\.minisign\packetward-blocklist.key"
```

3. Back it up like the updater key. Signing locally by hand works too:

```powershell
minisign -Sm blocklist.txt -s "$HOME\.minisign\packetward-blocklist.key"   # writes blocklist.txt.minisig
```

The app downloads `blocklist.txt` + `blocklist.txt.minisig` from the raw GitHub URL and **rejects the list unless the
signature verifies against the pinned key**. Rotating the key requires shipping a new app version with the new
pinned key.

## 3. The blocklist repository (`XeroHost/packetward-blocklist`)

Public repo, created by you. It holds:

- `blocklist.txt` — one IP or CIDR per line, `#` comments allowed;
- `blocklist.txt.minisig` — its signature (step 2);
- `nodes.json` — the XeroHost node list used by the speed test and MTR defaults. Format:

```json
{
  "version": 1,
  "nodes": [
    { "id": "mia", "name": "Miami",     "host": "REPLACE-WITH-REAL-HOSTNAME", "port": 443 },
    { "id": "dal", "name": "Dallas",    "host": "REPLACE-WITH-REAL-HOSTNAME", "port": 443 },
    { "id": "sao", "name": "São Paulo", "host": "REPLACE-WITH-REAL-HOSTNAME", "port": 443 }
  ]
}
```

Replace the hostnames when the nodes exist (Ashburn can be added later). The app ships with an **empty** node list
and with the raw URL of this file as a placeholder constant (`NODES_URL` in `crates/pw-diag`'s consumer, see
ARCHITECTURE §6.6); an empty or unreachable list simply means "custom servers only".

## 4. Optional: Authenticode signing

Releases start unsigned (documented SmartScreen prompt). When you have a certificate, add the secrets
`WINDOWS_CERTIFICATE` (base64 `.pfx`) and `WINDOWS_CERTIFICATE_PASSWORD`; the release workflow's signing step runs
only when they exist.

## 5. Checklist before tagging `v1.0.0`

- [x] Updater key generated (2026-11-21), public key in `tauri.conf.json`, secrets loaded. [ ] Key and password backed up by the owner and the VPS copy deleted (section 1.4).
- [ ] Blocklist key generated, pinned in `pinned_key.rs`, secret loaded in the blocklist repo, backed up.
- [ ] `nodes.json` has the real hostnames; the speed-server is deployed on those nodes.
- [ ] `SECURITY.md` has the real security contact (GitHub private vulnerability reporting is enabled in the meantime).
- [ ] The repository is public, a beta tag (`v0.1.0-beta.1`) was published and the updater was tested from the previous beta.
