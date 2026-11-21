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
| Tauri updater key | Signing the installer of each release (the signature goes inside `stable.json` / `beta.json`) so installed apps trust updates | `apps/desktop/src-tauri/tauri.conf.json` → `plugins.updater.pubkey` | GitHub Actions secret `TAURI_SIGNING_PRIVATE_KEY` (+ `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`) |
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
| stable | `https://raw.githubusercontent.com/XeroHost/packetward/updates/stable.json` | the release workflow, **only after a stable release** (tag `vX.Y.Z`) is published |
| beta | `https://raw.githubusercontent.com/XeroHost/packetward/updates/beta.json` | the release workflow after every beta **and** every stable release is published (so beta users also get a stable that supersedes their beta) |

Both files are in the orphan `updates` branch (no code in it) and contain the updater signature of that release. **A release has no `.sig` or
checksum asset: only the installer.** A file is never moved to an older version, and nothing is written unless the release was published.
raw.githubusercontent.com caches for about 5 minutes.

A beta can never reach somebody on stable, on four independent layers: a beta release only ever writes `beta.json`;
`release.mjs` refuses a stable manifest with a pre-release version (`assertChannel`, `checkDraft`);
the app's stable channel ignores any offered version that contains `-` (`UpdateChannel::accepts`); and semver ranks
`0.1.0-beta.1` below `0.1.0`, so nobody on a newer version is offered an older beta. The app checks at start and every 24 hours
(Settings switch, on by default) and **never installs without the user pressing the button**.

> The endpoints are on raw.githubusercontent.com: the repository must be **public** (it is, since 2026-11-21) or they answer 404.

### 1.4 Hand-over and deletion of the VPS copy (done 2026-11-21)

The owner confirmed the backup; the VPS copies were then overwritten with random bytes twice and removed, and their absence verified:
`packetward.key`, `packetward.key.password.txt` and a `packetward.zip` the owner had made to download them. Only `packetward.key.pub` (public)
remains. The private key now exists in the owner's password manager and as the GitHub secret `TAURI_SIGNING_PRIVATE_KEY` (write-only).
Further edits of the secrets must be done with `gh secret set`, not by hand in the web page (a manual save on 2026-11-21 replaced the values
and they had to be uploaded again). The original steps follow, kept for a future rotation.

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

### 1.6 How a release is published (and why it cannot go out half-done)

Push a tag `vX.Y.Z` (stable) or `vX.Y.Z-beta.N` (beta) **on a commit that is on `main`**. Nothing else starts a release (a branch push never does).
`guard` → `ci` (all checks, Windows included) → `build` (signs, writes a **draft** with only the installer) → `publish` (re-checks the draft
against the build's private proof: hash, updater JSON and the updater signature against the public key; publishes; and only then commits the channel
files to the `updates` branch). If any check fails, the release stops there: before `build` nothing exists, after it
only a draft that no client can see (delete it with `gh release delete <tag>`; re-running the workflow reuses it). Never create or edit the release by hand.

There is no "dry-run" branch any more: a failing check stops the run, and the only thing a passing run leaves before the last job is a draft.
To test the gates without publishing, push a test tag from a throwaway branch with the repository variable `RELEASE_BRANCH` set to that branch
and a deliberately broken test (or leave the variable unset to see the guard refuse a tag that is not on `main`).

The release workflow (`.github/workflows/release.yml`, M12) reads the two secrets. Without them it builds an **unsigned** installer and does not
touch the channel files, so no update is advertised by accident.

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

- [x] Updater key generated (2026-11-21), public key in `tauri.conf.json`, secrets loaded, key and password backed up by the owner, VPS copy deleted (section 1.4).
- [ ] Blocklist key generated, pinned in `pinned_key.rs`, secret loaded in the blocklist repo, backed up.
- [ ] `nodes.json` has the real hostnames; the speed-server is deployed on those nodes.
- [ ] `SECURITY.md` has the real security contact (GitHub private vulnerability reporting is enabled in the meantime).
- [ ] The repository is public, a beta tag (`v0.1.0-beta.1`) was published and the updater was tested from the previous beta.
