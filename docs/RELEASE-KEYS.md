# PacketWard — Release keys (do this on **your own PC**, never on the VPS)

Two keys are needed before the first public release. **No key is generated or stored on the development VPS**:
the repository only contains placeholders, and every feature that depends on a key fails *closed* (disabled)
until the key exists.

| Key | Used for | Public part lives in | Private part lives in |
|---|---|---|---|
| Tauri updater key | Signing update artifacts (`latest.json` + installers) so installed apps trust updates | `apps/desktop/src-tauri/tauri.conf.json` → `plugins.updater.pubkey` | GitHub Actions secret `TAURI_SIGNING_PRIVATE_KEY` (+ `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`) |
| Blocklist minisign key | Signing the shared XeroHost blocklist (`blocklist.txt.minisig`) | Pinned in the app: `crates/pw-intel/src/blocklist/pinned_key.rs` (`PINNED_PUBLIC_KEY`) | A secret of the repo `XeroHost/packetward-blocklist` |

> **If you lose the updater private key you can never ship another update to installed apps** (they only accept
> artifacts signed by it). Back it up before using it (step 3).

## 1. Tauri updater key (on your PC)

Requires Node + pnpm and a checkout of this repository.

```powershell
cd apps\desktop
pnpm install
# Choose a strong password when asked. The file is the PRIVATE key: keep it out of the repo.
pnpm tauri signer generate -w "$HOME\.tauri\packetward-updater.key"
```

This writes `packetward-updater.key` (private) and `packetward-updater.key.pub` (public).

1. Put the **public** key (the whole content of the `.pub` file, one line) in
   `apps/desktop/src-tauri/tauri.conf.json` replacing the placeholder under `plugins.updater.pubkey`
   (`REPLACE_WITH_UPDATER_PUBLIC_KEY`).
2. Load the private key and its password as secrets of the repository (needs `gh` logged in with admin rights):

```powershell
gh secret set TAURI_SIGNING_PRIVATE_KEY          --repo XeroHost/packetward < "$HOME\.tauri\packetward-updater.key"
gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD --repo XeroHost/packetward
# the second command asks for the value; paste the password you chose
```

3. **Back up** `packetward-updater.key` and the password in your password manager (two separate entries) and, if you
   want, an offline copy. Never commit them, never paste them in chat.

The release workflow (`.github/workflows/release.yml`, M11) reads these two secrets. Without them it builds
**unsigned** artifacts and skips publishing `latest.json`, so no update channel is advertised by accident.

## 2. Blocklist minisign key (on your PC)

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

- [ ] Updater key generated, public key in `tauri.conf.json`, secrets loaded, key backed up.
- [ ] Blocklist key generated, pinned in `pinned_key.rs`, secret loaded in the blocklist repo, backed up.
- [ ] `nodes.json` has the real hostnames; the speed-server is deployed on those nodes.
- [ ] `SECURITY.md` has the real security contact (GitHub private vulnerability reporting is enabled in the meantime).
- [ ] A beta tag (`v1.0.0-beta.1`) was published and the updater was tested from the previous beta.
