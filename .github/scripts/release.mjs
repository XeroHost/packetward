// SPDX-License-Identifier: GPL-3.0-or-later
// Helpers of .github/workflows/release.yml, kept in a script so they can be run and tested locally.
//
//   node .github/scripts/release.mjs prepare   validate the tag, stamp the version and the signing
//                                              options into the (uncommitted) release config
//   node .github/scripts/release.mjs manifest  write latest.json for the Tauri updater
//
// Inputs come from environment variables (see each command).
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs'

export const PUBKEY_PLACEHOLDER = 'REPLACE_WITH_UPDATER_PUBLIC_KEY'
const TAG_PATTERN = /^v(\d+\.\d+\.\d+)(-beta\.\d+)?$/

/** `v1.2.3` is stable, `v1.2.3-beta.4` is beta; anything else is not a release tag. */
export function parseTag(tag) {
  const match = TAG_PATTERN.exec(tag ?? '')
  if (!match) {
    throw new Error(
      `Tag "${tag}" is not a release tag: use vX.Y.Z (stable) or vX.Y.Z-beta.N (beta).`,
    )
  }
  return { version: tag.slice(1), base: match[1], beta: match[2] !== undefined }
}

/** `version` of [workspace.package] in the root Cargo.toml. */
export function workspaceVersion(cargoToml) {
  const section = /\[workspace\.package\][\s\S]*?(?=\n\[|$)/.exec(cargoToml)
  const match = /^version\s*=\s*"([^"]+)"/m.exec(section ? section[0] : '')
  if (!match) throw new Error('Could not find [workspace.package] version in Cargo.toml.')
  return match[1]
}

/**
 * Decides what the build does. `hasUpdaterKey` is whether the TAURI_SIGNING_PRIVATE_KEY secret
 * exists. Signed updater artifacts need the secret AND a real public key in tauri.conf.json: an app
 * built with the placeholder could not verify them.
 */
export function plan({
  tag,
  tauriConf,
  cargoVersion,
  packageVersion,
  hasUpdaterKey,
  signtool,
  thumbprint,
}) {
  const parsed = parseTag(tag)
  if (tauriConf.version !== parsed.base) {
    throw new Error(
      `Tag ${tag} does not match the app version ${tauriConf.version} in tauri.conf.json. ` +
        'Bump the version first (tauri.conf.json, package.json, Cargo.toml workspace version).',
    )
  }
  if (cargoVersion !== parsed.base) {
    throw new Error(`Tag ${tag} does not match the workspace version ${cargoVersion} in Cargo.toml.`)
  }
  if (packageVersion !== undefined && packageVersion !== parsed.base) {
    throw new Error(
      `Tag ${tag} does not match the version ${packageVersion} in apps/desktop/package.json.`,
    )
  }
  const pubkey = tauriConf.plugins?.updater?.pubkey ?? ''
  const placeholder = pubkey === '' || pubkey === PUBKEY_PLACEHOLDER
  if (hasUpdaterKey && placeholder) {
    throw new Error(
      'TAURI_SIGNING_PRIVATE_KEY exists but plugins.updater.pubkey in tauri.conf.json is still the ' +
        'placeholder. Put the public key in tauri.conf.json (docs/RELEASE-KEYS.md) before releasing.',
    )
  }
  return {
    version: parsed.version,
    prerelease: parsed.beta,
    signed: hasUpdaterKey && !placeholder,
    authenticode: Boolean(signtool && thumbprint),
    signtool,
    thumbprint,
  }
}

/** The release config with the version and the signing options of this run. */
export function stampConfig(releaseConf, p) {
  const conf = structuredClone(releaseConf)
  conf.version = p.version
  conf.bundle ??= {}
  conf.bundle.createUpdaterArtifacts = p.signed
  if (p.authenticode) {
    conf.bundle.windows ??= {}
    conf.bundle.windows.signCommand = {
      cmd: p.signtool,
      args: [
        'sign',
        '/sha1',
        p.thumbprint,
        '/fd',
        'sha256',
        '/tr',
        'http://timestamp.digicert.com',
        '/td',
        'sha256',
        '%1',
      ],
    }
  }
  return conf
}

/**
 * A stable release must carry a plain X.Y.Z version and a beta one X.Y.Z-beta.N: the stable channel
 * reads the latest.json of the newest stable release, so a pre-release version in it would reach everybody.
 */
export function assertChannel(version, prerelease) {
  const isBetaVersion = /-/.test(version ?? '')
  if (prerelease !== isBetaVersion) {
    throw new Error(
      `Version ${version} does not fit a ${prerelease ? 'pre-release' : 'stable release'}: a manifest must never put a pre-release version on the stable channel.`,
    )
  }
}

/** latest.json in the format of the Tauri updater (static manifest, one Windows target). */
export function manifest({ version, repo, tag, installerName, signature, notes, now }) {
  return {
    version,
    notes,
    pub_date: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    platforms: {
      'windows-x86_64': {
        signature: signature.trim(),
        url: `https://github.com/${repo}/releases/download/${tag}/${encodeURIComponent(installerName)}`,
      },
    },
  }
}

function setOutput(name, value) {
  const line = `${name}=${value}\n`
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, line)
  else process.stdout.write(line)
}

function main(command) {
  const env = process.env
  if (command === 'prepare') {
    const tauriConfPath = 'apps/desktop/src-tauri/tauri.conf.json'
    const releasePath = 'apps/desktop/src-tauri/tauri.release.conf.json'
    const packagePath = 'apps/desktop/package.json'
    const pkg = JSON.parse(readFileSync(packagePath, 'utf8'))
    const p = plan({
      tag: env.TAG,
      packageVersion: pkg.version,
      tauriConf: JSON.parse(readFileSync(tauriConfPath, 'utf8')),
      cargoVersion: workspaceVersion(readFileSync('Cargo.toml', 'utf8')),
      hasUpdaterKey: env.HAS_UPDATER_KEY === 'true',
      signtool: env.SIGNTOOL,
      thumbprint: env.CERT_THUMBPRINT,
    })
    const stamped = stampConfig(JSON.parse(readFileSync(releasePath, 'utf8')), p)
    writeFileSync(releasePath, JSON.stringify(stamped, null, 2) + '\n')
    setOutput('version', p.version)
    setOutput('prerelease', String(p.prerelease))
    setOutput('signed', String(p.signed))
  } else if (command === 'manifest') {
    assertChannel(env.VERSION, env.PRERELEASE === 'true')
    const out = manifest({
      version: env.VERSION,
      repo: env.REPO,
      tag: env.TAG,
      installerName: env.INSTALLER_NAME,
      signature: readFileSync(env.SIG_PATH, 'utf8'),
      notes: env.NOTES ?? '',
      now: new Date(),
    })
    writeFileSync(env.OUT ?? 'latest.json', JSON.stringify(out, null, 2) + '\n')
  } else {
    throw new Error('Usage: release.mjs prepare|manifest')
  }
}

if (process.argv[1]?.endsWith('release.mjs')) {
  try {
    main(process.argv[2])
  } catch (err) {
    console.error(`::error::${err.message}`)
    process.exit(1)
  }
}
