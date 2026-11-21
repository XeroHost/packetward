// SPDX-License-Identifier: GPL-3.0-or-later
// Helpers of .github/workflows/release.yml, kept in a script so they can be run and tested locally.
//
//   node .github/scripts/release.mjs guard            check the tag shape
//   node .github/scripts/release.mjs prepare          validate the tag, stamp the version and the signing
//                                                     options into the (uncommitted) release config
//   node .github/scripts/release.mjs manifest         write the updater JSON of one release (not uploaded as a file)
//   node .github/scripts/release.mjs check-draft      check the draft release and the proof before publishing
//   node .github/scripts/release.mjs update-channels  write stable.json / beta.json in the `updates` branch checkout
//
// Inputs come from environment variables (see each command).
import { createHash } from 'node:crypto'
import { appendFileSync, existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

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

/**
 * What the last job checks before the DRAFT release is published. The release carries ONLY the installer
 * (`files` = the draft's assets by name), and everything else travels as a private workflow artifact, the
 * "proof": `expectedSha256` (computed when the installer was built) and, for a signed release, the updater
 * `manifest` (the JSON that will be committed to the `updates` branch; the signature lives only in it).
 * Checks: nothing but the installer is attached; its hash is the one that was built; a signed release has a
 * manifest that names this version, this tag, this installer and a signature, and never a pre-release version
 * on a stable one; an unsigned release has no manifest. The cryptographic check of the signature against the
 * public key is verify-sig.mjs. Returns the list of problems; empty means publishable.
 */
export function checkDraft({ files, expectedSha256, manifest: updater, tag, version, repo, installerName, signed, prerelease }) {
  const problems = []
  const names = [...files.keys()]
  const extra = names.filter((n) => n !== installerName)
  if (extra.length > 0) problems.push(`the release must carry only the installer, but it also has: ${extra.join(', ')}`)
  const installer = files.get(installerName)
  if (!installer) problems.push(`the installer ${installerName} is missing`)
  else if (!expectedSha256) problems.push('the proof has no hash of the installer')
  else if (createHash('sha256').update(installer).digest('hex') !== expectedSha256.trim()) {
    problems.push('the installer in the release is not the one that was built (hash mismatch)')
  }
  if (!signed) {
    if (updater) problems.push('an unsigned release must not have an updater manifest')
    return problems
  }
  if (!updater) {
    problems.push('the updater manifest is missing')
    return problems
  }
  const entry = updater.platforms?.['windows-x86_64']
  const url = `https://github.com/${repo}/releases/download/${tag}/${encodeURIComponent(installerName)}`
  if (updater.version !== version) problems.push(`the manifest says version ${updater.version}, the release is ${version}`)
  if (/-/.test(updater.version ?? '') !== prerelease) {
    problems.push('the manifest version does not fit the channel: a stable manifest must never carry a pre-release version')
  }
  if (entry?.url !== url) problems.push('the manifest points to a different installer URL')
  if (!entry?.signature) problems.push('the manifest has no signature')
  return problems
}

/**
 * Compares two versions `X.Y.Z` or `X.Y.Z-beta.N` (semver: a pre-release is lower than its release, betas
 * compare by number). Returns -1, 0 or 1; an unreadable version counts as lower than any valid one.
 */
export function compareVersions(a, b) {
  const parse = (v) => {
    const match = /^(\d+)\.(\d+)\.(\d+)(?:-beta\.(\d+))?$/.exec(v ?? '')
    return match ? { n: [match[1], match[2], match[3]].map(Number), beta: match[4] === undefined ? Infinity : Number(match[4]) } : null
  }
  const [x, y] = [parse(a), parse(b)]
  if (!x || !y) return x ? 1 : y ? -1 : 0
  for (let i = 0; i < 3; i++) if (x.n[i] !== y.n[i]) return x.n[i] < y.n[i] ? -1 : 1
  return x.beta === y.beta ? 0 : x.beta < y.beta ? -1 : 1
}

/**
 * Which channel files a published release writes in the `updates` branch. A beta only updates `beta.json`;
 * a stable release updates both, so somebody on beta also receives a stable that is newer. A file is never
 * moved backwards: it is only replaced by a version that is the same or newer. `existing` holds the current
 * content of the files (a JSON string, or undefined when the file does not exist yet).
 */
export function channelUpdates({ existing, manifest: updater, prerelease }) {
  const targets = prerelease ? ['beta'] : ['stable', 'beta']
  const out = {}
  for (const name of targets) {
    let current
    try {
      current = existing?.[name] ? JSON.parse(existing[name]).version : undefined
    } catch {
      current = undefined
    }
    if (current === undefined || compareVersions(updater.version, current) >= 0) {
      out[name] = JSON.stringify(updater, null, 2) + '\n'
    }
  }
  return out
}

/** The updater JSON in the format of the Tauri updater (static manifest, one Windows target). */
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
  } else if (command === 'check-draft') {
    // DIR holds the assets downloaded from the draft release, PROOF the private artifact of the build job.
    const dir = env.DIR
    const proof = env.PROOF
    const files = new Map(readdirSync(dir).map((name) => [name, readFileSync(join(dir, name))]))
    const manifestPath = join(proof, 'manifest.json')
    const problems = checkDraft({
      files,
      expectedSha256: readFileSync(join(proof, 'sha256.txt'), 'utf8'),
      manifest: existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, 'utf8')) : null,
      tag: env.TAG,
      version: env.VERSION,
      repo: env.REPO,
      installerName: env.INSTALLER_NAME,
      signed: env.SIGNED === 'true',
      prerelease: env.PRERELEASE === 'true',
    })
    if (problems.length > 0) throw new Error(`The draft release is not publishable:\n - ${problems.join('\n - ')}`)
    console.log(`The draft release of ${env.TAG} is complete and consistent.`)
  } else if (command === 'update-channels') {
    // DIR is a checkout of the `updates` branch; MANIFEST is the updater JSON of the release just published.
    const dir = env.DIR
    const updater = JSON.parse(readFileSync(env.MANIFEST, 'utf8'))
    const read = (name) => (existsSync(join(dir, `${name}.json`)) ? readFileSync(join(dir, `${name}.json`), 'utf8') : undefined)
    const writes = channelUpdates({
      existing: { stable: read('stable'), beta: read('beta') },
      manifest: updater,
      prerelease: env.PRERELEASE === 'true',
    })
    for (const [name, text] of Object.entries(writes)) writeFileSync(join(dir, `${name}.json`), text)
    console.log(`Channels updated: ${Object.keys(writes).join(', ') || 'none (nothing newer)'}`)
  } else if (command === 'guard') {
    // A release tag is vX.Y.Z (stable) or vX.Y.Z-beta.N (beta); anything else never publishes.
    const parsed = parseTag(env.TAG)
    setOutput('version', parsed.version)
    setOutput('prerelease', String(parsed.beta))
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
    throw new Error('Usage: release.mjs guard|prepare|manifest|check-draft|update-channels')
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
