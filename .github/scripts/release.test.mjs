// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Run with: node --test .github/scripts/
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  PUBKEY_PLACEHOLDER,
  assertChannel,
  channelUpdates,
  checkDraft,
  compareVersions,
  manifest,
  parseTag,
  plan,
  stampConfig,
  workspaceVersion,
} from './release.mjs'

const conf = (pubkey) => ({ version: '1.2.3', plugins: { updater: { pubkey } } })
const base = { tag: 'v1.2.3', tauriConf: conf('REAL'), cargoVersion: '1.2.3' }

test('tags: stable and beta are accepted, everything else is not', () => {
  assert.deepEqual(parseTag('v1.2.3'), { version: '1.2.3', base: '1.2.3', beta: false })
  assert.deepEqual(parseTag('v1.2.3-beta.4'), {
    version: '1.2.3-beta.4',
    base: '1.2.3',
    beta: true,
  })
  for (const bad of ['1.2.3', 'v1.2', 'v1.2.3-rc.1', 'v1.2.3-beta', 'v1.2.3-beta.1.2', 'vX', '']) {
    assert.throws(() => parseTag(bad), /not a release tag/)
  }
})

test('workspace version is read from [workspace.package]', () => {
  const toml = '[workspace]\nmembers=[]\n\n[workspace.package]\nversion = "0.7.1"\nedition = "2021"\n\n[workspace.lints]\n'
  assert.equal(workspaceVersion(toml), '0.7.1')
  assert.throws(() => workspaceVersion('[package]\nversion = "1.0.0"\n'))
})

test('the tag must match the app and workspace versions', () => {
  assert.throws(() => plan({ ...base, tag: 'v1.2.4', hasUpdaterKey: false }), /does not match/)
  assert.throws(() => plan({ ...base, cargoVersion: '1.0.0', hasUpdaterKey: false }), /workspace/)
  assert.equal(plan({ ...base, tag: 'v1.2.3-beta.2', hasUpdaterKey: false }).prerelease, true)
})

test('package.json must carry the same base version', () => {
  assert.throws(() => plan({ ...base, packageVersion: '1.0.0', hasUpdaterKey: false }), /package\.json/)
  assert.equal(plan({ ...base, packageVersion: '1.2.3', hasUpdaterKey: false }).version, '1.2.3')
})

test('without the signing secret the build is unsigned and has no updater artifacts', () => {
  const p = plan({ ...base, hasUpdaterKey: false })
  assert.equal(p.signed, false)
  assert.equal(stampConfig({ bundle: { createUpdaterArtifacts: true } }, p).bundle.createUpdaterArtifacts, false)
})

test('with the secret and a real public key the artifacts are signed', () => {
  const p = plan({ ...base, hasUpdaterKey: true })
  assert.equal(p.signed, true)
  const stamped = stampConfig({ bundle: {} }, p)
  assert.equal(stamped.bundle.createUpdaterArtifacts, true)
  assert.equal(stamped.version, '1.2.3')
})

test('the secret with the placeholder public key is an error, never a silent unsigned build', () => {
  for (const pubkey of [PUBKEY_PLACEHOLDER, '']) {
    assert.throws(() => plan({ ...base, tauriConf: conf(pubkey), hasUpdaterKey: true }), /placeholder/)
  }
})

test('no secret and the placeholder key is the normal unsigned release', () => {
  assert.equal(plan({ ...base, tauriConf: conf(PUBKEY_PLACEHOLDER), hasUpdaterKey: false }).signed, false)
})

test('Authenticode is only added when a certificate was imported', () => {
  const none = stampConfig({ bundle: {} }, plan({ ...base, hasUpdaterKey: false }))
  assert.equal(none.bundle.windows, undefined)
  const p = plan({ ...base, hasUpdaterKey: false, signtool: 'C:\\sdk\\signtool.exe', thumbprint: 'AB12' })
  const stamped = stampConfig({ bundle: { windows: { nsis: {} } } }, p)
  assert.equal(stamped.bundle.windows.signCommand.cmd, 'C:\\sdk\\signtool.exe')
  assert.ok(stamped.bundle.windows.signCommand.args.includes('AB12'))
  assert.equal(stamped.bundle.windows.signCommand.args.at(-1), '%1')
  assert.deepEqual(stamped.bundle.windows.nsis, {})
})

test('latest.json has the shape the updater reads', () => {
  const out = manifest({
    version: '1.2.3-beta.1',
    repo: 'XeroHost/packetward',
    tag: 'v1.2.3-beta.1',
    installerName: 'PacketWard_1.2.3-beta.1_x64-setup.exe',
    signature: 'c2ln\n',
    notes: 'n',
    now: new Date('2026-01-02T03:04:05.678Z'),
  })
  assert.equal(out.version, '1.2.3-beta.1')
  assert.equal(out.pub_date, '2026-01-02T03:04:05Z')
  const target = out.platforms['windows-x86_64']
  assert.equal(target.signature, 'c2ln')
  assert.equal(
    target.url,
    'https://github.com/XeroHost/packetward/releases/download/v1.2.3-beta.1/PacketWard_1.2.3-beta.1_x64-setup.exe',
  )
})

test('a stable manifest never carries a pre-release version and a beta one always does', () => {
  assertChannel('0.1.0', false)
  assertChannel('0.1.0-beta.2', true)
  assert.throws(() => assertChannel('0.1.0-beta.2', false), /never put a pre-release/)
  assert.throws(() => assertChannel('0.1.0', true), /does not fit/)
})

// ---- the checks before a draft release is published
import { createHash } from 'node:crypto'

const sha = (data) => createHash('sha256').update(data).digest('hex')
const NAME = 'PacketWard_0.1.0_x64-setup.exe'
function draft({ signed = true, prerelease = false, mutate } = {}) {
  const version = prerelease ? '0.1.0-beta.1' : '0.1.0'
  const tag = `v${version}`
  const name = `PacketWard_${version}_x64-setup.exe`
  const installer = Buffer.from('installer bytes')
  const d = {
    files: new Map([[name, installer]]),
    expectedSha256: sha(installer),
    manifest: signed
      ? {
          version,
          platforms: {
            'windows-x86_64': {
              signature: 'c2ln',
              url: `https://github.com/XeroHost/packetward/releases/download/${tag}/${encodeURIComponent(name)}`,
            },
          },
        }
      : null,
    tag,
    version,
    repo: 'XeroHost/packetward',
    installerName: name,
    signed,
    prerelease,
  }
  mutate?.(d)
  return d
}
const problems = (opts) => checkDraft(draft(opts)).join(' | ')

test('a stable draft, a beta draft and an unsigned one with only the installer are publishable', () => {
  assert.deepEqual(checkDraft(draft()), [])
  assert.deepEqual(checkDraft(draft({ prerelease: true })), [])
  assert.deepEqual(checkDraft(draft({ signed: false })), [])
})

test('a release carries only the installer: no .sig, no SHA256SUMS, nothing else', () => {
  for (const extra of [`${NAME}.sig`, 'SHA256SUMS.txt', 'latest.json']) {
    assert.match(
      problems({ mutate: (d) => d.files.set(extra, Buffer.from('x')) }),
      /only the installer/,
      extra,
    )
  }
})

test('the installer must be the one that was built', () => {
  assert.match(problems({ mutate: (d) => d.files.set(d.installerName, Buffer.from('changed')) }), /hash mismatch/)
  assert.match(problems({ mutate: (d) => d.files.clear() }), /installer .* is missing/)
  assert.match(problems({ mutate: (d) => (d.expectedSha256 = '') }), /no hash/)
})

test('the manifest must name this release, and a stable one never a pre-release', () => {
  assert.match(problems({ mutate: (d) => (d.manifest = null) }), /manifest is missing/)
  assert.match(problems({ mutate: (d) => (d.manifest.version = '9.9.9') }), /says version 9.9.9/)
  assert.match(problems({ mutate: (d) => (d.manifest.platforms['windows-x86_64'].url = 'https://evil/x.exe') }), /different installer URL/)
  assert.match(problems({ mutate: (d) => (d.manifest.platforms['windows-x86_64'].signature = '') }), /no signature/)
  assert.match(
    problems({ mutate: (d) => { d.manifest.version = '0.1.0-beta.1'; d.version = '0.1.0-beta.1' } }),
    /must never carry a pre-release/,
  )
  assert.match(problems({ signed: false, mutate: (d) => (d.manifest = { version: '0.1.0' }) }), /unsigned release must not/)
})

// ---- channel files of the `updates` branch
test('versions compare like semver: a beta is below its release, betas by number', () => {
  assert.equal(compareVersions('0.1.0', '0.1.0-beta.9'), 1)
  assert.equal(compareVersions('0.1.0-beta.2', '0.1.0-beta.10'), -1)
  assert.equal(compareVersions('0.2.0-beta.1', '0.1.9'), 1)
  assert.equal(compareVersions('1.0.0', '1.0.0'), 0)
  assert.equal(compareVersions('nonsense', '0.0.1'), -1)
})

test('a beta release only updates beta.json; a stable one updates both', () => {
  const beta = draft({ prerelease: true }).manifest
  const stable = draft().manifest
  assert.deepEqual(Object.keys(channelUpdates({ existing: {}, manifest: beta, prerelease: true })), ['beta'])
  assert.deepEqual(Object.keys(channelUpdates({ existing: {}, manifest: stable, prerelease: false })).sort(), ['beta', 'stable'])
})

test('a channel file is never moved backwards', () => {
  const old = JSON.stringify({ version: '0.2.0' })
  const betaOld = JSON.stringify({ version: '0.2.0-beta.3' })
  // A stable 0.1.0 published after 0.2.0: neither file moves.
  assert.deepEqual(channelUpdates({ existing: { stable: old, beta: old }, manifest: draft().manifest, prerelease: false }), {})
  // A newer beta replaces beta.json only.
  const newer = { ...draft({ prerelease: true }).manifest, version: '0.2.0-beta.4' }
  assert.deepEqual(Object.keys(channelUpdates({ existing: { stable: old, beta: betaOld }, manifest: newer, prerelease: true })), ['beta'])
  // A damaged file is replaced.
  assert.deepEqual(Object.keys(channelUpdates({ existing: { beta: '{not json' }, manifest: newer, prerelease: true })), ['beta'])
})
