// SPDX-License-Identifier: GPL-3.0-or-later
// Run with: node --test .github/scripts/
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  PUBKEY_PLACEHOLDER,
  assertChannel,
  checkDraft,
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
function draft({ signed = true, prerelease = false, mutate } = {}) {
  const installerName = 'PacketWard_0.1.0_x64-setup.exe'
  const installer = Buffer.from('installer bytes')
  const sig = Buffer.from('c2lnbmF0dXJl\n')
  const files = new Map([[installerName, installer]])
  if (signed) files.set(`${installerName}.sig`, sig)
  if (signed && !prerelease) {
    const version = '0.1.0'
    files.set(
      'latest.json',
      Buffer.from(
        JSON.stringify({
          version,
          platforms: {
            'windows-x86_64': {
              signature: sig.toString().trim(),
              url: `https://github.com/XeroHost/packetward/releases/download/v${version}/${encodeURIComponent(installerName)}`,
            },
          },
        }),
      ),
    )
  }
  const lines = [...files].map(([name, data]) => `${sha(data)}  ${name}`)
  files.set('SHA256SUMS.txt', Buffer.from(lines.join('\n') + '\n'))
  mutate?.(files)
  return {
    files,
    tag: prerelease ? 'v0.1.0-beta.1' : 'v0.1.0',
    version: prerelease ? '0.1.0-beta.1' : '0.1.0',
    repo: 'XeroHost/packetward',
    installerName,
    signed,
    prerelease,
  }
}

test('a complete stable draft, a complete beta draft and an unsigned one are publishable', () => {
  assert.deepEqual(checkDraft(draft()), [])
  assert.deepEqual(checkDraft(draft({ prerelease: true })), [])
  assert.deepEqual(checkDraft(draft({ signed: false })), [])
})

test('a draft that is incomplete or inconsistent is not publishable', () => {
  const problems = (opts) => checkDraft(draft(opts)).join(' | ')
  assert.match(problems({ mutate: (f) => f.delete('latest.json') }), /latest.json is missing/)
  assert.match(problems({ mutate: (f) => f.delete('PacketWard_0.1.0_x64-setup.exe.sig') }), /signature .* is missing/)
  assert.match(problems({ mutate: (f) => f.set('PacketWard_0.1.0_x64-setup.exe', Buffer.from('changed')) }), /hash of/)
  assert.match(problems({ mutate: (f) => f.delete('PacketWard_0.1.0_x64-setup.exe') }), /installer .* is missing/)
  assert.match(problems({ mutate: (f) => f.delete('SHA256SUMS.txt') }), /SHA256SUMS.txt is missing/)
  assert.match(
    problems({
      mutate: (f) => {
        const m = JSON.parse(f.get('latest.json'))
        m.platforms['windows-x86_64'].signature = 'other'
        f.set('latest.json', Buffer.from(JSON.stringify(m)))
      },
    }),
    /different signature/,
  )
})

test('a beta draft must not carry latest.json, and no stable manifest names a pre-release', () => {
  assert.match(
    checkDraft(draft({ prerelease: true, mutate: (f) => f.set('latest.json', Buffer.from('{}')) })).join(' | '),
    /must not carry latest.json/,
  )
  const wrong = draft({
    mutate: (f) => {
      const m = JSON.parse(f.get('latest.json'))
      m.version = '0.1.0-beta.1'
      f.set('latest.json', Buffer.from(JSON.stringify(m)))
    },
  })
  assert.match(checkDraft(wrong).join(' | '), /pre-release version/)
})
