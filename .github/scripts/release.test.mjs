// SPDX-License-Identifier: GPL-3.0-or-later
// Run with: node --test .github/scripts/
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  PUBKEY_PLACEHOLDER,
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
