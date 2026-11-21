// SPDX-License-Identifier: GPL-3.0-or-later
// The fixtures hold a throwaway keypair's PUBLIC half, a file and its signature (the private half was
// discarded when they were made): no secret lives in this repository.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { verifyMinisign } from './verify-sig.mjs'

const dir = new URL('./fixtures/', import.meta.url)
const read = (name) => readFileSync(new URL(name, dir))
const good = {
  pubkeyB64: read('signer.pub').toString('utf8'),
  sigB64: read('data.bin.sig').toString('utf8'),
  data: read('data.bin'),
}

test('a signature made by the key verifies, and the key id is reported', () => {
  assert.match(verifyMinisign(good), /^[0-9a-f]{16}$/)
})

test('a changed file does not verify', () => {
  const data = Buffer.from(good.data)
  data[0] ^= 1
  assert.throws(() => verifyMinisign({ ...good, data }), /does not match the file/)
})

test('another key does not verify the signature', () => {
  assert.throws(
    () => verifyMinisign({ ...good, pubkeyB64: read('other.pub').toString('utf8') }),
    /different key/,
  )
})

test('a tampered signature or trusted comment does not verify', () => {
  const lines = Buffer.from(good.sigB64.trim(), 'base64').toString('utf8').split('\n')
  lines[2] = lines[2].replace('trusted comment: ', 'trusted comment: x')
  const sigB64 = Buffer.from(lines.join('\n')).toString('base64')
  assert.throws(() => verifyMinisign({ ...good, sigB64 }), /trusted comment/)
  assert.throws(() => verifyMinisign({ ...good, sigB64: 'not a signature' }), /minisign/)
})

test('the placeholder or an empty key is refused', () => {
  assert.throws(() => verifyMinisign({ ...good, pubkeyB64: 'REPLACE_WITH_UPDATER_PUBLIC_KEY' }), /minisign/)
  assert.throws(() => verifyMinisign({ ...good, pubkeyB64: '' }), /minisign/)
})
