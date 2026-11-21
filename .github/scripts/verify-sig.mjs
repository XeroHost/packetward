// SPDX-License-Identifier: GPL-3.0-or-later
// Verifies a Tauri updater signature (a minisign signature, base64 wrapped) against the public key in
// tauri.conf.json, exactly as the installed app will do. The release workflow runs it on every build before
// anything is published, so an installer that the app would refuse never reaches a release.
//
//   node .github/scripts/verify-sig.mjs <installer> <installer>.sig [tauri.conf.json]
//
// Prints only OK / the reason; it never reads or prints a private key.
import { createHash, createPublicKey, verify } from 'node:crypto'
import { readFileSync } from 'node:fs'

// SubjectPublicKeyInfo header of a raw ed25519 public key.
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

function decodeBase64Text(b64, what) {
  const text = Buffer.from(String(b64).trim(), 'base64').toString('utf8')
  if (!text.includes('\n')) throw new Error(`${what} is not a minisign file in base64`)
  return text.split(/\r?\n/)
}

function ed25519(publicKey, message, signature) {
  const key = createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, publicKey]),
    format: 'der',
    type: 'spki',
  })
  return verify(null, message, key, signature)
}

/**
 * `pubkeyB64`: the `plugins.updater.pubkey` string. `sigB64`: the content of the `.sig` file. `data`: the
 * signed file. Throws with the reason when it does not verify; returns the key id when it does.
 */
export function verifyMinisign({ pubkeyB64, sigB64, data }) {
  const pubLines = decodeBase64Text(pubkeyB64, 'the public key')
  const pub = Buffer.from((pubLines[1] ?? '').trim(), 'base64')
  if (pub.length !== 42 || pub.toString('latin1', 0, 2) !== 'Ed') {
    throw new Error('the public key is not a minisign ed25519 key')
  }
  const keyId = pub.subarray(2, 10)
  const publicKey = pub.subarray(10)

  const sigLines = decodeBase64Text(sigB64, 'the signature')
  const sig = Buffer.from((sigLines[1] ?? '').trim(), 'base64')
  if (sig.length !== 74) throw new Error('the signature has the wrong length')
  const algorithm = sig.toString('latin1', 0, 2)
  if (algorithm !== 'Ed' && algorithm !== 'ED') throw new Error('unknown signature algorithm')
  if (!sig.subarray(2, 10).equals(keyId)) {
    throw new Error('the signature was made by a different key than the public key in tauri.conf.json')
  }
  const signature = sig.subarray(10)
  // "ED" signs the BLAKE2b-512 hash of the file (what the Tauri CLI writes); "Ed" signs the file itself.
  const message = algorithm === 'ED' ? createHash('blake2b512').update(data).digest() : data
  if (!ed25519(publicKey, message, signature)) {
    throw new Error('the signature does not match the file (changed after signing, or another key)')
  }
  const trusted = (sigLines[2] ?? '').replace(/^trusted comment: ?/, '')
  const globalSig = Buffer.from((sigLines[3] ?? '').trim(), 'base64')
  if (!ed25519(publicKey, Buffer.concat([signature, Buffer.from(trusted, 'utf8')]), globalSig)) {
    throw new Error('the trusted comment of the signature was tampered with')
  }
  // minisign shows the key id with the bytes reversed (as in "minisign public key: 86363F43…").
  return Buffer.from(keyId).reverse().toString('hex')
}

function main() {
  const [file, sigFile, confPath = 'apps/desktop/src-tauri/tauri.conf.json'] = process.argv.slice(2)
  if (!file || !sigFile) throw new Error('Usage: verify-sig.mjs <file> <file.sig> [tauri.conf.json]')
  const conf = JSON.parse(readFileSync(confPath, 'utf8'))
  const keyId = verifyMinisign({
    pubkeyB64: conf.plugins?.updater?.pubkey ?? '',
    sigB64: readFileSync(sigFile, 'utf8'),
    data: readFileSync(file),
  })
  console.log(`OK: ${file} is signed by the updater key ${keyId.toUpperCase()}`)
}

if (process.argv[1]?.endsWith('verify-sig.mjs')) {
  try {
    main()
  } catch (err) {
    console.error(`::error::${err.message}`)
    process.exit(1)
  }
}
