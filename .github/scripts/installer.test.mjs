// SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
// Guards the inbound capture rule in the installer hooks and its development equivalent: they must
// stay one program-scoped INBOUND ALLOW rule in the PacketWard group, removed again on uninstall.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

const root = new URL('../../', import.meta.url)
const hooks = readFileSync(new URL('apps/desktop/src-tauri/installer/hooks.nsh', root), 'utf8')
const dev = readFileSync(new URL('tools/dev/capture-rule.ps1', root), 'utf8')
const NAME = 'PacketWard agent (raw capture)'

test('the installer creates one inbound allow rule for the agent executable in the PacketWard group', () => {
  const add = hooks.split('\n').find((l) => l.includes('New-NetFirewallRule'))
  assert.ok(add, 'no New-NetFirewallRule line in the hooks')
  assert.ok(add.includes(NAME), 'rule name')
  // The cmdlet text sits inside an NSIS-quoted command: a backslash precedes each inner quote.
  assert.match(add, /-Group \$.'PacketWard\$.'/)
  assert.match(add, /-Direction Inbound/)
  assert.match(add, /-Action Allow/)
  assert.match(add, /-Program \$.'\$INSTDIR.packetward-agent\.exe\$.'/)
  assert.equal(hooks.split('New-NetFirewallRule').length - 1, 1, 'exactly one rule is created')
})

test('the rule is replaced on upgrade and removed on uninstall', () => {
  const deletes = hooks.split('\n').filter((l) => l.includes('delete rule') && l.includes(NAME))
  assert.ok(deletes.length >= 2, 'removed before adding and on uninstall')
})

test('the development script creates the same rule and refuses to run silently', () => {
  assert.ok(dev.includes(`'${NAME}'`))
  assert.match(dev, /-Direction Inbound -Action Allow -Program/)
  assert.match(dev, /SupportsShouldProcess = \$true/)
  assert.match(dev, /\[ValidateSet\('Add', 'Remove', 'Status'\)\]/)
  assert.match(dev, /TEST VPS ONLY/)
})
