import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import { runForensicScan } from '../js/scan/scan.worker.js';

const catalog = JSON.parse(fs.readFileSync(new URL('../js/scan/catalog-rules.json', import.meta.url), 'utf8'));
const readFixture = (rel) => fs.readFileSync(new URL(`./fixtures/ios/${rel}`, import.meta.url), 'utf8');

test('iOS Screen Time: reconhece famílias nativas de Tempo de Uso como informativas peso 0 sem ignorar perfis suspeitos', async () => {
  const xml = readFixture('screentime-profiles.plist');
  const rep = await runForensicScan([{
    path: 'sysdiagnose/MCProfileEvents.plist',
    bytes: new TextEncoder().encode(xml)
  }], { catalog, osHint: 'ios' });

  assert.equal(rep.heuristic_index, 0);
  const st = rep.events.filter(e => e.rule_id === 'IOS_PLIST_SCREENTIME_NATIVE_001');
  assert.equal(st.length, 3);
  assert.ok(st.every(e => e.evidence_level === 'informational' && e.heuristic_weight === 0));

  // Perfil suspeito tentando disfarçar nome com "digital_health_restrictions" NÃO pode ser ignorado!
  const spoofXml = `<?xml version="1.0"?><plist><dict>
    <key>PayloadIdentifier</key><string>freefireproxy.xyz.digital_health_restrictions</string>
    <key>HTTPProxy</key><string>85.31.231.237</string>
  </dict></plist>`;
  const repSpoof = await runForensicScan([{
    path: 'sysdiagnose/MCProfileEvents.plist',
    bytes: new TextEncoder().encode(spoofXml)
  }], { catalog, osHint: 'ios' });

  assert.equal(repSpoof.events.filter(e => e.rule_id === 'IOS_PLIST_SCREENTIME_NATIVE_001').length, 0, 'Regex não pode ser permissiva para perfis disfarçados');
  assert.ok(repSpoof.events.some(e => e.rule_id === 'IOS_PLIST_PROXY_PROFILE_001'));
  assert.ok(repSpoof.events.some(e => e.rule_id === 'NETWORK_IP_CANDIDATE_001' && e.observed.object_path === '85.31.231.237'));
});

test('iOS Plist: detecta referências de perfil (Imazing.profile, 139.Spotifyx, 238.timx) e aliases (com-luxebypass)', async () => {
  const xml = `<?xml version="1.0"?><plist><dict>
    <key>PayloadIdentifier</key><string>Imazing.profile</string>
    <key>PayloadDisplayName</key><string>139.Spotifyx</string>
    <key>ServerAddress</key><string>com-luxebypass</string>
  </dict></plist>`;

  const rep = await runForensicScan([{
    path: 'sysdiagnose/MCSettingsEvents.plist',
    bytes: new TextEncoder().encode(xml)
  }], { catalog, osHint: 'ios' });

  assert.ok(rep.events.some(e => e.rule_id === 'PROFILE_REFERENCE_CANDIDATE_001' && e.observed.object_path === 'Imazing.profile'));
  assert.ok(rep.events.some(e => e.rule_id === 'PROFILE_REFERENCE_CANDIDATE_001' && e.observed.object_path === '139.Spotifyx'));
  assert.ok(rep.events.some(e => e.rule_id === 'PROXY_ALIAS_CANDIDATE_001' && e.observed.object_path === 'com-luxebypass'));
});

test('iOS .ips: valida Free Fire limpo com teamID 98573T3W6L pendente vs dylib injetada em usedImages', async () => {
  const repClean = await runForensicScan([{
    path: 'sysdiagnose/FreeFireMAX.ips',
    text: readFixture('freefire-clean.ips')
  }], { catalog, osHint: 'ios' });
  assert.equal(repClean.heuristic_index, 0);
  assert.ok(repClean.events.some(e => e.rule_id === 'IOS_IPS_TEAMID_PENDING_001'));

  const repInj = await runForensicScan([{
    path: 'sysdiagnose/FreeFire.ips',
    text: readFixture('freefire-injected.ips')
  }], { catalog, osHint: 'ios' });
  assert.ok(repInj.events.some(e => e.rule_id === 'IOS_IPS_USEDIMAGE_DYLIB_001'));
  assert.ok(repInj.events.some(e => e.rule_id === 'IOS_IPS_FF_SIDELOAD_001'));
});

test('iOS: preserva bloqueio de .tracev3 e UUIDText/DSC e Sandbox deny sem falsos positivos', async () => {
  const rep = await runForensicScan([
    { path: 'sysdiagnose/Persist/00001.tracev3', bytes: new Uint8Array([0x00, 0x10, 0x00, 0x00, 1, 2, 3, 4]) },
    { path: 'sysdiagnose/system_logs.logarchive/UUIDText/AA/1234', text: 'Imazing.profile TNTADB 85.31.231.237 Sileo\n' },
    { path: 'sysdiagnose/system_logs.log', text: '2026-11-27 12:00:00 Sandbox: FreeFire(111) deny(1) file-test-existence /Applications/Sileo.app\n' }
  ], { catalog, osHint: 'ios' });

  assert.equal(rep.heuristic_index, 0);
  assert.equal(rep.verdict.code, 'inconclusive');
  assert.equal(rep.coverage.unsupported_files.length, 1);
  assert.equal(rep.coverage.ignored_auxiliary.length, 1);
});
