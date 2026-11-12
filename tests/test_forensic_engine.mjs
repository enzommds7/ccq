import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  ForensicEngine,
  parseHexDumpLines,
  RULE_REGISTRY
} = require('../forensic_engine.js');

test('01 - Hífen em palavra não gera alerta de cassino', async () => {
  const engine = new ForensicEngine();
  const rep = await engine.analyzeFiles([{
    path: 'bugreport-2026-11-12.txt',
    text: '2026-11-12 10:00:00.000  1000  1000 I ActivityManager: Start proc com.android.chrome\nerro-de-rede-temporario\n'
  }], { osHint: 'android', yieldAsync: false });
  assert.equal(rep.alerts.filter(a => a.category === 'casino_activity').length, 0);
  assert.equal(rep.threat_score, 0);
});

test('02 - a4 dentro de endereço hexadecimal não gera alerta de proxy', async () => {
  const engine = new ForensicEngine();
  const rep = await engine.analyzeFiles([{
    path: 'tombstone_00.txt',
    text: 'fault addr 0x0000a400a4ff\nx0  0000007f1a4b2000  x1  0000a4a4a4000001\n'
  }], { osHint: 'android', yieldAsync: false });
  assert.equal(rep.alerts.filter(a => a.category.includes('proxy')).length, 0);
  assert.equal(rep.threat_score, 0);
});

test('03 - SH-Gpp2 no caminho específico + UnityMain + avc granted execute é anomalia contextual', async () => {
  const engine = new ForensicEngine();
  const log = 'auditd: type=1400 audit(0.0:263201): avc: granted { execute } for comm="UnityMain" path="/data/data/com.dts.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2" dev="dm-67" ino=2343323 scontext=u:r:untrusted_app:s0 tcontext=u:object_r:app_data_file:s0 tclass=file app=com.dts.freefiremax\n';
  const rep = await engine.analyzeFiles([{ path: 'audit.log', text: log }], { osHint: 'android', yieldAsync: false });
  const sh = rep.alerts.filter(a => a.signature_id === 'FF_GAMEASSET_SH_GPP2_AUDITD');
  assert.equal(sh.length, 1);
  assert.equal(sh[0].category, 'gameasset_anomaly');
  assert.equal(sh[0].evidence_tier, 'specific_anomaly');
  assert.equal(sh[0].process, 'UnityMain');
});

test('04 - SH-Gpp2 em mensagem não relacionada ao jogo não gera alerta relevante', async () => {
  const engine = new ForensicEngine();
  const log = '11-12 12:00:00.000  100  100 I BackupChat: Usuario enviou texto mencionando SH-Gpp2 no chat\n';
  const rep = await engine.analyzeFiles([{ path: 'chat.txt', text: log }], { osHint: 'android', yieldAsync: false });
  assert.equal(rep.alerts.filter(a => a.weight > 0).length, 0);
});

test('05 - avc: denied é diferenciado de avc: granted', async () => {
  const engine = new ForensicEngine();
  const log = 'auditd: type=1400 audit(0.0:100): avc: denied { execute } for comm="UnityMain" path="/data/user/0/com.dts.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2" app=com.dts.freefiremax\n';
  const rep = await engine.analyzeFiles([{ path: 'audit.log', text: log }], { osHint: 'android', yieldAsync: false });
  assert.equal(rep.alerts.filter(a => a.signature_id === 'FF_GAMEASSET_SH_GPP2_DENIED').length, 1);
  assert.equal(rep.alerts.filter(a => a.signature_id === 'FF_GAMEASSET_SH_GPP2_AUDITD').length, 0);
});

test('06 - LOW_MEMORY não indica cheat', async () => {
  const engine = new ForensicEngine();
  const log = '1681920: process=com.dts.freefiremax reason=3 (LOW_MEMORY) subreason=0 (UNKNOWN) status=0\n';
  const rep = await engine.analyzeFiles([{ path: 'bugreport.txt', text: log }], { osHint: 'android', yieldAsync: false });
  assert.equal(rep.threat_score, 0);
  assert.equal(rep.alerts[0].category, 'stability_crash');
});

test('07 - SIGSEGV sozinho não indica injeção', async () => {
  const engine = new ForensicEngine();
  const log = 'Cmdline: com.dts.freefiremax\npid: 18054, tid: 6626, name: UnityMain\nsignal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0000000000000318\nCause: null pointer dereference\n';
  const rep = await engine.analyzeFiles([{ path: 'tombstone_01.txt', text: log }], { osHint: 'android', yieldAsync: false });
  assert.equal(rep.threat_score, 0);
  assert.equal(rep.alerts[0].category, 'stability_crash');
});

test('08 - URL do GitHub em hex dump não indica trapaça', async () => {
  const engine = new ForensicEngine();
  const lines = [
    '    0000007070000370 6e6f734a2e74666f 213c09090a0d3e22  oft.Json">....<!',
    '    0000007070000380 7370747468202d2d 75687469672f2f3a  -- https://githu',
    '    0000007070000390 696a2f6d6f632e62 654e2f724a656c6c  b.com/jilleJr/Ne'
  ];
  const chunks = parseHexDumpLines(lines);
  assert.ok(chunks.some(c => c.urls.some(u => u.includes('github.com/jilleJr/Ne'))));
  const rep = await engine.analyzeFiles([{ path: 'tombstone_02.txt', text: lines.join('\n') }], { osHint: 'android', yieldAsync: false });
  assert.equal(rep.threat_score, 0);
  assert.equal(rep.alerts.filter(a => a.category === 'github_hexdump').length, 1);
});

test('09 - MobileBackup sozinho não comprova restauração', async () => {
  const engine = new ForensicEngine();
  const log = '2026-11-12 09:00:00 MobileBackup daemon registered as available service\n';
  const rep = await engine.analyzeFiles([{ path: 'sysdiagnose/system_logs.log', text: log }], { osHint: 'ios', yieldAsync: false });
  assert.equal(rep.threat_score, 0);
  assert.equal(rep.alerts[0].evidence_tier, 'textual_reference');
});

test('10 - itunesstored não é prova de restauração', async () => {
  const engine = new ForensicEngine();
  const log = '2026-11-12 09:05:00 itunesstored checking App Store receipt\n';
  const rep = await engine.analyzeFiles([{ path: 'sysdiagnose/system_logs.log', text: log }], { osHint: 'ios', yieldAsync: false });
  assert.equal(rep.threat_score, 0);
  assert.equal(rep.alerts[0].evidence_tier, 'textual_reference');
});

test('11 - IDs de perfis pesquisados nos campos corretos com match exato', async () => {
  const engine = new ForensicEngine();
  const repBenign = await engine.analyzeFiles([{ path: 'notes.txt', text: 'texto com.xtremo.mobile.helper\n' }], { osHint: 'android', yieldAsync: false });
  assert.equal(repBenign.alerts.filter(a => a.category === 'profile_package_id').length, 0);

  const repReal = await engine.analyzeFiles([{ path: 'packages.txt', text: 'Package [com.xtremo.mobile] userId=10299\n' }], { osHint: 'android', yieldAsync: false });
  assert.equal(repReal.alerts.filter(a => a.category === 'profile_package_id').length, 1);
});

test('12 - Eventos repetidos (4000x) não multiplicam risco', async () => {
  const engine = new ForensicEngine();
  const line = 'auditd: type=1400 audit(0.0:1): avc: granted { execute } for comm="UnityMain" path="/data/user/0/com.dts.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2" app=com.dts.freefiremax\n';
  const rep1 = await engine.analyzeFiles([{ path: 'audit.log', text: line }], { osHint: 'android', yieldAsync: false });
  const rep4000 = await engine.analyzeFiles([{ path: 'audit.log', text: line.repeat(4000) }], { osHint: 'android', yieldAsync: false });
  assert.equal(rep1.threat_score, rep4000.threat_score);
  assert.equal(rep4000.counters.unique_events, 1);
  assert.equal(rep4000.counters.raw_occurrences, 4000);
});

test('13 - Arquivo .tracev3 não interpretado gera cobertura incompleta, sem ameaças inventadas', async () => {
  const engine = new ForensicEngine();
  const fakeBytes = new Uint8Array([0x00, 0x10, 0x00, 0x00, 104, 100, 98, 0, 97, 52, 32, 109, 105, 116, 109, 0]);
  const rep = await engine.analyzeFiles([{ path: 'sysdiagnose/Persist/0001.tracev3', bytes: fakeBytes }], { osHint: 'ios', yieldAsync: false });
  assert.equal(rep.counters.unanalyzed_files, 1);
  assert.equal(rep.alerts.length, 0);
  assert.equal(rep.threat_score, 0);
  assert.ok(rep.verdict.status.includes('COBERTURA INCOMPLETA'));
});

test('14 - Logs legítimos com palavras suspeitas não provocam punições', async () => {
  const engine = new ForensicEngine();
  const log = '11-12 10:00:00.000  1000  1000 I logd: dropped 0 logs, filter applied, skip=false, ignore=false\n11-12 10:00:01.000  1000  1000 D ConnectivityService: proxy_host=none\n';
  const rep = await engine.analyzeFiles([{ path: 'logcat.txt', text: log }], { osHint: 'android', yieldAsync: false });
  assert.equal(rep.threat_score, 0);
  assert.equal(rep.verdict.color, 'green');
});

test('15 - Evidências independentes são correlacionadas e elevam confiança', async () => {
  const engine = new ForensicEngine();
  const files = [
    { path: 'audit.log', text: 'auditd: type=1400 audit(0.0:263201): avc: granted { execute } for comm="UnityMain" path="/data/data/com.dts.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2" app=com.dts.freefiremax\n' },
    { path: 'packages.txt', text: 'Package [com.dts.freefiremax] userId=10300\n  installerPackageName=com.whatsapp\n' },
    { path: 'logcat.txt', text: '11-12 11:00:00.000  2000  2000 I init: starting service frida-server\n' }
  ];
  const rep = await engine.analyzeFiles(files, { osHint: 'android', yieldAsync: false });
  const sh = rep.alerts.find(a => a.signature_id === 'FF_GAMEASSET_SH_GPP2_AUDITD');
  assert.equal(sh.evidence_tier, 'corroborated_evidence');
  assert.equal(sh.confidence, 'high');
  assert.ok(sh.corroborating_evidence.length >= 2);
});

test('16 - Teste de desempenho com grande volume (60.000 linhas)', async () => {
  const engine = new ForensicEngine();
  const line = '11-12 10:00:00.123  1000  1001 D SurfaceFlinger: frame rendered normal-mode 0x7f1a4b20\n';
  const bigText = line.repeat(60000);
  const t0 = performance.now();
  const rep = await engine.analyzeFiles([{ path: 'bugreport_big.txt', text: bigText }], { osHint: 'android', yieldAsync: false });
  const elapsedMs = performance.now() - t0;
  assert.ok(elapsedMs < 5000, `Demorou ${elapsedMs}ms`);
  assert.equal(rep.threat_score, 0);
  assert.equal(rep.counters.checked_lines, 60000);
});

test('17 - Tokens curtos/hexadecimais estão inativos (experimental_inactive)', () => {
  const exp = RULE_REGISTRY.filter(r => r.status === 'experimental_inactive');
  assert.equal(exp.length, 89);
  assert.ok(exp.every(r => r.baseWeight === 0));
});
