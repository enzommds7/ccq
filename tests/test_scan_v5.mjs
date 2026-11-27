import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import { runForensicScan } from '../js/scan/scan.worker.js';
import { parseBinaryPlist } from '../js/scan/parsers/ios-parser.js';
import { classifyArchiveEntry, loadJSZip, sanitizeArchivePath } from '../js/scan/archive-reader.js';
import { createMatcher } from '../js/scan/engine/matcher.js';

const JSZip = await loadJSZip();
const catalog = JSON.parse(fs.readFileSync(new URL('../js/scan/catalog-rules.json', import.meta.url), 'utf8'));

/** Helper para construir um bplist00 válido em memória para teste sem dependências externas */
function buildTestBinaryPlist(entries) {
  // Constrói dicionário plano { string: string } em bplist00 com offsetIntSize=2, objectRefSize=1
  const asciiEnc = (s) => Uint8Array.from(s, c => c.charCodeAt(0));
  const parts = [asciiEnc('bplist00')];
  let cursor = 8;
  const offsets = [];

  const keys = Object.keys(entries);
  const numObjects = 1 + keys.length * 2;
  const keyRefs = [];
  const valRefs = [];

  // Object 0 será o dict
  offsets.push(cursor);
  const dictBytes = new Uint8Array(1 + keys.length * 2);
  dictBytes[0] = keys.length < 15 ? (0xd0 | keys.length) : 0xd0;
  for (let i = 0; i < keys.length; i++) {
    const kIdx = 1 + i * 2;
    const vIdx = 2 + i * 2;
    keyRefs.push(kIdx);
    valRefs.push(vIdx);
    dictBytes[1 + i] = kIdx;
    dictBytes[1 + keys.length + i] = vIdx;
  }
  parts.push(dictBytes);
  cursor += dictBytes.length;

  const pushAsciiStr = (str) => {
    offsets.push(cursor);
    const raw = asciiEnc(str);
    let hdr;
    if (raw.length < 15) {
      hdr = Uint8Array.from([0x50 | raw.length]);
    } else {
      hdr = Uint8Array.from([0x5f, 0x10, raw.length]);
    }
    parts.push(hdr, raw);
    cursor += hdr.length + raw.length;
  };

  for (const k of keys) {
    pushAsciiStr(k);
    pushAsciiStr(String(entries[k]));
  }

  const offsetTableOffset = cursor;
  const offsetTable = new Uint8Array(numObjects * 2);
  const otView = new DataView(offsetTable.buffer);
  for (let i = 0; i < numObjects; i++) {
    otView.setUint16(i * 2, offsets[i], false);
  }
  parts.push(offsetTable);

  const trailer = new Uint8Array(32);
  const trView = new DataView(trailer.buffer);
  trailer[6] = 2; // offsetIntSize
  trailer[7] = 1; // objectRefSize
  trView.setBigUint64(8, BigInt(numObjects), false);
  trView.setBigUint64(16, 0n, false); // topObject = 0
  trView.setBigUint64(24, BigInt(offsetTableOffset), false);
  parts.push(trailer);

  const totalLen = parts.reduce((acc, p) => acc + p.length, 0);
  const out = new Uint8Array(totalLen);
  let pos = 0;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

test('01 - UUIDText e DSC com frida-server, cydia, sileo, dopamine geram 0 alertas de risco', async () => {
  const rep = await runForensicScan([
    { path: 'sysdiagnose/system_logs.logarchive/UUIDText/AA/BBCCDD', text: 'frida-server cydia sileo dopamine /var/jb/basebin/launchdhook.dylib\n' },
    { path: 'sysdiagnose/system_logs.logarchive/DSC/000123', text: 'DOPAMINE_INITIALIZED=1 Sileo Cydia MobileSubstrate\n' }
  ], { catalog, osHint: 'ios' });

  assert.equal(rep.heuristic_index, 0);
  assert.equal(rep.events.length, 0);
  assert.equal(rep.coverage.ignored_auxiliary.length, 2);
});

test('02 - Sileo em Sandbox: deny file-test-existence não confirma instalação (0 risco)', async () => {
  const rep = await runForensicScan([{
    path: 'sysdiagnose/system_logs.log',
    text: '2026-11-22 14:00:00.000 Sandbox: FreeFire(412) deny(1) file-test-existence /Applications/Sileo.app\n'
  }], { catalog, osHint: 'ios' });

  assert.equal(rep.heuristic_index, 0);
  assert.equal(rep.counters.anomaly_review, 0);
  assert.equal(rep.counters.corroborated_evidence, 0);
  assert.equal(rep.events[0].rule_id, 'IOS_SANDBOX_DENY_PROBE_001');
  assert.equal(rep.events[0].evidence_level, 'informational');
});

test('03 - Tokens hex curtos (06, a4, b9), hífen isolado e Regedit solto geram 0 penalidade', async () => {
  const matcher = createMatcher(catalog);
  assert.equal(matcher.inactiveTokensCount, 76);
  assert.ok(matcher.inactiveGroupIds.includes('PROXY_SHORT_TOKENS'));

  const rep = await runForensicScan([{
    path: 'tombstone_00',
    text: 'fault addr 0x0000a400b906\nerro-de-rede-06-a4-b9\nRegedit mencionado em conversa comum de jogador\n'
  }], { catalog, osHint: 'android' });

  assert.equal(rep.heuristic_index, 0);
  assert.equal(rep.counters.anomaly_review, 0);
  assert.equal(rep.counters.corroborated_evidence, 0);
});

test('04 - LOW_MEMORY, SIGSEGV, PR_PAC_*, libil2cpp.so padrão e GitHub em hex dump têm peso 0', async () => {
  const lines = [
    '1681920: process=com.dts.freefireth reason=3 (LOW_MEMORY) subreason=0 (UNKNOWN) status=0',
    'Cmdline: com.dts.freefiremax',
    'signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0000000000000318',
    'pac_enabled_keys: PR_PAC_APIAKEY, PR_PAC_APIBKEY',
    '    #00 pc 0000000001234560  /data/app/com.dts.freefiremax/lib/arm64/libil2cpp.so',
    '    0000007070000370 6e6f734a2e74666f 213c09090a0d3e22  oft.Json">....<!',
    '    0000007070000380 7370747468202d2d 75687469672f2f3a  -- https://githu',
    '    0000007070000390 696a2f6d6f632e62 654e2f724a656c6c  b.com/jilleJr/Ne'
  ];
  const rep = await runForensicScan([{ path: 'tombstone_01', text: lines.join('\n') }], { catalog, osHint: 'android' });

  assert.equal(rep.heuristic_index, 0);
  assert.ok(rep.events.every(e => e.evidence_level === 'informational'));
  assert.ok(rep.events.some(e => e.rule_id === 'HEXDUMP_URL_REF_001'));
  assert.ok(rep.events.some(e => e.rule_id === 'ANDROID_STABILITY_LOW_MEMORY_001'));
  assert.ok(rep.events.some(e => e.rule_id === 'ANDROID_STABILITY_CRASH_001'));
});

test('05 - USB, MTP, PTP, chatty, dropped, itunesstored, SetupAssistant, Screen Time e HoldingTankManifest são informativos', async () => {
  const repAndroid = await runForensicScan([{
    path: 'logcat.txt',
    text: [
      '11-22 10:00:00.000  1000  1000 I UsbService: USB connected persist.sys.usb.config=mtp,ptp',
      '11-22 10:00:01.000  1000  1000 I logd: chatty expire 5 lines, dropped logs=0',
      '11-22 10:00:02.000  1000  1000 D DhcpClient: DHCP lease obtained'
    ].join('\n')
  }], { catalog, osHint: 'android' });

  assert.equal(repAndroid.heuristic_index, 0);
  assert.ok(repAndroid.coverage.logging_diagnostics.includes('chatty'));
  assert.ok(repAndroid.coverage.logging_diagnostics.includes('dropped logs'));
  assert.equal(repAndroid.verdict.code, 'informational');

  const plistScreenTime = `<?xml version="1.0"?><plist><dict><key>PayloadIdentifier</key><string>system.dateandtime.force_date_time_configuration_1234-restrictions</string></dict></plist>`;
  const repIos = await runForensicScan([
    { path: 'sysdiagnose/system_logs.log', text: '2026-11-22 10:00:00 itunesstored SetupAssistant MobileBackup active\n' },
    { path: 'sysdiagnose/HoldingTankManifest.plist', bytes: new TextEncoder().encode('<plist/>') },
    { path: 'sysdiagnose/MCProfileEvents.plist', bytes: new TextEncoder().encode(plistScreenTime) }
  ], { catalog, osHint: 'ios' });

  assert.equal(repIos.heuristic_index, 0);
  assert.equal(repIos.verdict.code, 'informational');
  assert.ok(repIos.events.some(e => e.rule_id === 'IOS_PLIST_HOLDINGTANK_001'));
  assert.ok(repIos.events.some(e => e.rule_id === 'IOS_PLIST_SCREENTIME_NATIVE_001'));
  assert.ok(repIos.events.some(e => e.rule_id === 'IOS_BACKUP_RESTORE_EVENT_001'));
});

test('06 - bugreport parcial ou .tracev3 gera INCONCLUSIVO (nunca "100% limpo")', async () => {
  const repTrace = await runForensicScan([{
    path: 'sysdiagnose/Persist/000001.tracev3',
    bytes: new Uint8Array([0x00, 0x10, 0x00, 0x00, 104, 100, 98, 0])
  }], { catalog, osHint: 'ios' });
  assert.equal(repTrace.verdict.code, 'inconclusive');
  assert.equal(repTrace.verdict.status, 'INCONCLUSIVO');
  assert.equal(repTrace.coverage.status, 'insuficiente');
  assert.equal(repTrace.coverage.unsupported_files.length, 1);
  assert.ok(!JSON.stringify(repTrace).toLowerCase().includes('100% limpo'));

  const repPartialBugreport = await runForensicScan([{
    path: 'bugreport-partial.txt',
    text: '11-22 10:00:00.000  1000  1000 I ActivityManager: Start proc com.dts.freefireth\n'
  }], { catalog, osHint: 'android' });
  assert.equal(repPartialBugreport.verdict.code, 'inconclusive');
  assert.equal(repPartialBugreport.coverage.status, 'parcial');
  assert.ok(repPartialBugreport.coverage.gaps.length >= 1);
});

test('07 - 10.000 repetições do mesmo evento geram 1 evento único deduplicado (occurrence_count=10000)', async () => {
  const line = 'auditd: type=1400 audit(0.0:1): avc: granted { execute } for comm="UnityMain" path="/data/user/0/com.dts.freefireth/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2" app=com.dts.freefireth\n';
  const rep1 = await runForensicScan([{ path: 'audit.log', text: line }], { catalog, osHint: 'android' });
  const rep10k = await runForensicScan([{ path: 'audit.log', text: line.repeat(10000) }], { catalog, osHint: 'android' });

  assert.equal(rep1.heuristic_index, rep10k.heuristic_index);
  assert.equal(rep10k.counters.unique_events, 1);
  assert.equal(rep10k.counters.raw_occurrences, 10000);
  assert.equal(rep10k.events[0].occurrence_count, 10000);
});

test('08 - ZIP com path traversal (../), TAR com symlink e entrada > limite são rejeitados com segurança', async () => {
  assert.equal(sanitizeArchivePath('../../etc/passwd').ok, false);
  assert.equal(sanitizeArchivePath('/abs/path.txt').ok, false);
  assert.equal(sanitizeArchivePath('folder/file.txt').normalized, 'folder/file.txt');

  // ZIP malicioso com path traversal (../) real nos headers + symlink Unix
  const zip = new JSZip();
  zip.file('XX/evil.txt', 'frida-server');
  zip.file('safe_symlink', 'target', { unixPermissions: 0o120777 });
  zip.file('bugreport.txt', 'ro.boot.verifiedbootstate=green\n');
  const zipBytes = await zip.generateAsync({ type: 'uint8array', platform: 'UNIX' });
  // Substitui 'XX/' por '../' diretamente nos headers local + central directory (mesmo tamanho em bytes)
  for (let i = 0; i <= zipBytes.length - 11; i++) {
    if (zipBytes[i] === 88 && zipBytes[i + 1] === 88 && zipBytes[i + 2] === 47) { // "XX/"
      zipBytes[i] = 46; // '.'
      zipBytes[i + 1] = 46; // '.'
      zipBytes[i + 2] = 47; // '/'
    }
  }

  const repZip = await runForensicScan([{
    name: 'malicious.zip',
    size: zipBytes.length,
    slice: (s, e) => ({ arrayBuffer: async () => zipBytes.slice(s, e).buffer }),
    arrayBuffer: async () => zipBytes.buffer
  }], { catalog });

  assert.equal(repZip.coverage.rejected_security.length, 2);
  assert.equal(repZip.coverage.analyzed_files, 1);

  // TAR ustar sintético contendo entrada symlink (type = '2')
  const tarBuf = new Uint8Array(1536);
  const enc = new TextEncoder();
  tarBuf.set(enc.encode('evil_link'), 0);
  tarBuf.set(enc.encode('00000000000\0'), 124);
  tarBuf[156] = '2'.charCodeAt(0); // symlink
  tarBuf.set(enc.encode('ustar'), 257);
  const repTar = await runForensicScan([{
    name: 'evil.tar',
    size: tarBuf.length,
    slice: (s, e) => ({ arrayBuffer: async () => tarBuf.slice(s, e).buffer }),
    arrayBuffer: async () => tarBuf.buffer
  }], { catalog });
  assert.equal(repTar.coverage.rejected_security.length, 1);

  // Teste de limite por entrada
  const repLim = await runForensicScan([{
    path: 'huge.txt',
    text: 'a'.repeat(500)
  }], { catalog, limits: { maxEntryBytes: 100 } });
  assert.equal(repLim.coverage.rejected_limits.length, 1);
  assert.equal(repLim.verdict.code, 'inconclusive');
});

test('09 - Free Fire normal (com.dts.freefireth) e MAX (com.dts.freefiremax): auditd granted/denied, -SHgap-, JAR e origem', async () => {
  const rep = await runForensicScan([
    {
      path: 'audit.log',
      text: [
        'auditd: type=1400 audit(0.0:1): avc: granted { execute } for comm="UnityMain" path="/data/data/com.dts.freefireth/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2" app=com.dts.freefireth',
        'auditd: type=1400 audit(0.0:2): avc: denied { execute } for comm="UnityMain" path="/data/user/0/com.dts.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2" app=com.dts.freefiremax',
        '11-22 12:00:00.000 100 100 I DexClassLoader: loaded /data/data/com.dts.freefireth/cache/app_resources_lib.jar',
        '11-22 12:01:00.000 100 100 I ChatApp: comentario com SH-Gpp2 solto sem caminho'
      ].join('\n')
    },
    {
      path: 'packages',
      text: 'Package [com.dts.freefireth] versionName=1.105\n  installerPackageName=com.android.vending\n'
    }
  ], { catalog, osHint: 'android' });

  assert.ok(rep.events.some(e => e.rule_id === 'ANDROID_GAME_SH_GPP2_EXEC_001' && e.observed.package === 'com.dts.freefireth'));
  assert.ok(rep.events.some(e => e.rule_id === 'ANDROID_GAME_SH_GPP2_DENIED_001' && e.heuristic_weight === 0));
  assert.ok(rep.events.some(e => e.rule_id === 'ANDROID_GAME_JAR_LOADED_001'));
  assert.ok(!rep.events.some(e => e.rule_id === 'ANDROID_FF_NON_PLAYSTORE_001'));
});

test('10 - Android settings (SetEdit / shell): valores padrão vs alteração anômala', async () => {
  const rep = await runForensicScan([{
    path: 'dumpsys_settings.txt',
    text: [
      'pkg:com.android.shell name=long_press_timeout value=400',
      'pkg:by4a.setedit22 name=peak_refresh_rate value=120',
      'pkg:by4a.setedit22 name=pointer_speed value=7'
    ].join('\n')
  }], { catalog, osHint: 'android' });

  const defaults = rep.events.filter(e => e.rule_id === 'ANDROID_SETTINGS_DEFAULT_001');
  const anomalies = rep.events.filter(e => e.rule_id === 'ANDROID_SETTINGS_SETEDIT_ANOMALY_001');
  assert.equal(defaults.length, 2);
  assert.equal(anomalies.length, 1);
  assert.equal(anomalies[0].observed.operation, 'pointer_speed');
});

test('11 - ADB loopback local (127.0.0.1:5555 Brevent/Shizuku) vs conexão remota real', async () => {
  const repLocal = await runForensicScan([{
    path: 'logcat.txt',
    text: '11-22 11:00:00.000  1000  1000 D adbd: socket listening on 127.0.0.1:5555\n'
  }], { catalog, osHint: 'android' });
  assert.equal(repLocal.heuristic_index, 0);
  assert.equal(repLocal.events[0].rule_id, 'ANDROID_ADB_LOCAL_LOOPBACK_001');

  const repRemote = await runForensicScan([{
    path: 'logcat.txt',
    text: '11-22 11:00:00.000  1000  1000 D adbd: client connected from 192.168.1.44:5555\n'
  }], { catalog, osHint: 'android' });
  assert.equal(repRemote.events[0].rule_id, 'ANDROID_ADB_REMOTE_001');
  assert.equal(repRemote.events[0].evidence_level, 'anomaly_review');
});

test('12 - iOS .ips JSON: itemID oficial, teamID 98573T3W6L pendente e usedImages com dylib fora do baseline', async () => {
  const cleanIps = JSON.stringify({
    bundleID: 'com.dts.freefiremax',
    procName: 'FreeFireMAX',
    distributorID: 'com.apple.AppStore',
    itemID: '1480516829',
    teamID: '98573T3W6L',
    usedImages: [{ path: '/private/var/containers/Bundle/Application/UUID/FreeFireMAX.app/FreeFireMAX' }]
  });
  const repClean = await runForensicScan([{ path: 'sysdiagnose/FreeFire.ips', text: cleanIps }], { catalog, osHint: 'ios' });
  assert.equal(repClean.heuristic_index, 0);
  assert.equal(repClean.events[0].rule_id, 'IOS_IPS_TEAMID_PENDING_001');

  const taintedIps = JSON.stringify({
    bundleID: 'com.dts.freefireth',
    procName: 'FreeFire',
    distributorID: 'com.altstore.AltStore',
    itemID: '9999999999',
    usedImages: [
      { path: '/System/Library/Frameworks/Foundation.framework/Foundation' },
      { path: '/var/jb/basebin/launchdhook.dylib' }
    ]
  });
  const repTainted = await runForensicScan([{ path: 'sysdiagnose/FreeFire.ips', text: taintedIps }], { catalog, osHint: 'ios' });
  assert.ok(repTainted.events.some(e => e.rule_id === 'IOS_IPS_USEDIMAGE_DYLIB_001'));
  assert.ok(repTainted.events.some(e => e.rule_id === 'IOS_IPS_FF_SIDELOAD_001'));
});

test('13 - Binary Plist (bplist00) é decodificado corretamente sem corrupção UTF-8', async () => {
  const bplist = buildTestBinaryPlist({
    PayloadIdentifier: 'freefireproxy.xyz',
    PayloadDisplayName: 'Proxy Test Profile'
  });
  const parsed = parseBinaryPlist(bplist);
  assert.equal(parsed.PayloadIdentifier, 'freefireproxy.xyz');

  const rep = await runForensicScan([{
    path: 'sysdiagnose/MCProfileEvents.plist',
    bytes: bplist
  }], { catalog, osHint: 'ios' });

  assert.equal(rep.events.filter(e => e.rule_id === 'IOS_PLIST_PROXY_PROFILE_001').length, 1);
  assert.equal(rep.events[0].source.format, 'bplist00');
});

test('14 - Allowlist sem extensão inclui tombstone_*, anr_*, mountinfo e lsaw.csstoredump', () => {
  assert.equal(classifyArchiveEntry('FS/data/tombstones/tombstone_09').action, 'analyze_text');
  assert.equal(classifyArchiveEntry('FS/data/anr/anr_2026-11-22').action, 'analyze_text');
  assert.equal(classifyArchiveEntry('FS/proc/123/mountinfo').action, 'analyze_text');
  assert.equal(classifyArchiveEntry('sysdiagnose/lsaw.csstoredump').action, 'analyze_text');
  assert.equal(classifyArchiveEntry('FS/sdcard/video.mp4').action, 'skip_ignored');
  assert.equal(classifyArchiveEntry('FS/data/trace.perfetto-trace').action, 'skip_ignored');
});

test('15 - Correlação exige >= 2 fontes independentes para EVIDÊNCIA CORROBORADA', async () => {
  const rep = await runForensicScan([
    {
      path: 'audit.log',
      text: 'auditd: type=1400 audit(0.0:263201): avc: granted { execute } for comm="UnityMain" path="/data/data/com.dts.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2" app=com.dts.freefiremax\n'
    },
    {
      path: 'packages',
      text: 'Package [com.dts.freefiremax] versionName=2.104\n  installerPackageName=com.whatsapp\n'
    }
  ], { catalog, osHint: 'android' });

  assert.equal(rep.verdict.code, 'corroborated_evidence');
  assert.equal(rep.verdict.status, 'EVIDÊNCIA CORROBORADA');
  assert.ok(rep.counters.corroborated_evidence >= 1);
  const sh = rep.events.find(e => e.rule_id === 'ANDROID_GAME_SH_GPP2_EXEC_001');
  assert.equal(sh.evidence_level, 'corroborated_evidence');
  assert.ok(sh.corroboration.length >= 1);
});

test('16 - Streaming em chunks de 1 MB processa arquivo > 50 MB sem travar nem usar split()', async () => {
  const sampleLine = '11-22 10:00:00.123  1000  1001 D SurfaceFlinger: frame normal-mode 0x7f1a4b20 a4 06 b9\n';
  const lineBytes = new TextEncoder().encode(sampleLine);
  const targetSize = 52 * 1024 * 1024; // > 50 MB (~52 MB)
  const repeatCount = Math.ceil(targetSize / lineBytes.length);
  const bigBuf = new Uint8Array(repeatCount * lineBytes.length);
  for (let i = 0; i < repeatCount; i++) {
    bigBuf.set(lineBytes, i * lineBytes.length);
  }

  const fakeBlob = new Blob([bigBuf]);
  fakeBlob.name = 'bugreport_52mb.txt';

  const t0 = performance.now();
  const rep = await runForensicScan([fakeBlob], { catalog, osHint: 'android' });
  const elapsedMs = performance.now() - t0;

  assert.ok(rep.coverage.checked_bytes >= 50 * 1024 * 1024);
  assert.equal(rep.coverage.checked_lines, repeatCount);
  assert.equal(rep.heuristic_index, 0);
  assert.ok(elapsedMs < 15000, `Streaming 52 MB demorou ${elapsedMs.toFixed(0)}ms`);
});
