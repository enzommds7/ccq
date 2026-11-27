import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import { runForensicScan } from '../js/scan/scan.worker.js';

const catalog = JSON.parse(fs.readFileSync(new URL('../js/scan/catalog-rules.json', import.meta.url), 'utf8'));
const readFixture = (rel) => fs.readFileSync(new URL(`./fixtures/android/${rel}`, import.meta.url), 'utf8');

test('Android Settings: reconhece formatos "=" e ":", diferencia padrão, alterado e desconhecido e ignora linha quebrada', async () => {
  const rep = await runForensicScan([{
    path: 'bugreport-settings-adb.txt',
    text: readFixture('bugreport-settings-adb.txt')
  }], { catalog, osHint: 'android' });

  // Valor padrão (long_press_timeout=400) -> informational peso 0
  const def = rep.events.find(e => e.rule_id === 'ANDROID_SETTINGS_DEFAULT_001' && e.observed.operation === 'long_press_timeout');
  assert.ok(def, 'Deve registrar configuração padrão');
  assert.equal(def.evidence_level, 'informational');
  assert.equal(def.heuristic_weight, 0);
  assert.equal(def.observed.outcome, '400');

  // SetEdit alterado (name:long_press_timeout value:150) -> anomaly_review
  const setedit = rep.events.find(e => e.rule_id === 'ANDROID_SETTINGS_SETEDIT_ANOMALY_001');
  assert.ok(setedit, 'Deve detectar alteração via SetEdit com ":"');
  assert.equal(setedit.observed.operation, 'long_press_timeout');
  assert.equal(setedit.observed.outcome, '150');
  assert.equal(setedit.observed.package, 'by4a.setedit22');
  assert.equal(setedit.evidence_level, 'anomaly_review');

  // Shell alterado com baseline conhecido (touch_slop, multi_press_timeout, activity_starts_logging_enabled)
  const shellAnom = rep.events.filter(e => e.rule_id === 'ANDROID_SETTINGS_SHELL_ANOMALY_001');
  assert.equal(shellAnom.length, 3);
  const touchSlop = shellAnom.find(e => e.observed.operation === 'touch_slop');
  assert.ok(touchSlop);
  assert.equal(touchSlop.observed.outcome, '1');
  assert.equal(touchSlop.domain, 'integridade_do_jogo');
  assert.equal(touchSlop.evidence_level, 'anomaly_review');

  const logDisabled = shellAnom.find(e => e.observed.operation === 'activity_starts_logging_enabled');
  assert.ok(logDisabled);
  assert.equal(logDisabled.observed.outcome, '0');
  assert.equal(logDisabled.domain, 'seguranca_do_dispositivo');

  // Configuração desconhecida -> unvalidated_reference com peso 0 (nunca acusar automaticamente)
  const unknownPref = rep.events.find(e => e.rule_id === 'ANDROID_SETTINGS_UNKNOWN_001' && e.observed.operation === 'oem_custom_unknown_pref');
  assert.ok(unknownPref, 'Configuração desconhecida deve virar unvalidated_reference');
  assert.equal(unknownPref.evidence_level, 'unvalidated_reference');
  assert.equal(unknownPref.heuristic_weight, 0);

  // Linha com campo value ausente (broken_entry_no_value) -> NÃO gera anomalia
  assert.ok(!rep.events.some(e => e.observed.operation === 'broken_entry_no_value'));
});

test('Android ADB: diferencia porta configurada, serviço ativo, loopback, conexão remota, USB, wireless e forward', async () => {
  // 1. Porta configurada sem conexão estabelecida ([service.adb.tcp.port]: [5555])
  const repPortOnly = await runForensicScan([{
    path: 'bugreport-port.txt',
    text: '[ro.boot.verifiedbootstate]: [green]\n[service.adb.tcp.port]: [5555]\n[persist.adb.tcp.port]: []\n[init.svc.adbd]: [running]\n'
  }], { catalog, osHint: 'android' });
  const portEv = repPortOnly.events.find(e => e.rule_id === 'ANDROID_ADB_TCP_PORT_CONFIGURED_001');
  assert.ok(portEv, 'Deve reconhecer [service.adb.tcp.port]: [5555]');
  assert.equal(portEv.evidence_level, 'anomaly_review');
  assert.equal(portEv.domain, 'depuracao');
  assert.equal(portEv.observed.outcome, '5555');
  assert.ok(!repPortOnly.events.some(e => e.rule_id === 'ANDROID_ADB_REMOTE_001'), 'Porta configurada não é conexão remota estabelecida');
  assert.ok(repPortOnly.events.some(e => e.rule_id === 'ANDROID_ADB_SERVICE_ACTIVE_001' && e.evidence_level === 'informational'));

  // 2. Loopback local (Brevent/Shizuku) -> informational peso 0
  const repLoop = await runForensicScan([{
    path: 'logcat.txt',
    text: '11-27 10:00:00.000 1000 1000 D adbd: socket listening on 127.0.0.1:5555\n'
  }], { catalog, osHint: 'android' });
  assert.equal(repLoop.heuristic_index, 0);
  assert.ok(repLoop.events.some(e => e.rule_id === 'ANDROID_ADB_LOCAL_LOOPBACK_001' && e.evidence_level === 'informational'));

  // 3. Conexão remota efetivamente registrada -> anomaly_review distinto
  const repRemote = await runForensicScan([{
    path: 'logcat.txt',
    text: '11-27 10:01:00.000 1000 1000 I adbd: client connected from 192.168.1.44:5555\n'
  }], { catalog, osHint: 'android' });
  assert.ok(repRemote.events.some(e => e.rule_id === 'ANDROID_ADB_REMOTE_001' && e.evidence_level === 'anomaly_review'));

  // 4. Depuração USB e Wireless isoladas -> informational peso 0
  const repUsbWifi = await runForensicScan([{
    path: 'dumpsys_adb.txt',
    text: 'adb_enabled=1\nadb_wifi_enabled=1\npersist.sys.usb.config=mtp,adb\n'
  }], { catalog, osHint: 'android' });
  assert.equal(repUsbWifi.heuristic_index, 0);
  assert.ok(repUsbWifi.events.some(e => e.rule_id === 'ANDROID_ADB_USB_DEBUGGING_001'));
  assert.ok(repUsbWifi.events.some(e => e.rule_id === 'ANDROID_ADB_WIRELESS_DEBUGGING_001'));

  // 5. Encaminhamento de portas (adb forward / reverse) -> anomaly_review específico
  const repFwd = await runForensicScan([{
    path: 'logcat.txt',
    text: '11-27 10:05:00.000 2000 2000 I shell: adb reverse tcp:8080 tcp:8080\n'
  }], { catalog, osHint: 'android' });
  assert.ok(repFwd.events.some(e => e.rule_id === 'ANDROID_ADB_PORT_FORWARD_001' && e.evidence_level === 'anomaly_review'));
});

test('Android SH-Gpp2 auditd: com app=, sem app=, denied, processo incompatível e ausência de execute', async () => {
  const rep = await runForensicScan([{
    path: 'audit.log',
    text: readFixture('auditd-shgpp2.log')
  }], { catalog, osHint: 'android' });

  // granted + execute com app= e sem app= (inferido via canonical_path)
  const execs = rep.events.filter(e => e.rule_id === 'ANDROID_GAME_SH_GPP2_EXEC_001');
  assert.equal(execs.length, 2);
  assert.ok(execs.some(e => e.observed.package === 'com.dts.freefiremax'));
  const ffNormal = execs.find(e => e.observed.package === 'com.dts.freefireth');
  assert.ok(ffNormal, 'Deve extrair com.dts.freefireth do canonical_path quando app= estiver ausente');
  assert.equal(ffNormal.observed.process, 'UnityMain');

  // denied -> informational peso 0
  const denied = rep.events.find(e => e.rule_id === 'ANDROID_GAME_SH_GPP2_DENIED_001');
  assert.ok(denied);
  assert.equal(denied.evidence_level, 'informational');
  assert.equal(denied.heuristic_weight, 0);

  // processo/app incompatível com o dono do arquivo -> inconsistência contextual explícita
  const mismatch = rep.events.find(e => e.rule_id === 'ANDROID_GAME_SH_GPP2_CTX_MISMATCH_001');
  assert.ok(mismatch, 'Deve registrar inconsistência contextual quando processo/app não corresponde ao dono do arquivo');
  assert.equal(mismatch.evidence_level, 'anomaly_review');
  assert.equal(mismatch.observed.package, 'com.dts.freefiremax');
  assert.equal(mismatch.observed.process, 'sh');

  // granted apenas read sem execute/comm -> não presumir execução (unvalidated_reference, peso 0)
  const refOnly = rep.events.find(e => e.rule_id === 'ANDROID_GAME_SH_GPP2_PATH_REF_001');
  assert.ok(refOnly);
  assert.equal(refOnly.evidence_level, 'unvalidated_reference');
  assert.equal(refOnly.heuristic_weight, 0);
});

test('Android Overlays: ignora sistema/OEM, trata legítimos como informativos e marca candidatos/terceiros com contexto', async () => {
  const rep = await runForensicScan([{
    path: 'dumpsys_window.txt',
    text: readFixture('dumpsys-window-overlays.txt')
  }], { catalog, osHint: 'android' });

  const suspicious = rep.events.filter(e => e.rule_id === 'ANDROID_OVERLAY_ACTIVE_001');
  assert.equal(suspicious.length, 2, 'Deve sinalizar apenas com.zayon.optimize e com.unknown.floatmenu');

  const zayon = suspicious.find(e => e.observed.package === 'com.zayon.optimize');
  assert.ok(zayon);
  assert.equal(zayon.evidence_level, 'anomaly_review');
  assert.equal(zayon.observed.foreground_app, 'com.dts.freefiremax');
  assert.equal(zayon.observed.visibility, 'visible');
  assert.ok(zayon.observed.window_name.includes('OverlayPanel'));

  // Overlay legítimo conhecido (WhatsApp) -> informational peso 0
  const wa = rep.events.find(e => e.rule_id === 'ANDROID_OVERLAY_LEGITIMATE_001' && e.observed.package === 'com.whatsapp');
  assert.ok(wa, 'Overlay legítimo conhecido deve ser informational peso 0');
  assert.equal(wa.heuristic_weight, 0);

  // Nenhum sistema/OEM/ShellDropTarget/Shell Root Leash deve gerar anomalia
  assert.ok(!suspicious.some(e => /(android$|com\.android\.|com\.google\.|com\.miui\.|com\.transsion\.|ShellDropTarget|Shell Root Leash)/i.test(e.observed.package)));
});

test('Android: detecta indicadores v5.1 com contexto técnico e rejeita Proxyhandler genérico', async () => {
  const rep = await runForensicScan([
    {
      path: 'packages',
      text: [
        'Package [com.netflix.mediaclientxx] versionName=1.0',
        '  installerPackageName=null',
        'Package [com.spotify.musicx] versionName=2.0',
        '  installerPackageName=null',
        'Package [Proxyhandler] versionName=1.0',
        '  installerPackageName=com.android.vending'
      ].join('\n')
    },
    {
      path: 'network.log',
      text: '11-27 12:00:00.000 100 100 I Net: connect host=85.31.231.237 dns=freefireproxy-xyz alias=dash-proxy\n'
    },
    {
      path: 'logcat.txt',
      text: '11-27 12:01:00.000 200 200 I shell: starting service TNTADB\n'
    }
  ], { catalog, osHint: 'android' });

  assert.ok(rep.events.some(e => e.rule_id === 'ANDROID_PKG_CANDIDATE_001' && e.observed.package === 'com.netflix.mediaclientxx'));
  assert.ok(rep.events.some(e => e.rule_id === 'ANDROID_PKG_CANDIDATE_001' && e.observed.package === 'com.spotify.musicx'));
  assert.ok(!rep.events.some(e => e.observed.package === 'Proxyhandler'), 'Proxyhandler foi removido de ANDROID_PACKAGE_CANDIDATES');
  assert.ok(rep.events.some(e => e.rule_id === 'NETWORK_IP_CANDIDATE_001' && e.observed.object_path === '85.31.231.237'));
  assert.ok(rep.events.some(e => e.rule_id === 'PROXY_ALIAS_CANDIDATE_001' && e.observed.object_path === 'freefireproxy-xyz'));
  assert.ok(rep.events.some(e => e.rule_id === 'TOOL_INDICATOR_CANDIDATE_001' && e.observed.object_path === 'TNTADB'));
});
