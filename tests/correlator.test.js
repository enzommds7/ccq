import test from 'node:test';
import assert from 'node:assert/strict';

import { correlateAndBuildReport } from '../js/scan/engine/correlator.js';
import { createCoverageTracker } from '../js/scan/archive-reader.js';
import { buildCanonicalEvent } from '../js/scan/engine/matcher.js';

test('Correlator impede inflação artificial de pontuação para eventos da mesma família técnica', () => {
  const cov = createCoverageTracker();
  cov.analyzed_files = 1;
  cov.boot_keys_seen.add('verifiedbootstate');

  const events = [1, 2, 3, 4, 5].map(i => buildCanonicalEvent({
    ruleId: 'ANDROID_PKG_CANDIDATE_001',
    domain: 'integridade_do_jogo',
    title: `Pkg ${i}`,
    source: { path: 'packages', format: 'packagemanager', line: i },
    observed: { package: `com.fake.pkg${i}` },
    evidenceLevel: 'anomaly_review',
    heuristicWeight: 20,
    interpretation: 'Candidato',
    recommendedAction: 'Revisar',
    dedupKey: `pkg_${i}`
  }));

  const signals = new Map([['android_candidate_pkg', '5 pacotes em PackageManager']]);
  const rep = correlateAndBuildReport({
    events,
    rawOccurrences: 5,
    signals,
    coverage: cov,
    deviceInfo: {},
    osDetected: 'ANDROID',
    durationMs: 10,
    catalogMeta: { version: '5.1-clean' },
    inactiveRulesCount: 76
  });

  // Mesma fonte técnica (apenas PackageManager): NÃO promove a corroborated_evidence e limita inflação
  assert.equal(rep.verdict.code, 'anomaly_review');
  assert.equal(rep.counters.corroborated_evidence, 0);
  assert.ok(rep.heuristic_index <= 35, `Esperado teto anti-inflação por família única, obtido ${rep.heuristic_index}`);
});

test('Correlator não gera EVIDÊNCIA CORROBORADA apenas por ADB TCP + shell settings (perfil compatível com Brevent/Shizuku)', () => {
  const cov = createCoverageTracker();
  cov.analyzed_files = 1;
  cov.boot_keys_seen.add('verifiedbootstate');

  const events = [
    buildCanonicalEvent({
      ruleId: 'ANDROID_ADB_TCP_PORT_CONFIGURED_001',
      domain: 'depuracao',
      title: 'ADB TCP 5555',
      source: { path: 'bugreport.txt', format: 'getprop', line: 1 },
      observed: { operation: 'adb_tcp_port_configured', outcome: '5555' },
      evidenceLevel: 'anomaly_review',
      heuristicWeight: 8,
      interpretation: 'Porta configurada',
      recommendedAction: 'Revisar',
      dedupKey: 'adb_5555'
    }),
    buildCanonicalEvent({
      ruleId: 'ANDROID_SETTINGS_SHELL_ANOMALY_001',
      domain: 'integridade_do_jogo',
      title: 'Shell touch_slop',
      source: { path: 'bugreport.txt', format: 'dumpsys_settings', line: 2 },
      observed: { package: 'com.android.shell', operation: 'touch_slop', outcome: '1' },
      evidenceLevel: 'anomaly_review',
      heuristicWeight: 10,
      interpretation: 'Alteração via shell',
      recommendedAction: 'Revisar',
      dedupKey: 'shell_touch'
    })
  ];

  const signals = new Map([
    ['android_adb_tcp_port', 'ADB TCP port=5555'],
    ['android_shell_settings_anomaly', 'com.android.shell touch_slop=1']
  ]);

  const rep = correlateAndBuildReport({
    events,
    rawOccurrences: 2,
    signals,
    coverage: cov,
    deviceInfo: {},
    osDetected: 'ANDROID',
    durationMs: 5,
    catalogMeta: { version: '5.1-clean' },
    inactiveRulesCount: 76
  });

  assert.equal(rep.verdict.code, 'anomaly_review');
  assert.equal(rep.counters.corroborated_evidence, 0);
});

test('Correlator promove para EVIDÊNCIA CORROBORADA com 2 fontes independentes reais sem dobrar peso para 100', () => {
  const cov = createCoverageTracker();
  cov.analyzed_files = 2;
  cov.boot_keys_seen.add('verifiedbootstate');

  const events = [
    buildCanonicalEvent({
      ruleId: 'ANDROID_OVERLAY_ACTIVE_001',
      domain: 'integridade_do_jogo',
      title: 'Overlay com.zayon.optimize',
      source: { path: 'dumpsys_window.txt', format: 'dumpsys_window', line: 10 },
      observed: { package: 'com.zayon.optimize' },
      evidenceLevel: 'anomaly_review',
      heuristicWeight: 15,
      interpretation: 'Overlay ativo',
      recommendedAction: 'Revisar',
      dedupKey: 'ov_zayon'
    }),
    buildCanonicalEvent({
      ruleId: 'ANDROID_FF_NON_PLAYSTORE_001',
      domain: 'integridade_do_jogo',
      title: 'FF fora da Play Store',
      source: { path: 'packages', format: 'packagemanager', line: 20 },
      observed: { package: 'com.dts.freefiremax' },
      evidenceLevel: 'anomaly_review',
      heuristicWeight: 30,
      interpretation: 'Instalador externo',
      recommendedAction: 'Revisar',
      dedupKey: 'ff_ext'
    })
  ];

  const signals = new Map([
    ['android_overlay_active', 'WindowToken type=2038 com.zayon.optimize'],
    ['ff_non_playstore', 'PackageManager com.dts.freefiremax via com.whatsapp']
  ]);

  const rep = correlateAndBuildReport({
    events,
    rawOccurrences: 2,
    signals,
    coverage: cov,
    deviceInfo: {},
    osDetected: 'ANDROID',
    durationMs: 12,
    catalogMeta: { version: '5.1-clean' },
    inactiveRulesCount: 76
  });

  assert.equal(rep.verdict.code, 'corroborated_evidence');
  assert.equal(rep.counters.corroborated_evidence, 2);
  // Sem inflação artificial: 15 + 30 + bônus limitado (15) = 60, não 100!
  assert.ok(rep.heuristic_index >= 55 && rep.heuristic_index < 90, `Esperado peso calibrado sem inflação, obtido ${rep.heuristic_index}`);
});
