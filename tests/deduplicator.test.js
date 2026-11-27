import test from 'node:test';
import assert from 'node:assert/strict';

import { createDeduplicator } from '../js/scan/engine/deduplicator.js';
import { buildCanonicalEvent } from '../js/scan/engine/matcher.js';

test('Deduplicator agrupa 5.000 repetições em 1 evento único sem multiplicar heuristic_weight', () => {
  const dedup = createDeduplicator();
  for (let i = 1; i <= 5000; i++) {
    dedup.add(buildCanonicalEvent({
      ruleId: 'ANDROID_OVERLAY_ACTIVE_001',
      domain: 'integridade_do_jogo',
      title: 'Overlay',
      source: { path: 'dumpsys_window.txt', format: 'dumpsys_window', line: i },
      observed: { package: 'com.zayon.optimize', operation: 'TYPE_APPLICATION_OVERLAY (2038)' },
      evidenceLevel: 'anomaly_review',
      heuristicWeight: 15,
      interpretation: 'Overlay ativo',
      recommendedAction: 'Revisar',
      dedupKey: 'ANDROID_OVERLAY_ACTIVE_001|com.zayon.optimize'
    }));
  }

  const out = dedup.finalize();
  assert.equal(out.uniqueEvents, 1);
  assert.equal(out.rawOccurrences, 5000);
  assert.equal(out.events[0].occurrence_count, 5000);
  assert.equal(out.events[0].heuristic_weight, 15);
});

test('Deduplicator ordena eventos por nível de evidência e peso heurístico', () => {
  const dedup = createDeduplicator();
  dedup.add(buildCanonicalEvent({
    ruleId: 'INFO_1', domain: 'estabilidade', title: 'Info',
    source: { path: 'a.log', format: 'log', line: 1 }, observed: {},
    evidenceLevel: 'informational', heuristicWeight: 0, interpretation: '', recommendedAction: '', dedupKey: 'i1'
  }));
  dedup.add(buildCanonicalEvent({
    ruleId: 'ANOM_1', domain: 'integridade_do_jogo', title: 'Anom',
    source: { path: 'a.log', format: 'log', line: 2 }, observed: {},
    evidenceLevel: 'anomaly_review', heuristicWeight: 25, interpretation: '', recommendedAction: '', dedupKey: 'a1'
  }));
  dedup.add(buildCanonicalEvent({
    ruleId: 'REF_1', domain: 'rede', title: 'Ref',
    source: { path: 'a.log', format: 'log', line: 3 }, observed: {},
    evidenceLevel: 'unvalidated_reference', heuristicWeight: 0, interpretation: '', recommendedAction: '', dedupKey: 'r1'
  }));

  const { events } = dedup.finalize();
  assert.deepEqual(events.map(e => e.evidence_level), ['anomaly_review', 'unvalidated_reference', 'informational']);
});
