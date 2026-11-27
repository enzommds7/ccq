import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import { createMatcher } from '../js/scan/engine/matcher.js';

const catalog = JSON.parse(fs.readFileSync(new URL('../js/scan/catalog-rules.json', import.meta.url), 'utf8'));

test('Matcher consome todas as categorias ativas do catálogo e mantém PROXY_SHORT_TOKENS desativado', () => {
  const matcher = createMatcher(catalog);

  // PROXY_SHORT_TOKENS desativado
  assert.equal(matcher.inactiveTokensCount, 76);
  assert.deepEqual(matcher.inactiveGroupIds, ['PROXY_SHORT_TOKENS']);

  // Pacotes Android: novos incluídos, Proxyhandler removido, sem aliases hifenizados
  assert.equal(matcher.androidPackageMap.has('com.netflix.mediaclientxx'), true);
  assert.equal(matcher.androidPackageMap.has('com.spotify.musicx'), true);
  assert.equal(matcher.androidPackageMap.has('proxyhandler'), false);
  for (const pkg of matcher.androidPackageMap.keys()) {
    assert.ok(!pkg.includes('-'), `Alias com hífen não deve estar em ANDROID_PACKAGE_CANDIDATES: ${pkg}`);
  }

  // Categorias separadas efetivamente consumidas pelo matcher
  assert.equal(matcher.overlayCandidateMap.has('com.zayon.optimize'), true);
  assert.equal(matcher.networkIpMap.has('85.31.231.237'), true);
  assert.equal(matcher.profileRefMap.has('imazing.profile'), true);
  assert.equal(matcher.profileRefMap.has('139.spotifyx'), true);
  assert.equal(matcher.profileRefMap.has('238.timx'), true);
  assert.equal(matcher.toolIndicatorMap.has('tntadb'), true);
  assert.equal(matcher.textualAliasMap.has('com-xtremo-mobile'), true);
  assert.equal(matcher.textualAliasMap.has('dash-proxy'), true);
  assert.equal(matcher.textualAliasMap.has('com-luxebypass'), true);
  assert.equal(matcher.textualAliasMap.has('freefireproxy-xyz'), true);

  // Sem duplicidades dentro de cada grupo
  for (const g of catalog.groups) {
    const lower = g.items.map(i => i.toLowerCase());
    assert.equal(new Set(lower).size, lower.length, `Grupo ${g.id} não pode ter duplicatas`);
  }
});

test('Matcher evita falsos positivos por substring em fronteiras de IP, ferramenta e aliases', () => {
  const matcher = createMatcher(catalog);

  // Substring em IP maior não deve casar 85.31.231.237
  assert.deepEqual(matcher.findAllMatches(matcher.networkIpRe, '185.31.231.2370'), []);
  assert.deepEqual(matcher.findAllMatches(matcher.networkIpRe, 'host=85.31.231.237:443'), ['85.31.231.237']);

  // Substring em ferramenta TNTADB
  assert.deepEqual(matcher.findAllMatches(matcher.toolIndicatorRe, 'MYTNTADBTOOL'), []);
  assert.deepEqual(matcher.findAllMatches(matcher.toolIndicatorRe, 'service TNTADB started'), ['TNTADB']);

  // Alias com hífen exige fronteira exata
  assert.deepEqual(matcher.findAllMatches(matcher.textualAliasRe, 'my-dash-proxy-test'), []);
  assert.deepEqual(matcher.findAllMatches(matcher.textualAliasRe, 'profile=dash-proxy;'), ['dash-proxy']);
});
