/* ══════════════════════════════════════════════════════════════════
   ccq scan — WEB WORKER & ORQUESTRADOR STREAMING
   - Roda 100% fora da UI Thread no navegador e é importável no Node.js
   - Processa 1 entrada por vez em chunks de 1 MB com indexOf('\n')
   - Carrega catalog-rules.json sob demanda e pré-compila matcher uma única vez
   - Suporta cancelamento cooperativo e liberação de estado entre análises
   ══════════════════════════════════════════════════════════════════ */
import {
  DEFAULT_LIMITS,
  createCoverageTracker,
  forEachLineChunked,
  streamInputSource
} from './archive-reader.js';
import { createMatcher, buildCanonicalEvent } from './engine/matcher.js';
import { createDeduplicator } from './engine/deduplicator.js';
import { correlateAndBuildReport } from './engine/correlator.js';
import { canonicalizeAndroidPath, createAndroidFileAnalyzer } from './parsers/android-parser.js';
import { analyzeIosIpsText, analyzeIosPlistBytes, createIosTextAnalyzer } from './parsers/ios-parser.js';

const FF_JAR_METADATA_RE = /\/data\/(?:user\/0|data)\/(com\.dts\.freefire(?:max|th))\/cache\/(app_resources_lib\.jar|google_api_resources_lib\.jar)$/i;
const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

function detectOsFromPaths(paths) {
  let iosScore = 0;
  let androidScore = 0;
  for (const raw of paths) {
    const p = raw.toLowerCase();
    if (p.includes('sysdiagnose') || p.endsWith('.plist') || p.endsWith('.tracev3') || p.endsWith('.ips') || p.includes('mobilebackup')) {
      iosScore++;
    }
    if (p.includes('bugreport') || p.includes('logcat') || p.includes('dumpsys') || p.includes('tombstone_') || p.includes('packages')) {
      androidScore++;
    }
  }
  return iosScore > androidScore ? 'IOS' : 'ANDROID';
}

export async function runForensicScan(inputs, options = {}) {
  const t0 = typeof performance !== 'undefined' ? performance.now() : Date.now();
  const catalog = options.catalog;
  if (!catalog) {
    throw new Error('Catálogo de regras forenses não fornecido ao motor.');
  }

  const matcher = options.matcher || createMatcher(catalog);
  const limits = { ...DEFAULT_LIMITS, ...(options.limits || {}) };
  const coverage = createCoverageTracker();
  const dedup = createDeduplicator();
  const signals = new Map();
  const seenPaths = [];
  const deviceInfo = { brand: '', model: '', osVersion: '', serial: '', kernel: '' };

  const onProgress = options.onProgress || null;
  const onLog = options.onLog || null;
  const signal = options.signal || null;

  const checkCancelled = () => {
    if (signal && signal.aborted) {
      const err = new Error('Análise cancelada pelo usuário ou encerramento de sessão.');
      err.code = 'SCAN_CANCELLED';
      throw err;
    }
  };

  const emitEvent = (ev) => dedup.add(ev);
  const addSignal = (key, desc) => {
    if (!signals.has(key)) signals.set(key, desc);
  };

  await streamInputSource(inputs, {
    limits,
    coverage,
    onProgress,
    signal,
    onEntry: async (entry) => {
      checkCancelled();
      seenPaths.push(entry.path);
      const isIosFile = entry.format.startsWith('ios_') || entry.path.toLowerCase().includes('sysdiagnose');

      if (entry.action === 'analyze_metadata_only') {
        coverage.analyzed_files++;
        const cpath = canonicalizeAndroidPath(entry.path);
        const jm = FF_JAR_METADATA_RE.exec(cpath);
        if (jm) {
          emitEvent(buildCanonicalEvent({
            ruleId: 'ANDROID_GAME_JAR_PRESENT_001',
            domain: 'integridade_do_jogo',
            title: `Arquivo JAR em cache do Free Fire (${jm[2]})`,
            source: { path: entry.path, format: entry.format, line: 0 },
            observed: { process: 'ArchiveEntry', package: jm[1], operation: 'jar_entry_present', outcome: 'present_only', object_path: cpath },
            evidenceLevel: 'unvalidated_reference',
            heuristicWeight: 0,
            interpretation: `Arquivo ${jm[2]} listado no pacote ${jm[1]} sem leitura de bytecode como texto nem confirmação de carregamento ClassLoader.`,
            alternativeExplanations: ['Cache legítimo de recurso auxiliar'],
            recommendedAction: 'Verificar logs de execução/ClassLoader correspondentes.',
            dedupKey: `ANDROID_GAME_JAR_PRESENT_001|${jm[1]}|${jm[2]}`
          }));
        }
        return;
      }

      if (entry.action === 'analyze_bytes' && entry.format === 'ios_plist') {
        coverage.analyzed_files++;
        const bytes = await entry.getBytes();
        coverage.checked_bytes += bytes.byteLength;
        analyzeIosPlistBytes({
          filePath: entry.path,
          bytes,
          matcher,
          emitEvent,
          addSignal,
          deviceInfo,
          coverage
        });
        return;
      }

      if (entry.format === 'ios_ips') {
        coverage.analyzed_files++;
        const src = await entry.getSource();
        let text = '';
        if (typeof src === 'string') {
          text = src;
        } else if (src instanceof Uint8Array) {
          text = utf8Decoder.decode(src);
        } else if (src && typeof src.text === 'function') {
          text = await src.text();
        }
        coverage.checked_bytes += text.length;
        coverage.checked_lines += text ? (text.match(/\n/g) || []).length + 1 : 0;
        analyzeIosIpsText({
          filePath: entry.path,
          text,
          matcher,
          emitEvent,
          addSignal,
          coverage
        });
        return;
      }

      // Streaming linha a linha em chunks de 1 MB (sem text.split(/\r?\n/) e sem reter buffer em RAM)
      coverage.analyzed_files++;
      const src = await entry.getSource();
      const analyzer = isIosFile
        ? createIosTextAnalyzer({ filePath: entry.path, format: entry.format, matcher, emitEvent, addSignal, deviceInfo, coverage })
        : createAndroidFileAnalyzer({ filePath: entry.path, format: entry.format, matcher, emitEvent, addSignal, deviceInfo, coverage });

      const stats = await forEachLineChunked(
        src,
        (line, lineNo, prevLine, nextLine) => analyzer.feedLine(line, lineNo, prevLine, nextLine),
        {
          chunkSizeBytes: limits.chunkSizeBytes,
          onChunkProgress: (bytesRead, totalBytes) => {
            checkCancelled();
            if (onProgress && totalBytes > limits.chunkSizeBytes) {
              const ratio = Math.min(1, bytesRead / totalBytes);
              onProgress(Math.min(94, Math.round(20 + ratio * 74)), `Streaming ${entry.path.split('/').pop()} (${Math.round(ratio * 100)}%)...`);
            }
          }
        }
      );

      analyzer.finish();
      coverage.checked_lines += stats.linesRead;
      coverage.checked_bytes += stats.bytesRead;

      if (onLog && entry.size > 2 * 1024 * 1024) {
        onLog('STREAM', `${entry.path.split('/').pop()}: ${stats.linesRead.toLocaleString('pt-BR')} linhas em chunks de 1 MB.`);
      }
    }
  });

  const { events, rawOccurrences } = dedup.finalize();
  const osDetected = (options.osHint && options.osHint !== 'auto')
    ? options.osHint.toUpperCase()
    : detectOsFromPaths(seenPaths);

  const durationMs = (typeof performance !== 'undefined' ? performance.now() : Date.now()) - t0;

  return correlateAndBuildReport({
    events,
    rawOccurrences,
    signals,
    coverage,
    deviceInfo,
    osDetected,
    durationMs,
    catalogMeta: matcher.catalogMeta,
    inactiveRulesCount: matcher.inactiveTokensCount
  });
}

// ── Boot do Web Worker quando executado no Browser ──
const isWebWorkerContext =
  typeof self !== 'undefined' &&
  typeof self.postMessage === 'function' &&
  typeof window === 'undefined';

if (isWebWorkerContext) {
  let cachedCatalog = null;
  let cachedMatcher = null;
  let activeScanSignal = null;

  const ensureCatalogAndMatcher = async () => {
    if (cachedCatalog && cachedMatcher) {
      return { catalog: cachedCatalog, matcher: cachedMatcher };
    }
    const resp = await fetch(new URL('./catalog-rules.json', import.meta.url));
    if (!resp.ok) {
      throw new Error(`Falha ao carregar catalog-rules.json (HTTP ${resp.status}).`);
    }
    cachedCatalog = await resp.json();
    cachedMatcher = createMatcher(cachedCatalog);
    return { catalog: cachedCatalog, matcher: cachedMatcher };
  };

  self.onmessage = async (event) => {
    const msg = event && event.data;
    if (!msg) return;

    if (msg.type === 'CANCEL_SCAN') {
      if (activeScanSignal) activeScanSignal.aborted = true;
      return;
    }

    if (msg.type !== 'START_SCAN') return;

    if (activeScanSignal) activeScanSignal.aborted = true;
    const scanSignal = { aborted: false };
    activeScanSignal = scanSignal;

    try {
      self.postMessage({ type: 'PROGRESS', pct: 5, label: 'Inicializando catálogo forense no Worker...' });
      const { catalog, matcher } = await ensureCatalogAndMatcher();
      if (scanSignal.aborted) return;

      self.postMessage({
        type: 'LOG',
        prefix: 'WORKER',
        msg: `Catálogo ${catalog.meta.version} pré-compilado (${matcher.inactiveTokensCount} tokens curtos inativos).`,
        cssClass: 'terminal-info'
      });

      const report = await runForensicScan(msg.files || [], {
        catalog,
        matcher,
        limits: msg.limits,
        signal: scanSignal,
        onProgress: (pct, label) => {
          if (!scanSignal.aborted) self.postMessage({ type: 'PROGRESS', pct, label });
        },
        onLog: (prefix, text, cssClass = 'terminal-info') => {
          if (!scanSignal.aborted) self.postMessage({ type: 'LOG', prefix, msg: text, cssClass });
        }
      });

      if (!scanSignal.aborted) {
        self.postMessage({ type: 'RESULT', report });
      }
    } catch (err) {
      if (err && err.code === 'SCAN_CANCELLED') {
        self.postMessage({ type: 'CANCELLED' });
      } else if (!scanSignal.aborted) {
        self.postMessage({ type: 'ERROR', message: err && err.message ? err.message : String(err) });
      }
    } finally {
      if (activeScanSignal === scanSignal) activeScanSignal = null;
    }
  };
}
