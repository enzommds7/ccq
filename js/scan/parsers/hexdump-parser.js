/* ══════════════════════════════════════════════════════════════════
   CACIQUE SCAN v5.0 — PARSER STREAMING DE HEX DUMPS
   - Reconstrói strings/URLs da coluna ASCII contígua em tombstones/dumps
   - Trata URLs de bibliotecas open-source (ex.: GitHub) em estabilidade
     com heuristic_weight = 0 (nunca acusa trapaça)
   ══════════════════════════════════════════════════════════════════ */
import { buildCanonicalEvent } from '../engine/matcher.js';

const HEX_DUMP_LINE_RE = /^\s*([0-9a-fA-F]{8,16})\s+(?:[0-9a-fA-F]{4,16}\s+){1,8}\s+(.{1,32})\s*$/;
const URL_RE = /https?:\/\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]+/gi;

export function reconstructHexDumpLines(lines) {
  const results = [];
  let block = [];
  let startIdx = 0;

  const flush = () => {
    if (block.length === 0) return;
    const joined = block.map(b => b.ascii).join('');
    URL_RE.lastIndex = 0;
    const urls = [];
    let m;
    while ((m = URL_RE.exec(joined)) !== null) {
      urls.push(m[0]);
    }
    if (urls.length > 0) {
      results.push({
        startAddr: block[0].addr,
        endAddr: block[block.length - 1].addr,
        lineStart: startIdx + 1,
        joined,
        urls
      });
    }
    block = [];
  };

  for (let i = 0; i < lines.length; i++) {
    const m = HEX_DUMP_LINE_RE.exec(lines[i]);
    if (m) {
      if (block.length === 0) startIdx = i;
      block.push({ addr: m[1], ascii: m[2] });
    } else {
      flush();
    }
  }
  flush();
  return results;
}

export function createHexDumpParser(filePath, emitEvent) {
  let block = [];
  let firstLineNo = 0;

  const flush = () => {
    if (block.length === 0) return;
    const joined = block.map(b => b.ascii).join('');
    URL_RE.lastIndex = 0;
    const urls = [];
    let m;
    while ((m = URL_RE.exec(joined)) !== null) {
      urls.push(m[0]);
    }

    if (urls.length > 0) {
      const hasGithub = urls.some(u => u.toLowerCase().includes('github.com'));
      const urlList = urls.slice(0, 3).join(', ');
      emitEvent(buildCanonicalEvent({
        ruleId: 'HEXDUMP_URL_REF_001',
        domain: 'estabilidade',
        title: hasGithub
          ? 'URL de Biblioteca/GitHub Reconstruída em Hex Dump (Informativo)'
          : 'URL Reconstruída em Hex Dump de Memória (Informativo)',
        source: { path: filePath, format: 'hex_dump', line: firstLineNo },
        observed: {
          process: 'Crash/Memory Dump',
          operation: 'hexdump_ascii_reconstruction',
          outcome: 'reconstructed',
          object_path: urlList
        },
        evidenceLevel: 'informational',
        heuristicWeight: 0,
        interpretation: `Strings contíguas entre os endereços ${block[0].addr}..${block[block.length - 1].addr} contêm URL (${urlList}), típica de metadados de SDKs/bibliotecas embarcadas (ex.: Newtonsoft.Json).`,
        alternativeExplanations: [
          'Metadado ou licença de biblioteca open-source carregada em memória',
          'Header XML/JSON residual em dump de processo durante falha'
        ],
        recommendedAction: 'Nenhuma ação punitiva. Preservar apenas como diagnóstico de crash.',
        snippet: {
          prev_line: '',
          current_line: `Hex ${block[0].addr}..${block[block.length - 1].addr}: ${joined.slice(0, 180)}`,
          next_line: ''
        },
        dedupKey: `HEXDUMP_URL_REF_001|${filePath}|${urlList}`
      }));
    }
    block = [];
  };

  return {
    feedLine(line, lineNo) {
      const m = HEX_DUMP_LINE_RE.exec(line);
      if (m) {
        if (block.length === 0) firstLineNo = lineNo;
        block.push({ addr: m[1], ascii: m[2] });
        if (block.length >= 64) flush();
      } else {
        flush();
      }
    },
    finish() {
      flush();
    }
  };
}
