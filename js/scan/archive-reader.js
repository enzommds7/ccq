/* ══════════════════════════════════════════════════════════════════
   CACIQUE SCAN v5.0 — ARCHIVE READER SEGURO & STREAMING
   - Suporta ZIP (JSZip lazy em Worker/Node), TAR, TAR.GZ e arquivos soltos
   - Bloqueia Path Traversal (../), symlinks e explosão de tamanho
   - Leitura em chunks de 1 MB com indexOf('\n') — zero split() total
   ══════════════════════════════════════════════════════════════════ */

export const DEFAULT_LIMITS = Object.freeze({
  maxRelevantEntries: 500,
  maxEntryBytes: 120 * 1024 * 1024,
  maxTotalUncompressedBytes: 512 * 1024 * 1024,
  maxBinaryEntryBytes: 15 * 1024 * 1024,
  chunkSizeBytes: 1024 * 1024
});

const IGNORED_EXTENSIONS = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'ico', 'heic',
  'mp4', 'mov', 'avi', 'mkv', 'mp3', 'wav', 'ogg', 'm4a',
  'ttf', 'otf', 'woff', 'woff2',
  'pb', 'proto', 'perfetto-trace', 'hprof', 'apk', 'arsc',
  'vdex', 'odex', 'oat', 'zip', 'gz', 'tar', 'tgz', 'dmg', 'ipa'
]);

const TEXT_EXTENSIONS = new Set([
  'txt', 'log', 'prop', 'xml', 'json', 'csv', 'conf', 'cfg',
  'properties', 'yaml', 'yml', 'ini', 'md', 'dump', 'out'
]);

const NO_EXT_ALLOWLIST = new Set([
  'packages', 'services', 'dumpsys', 'logcat',
  'procrank', 'processes', 'bugreport', 'meminfo',
  'cpuinfo', 'batterystats', 'usage_stats', 'settings',
  'audit', 'selinux', 'getprop', 'ps', 'mounts',
  'mountinfo', 'lsaw.csstoredump'
]);

const ARCHIVE_RE = /\.(zip|tar\.gz|tgz|tar|gz)$/i;
const latin1Decoder = new TextDecoder('latin1');
const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

export function createCoverageTracker() {
  return {
    total_container_entries: 0,
    analyzed_files: 0,
    skipped_ignored: 0,
    checked_lines: 0,
    checked_bytes: 0,
    unsupported_files: [],
    ignored_auxiliary: [],
    rejected_limits: [],
    rejected_security: [],
    gaps: [],
    logging_diagnostics: new Set(),
    boot_keys_seen: new Set(),
    saw_bugreport: false,
    saw_getprop: false,
    saw_packagemanager: false,
    saw_ios_unified_log: false,
    saw_ios_ips: false,
    saw_ios_plist: false,
    status: 'completa'
  };
}

export function sanitizeArchivePath(rawPath) {
  if (typeof rawPath !== 'string' || !rawPath.trim()) {
    return { ok: false, reason: 'empty_path' };
  }
  if (rawPath.includes('\0')) {
    return { ok: false, reason: 'null_byte' };
  }

  const slashPath = rawPath.replace(/\\/g, '/').trim();
  if (slashPath.startsWith('/') || /^[a-zA-Z]:/.test(slashPath)) {
    return { ok: false, reason: 'absolute_path' };
  }

  const segments = slashPath.split('/');
  const clean = [];
  for (const seg of segments) {
    if (!seg || seg === '.') continue;
    if (seg === '..') {
      return { ok: false, reason: 'path_traversal' };
    }
    clean.push(seg);
  }

  if (clean.length === 0) {
    return { ok: false, reason: 'empty_path' };
  }
  return { ok: true, normalized: clean.join('/') };
}

export function isIosAuxiliaryCatalogPath(normalizedPath) {
  const segs = normalizedPath.toLowerCase().split('/');
  return segs.includes('uuidtext') || segs.includes('dsc') || segs.includes('timesync');
}

function getExtension(lowerBase) {
  const idx = lowerBase.lastIndexOf('.');
  if (idx <= 0 || idx === lowerBase.length - 1) return '';
  return lowerBase.slice(idx + 1);
}

export function classifyArchiveEntry(normalizedPath, sizeBytes = 0, limits = DEFAULT_LIMITS, isLooseInput = false) {
  const lower = normalizedPath.toLowerCase();
  const base = lower.split('/').pop() || '';
  const ext = getExtension(base);

  if (isIosAuxiliaryCatalogPath(lower)) {
    return {
      action: 'ignore_aux',
      format: 'ios_logarchive_aux',
      reason: 'Catálogo auxiliar binário de system_logs.logarchive (UUIDText/DSC/timesync) excluído da varredura textual.'
    };
  }

  if (lower.endsWith('.tracev3')) {
    return {
      action: 'unsupported',
      format: 'ios_tracev3',
      reason: "Arquivo binário Apple Unified Log (.tracev3) requer conversão externa (ex.: macOS 'log show'); não varrido como texto."
    };
  }

  // Verificar extensão de mídia/binário pesado antes de descomprimir
  if (IGNORED_EXTENSIONS.has(ext) || lower.endsWith('.perfetto-trace')) {
    return { action: 'skip_ignored', format: 'ignored_media_or_bin' };
  }

  if (sizeBytes > limits.maxEntryBytes) {
    return {
      action: 'reject_limit',
      format: 'oversized_entry',
      reason: `Entrada excede limite máximo de ${(limits.maxEntryBytes / (1024 * 1024)).toFixed(0)} MB (${(sizeBytes / (1024 * 1024)).toFixed(1)} MB).`
    };
  }

  if (ext === 'ips' || lower.includes('crashreporter')) {
    return { action: 'analyze_text', format: 'ios_ips' };
  }

  if (ext === 'plist' || ext === 'mobileconfig') {
    return { action: 'analyze_bytes', format: 'ios_plist' };
  }

  if (ext === 'jar') {
    return { action: 'analyze_metadata_only', format: 'android_jar_entry' };
  }

  if (base.startsWith('tombstone_')) {
    return { action: 'analyze_text', format: 'android_tombstone' };
  }
  if (base.startsWith('anr_')) {
    return { action: 'analyze_text', format: 'android_anr' };
  }
  if (base === 'mountinfo') {
    return { action: 'analyze_text', format: 'android_mountinfo' };
  }
  if (base === 'lsaw.csstoredump') {
    return { action: 'analyze_text', format: 'ios_lsaw' };
  }

  if (NO_EXT_ALLOWLIST.has(base) || base.startsWith('bugreport') || base.startsWith('logcat') || base.startsWith('dumpsys')) {
    return { action: 'analyze_text', format: base.startsWith('logcat') ? 'android_logcat' : 'android_bugreport' };
  }

  if (lower.includes('sh-gpp2') || lower.includes('-shgap-')) {
    return { action: 'analyze_metadata_and_text', format: 'android_gameasset_ref' };
  }

  if (TEXT_EXTENSIONS.has(ext)) {
    if (lower.includes('sysdiagnose') || base.includes('system_logs') || base.includes('unified')) {
      return { action: 'analyze_text', format: 'ios_unified_log' };
    }
    return { action: 'analyze_text', format: 'text_log' };
  }

  if (lower.includes('bugreport') || lower.includes('logcat')) {
    return { action: 'analyze_text', format: 'android_bugreport' };
  }
  if (lower.includes('sysdiagnose')) {
    return { action: 'analyze_text', format: 'ios_unified_log' };
  }

  if (isLooseInput) {
    return { action: 'analyze_text', format: 'text_log' };
  }

  return { action: 'skip_ignored', format: 'unrecognized' };
}

/**
 * Lê um Blob/File, Uint8Array ou string linha por linha usando chunks de 1 MB e indexOf('\n').
 * Nunca divide o arquivo inteiro com split(/\r?\n/).
 */
export async function forEachLineChunked(source, onLine, options = {}) {
  const chunkSize = options.chunkSizeBytes || DEFAULT_LIMITS.chunkSizeBytes;
  const onChunkProgress = options.onChunkProgress || null;

  let linesRead = 0;
  let bytesRead = 0;
  let prevLine = '';
  let currLine = null;

  const dispatchLine = (nextLine) => {
    if (currLine !== null) {
      linesRead++;
      onLine(currLine, linesRead, prevLine, nextLine || '');
      prevLine = currLine.slice(0, 220);
    }
    currLine = nextLine;
  };

  if (typeof source === 'string') {
    const total = source.length;
    let pos = 0;
    let lastProgressAt = 0;
    while (pos < total) {
      let nl = source.indexOf('\n', pos);
      if (nl === -1) nl = total;
      let line = source.slice(pos, nl);
      if (line.endsWith('\r')) line = line.slice(0, -1);
      dispatchLine(line);
      pos = nl + 1;

      if (onChunkProgress && pos - lastProgressAt >= chunkSize) {
        lastProgressAt = pos;
        onChunkProgress(pos, total);
      }
    }
    if (currLine !== null) {
      linesRead++;
      onLine(currLine, linesRead, prevLine, '');
    }
    return { linesRead, bytesRead: total };
  }

  const isBytes = source instanceof Uint8Array;
  const totalBytes = isBytes ? source.length : (source && typeof source.size === 'number' ? source.size : 0);
  const decoder = new TextDecoder('utf-8', { fatal: false });
  let carry = '';
  let offset = 0;

  while (offset < totalBytes) {
    const end = Math.min(totalBytes, offset + chunkSize);
    let u8;
    if (isBytes) {
      u8 = source.subarray(offset, end);
    } else {
      const sliceBlob = source.slice(offset, end);
      const ab = await sliceBlob.arrayBuffer();
      u8 = new Uint8Array(ab);
    }

    const isLast = end >= totalBytes;
    const textChunk = decoder.decode(u8, { stream: !isLast });
    const combined = carry ? (carry + textChunk) : textChunk;
    let pos = 0;

    while (true) {
      const nl = combined.indexOf('\n', pos);
      if (nl === -1) {
        carry = combined.slice(pos);
        break;
      }
      let line = combined.slice(pos, nl);
      if (line.endsWith('\r')) line = line.slice(0, -1);
      dispatchLine(line);
      pos = nl + 1;
    }

    offset = end;
    bytesRead = offset;
    if (onChunkProgress) onChunkProgress(bytesRead, totalBytes);
  }

  if (carry.length > 0) {
    if (carry.endsWith('\r')) carry = carry.slice(0, -1);
    dispatchLine(carry);
  }
  if (currLine !== null) {
    linesRead++;
    onLine(currLine, linesRead, prevLine, '');
  }

  return { linesRead, bytesRead };
}

let cachedJSZip = null;

export async function loadJSZip() {
  if (cachedJSZip) return cachedJSZip;
  if (typeof globalThis !== 'undefined' && typeof globalThis.JSZip === 'function') {
    cachedJSZip = globalThis.JSZip;
    return cachedJSZip;
  }

  // Node.js environment
  if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    const { createRequire } = await import('node:module');
    const req = createRequire(import.meta.url);
    const mod = req('../../jszip.min.js');
    cachedJSZip = (typeof mod === 'function') ? mod : globalThis.JSZip;
    if (typeof cachedJSZip === 'function') return cachedJSZip;
  }

  // Browser Module Web Worker (importScripts é proibido em module workers)
  try {
    await import(new URL('../../jszip.min.js', import.meta.url).href);
    if (typeof self !== 'undefined' && typeof self.JSZip === 'function') {
      cachedJSZip = self.JSZip;
      return cachedJSZip;
    }
  } catch (_) {}

  await import('https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js');
  if (typeof self !== 'undefined' && typeof self.JSZip === 'function') {
    cachedJSZip = self.JSZip;
    return cachedJSZip;
  }
  throw new Error('Não foi possível inicializar JSZip sob demanda no Worker.');
}

async function gunzipWithLimit(source, maxBytes) {
  if (typeof DecompressionStream === 'undefined') {
    throw new Error('Navegador sem suporte a DecompressionStream gzip. Extraia o pacote e use "Pasta extraída".');
  }
  const readable = (source instanceof Uint8Array)
    ? new Response(source).body
    : source.stream();
  const stream = readable.pipeThrough(new DecompressionStream('gzip'));
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        const err = new Error(`Descompressão gzip excedeu limite máximo de ${(maxBytes / (1024 * 1024)).toFixed(0)} MB.`);
        err.code = 'LIMIT_EXCEEDED';
        throw err;
      }
      chunks.push(value);
    }
  }

  const out = new Uint8Array(total);
  let off = 0;
  for (const ch of chunks) {
    out.set(ch, off);
    off += ch.byteLength;
  }
  return out;
}

function isZipMagic(bytes) {
  return bytes && bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b;
}

function isUstarMagic(buf) {
  return buf.length >= 512 && latin1Decoder.decode(buf.subarray(257, 262)) === 'ustar';
}

function isVirtualInputFile(item) {
  return item && typeof item === 'object' && ('text' in item || 'bytes' in item) && typeof item.arrayBuffer !== 'function';
}

async function readItemHeadBytes(item, n = 4) {
  if (item.bytes instanceof Uint8Array) return item.bytes.subarray(0, n);
  if (typeof item.slice === 'function') {
    const ab = await item.slice(0, n).arrayBuffer();
    return new Uint8Array(ab);
  }
  return new Uint8Array(0);
}

async function readItemAsUint8Array(item) {
  if (item.bytes instanceof Uint8Array) return item.bytes;
  if (typeof item.arrayBuffer === 'function') {
    return new Uint8Array(await item.arrayBuffer());
  }
  if (typeof item.text === 'string') {
    return new TextEncoder().encode(item.text);
  }
  return new Uint8Array(0);
}

async function processSingleVirtualOrRawEntry({ rawPath, sizeBytes, isLoose, getBytes, getSourceForStreaming, limits, coverage, onEntry }) {
  coverage.total_container_entries++;

  const san = sanitizeArchivePath(rawPath);
  if (!san.ok) {
    coverage.rejected_security.push({ file: String(rawPath || ''), reason: `Caminho inseguro rejeitado (${san.reason})` });
    return;
  }

  const cls = classifyArchiveEntry(san.normalized, sizeBytes, limits, isLoose);
  if (cls.action === 'ignore_aux') {
    coverage.ignored_auxiliary.push({ file: san.normalized, reason: cls.reason });
    return;
  }
  if (cls.action === 'unsupported') {
    coverage.unsupported_files.push({ file: san.normalized, reason: cls.reason });
    return;
  }
  if (cls.action === 'reject_limit') {
    coverage.rejected_limits.push({ file: san.normalized, reason: cls.reason });
    return;
  }
  if (cls.action === 'skip_ignored') {
    coverage.skipped_ignored++;
    return;
  }

  if (coverage.analyzed_files >= limits.maxRelevantEntries) {
    coverage.rejected_limits.push({
      file: san.normalized,
      reason: `Limite máximo de ${limits.maxRelevantEntries} entradas relevantes atingido.`
    });
    return;
  }

  await onEntry({
    path: san.normalized,
    format: cls.format,
    action: cls.action,
    size: sizeBytes,
    getBytes,
    getSource: getSourceForStreaming
  });
}

async function streamZipArchive(item, limits, coverage, onEntry, onProgress) {
  const JSZip = await loadJSZip();
  if (onProgress) onProgress(12, `Indexando ZIP ${item.name || 'arquivo.zip'}...`);

  const rawBuf = await readItemAsUint8Array(item);
  const zip = await JSZip.loadAsync(rawBuf);
  const allEntries = Object.values(zip.files);
  let accumulatedUncompressed = 0;

  for (let i = 0; i < allEntries.length; i++) {
    const zEntry = allEntries[i];
    if (zEntry.dir) continue;

    coverage.total_container_entries++;
    const rawZipPath = zEntry.unsafeOriginalName || zEntry.name;
    const san = sanitizeArchivePath(rawZipPath);
    if (!san.ok) {
      coverage.rejected_security.push({ file: rawZipPath, reason: `Path traversal / caminho inválido rejeitado (${san.reason})` });
      continue;
    }

    // Bloquear symlink Unix em ZIP (S_IFLNK = 0o120000)
    if (typeof zEntry.unixPermissions === 'number' && (zEntry.unixPermissions & 0o170000) === 0o120000) {
      coverage.rejected_security.push({ file: san.normalized, reason: 'Link simbólico em ZIP rejeitado por segurança.' });
      continue;
    }

    const declaredSize = (zEntry._data && typeof zEntry._data.uncompressedSize === 'number')
      ? zEntry._data.uncompressedSize
      : 0;

    const cls = classifyArchiveEntry(san.normalized, declaredSize, limits, false);
    if (cls.action === 'ignore_aux') {
      coverage.ignored_auxiliary.push({ file: san.normalized, reason: cls.reason });
      continue;
    }
    if (cls.action === 'unsupported') {
      coverage.unsupported_files.push({ file: san.normalized, reason: cls.reason });
      continue;
    }
    if (cls.action === 'reject_limit') {
      coverage.rejected_limits.push({ file: san.normalized, reason: cls.reason });
      continue;
    }
    if (cls.action === 'skip_ignored') {
      coverage.skipped_ignored++;
      continue;
    }

    if (coverage.analyzed_files >= limits.maxRelevantEntries) {
      coverage.rejected_limits.push({
        file: san.normalized,
        reason: `Limite máximo de ${limits.maxRelevantEntries} entradas relevantes atingido.`
      });
      continue;
    }

    if (onProgress) {
      const pct = Math.min(88, 15 + Math.round((i / Math.max(1, allEntries.length)) * 70));
      onProgress(pct, `Extraindo (${i + 1}/${allEntries.length}): ${san.normalized.split('/').pop()}`);
    }

    if (cls.action === 'analyze_metadata_only') {
      await onEntry({
        path: san.normalized,
        format: cls.format,
        action: cls.action,
        size: declaredSize,
        getBytes: async () => new Uint8Array(0),
        getSource: async () => ''
      });
      continue;
    }

    // Descompacta apenas 1 entrada por vez e verifica tamanho real pós-descompactação (anti zip-bomb)
    const u8 = await zEntry.async('uint8array');
    if (u8.byteLength > limits.maxEntryBytes) {
      coverage.rejected_limits.push({
        file: san.normalized,
        reason: `Tamanho real descomprimido (${(u8.byteLength / (1024 * 1024)).toFixed(1)} MB) excede limite de ${(limits.maxEntryBytes / (1024 * 1024)).toFixed(0)} MB.`
      });
      continue;
    }

    accumulatedUncompressed += u8.byteLength;
    if (accumulatedUncompressed > limits.maxTotalUncompressedBytes) {
      coverage.rejected_limits.push({
        file: san.normalized,
        reason: `Volume total descomprimido excedeu ${(limits.maxTotalUncompressedBytes / (1024 * 1024)).toFixed(0)} MB.`
      });
      break;
    }

    await onEntry({
      path: san.normalized,
      format: cls.format,
      action: cls.action,
      size: u8.byteLength,
      getBytes: async () => u8,
      getSource: async () => u8
    });
  }
}

async function streamTarOrGzip(item, limits, coverage, onEntry, onProgress) {
  const lower = (item.name || '').toLowerCase();
  if (onProgress) onProgress(12, `Descomprimindo ${item.name || 'container'}...`);

  let raw;
  try {
    if (lower.endsWith('.tar')) {
      raw = await readItemAsUint8Array(item);
      if (raw.byteLength > limits.maxTotalUncompressedBytes) {
        coverage.rejected_limits.push({
          file: item.name || 'archive.tar',
          reason: `Arquivo TAR excede limite de ${(limits.maxTotalUncompressedBytes / (1024 * 1024)).toFixed(0)} MB.`
        });
        return;
      }
    } else {
      const sourceStreamable = (item.bytes instanceof Uint8Array) ? item.bytes : item;
      raw = await gunzipWithLimit(sourceStreamable, limits.maxTotalUncompressedBytes);
    }
  } catch (err) {
    if (err && err.code === 'LIMIT_EXCEEDED') {
      coverage.rejected_limits.push({ file: item.name || 'archive.gz', reason: err.message });
      return;
    }
    throw err;
  }

  if (isUstarMagic(raw)) {
    const cstr = (b) => latin1Decoder.decode(b).replace(/\0[\s\S]*$/, '');
    let off = 0;
    let pendingName = null;

    while (off + 512 <= raw.length) {
      const h = raw.subarray(off, off + 512);
      if (h[0] === 0 && h.every(b => b === 0)) break;

      let name = cstr(h.subarray(0, 100));
      const prefix = cstr(h.subarray(345, 500));
      const size = parseInt(cstr(h.subarray(124, 136)).trim() || '0', 8) || 0;
      const type = String.fromCharCode(h[156] || 48);
      const dataStart = off + 512;
      const data = raw.subarray(dataStart, dataStart + size);

      if (type === 'L') {
        pendingName = cstr(data);
      } else if (type === 'x') {
        const m = utf8Decoder.decode(data).match(/\d+ path=([^\n]+)\n/);
        if (m) pendingName = m[1];
      } else if (type === '1' || type === '2') {
        const linkPath = pendingName || (prefix ? `${prefix}/${name}` : name);
        coverage.rejected_security.push({
          file: linkPath,
          reason: `Link simbólico/hardlink (type=${type}) em TAR rejeitado por segurança.`
        });
        pendingName = null;
      } else if (type === '0' || type === '7') {
        if (pendingName) name = pendingName;
        else if (prefix) name = `${prefix}/${name}`;
        pendingName = null;

        await processSingleVirtualOrRawEntry({
          rawPath: name,
          sizeBytes: size,
          isLoose: false,
          getBytes: async () => data,
          getSourceForStreaming: async () => data,
          limits,
          coverage,
          onEntry
        });
      } else if (type !== 'g') {
        pendingName = null;
      }
      off = dataStart + Math.ceil(size / 512) * 512;
    }
    return;
  }

  // Arquivo .gz simples contendo um único log
  const cleanName = (item.name || 'log.txt').replace(/\.gz$/i, '') || 'log.txt';
  await processSingleVirtualOrRawEntry({
    rawPath: cleanName,
    sizeBytes: raw.byteLength,
    isLoose: true,
    getBytes: async () => raw,
    getSourceForStreaming: async () => raw,
    limits,
    coverage,
    onEntry
  });
}

export async function streamInputSource(inputs, options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...(options.limits || {}) };
  const coverage = options.coverage || createCoverageTracker();
  const onEntry = options.onEntry;
  const onProgress = options.onProgress || null;

  const list = Array.from(inputs || []);
  for (let i = 0; i < list.length; i++) {
    const item = list[i];

    // Entrada virtual direta (usada pelos testes ou logs em memória): { path, text, bytes }
    if (isVirtualInputFile(item)) {
      const p = item.path || item.name || 'unknown.txt';
      const bytesLen = item.bytes ? item.bytes.byteLength : (typeof item.text === 'string' ? item.text.length : 0);

      if (bytesLen > limits.maxEntryBytes) {
        const san = sanitizeArchivePath(p);
        coverage.rejected_limits.push({
          file: san.ok ? san.normalized : p,
          reason: `Entrada excede limite máximo de ${(limits.maxEntryBytes / (1024 * 1024)).toFixed(0)} MB.`
        });
        continue;
      }

      await processSingleVirtualOrRawEntry({
        rawPath: p,
        sizeBytes: bytesLen,
        isLoose: true,
        getBytes: async () => {
          if (item.bytes instanceof Uint8Array) return item.bytes;
          return new TextEncoder().encode(item.text || '');
        },
        getSourceForStreaming: async () => {
          if (typeof item.text === 'string') return item.text;
          if (item.bytes instanceof Uint8Array) return item.bytes;
          return '';
        },
        limits,
        coverage,
        onEntry
      });
      continue;
    }

    // File / Blob do navegador
    const rawName = item.webkitRelativePath || item.name || 'unknown.txt';
    const isSingleArchive = list.length === 1 && ARCHIVE_RE.test(rawName);
    const head = isSingleArchive ? await readItemHeadBytes(item, 4) : null;

    if (isSingleArchive && (rawName.toLowerCase().endsWith('.zip') || isZipMagic(head))) {
      await streamZipArchive(item, limits, coverage, onEntry, onProgress);
      continue;
    }
    if (isSingleArchive) {
      await streamTarOrGzip(item, limits, coverage, onEntry, onProgress);
      continue;
    }

    if (onProgress) {
      const pct = Math.min(88, 10 + Math.round((i / Math.max(1, list.length)) * 75));
      onProgress(pct, `Lendo (${i + 1}/${list.length}): ${rawName.split('/').pop()}`);
    }

    await processSingleVirtualOrRawEntry({
      rawPath: rawName,
      sizeBytes: item.size || 0,
      isLoose: true,
      getBytes: async () => new Uint8Array(await item.arrayBuffer()),
      getSourceForStreaming: async () => item, // Blob/File fatiado em streaming 1 MB por vez!
      limits,
      coverage,
      onEntry
    });
  }

  return coverage;
}
