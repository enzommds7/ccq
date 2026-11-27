import test from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyArchiveEntry,
  createCoverageTracker,
  forEachLineChunked,
  loadJSZip,
  sanitizeArchivePath,
  streamInputSource
} from '../js/scan/archive-reader.js';

const JSZip = await loadJSZip();

test('Archive Reader: sanitiza caminhos e bloqueia path traversal, caminhos absolutos e null bytes', () => {
  assert.equal(sanitizeArchivePath('../secret.txt').ok, false);
  assert.equal(sanitizeArchivePath('a/b/../../etc/passwd').ok, false);
  assert.equal(sanitizeArchivePath('/etc/passwd').ok, false);
  assert.equal(sanitizeArchivePath('C:\\Windows\\win.ini').ok, false);
  assert.equal(sanitizeArchivePath('good\0evil.txt').ok, false);
  assert.equal(sanitizeArchivePath('FS\\data\\tombstones\\tombstone_00').normalized, 'FS/data/tombstones/tombstone_00');
});

test('Archive Reader: trata ZIP corrompido graciosamente registrando lacuna sem quebrar o scan', async () => {
  const corruptBytes = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0xff, 0xee, 0xdd, 0xcc, 0x00, 0x01]);
  const coverage = createCoverageTracker();
  const entries = [];

  await streamInputSource([{
    name: 'corrupted.zip',
    size: corruptBytes.length,
    slice: (s, e) => ({ arrayBuffer: async () => corruptBytes.slice(s, e).buffer }),
    arrayBuffer: async () => corruptBytes.buffer
  }], {
    coverage,
    onEntry: async (e) => entries.push(e)
  });

  assert.equal(entries.length, 0);
  assert.ok(coverage.gaps.length >= 1, 'ZIP corrompido deve registrar lacuna de cobertura em vez de travar');
});

test('Archive Reader: bloqueia ZIP bomb / tamanho excessivo e symlinks preservando entradas válidas', async () => {
  const zip = new JSZip();
  zip.file('ok.log', 'linha limpa\n');
  zip.file('huge.log', 'X'.repeat(4096));
  zip.file('sym', 'target', { unixPermissions: 0o120777 });
  const zipBytes = await zip.generateAsync({ type: 'uint8array', platform: 'UNIX' });

  const coverage = createCoverageTracker();
  const processed = [];

  await streamInputSource([{
    name: 'mixed.zip',
    size: zipBytes.length,
    slice: (s, e) => ({ arrayBuffer: async () => zipBytes.slice(s, e).buffer }),
    arrayBuffer: async () => zipBytes.buffer
  }], {
    limits: { maxEntryBytes: 512, maxTotalUncompressedBytes: 2048 },
    coverage,
    onEntry: async (e) => {
      processed.push(e.path);
      coverage.analyzed_files++;
    }
  });

  assert.deepEqual(processed, ['ok.log']);
  assert.equal(coverage.rejected_limits.length, 1);
  assert.equal(coverage.rejected_security.length, 1);
});

test('Archive Reader: forEachLineChunked lê corretamente linhas divididas entre fronteiras de chunk', async () => {
  const text = 'primeira linha\nsegunda linha longa para cruzar chunk\nterceira\r\nquarta';
  const bytes = new TextEncoder().encode(text);
  const seen = [];

  const stats = await forEachLineChunked(bytes, (line, lineNo, prev, next) => {
    seen.push({ line, lineNo, prev, next });
  }, { chunkSizeBytes: 12 });

  assert.equal(stats.linesRead, 4);
  assert.deepEqual(seen.map(s => s.line), ['primeira linha', 'segunda linha longa para cruzar chunk', 'terceira', 'quarta']);
  assert.equal(seen[1].prev, 'primeira linha');
  assert.equal(seen[1].next, 'terceira');
});

test('Archive Reader: allowlist e exclusões forenses (UUIDText, .tracev3, mídia, tombstone, mountinfo)', () => {
  assert.equal(classifyArchiveEntry('system_logs.logarchive/UUIDText/00/AB').action, 'ignore_aux');
  assert.equal(classifyArchiveEntry('system_logs.logarchive/Persist/001.tracev3').action, 'unsupported');
  assert.equal(classifyArchiveEntry('DCIM/photo.png').action, 'skip_ignored');
  assert.equal(classifyArchiveEntry('FS/data/tombstones/tombstone_02').action, 'analyze_text');
  assert.equal(classifyArchiveEntry('FS/proc/1/mountinfo').action, 'analyze_text');
  assert.equal(classifyArchiveEntry('sysdiagnose/lsaw.csstoredump').action, 'analyze_text');
});
