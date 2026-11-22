/* ══════════════════════════════════════════════════════════════════
   CACIQUE SCAN v5.0 — PARSER FORENSE iOS (PLIST XML + bplist00 + IPS + LOGS)
   - Nunca varre UUIDText / DSC / timesync de system_logs.logarchive
   - Decodifica bplist00 binário sem corrupção UTF-8
   - Valida .ips (itemID 1300146617/1480516829, usedImages, teamID pending)
   - Trata Sandbox: deny, itunesstored, SetupAssistant e Screen Time sem falso positivo
   ══════════════════════════════════════════════════════════════════ */
import { buildCanonicalEvent, extractLineMeta } from '../engine/matcher.js';
import { isIosAuxiliaryCatalogPath } from '../archive-reader.js';

const BPLIST_MAGIC = 'bplist00';
const utf8Dec = new TextDecoder('utf-8', { fatal: false });
const utf16BeDec = new TextDecoder('utf-16be', { fatal: false });
const latin1Dec = new TextDecoder('latin1');

const SANDBOX_DENY_RE = /\bSandbox:.*?\bdeny\b/i;
const ENV_OR_PROC_CTX_RE = /(DYLD_INSERT_LIBRARIES|DOPAMINE_|JBUPDATE_|jbserver|jbctl|usedImages|Process:|Application:|\.dylib\b|execve|posix_spawn|launchd)/i;
const PROC_EVENT_RE = /(^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|Process:|launched|spawn|exec|CFBundleIdentifier|bundleID)/i;
const NET_PROXY_RE = /(PayloadIdentifier|PayloadOrganization|ServerAddress|HTTPProxy|HTTPSProxy|DNS|proxy|http:\/\/|https:\/\/|\.apple\.dns)/i;
const SCREENTIME_NATIVE_RE = /^system\.dateandtime\.force_date_time_configuration_.*-restrictions$/i;

const SUSPICIOUS_DYLIB_RE = /(\/var\/jb\/|\/Library\/MobileSubstrate\/|\/usr\/lib\/TweakInject\/|basebin\/launchdhook\.dylib|ElleKit|Substitute|libhooker|FridaGadget)/i;
const APPLE_OFFICIAL_PREFIXES = ['/system/library/', '/usr/lib/system/', '/usr/lib/lib', '/developer/'];

export function isBinaryPlist(bytes) {
  if (!bytes || bytes.length < 8) return false;
  for (let i = 0; i < 8; i++) {
    if (bytes[i] !== BPLIST_MAGIC.charCodeAt(i)) return false;
  }
  return true;
}

function readUIntBE(bytes, offset, byteCount) {
  if (offset < 0 || offset + byteCount > bytes.length) {
    throw new Error('bplist00_out_of_bounds');
  }
  let val = 0n;
  for (let i = 0; i < byteCount; i++) {
    val = (val << 8n) | BigInt(bytes[offset + i]);
  }
  return Number(val);
}

/**
 * Decodificador puro JS de Apple Binary Property List (bplist00) com limites anti-DoS.
 */
export function parseBinaryPlist(bytes) {
  if (!isBinaryPlist(bytes) || bytes.length < 40) {
    throw new Error('Arquivo bplist00 inválido ou truncado.');
  }

  const trailerOff = bytes.length - 32;
  const offsetIntSize = bytes[trailerOff + 6];
  const objectRefSize = bytes[trailerOff + 7];
  const numObjects = readUIntBE(bytes, trailerOff + 8, 8);
  const topObject = readUIntBE(bytes, trailerOff + 16, 8);
  const offsetTableOffset = readUIntBE(bytes, trailerOff + 24, 8);

  if (![1, 2, 4, 8].includes(offsetIntSize) || ![1, 2, 4, 8].includes(objectRefSize)) {
    throw new Error('bplist00_invalid_int_size');
  }
  if (numObjects <= 0 || numObjects > 25000 || topObject >= numObjects) {
    throw new Error('bplist00_invalid_object_count');
  }
  if (offsetTableOffset + numObjects * offsetIntSize > trailerOff) {
    throw new Error('bplist00_corrupt_offset_table');
  }

  const offsets = new Array(numObjects);
  for (let i = 0; i < numObjects; i++) {
    offsets[i] = readUIntBE(bytes, offsetTableOffset + i * offsetIntSize, offsetIntSize);
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const parseIntObject = (pos, info) => {
    const byteLen = 1 << info;
    if (pos + byteLen > offsetTableOffset) throw new Error('bplist00_oob_int');
    if (byteLen <= 8) return readUIntBE(bytes, pos, byteLen);
    return `<int${byteLen * 8}>`;
  };

  const readObjLength = (pos, info) => {
    if (info !== 0x0f) return { length: info, nextPos: pos };
    if (pos >= offsetTableOffset) throw new Error('bplist00_oob_len');
    const marker = bytes[pos];
    if ((marker & 0xf0) !== 0x10) throw new Error('bplist00_invalid_len_marker');
    const intInfo = marker & 0x0f;
    const lenBytes = 1 << intInfo;
    const length = readUIntBE(bytes, pos + 1, lenBytes);
    return { length, nextPos: pos + 1 + lenBytes };
  };

  const decodeObj = (objIdx, depth = 0, stack = new Set()) => {
    if (depth > 32) return '[MAX_DEPTH]';
    if (objIdx < 0 || objIdx >= numObjects) throw new Error('bplist00_bad_ref');
    if (stack.has(objIdx)) return '[CYCLE]';
    stack.add(objIdx);

    const start = offsets[objIdx];
    if (start < 8 || start >= offsetTableOffset) throw new Error('bplist00_bad_offset');
    const marker = bytes[start];
    const objType = (marker & 0xf0) >> 4;
    const info = marker & 0x0f;

    let result;
    if (objType === 0x0) {
      if (info === 0x00) result = null;
      else if (info === 0x08) result = false;
      else if (info === 0x09) result = true;
      else result = null;
    } else if (objType === 0x1) {
      result = parseIntObject(start + 1, info);
    } else if (objType === 0x2) {
      const byteLen = 1 << info;
      if (byteLen === 4) result = view.getFloat32(start + 1, false);
      else if (byteLen === 8) result = view.getFloat64(start + 1, false);
      else result = 0;
    } else if (objType === 0x3) {
      const appleEpochSec = view.getFloat64(start + 1, false);
      const unixMs = (appleEpochSec + 978307200) * 1000;
      result = new Date(unixMs).toISOString();
    } else if (objType === 0x4) {
      const { length } = readObjLength(start + 1, info);
      result = `<data:${length}B>`;
    } else if (objType === 0x5) {
      const { length, nextPos } = readObjLength(start + 1, info);
      result = latin1Dec.decode(bytes.subarray(nextPos, Math.min(offsetTableOffset, nextPos + length)));
    } else if (objType === 0x6) {
      const { length, nextPos } = readObjLength(start + 1, info);
      result = utf16BeDec.decode(bytes.subarray(nextPos, Math.min(offsetTableOffset, nextPos + length * 2)));
    } else if (objType === 0x8) {
      result = readUIntBE(bytes, start + 1, info + 1);
    } else if (objType === 0xa) {
      const { length, nextPos } = readObjLength(start + 1, info);
      const arr = [];
      for (let i = 0; i < length; i++) {
        const ref = readUIntBE(bytes, nextPos + i * objectRefSize, objectRefSize);
        arr.push(decodeObj(ref, depth + 1, stack));
      }
      result = arr;
    } else if (objType === 0xd) {
      const { length, nextPos } = readObjLength(start + 1, info);
      const dict = {};
      const valTableStart = nextPos + length * objectRefSize;
      for (let i = 0; i < length; i++) {
        const keyRef = readUIntBE(bytes, nextPos + i * objectRefSize, objectRefSize);
        const valRef = readUIntBE(bytes, valTableStart + i * objectRefSize, objectRefSize);
        const keyVal = String(decodeObj(keyRef, depth + 1, stack));
        dict[keyVal] = decodeObj(valRef, depth + 1, stack);
      }
      result = dict;
    } else {
      result = null;
    }

    stack.delete(objIdx);
    return result;
  };

  return decodeObj(topObject, 0, new Set());
}

export function parseXmlPlistKeyValues(text) {
  const fields = [];
  const kvRe = /<key>([^<]+)<\/key>\s*<(string|integer|real)>([^<]*)<\/\2>/gi;
  let m;
  while ((m = kvRe.exec(text)) !== null) {
    fields.push({ key: m[1].trim(), value: m[3].trim() });
  }
  return fields;
}

function collectPlistEntries(node, keyPath, out) {
  if (node === null || node === undefined) return;
  if (typeof node === 'string' || typeof node === 'number' || typeof node === 'boolean') {
    out.push({ key: keyPath, value: String(node) });
    return;
  }
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      collectPlistEntries(node[i], keyPath, out);
    }
    return;
  }
  if (typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) {
      collectPlistEntries(v, k, out);
    }
  }
}

const RELEVANT_PLIST_KEYS = new Set([
  'payloadidentifier', 'payloadorganization', 'payloaddisplayname',
  'serveraddress', 'httpproxy', 'httpsproxy', 'proxyautoconfigurlstring',
  'dnsserveraddresses', 'servername', 'remoteaddress', 'profileidentifier',
  'identifier', 'bundleidentifier', 'cfbundleidentifier', 'proxy'
]);

export function analyzeIosPlistBytes({ filePath, bytes, matcher, emitEvent, addSignal, deviceInfo, coverage }) {
  if (isIosAuxiliaryCatalogPath(filePath)) {
    coverage.ignored_auxiliary.push({ file: filePath, reason: 'UUIDText/DSC ignorado por guarda dupla.' });
    return;
  }
  coverage.saw_ios_plist = true;

  const baseName = filePath.split('/').pop() || '';
  if (baseName.toLowerCase() === 'holdingtankmanifest.plist') {
    emitEvent(buildCanonicalEvent({
      ruleId: 'IOS_PLIST_HOLDINGTANK_001',
      domain: 'sistema_backup',
      title: 'Metadado Nativo HoldingTankManifest.plist (Informativo)',
      source: { path: filePath, format: 'ios_plist', line: 1 },
      observed: { process: 'sysdiagnose', operation: 'plist_metadata', object_path: filePath },
      evidenceLevel: 'informational',
      heuristicWeight: 0,
      interpretation: 'HoldingTankManifest.plist é artefato nativo de diagnóstico do iOS.',
      alternativeExplanations: ['Arquivo padrão de sysdiagnose Apple'],
      recommendedAction: 'Nenhuma ação necessária.',
      dedupKey: `IOS_PLIST_HOLDINGTANK_001|${filePath}`
    }));
    return;
  }

  let kvList = [];
  let isBplist = isBinaryPlist(bytes);

  if (isBplist) {
    try {
      const parsed = parseBinaryPlist(bytes);
      collectPlistEntries(parsed, 'root', kvList);
    } catch (err) {
      coverage.gaps.push({ file: filePath, reason: `Binary plist inválido/truncado (${err.message}); leitura UTF-8 bloqueada.` });
      return;
    }
  } else {
    const xmlText = utf8Dec.decode(bytes);
    kvList = parseXmlPlistKeyValues(xmlText);
  }

  for (const { key, value } of kvList) {
    const kLow = key.toLowerCase();
    const vTrim = value.trim();
    const vLow = vTrim.toLowerCase();

    if (!deviceInfo.model && kLow === 'producttype') deviceInfo.model = vTrim;
    if (!deviceInfo.osVersion && kLow === 'productversion') deviceInfo.osVersion = `iOS ${vTrim}`;
    if (!deviceInfo.serial && kLow === 'serialnumber') deviceInfo.serial = vTrim;

    if (SCREENTIME_NATIVE_RE.test(vTrim)) {
      emitEvent(buildCanonicalEvent({
        ruleId: 'IOS_PLIST_SCREENTIME_NATIVE_001',
        domain: 'seguranca_do_dispositivo',
        title: `Perfil Nativo Apple Tempo de Uso (${vTrim})`,
        source: { path: filePath, format: isBplist ? 'bplist00' : 'xml_plist', line: 1 },
        observed: { process: 'ManagedConfiguration', operation: key, object_path: vTrim },
        evidenceLevel: 'informational',
        heuristicWeight: 0,
        interpretation: 'Restrição nativa do recurso Tempo de Uso (Screen Time) do iOS. Não indica proxy nem jailbreak.',
        alternativeExplanations: ['Controle parental ou restrição de data/hora nativa do iOS'],
        recommendedAction: 'Nenhuma ação necessária.',
        dedupKey: `IOS_PLIST_SCREENTIME_NATIVE_001|${vLow}`
      }));
      continue;
    }

    if (RELEVANT_PLIST_KEYS.has(kLow)) {
      // Correspondência exata em campo estruturado de perfil/proxy
      let matchedCanonical = matcher.proxyNamedMap.get(vLow) || null;
      if (!matchedCanonical && matcher.proxyNamedRe) {
        const m = matcher.findAllMatches(matcher.proxyNamedRe, vTrim);
        if (m.length > 0) matchedCanonical = matcher.proxyNamedMap.get(m[0].toLowerCase()) || m[0];
      }
      if (matchedCanonical) {
        addSignal('ios_proxy_profile', `Plist ${key}=${vTrim}`);
        emitEvent(buildCanonicalEvent({
          ruleId: 'IOS_PLIST_PROXY_PROFILE_001',
          domain: 'rede',
          title: `Perfil/Proxy Candidato em Plist iOS (${matchedCanonical})`,
          source: { path: filePath, format: isBplist ? 'bplist00' : 'xml_plist', line: 1 },
          observed: { process: 'ManagedConfiguration', package: vTrim, operation: key, object_path: matchedCanonical },
          evidenceLevel: 'anomaly_review',
          heuristicWeight: 25,
          interpretation: `Campo estruturado '${key}' em ${isBplist ? 'bplist00' : 'XML plist'} corresponde exatamente a '${matchedCanonical}'.`,
          alternativeExplanations: ['Perfil antigo salvo e inativo no momento da partida'],
          recommendedAction: 'Verificar em MCProfileEvents se o perfil estava ativo durante a partida.',
          snippet: { prev_line: '', current_line: `${key} = ${vTrim}`, next_line: '' },
          dedupKey: `IOS_PLIST_PROXY_PROFILE_001|${matchedCanonical.toLowerCase()}`
        }));
      }
    }
  }
}

export function analyzeIosIpsText({ filePath, text, matcher, emitEvent, addSignal, coverage }) {
  if (isIosAuxiliaryCatalogPath(filePath)) return;
  coverage.saw_ios_ips = true;

  const trimmed = (text || '').trim();
  if (!trimmed) return;

  let header = {};
  let body = {};
  const firstNl = trimmed.indexOf('\n');

  try {
    if (firstNl !== -1 && trimmed.startsWith('{')) {
      const line1 = trimmed.slice(0, firstNl).trim();
      const rest = trimmed.slice(firstNl + 1).trim();
      header = JSON.parse(line1);
      if (rest.startsWith('{')) {
        body = JSON.parse(rest);
      }
    } else if (trimmed.startsWith('{')) {
      body = JSON.parse(trimmed);
    }
  } catch (_) {
    // Caso o .ips não seja JSON padrão, cair para inspeção mínima segura
    return;
  }

  const bundleID = String(body.bundleID || header.bundleID || body.coalitionName || '').trim();
  const procName = String(body.procName || header.app_name || 'Process').trim();
  const appStoreMeta = body.appStoreMeta || body.storeCohort || {};
  const itemID = String(body.itemID || header.itemID || appStoreMeta.itemID || '').trim();
  const distributorID = String(body.distributorID || header.distributorID || '').trim();
  const teamID = String(body.teamID || header.teamID || (body.codeSigningInfo && body.codeSigningInfo.teamID) || '').trim();

  const iosApps = (matcher.baselines && matcher.baselines.ios_freefire_apps) || {
    'com.dts.freefireth': { itemID: '1300146617', name: 'Free Fire' },
    'com.dts.freefiremax': { itemID: '1480516829', name: 'Free Fire MAX' }
  };
  const pendingTeamIds = new Set((matcher.baselines && matcher.baselines.ios_pending_baseline_team_ids) || ['98573T3W6L']);

  if (teamID && pendingTeamIds.has(teamID)) {
    emitEvent(buildCanonicalEvent({
      ruleId: 'IOS_IPS_TEAMID_PENDING_001',
      domain: 'integridade_do_jogo',
      title: `Team ID ${teamID} em baseline pendente (${bundleID || procName})`,
      source: { path: filePath, format: 'ios_ips_json', line: 1 },
      observed: { process: procName, package: bundleID || procName, operation: 'codesign_team_id', outcome: `pending_official_baseline (${teamID})` },
      evidenceLevel: 'informational',
      heuristicWeight: 0,
      interpretation: `O Team ID '${teamID}' está classificado como pending_official_baseline até validação formal contra certificado Garena oficial.`,
      alternativeExplanations: ['Certificado oficial ou regional legítimo da publicadora'],
      recommendedAction: 'Não punir exclusivamente pelo Team ID 98573T3W6L.',
      dedupKey: `IOS_IPS_TEAMID_PENDING_001|${teamID}|${bundleID}`
    }));
  }

  const ffBaseline = iosApps[bundleID.toLowerCase()];
  if (ffBaseline) {
    const badItem = itemID && itemID !== ffBaseline.itemID;
    const badDist = distributorID && distributorID !== 'com.apple.AppStore';
    if (badItem || badDist) {
      addSignal('ios_ff_non_appstore', `.ips ${bundleID} (${distributorID || `itemID=${itemID}`})`);
      emitEvent(buildCanonicalEvent({
        ruleId: 'IOS_IPS_FF_SIDELOAD_001',
        domain: 'integridade_do_jogo',
        title: `Divergência de distribuição App Store em ${ffBaseline.name} (.ips)`,
        source: { path: filePath, format: 'ios_ips_json', line: 1 },
        observed: {
          process: procName,
          package: bundleID,
          operation: 'ips_metadata',
          outcome: `distributorID=${distributorID || 'N/A'}, itemID=${itemID || 'N/A'}`
        },
        evidenceLevel: 'anomaly_review',
        heuristicWeight: 30,
        interpretation: `Crash .ips do ${bundleID} diverge do baseline App Store oficial (esperado itemID=${ffBaseline.itemID}, distributorID=com.apple.AppStore).`,
        alternativeExplanations: ['Build TestFlight oficial ou metadado ausente em versão antiga do iOS'],
        recommendedAction: 'Confirmar procedência da instalação via AltStore/Enterprise e buscar evidências em usedImages.',
        dedupKey: `IOS_IPS_FF_SIDELOAD_001|${bundleID}|${distributorID}|${itemID}`
      }));
    }
  }

  // Inspecionar usedImages buscando apenas .dylib fora dos caminhos oficiais
  const usedImages = Array.isArray(body.usedImages) ? body.usedImages : [];
  for (const img of usedImages) {
    const imgPath = typeof img === 'string' ? img : (img && (img.path || img.name)) || '';
    if (!imgPath) continue;
    const lowImg = imgPath.toLowerCase();
    const isAppleSys = APPLE_OFFICIAL_PREFIXES.some(pref => lowImg.startsWith(pref)) && !lowImg.includes('/tweakinject');
    if (isAppleSys) continue;

    if (SUSPICIOUS_DYLIB_RE.test(imgPath)) {
      addSignal('ios_usedimage_injection', `.ips usedImages: ${imgPath}`);
      emitEvent(buildCanonicalEvent({
        ruleId: 'IOS_IPS_USEDIMAGE_DYLIB_001',
        domain: 'integridade_do_jogo',
        title: `Dylib de Hooking/Jailbreak em usedImages (.ips): ${imgPath.split('/').pop()}`,
        source: { path: filePath, format: 'ios_ips_json', line: 1 },
        observed: { process: procName, package: bundleID || procName, operation: 'usedImages', outcome: 'loaded_in_process', object_path: imgPath },
        evidenceLevel: 'anomaly_review',
        heuristicWeight: 35,
        interpretation: `Biblioteca dinâmica fora dos diretórios oficiais Apple carregada na imagem do processo '${procName}': ${imgPath}.`,
        alternativeExplanations: ['Tweak global de sistema carregado sem atuação direta contra o jogo'],
        recommendedAction: 'Revisão especializada comparando processo afetado e eventuais tweaks/proxies.',
        snippet: { prev_line: '', current_line: `usedImages: ${imgPath}`, next_line: '' },
        dedupKey: `IOS_IPS_USEDIMAGE_DYLIB_001|${procName}|${imgPath}`
      }));
    }
  }
}

export function createIosTextAnalyzer({ filePath, format, matcher, emitEvent, addSignal, deviceInfo, coverage }) {
  const isAuxCatalog = isIosAuxiliaryCatalogPath(filePath);
  if (isAuxCatalog) {
    coverage.ignored_auxiliary.push({ file: filePath, reason: 'Catálogo UUIDText/DSC excluído da varredura textual.' });
    return { feedLine() {}, finish() {} };
  }
  coverage.saw_ios_unified_log = true;

  const makeSnippet = (p, c, n) => ({
    prev_line: (p || '').slice(0, 200),
    current_line: (c || '').slice(0, 240),
    next_line: (n || '').slice(0, 200)
  });

  return {
    feedLine(line, lineNo, prevLine, nextLine) {
      if (!line) return;
      const meta = extractLineMeta(line);

      if (!deviceInfo.model) {
        const mp = /<key>ProductType<\/key>\s*<string>([^<]+)<\/string>/i.exec(line);
        if (mp) deviceInfo.model = mp[1].trim();
      }
      if (!deviceInfo.osVersion) {
        const mv = /<key>ProductVersion<\/key>\s*<string>([^<]+)<\/string>/i.exec(line);
        if (mv) deviceInfo.osVersion = `iOS ${mv[1].trim()}`;
      }

      // 1. GUARDA CRÍTICA: Sandbox: deny (ex.: file-test-existence /Applications/Sileo.app) NUNCA confirma instalação!
      if (SANDBOX_DENY_RE.test(line)) {
        emitEvent(buildCanonicalEvent({
          ruleId: 'IOS_SANDBOX_DENY_PROBE_001',
          domain: 'seguranca_do_dispositivo',
          title: 'Tentativa bloqueada pelo Sandbox iOS (file-test-existence / deny)',
          source: { path: filePath, format: format || 'ios_unified_log', line: lineNo },
          observed: { timestamp: meta.timestamp, process: meta.process || 'Sandbox', operation: 'sandbox_deny', outcome: 'blocked' },
          evidenceLevel: 'informational',
          heuristicWeight: 0,
          interpretation: 'O iOS Sandbox bloqueou uma sondagem (ex.: verificação de existência de arquivo pelo anti-cheat do próprio app). Isso NÃO comprova instalação.',
          alternativeExplanations: ['Sondagem defensiva padrão executada por SDKs anti-cheat em aparelhos limpos'],
          recommendedAction: 'Nunca usar evento Sandbox: deny como prova de jailbreak.',
          snippet: makeSnippet(prevLine, line, nextLine),
          dedupKey: `IOS_SANDBOX_DENY_PROBE_001|${filePath}`
        }));
        return;
      }

      // 2. Backup / Restore (itunesstored, SetupAssistant, MobileBackup, etc.) — SEMPRE informativo
      const backupMatches = matcher.findAllMatches(matcher.iosBackupRe, line);
      if (backupMatches.length > 0) {
        const term = backupMatches[0];
        const isNativeDaemon = /^(itunesstored|setupassistant)$/i.test(term);
        emitEvent(buildCanonicalEvent({
          ruleId: 'IOS_BACKUP_RESTORE_EVENT_001',
          domain: 'sistema_backup',
          title: isNativeDaemon
            ? `Daemon Nativo iOS (${term}) — Informativo`
            : `Evento de Serviço Backup/Restore iOS (${term})`,
          source: { path: filePath, format: format || 'ios_unified_log', line: lineNo },
          observed: { timestamp: meta.timestamp, process: term, operation: 'backup_restore_service', outcome: 'informational' },
          evidenceLevel: 'informational',
          heuristicWeight: 0,
          interpretation: isNativeDaemon
            ? `'${term}' é processo nativo padrão da Apple (App Store / Assistente de Configuração) e não comprova restauração de backup.`
            : `Referência ao serviço '${term}'. Operações de backup/restore no iOS não implicam trapaça.`,
          alternativeExplanations: ['Operação normal do iOS / iCloud / App Store'],
          recommendedAction: 'Apenas informativo; não gera penalidade.',
          snippet: makeSnippet(prevLine, line, nextLine),
          dedupKey: `IOS_BACKUP_RESTORE_EVENT_001|${term.toLowerCase()}`
        }));
      }

      // 3. Dopamine / Tweaks (somente em contexto estruturado de ambiente/processo/usedImages)
      if (ENV_OR_PROC_CTX_RE.test(line) && matcher.iosDopamineRe) {
        const dMatches = matcher.findAllMatches(matcher.iosDopamineRe, line);
        for (const tok of dMatches) {
          addSignal('ios_dopamine_runtime', `Unified/Proc: ${tok}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'IOS_DOPAMINE_EVENT_001',
            domain: 'seguranca_do_dispositivo',
            title: `Indicador de Ambiente Dopamine/Tweak (${tok})`,
            source: { path: filePath, format: format || 'ios_unified_log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'launchd', operation: 'runtime_indicator', object_path: tok },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 25,
            interpretation: `Indicador de alta especificidade '${tok}' observado em contexto estruturado de processo/variável/dylib.`,
            alternativeExplanations: ['Jailbreak prévio ou inativo sem atuação direta contra o jogo'],
            recommendedAction: 'Correlacionar com .ips (usedImages) ou perfis ativos.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `IOS_DOPAMINE_EVENT_001|${tok.toLowerCase()}`
          }));
        }
      }

      // 4. Termos de Jailbreak (apenas em evento decodificado com processo e operação, nunca string solta)
      if (PROC_EVENT_RE.test(line) && matcher.iosJailbreakRe) {
        const jMatches = matcher.findAllMatches(matcher.iosJailbreakRe, line);
        for (const tok of jMatches) {
          addSignal('ios_jailbreak_runtime', `iOS log process: ${tok}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'IOS_JAILBREAK_EVENT_001',
            domain: 'seguranca_do_dispositivo',
            title: `Evento com Referência a Jailbreak/Hooking (${tok})`,
            source: { path: filePath, format: format || 'ios_unified_log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'iOS Process', operation: 'decoded_log_event', object_path: tok },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 15,
            interpretation: `Termo '${tok}' observado em evento de processo decodificado (fora de Sandbox: deny e fora de UUIDText/DSC).`,
            alternativeExplanations: ['Log histórico ou biblioteca não carregada no Free Fire'],
            recommendedAction: 'Confirmar via usedImages no .ips antes de concluir interferência.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `IOS_JAILBREAK_EVENT_001|${tok.toLowerCase()}`
          }));
        }
      }

      // 5. Proxies nomeados em logs iOS apenas com contexto de rede/DNS/perfil
      if (NET_PROXY_RE.test(line) && matcher.proxyNamedRe) {
        const pMatches = matcher.findAllMatches(matcher.proxyNamedRe, line);
        for (const tok of pMatches) {
          const canon = matcher.proxyNamedMap.get(tok.toLowerCase()) || tok;
          addSignal('proxy_named_domain', `iOS network/profile: ${canon}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'PROXY_NAMED_DOMAIN_001',
            domain: 'rede',
            title: `Domínio/Perfil Candidato em Log iOS (${canon})`,
            source: { path: filePath, format: format || 'ios_unified_log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'mDNSResponder/NE', operation: 'network_profile_ref', object_path: canon },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 20,
            interpretation: `Indicador '${canon}' detectado em evento com contexto de rede/DNS/perfil.`,
            alternativeExplanations: ['Consulta DNS ou histórico sem túnel ativo durante a partida'],
            recommendedAction: 'Verificar horário e correlação com perfis ativos.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `PROXY_NAMED_DOMAIN_001|${canon.toLowerCase()}`
          }));
        }
      }
    },
    finish() {}
  };
}
