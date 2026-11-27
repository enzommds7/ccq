/* ══════════════════════════════════════════════════════════════════
   ccq scan — PARSER FORENSE iOS (PLIST XML + bplist00 + IPS + LOGS)
   - Nunca varre UUIDText / DSC / timesync de system_logs.logarchive
   - Nunca interpreta .tracev3 como texto
   - Decodifica bplist00 binário sem corrupção UTF-8
   - Valida .ips (itemID 1300146617/1480516829, usedImages, teamID pending)
   - Trata Sandbox: deny, itunesstored, SetupAssistant e Screen Time nativo sem falso positivo
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
const NET_PROXY_RE = /(PayloadIdentifier|PayloadOrganization|PayloadDisplayName|ServerAddress|HTTPProxy|HTTPSProxy|SOCKSProxy|DNS|proxy|VPN|NEVPN|NEDNS|http:\/\/|https:\/\/|\.apple\.dns)/i;
const PROFILE_LOG_CTX_RE = /(MCProfile|ManagedConfiguration|profiled|PayloadIdentifier|PayloadDisplayName|PayloadOrganization|ConfigurationProfile|configuration_profile)/i;

// Expressão estritamente ancorada às famílias legítimas Apple/system de Tempo de Uso (Screen Time).
// Não aceita prefixos arbitrários ou domínios de terceiros tentando disfarçar perfis suspeitos.
export const SCREENTIME_NATIVE_RE = /^(?:system\.dateandtime\.force_date_time_configuration_[a-z0-9._-]+-restrictions|system\.web\.contentfilter\.[a-z0-9._-]*(?:digital_health_restrictions|basic-restrictions)|com\.apple\.(?:webcontentfilter|familycontrols|applicationaccess|screentime)\.[a-z0-9._-]*(?:digital_health_restrictions|basic-restrictions|-restrictions))$/i;

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

const PROFILE_ID_PLIST_KEYS = new Set([
  'payloadidentifier', 'profileidentifier', 'identifier',
  'configurationidentifier', 'declarationidentifier'
]);

const NETWORK_PLIST_KEYS = new Set([
  'serveraddress', 'httpproxy', 'httpsproxy', 'socksproxy',
  'proxyautoconfigurlstring', 'dnsserveraddresses', 'dnsservers',
  'servername', 'remoteaddress', 'remoteserver', 'server',
  'proxy', 'matchdomains', 'supplementalmatchdomains'
]);

function matchStructuredProxyCandidate(value, matcher) {
  const vTrim = value.trim();
  const vLow = vTrim.toLowerCase();
  if (!vLow) return null;

  const exact = matcher.proxyNamedMap.get(vLow);
  if (exact) return exact;

  if (matcher.proxyNamedRe) {
    const m = matcher.findAllMatches(matcher.proxyNamedRe, vTrim);
    if (m.length > 0) return matcher.proxyNamedMap.get(m[0].toLowerCase()) || m[0];
  }

  // Suporta subdomínios ou PayloadIdentifier composto por segmentos separados por '.'
  // (ex.: sub.freefireproxy.xyz ou freefireproxy.xyz.digital_health_restrictions)
  for (const [keyLow, canon] of matcher.proxyNamedMap.entries()) {
    if (!keyLow.includes('.')) continue;
    if (
      vLow.startsWith(`${keyLow}.`) ||
      vLow.endsWith(`.${keyLow}`) ||
      vLow.includes(`.${keyLow}.`)
    ) {
      return canon;
    }
  }
  return null;
}

const RELEVANT_PLIST_KEYS = new Set([
  'payloadidentifier', 'payloadorganization', 'payloaddisplayname', 'payloaddescription',
  'payloadtype', 'payloadcertificatefilename', 'payloadcertificatedisplayname',
  'serveraddress', 'httpproxy', 'httpsproxy', 'socksproxy', 'proxyautoconfigurlstring',
  'dnsserveraddresses', 'dnsservers', 'servername', 'remoteaddress', 'remoteserver',
  'server', 'profileidentifier', 'identifier', 'bundleidentifier', 'cfbundleidentifier',
  'proxy', 'matchdomains', 'supplementalmatchdomains'
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

  const plistFormat = isBplist ? 'bplist00' : 'xml_plist';

  for (const { key, value } of kvList) {
    const kLow = key.toLowerCase();
    const vTrim = value.trim();
    const vLow = vTrim.toLowerCase();

    if (!deviceInfo.model && kLow === 'producttype') deviceInfo.model = vTrim;
    if (!deviceInfo.osVersion && kLow === 'productversion') deviceInfo.osVersion = `iOS ${vTrim}`;
    if (!deviceInfo.serial && kLow === 'serialnumber') deviceInfo.serial = vTrim;

    // Validar contexto de chave de identificador de perfil antes de classificar como Tempo de Uso nativo
    if ((PROFILE_ID_PLIST_KEYS.has(kLow) || kLow === 'root') && SCREENTIME_NATIVE_RE.test(vTrim)) {
      emitEvent(buildCanonicalEvent({
        ruleId: 'IOS_PLIST_SCREENTIME_NATIVE_001',
        domain: 'seguranca_do_dispositivo',
        title: `Perfil Nativo Apple Tempo de Uso (${vTrim})`,
        source: { path: filePath, format: plistFormat, line: 1 },
        observed: { process: 'ManagedConfiguration', operation: key, object_path: vTrim },
        evidenceLevel: 'informational',
        heuristicWeight: 0,
        interpretation: 'Restrição nativa do recurso Tempo de Uso (Screen Time) do iOS validada por identificador ancorado em campo de perfil. Não indica proxy nem jailbreak.',
        alternativeExplanations: ['Controle parental, restrição de conteúdo web ou restrição de data/hora nativa do iOS'],
        recommendedAction: 'Nenhuma ação necessária.',
        dedupKey: `IOS_PLIST_SCREENTIME_NATIVE_001|${vLow}`
      }));
      continue;
    }

    if (RELEVANT_PLIST_KEYS.has(kLow)) {
      // 1. Proxies / domínios nomeados em campo estruturado de perfil/rede
      const matchedCanonical = matchStructuredProxyCandidate(vTrim, matcher);
      if (matchedCanonical) {
        addSignal('ios_proxy_profile', `Plist ${key}=${vTrim}`);
        emitEvent(buildCanonicalEvent({
          ruleId: 'IOS_PLIST_PROXY_PROFILE_001',
          domain: 'rede',
          title: `Perfil/Proxy Candidato em Plist iOS (${matchedCanonical})`,
          source: { path: filePath, format: plistFormat, line: 1 },
          observed: { process: 'ManagedConfiguration', package: vTrim, operation: key, object_path: matchedCanonical },
          evidenceLevel: 'anomaly_review',
          heuristicWeight: 25,
          interpretation: `Campo estruturado '${key}' em ${plistFormat} corresponde a '${matchedCanonical}'.`,
          alternativeExplanations: ['Perfil antigo salvo e inativo no momento da partida'],
          recommendedAction: 'Verificar em MCProfileEvents se o perfil estava ativo durante a partida.',
          snippet: { prev_line: '', current_line: `${key} = ${vTrim}`, next_line: '' },
          dedupKey: `IOS_PLIST_PROXY_PROFILE_001|${matchedCanonical.toLowerCase()}`
        }));
      }

      // 2. Endereços IP candidatos em campos estruturados de rede/proxy/DNS/VPN (sem reputação maliciosa permanente)
      if (NETWORK_PLIST_KEYS.has(kLow) && matcher.networkIpRe) {
        const ipMatches = matcher.findAllMatches(matcher.networkIpRe, vTrim);
        for (const ip of ipMatches) {
          const canonIp = matcher.networkIpMap.get(ip.toLowerCase()) || ip;
          addSignal('network_ip_candidate', `Plist ${key}=${canonIp}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'NETWORK_IP_CANDIDATE_001',
            domain: 'rede',
            title: `Endereço IP Candidato em Plist de Rede/Proxy (${canonIp})`,
            source: { path: filePath, format: plistFormat, line: 1 },
            observed: { process: 'ManagedConfiguration', operation: key, outcome: 'candidate_ip_in_plist', object_path: canonIp },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 15,
            interpretation: `IP candidato '${canonIp}' encontrado em campo de configuração de rede '${key}'. Um endereço IP isolado não possui reputação maliciosa permanente sem validação independente.`,
            alternativeExplanations: ['IP reciclado por provedor VPS/hosting ou configuração de rede inativa'],
            recommendedAction: 'Validar se o perfil estava ativo no horário da partida e correlacionar com DNS/VPN.',
            snippet: { prev_line: '', current_line: `${key} = ${vTrim}`, next_line: '' },
            dedupKey: `NETWORK_IP_CANDIDATE_001|${canonIp}`
          }));
        }
      }

      // 3. Referências de perfil candidatas (Imazing.profile, 139.Spotifyx, 238.timx)
      if (matcher.profileRefRe) {
        let matchedProf = matcher.profileRefMap.get(vLow) || null;
        if (!matchedProf) {
          const pm = matcher.findAllMatches(matcher.profileRefRe, vTrim);
          if (pm.length > 0) matchedProf = matcher.profileRefMap.get(pm[0].toLowerCase()) || pm[0];
        }
        if (matchedProf) {
          addSignal('profile_ref_candidate', `Plist ${key}=${matchedProf}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'PROFILE_REFERENCE_CANDIDATE_001',
            domain: 'rede',
            title: `Referência de Perfil Candidata em Plist iOS (${matchedProf})`,
            source: { path: filePath, format: plistFormat, line: 1 },
            observed: { process: 'ManagedConfiguration', operation: key, outcome: 'profile_reference_candidate', object_path: matchedProf },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 15,
            interpretation: `Campo estruturado '${key}' referencia o identificador de perfil candidato '${matchedProf}'. Requer verificação de conteúdo e período de ativação.`,
            alternativeExplanations: ['Perfil instalado via iMazing para backup/gestão legítima ou perfil antigo inativo'],
            recommendedAction: 'Inspecionar payload completo (DNS/Proxy/Certificado) e estado ativo em MCProfileEvents.',
            snippet: { prev_line: '', current_line: `${key} = ${vTrim}`, next_line: '' },
            dedupKey: `PROFILE_REFERENCE_CANDIDATE_001|${matchedProf.toLowerCase()}`
          }));
        }
      }

      // 4. Aliases textuais de proxy/bypass (com-luxebypass, dash-proxy, freefireproxy-xyz, com-xtremo-mobile)
      if (matcher.textualAliasRe) {
        let matchedAlias = matcher.textualAliasMap.get(vLow) || null;
        if (!matchedAlias) {
          const am = matcher.findAllMatches(matcher.textualAliasRe, vTrim);
          if (am.length > 0) matchedAlias = matcher.textualAliasMap.get(am[0].toLowerCase()) || am[0];
        }
        if (matchedAlias) {
          addSignal('proxy_alias_candidate', `Plist ${key}=${matchedAlias}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'PROXY_ALIAS_CANDIDATE_001',
            domain: 'rede',
            title: `Alias Textual de Proxy/Bypass em Plist iOS (${matchedAlias})`,
            source: { path: filePath, format: plistFormat, line: 1 },
            observed: { process: 'ManagedConfiguration', operation: key, outcome: 'textual_alias_in_plist', object_path: matchedAlias },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 15,
            interpretation: `Alias textual '${matchedAlias}' encontrado no campo '${key}'. Não é tratado como pacote convencional, mas requer revisão no contexto de perfil/rede.`,
            alternativeExplanations: ['Referência residual de perfil inativo'],
            recommendedAction: 'Correlacionar com servidores proxy/DNS ativos e timestamp da partida.',
            snippet: { prev_line: '', current_line: `${key} = ${vTrim}`, next_line: '' },
            dedupKey: `PROXY_ALIAS_CANDIDATE_001|${matchedAlias.toLowerCase()}`
          }));
        }
      }

      // 5. Indicadores de ferramentas candidatas (ex.: TNTADB) em campo estruturado
      if (matcher.toolIndicatorRe) {
        const tm = matcher.findAllMatches(matcher.toolIndicatorRe, vTrim);
        for (const t of tm) {
          const canonTool = matcher.toolIndicatorMap.get(t.toLowerCase()) || t;
          addSignal('tool_indicator_detected', `Plist ${key}=${canonTool}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'TOOL_INDICATOR_CANDIDATE_001',
            domain: 'depuracao',
            title: `Indicador de Ferramenta Candidata em Plist (${canonTool})`,
            source: { path: filePath, format: plistFormat, line: 1 },
            observed: { process: 'ManagedConfiguration', operation: key, outcome: 'tool_indicator', object_path: canonTool },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 15,
            interpretation: `Identificador de ferramenta '${canonTool}' observado no campo '${key}'. Requer validação técnica independente.`,
            alternativeExplanations: ['Ferramenta de teste/depuração sem relação com o jogo'],
            recommendedAction: 'Correlacionar com execuções ou perfis ativos no período competitivo.',
            snippet: { prev_line: '', current_line: `${key} = ${vTrim}`, next_line: '' },
            dedupKey: `TOOL_INDICATOR_CANDIDATE_001|${canonTool.toLowerCase()}`
          }));
        }
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
    if (trimmed.startsWith('{')) {
      try {
        // Suporta .ips formatado como objeto JSON único (incluindo pretty-printed multi-linha)
        const singleDoc = JSON.parse(trimmed);
        if (singleDoc && typeof singleDoc === 'object') {
          body = singleDoc;
        }
      } catch (_) {
        // Formato nativo Apple .ips com 2 documentos JSON: header na linha 1 + body no restante
        if (firstNl !== -1) {
          const line1 = trimmed.slice(0, firstNl).trim();
          const rest = trimmed.slice(firstNl + 1).trim();
          header = JSON.parse(line1);
          if (rest.startsWith('{')) {
            body = JSON.parse(rest);
          }
        } else {
          return;
        }
      }
    } else {
      return;
    }
  } catch (_) {
    // Caso o .ips não seja JSON padrão, encerrar sem gerar falso positivo
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

      // 5. Proxies nomeados, IPs candidatos, aliases textuais e referências de perfil em logs iOS apenas com contexto de rede/DNS/perfil
      const hasNetProxyCtx = NET_PROXY_RE.test(line);
      const hasProfileCtx = PROFILE_LOG_CTX_RE.test(line);

      if (hasNetProxyCtx && matcher.proxyNamedRe) {
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

      if (hasNetProxyCtx && matcher.networkIpRe) {
        const ipMatches = matcher.findAllMatches(matcher.networkIpRe, line);
        for (const ip of ipMatches) {
          const canonIp = matcher.networkIpMap.get(ip.toLowerCase()) || ip;
          addSignal('network_ip_candidate', `iOS network: ${canonIp}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'NETWORK_IP_CANDIDATE_001',
            domain: 'rede',
            title: `Endereço IP Candidato em Log de Rede iOS (${canonIp})`,
            source: { path: filePath, format: format || 'ios_unified_log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'mDNSResponder/NE', operation: 'network_ip_ref', object_path: canonIp },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 15,
            interpretation: `IP candidato '${canonIp}' observado em evento de rede/proxy/DNS iOS. Endereços IP isolados não têm reputação maliciosa permanente.`,
            alternativeExplanations: ['Endereço IP compartilhado ou tráfego sem relação com o jogo'],
            recommendedAction: 'Validar janela temporal da partida e correlacionar com perfis ativos.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `NETWORK_IP_CANDIDATE_001|${canonIp}`
          }));
        }
      }

      if (hasNetProxyCtx && matcher.textualAliasRe) {
        const aliasMatches = matcher.findAllMatches(matcher.textualAliasRe, line);
        for (const al of aliasMatches) {
          const canonAl = matcher.textualAliasMap.get(al.toLowerCase()) || al;
          addSignal('proxy_alias_candidate', `iOS network/profile alias: ${canonAl}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'PROXY_ALIAS_CANDIDATE_001',
            domain: 'rede',
            title: `Alias Textual de Proxy/Bypass em Log iOS (${canonAl})`,
            source: { path: filePath, format: format || 'ios_unified_log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'mDNSResponder/NE', operation: 'textual_alias_ref', object_path: canonAl },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 15,
            interpretation: `Alias textual '${canonAl}' encontrado em log de rede/perfil iOS. Requer revisão contextual.`,
            alternativeExplanations: ['Referência residual de perfil ou consulta sem sessão ativa'],
            recommendedAction: 'Correlacionar com MCProfileEvents e servidores ativos no período.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `PROXY_ALIAS_CANDIDATE_001|${canonAl.toLowerCase()}`
          }));
        }
      }

      if ((hasNetProxyCtx || hasProfileCtx) && matcher.profileRefRe) {
        const profMatches = matcher.findAllMatches(matcher.profileRefRe, line);
        for (const pr of profMatches) {
          const canonPr = matcher.profileRefMap.get(pr.toLowerCase()) || pr;
          addSignal('profile_ref_candidate', `iOS profile ref: ${canonPr}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'PROFILE_REFERENCE_CANDIDATE_001',
            domain: 'rede',
            title: `Referência de Perfil Candidata em Log iOS (${canonPr})`,
            source: { path: filePath, format: format || 'ios_unified_log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'profiled', operation: 'profile_reference', object_path: canonPr },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 15,
            interpretation: `Referência de perfil '${canonPr}' observada em log de perfil/rede iOS.`,
            alternativeExplanations: ['Perfil criado pelo iMazing para fins legítimos ou perfil antigo inativo'],
            recommendedAction: 'Inspecionar payload e estado ativo do perfil.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `PROFILE_REFERENCE_CANDIDATE_001|${canonPr.toLowerCase()}`
          }));
        }
      }

      if ((ENV_OR_PROC_CTX_RE.test(line) || PROC_EVENT_RE.test(line)) && matcher.toolIndicatorRe) {
        const toolMatches = matcher.findAllMatches(matcher.toolIndicatorRe, line);
        for (const t of toolMatches) {
          const canonTool = matcher.toolIndicatorMap.get(t.toLowerCase()) || t;
          addSignal('tool_indicator_detected', `iOS tool ref: ${canonTool}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'TOOL_INDICATOR_CANDIDATE_001',
            domain: 'depuracao',
            title: `Indicador de Ferramenta Candidata em Log iOS (${canonTool})`,
            source: { path: filePath, format: format || 'ios_unified_log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'iOS Process', operation: 'tool_indicator', object_path: canonTool },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 15,
            interpretation: `Ferramenta candidata '${canonTool}' registrada em evento de processo/ambiente iOS.`,
            alternativeExplanations: ['Ferramenta de teste sem relação com a partida'],
            recommendedAction: 'Correlacionar com evidências de execução ou modificação.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `TOOL_INDICATOR_CANDIDATE_001|${canonTool.toLowerCase()}`
          }));
        }
      }
    },
    finish() {}
  };
}
