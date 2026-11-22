/* ══════════════════════════════════════════════════════════════════
   CACIQUE SCAN v5.0 — MATCHER & COMPILADOR DE REGRAS (BOOT ÚNICO)
   - Pré-compila RegExp, Sets e Maps uma única vez no boot do Worker
   - Mantém PROXY_SHORT_TOKENS (disabled/inactive_research_only) fora de uso
   - Padroniza eventos no Contrato Canônico v5.0
   ══════════════════════════════════════════════════════════════════ */

export const RULE_VERSION = '5.0.0';

export const DOMAIN_LABELS = Object.freeze({
  seguranca_do_dispositivo: 'Segurança do Dispositivo',
  depuracao: 'Depuração (ADB / USB)',
  rede: 'Rede & Proxy',
  estabilidade: 'Estabilidade & Memória',
  integridade_do_jogo: 'Integridade do Jogo',
  cobertura_log: 'Qualidade & Cobertura de Log',
  sistema_backup: 'Sistema & Backup/Restore'
});

export const EVIDENCE_LEVEL_LABELS = Object.freeze({
  informational: 'INFORMATIVO',
  unvalidated_reference: 'REFERÊNCIA NÃO VALIDADA',
  anomaly_review: 'ANOMALIA PARA REVISÃO',
  corroborated_evidence: 'EVIDÊNCIA CORROBORADA',
  inconclusive: 'INCONCLUSIVO'
});

export const EVIDENCE_LEVEL_RANK = Object.freeze({
  informational: 0,
  inconclusive: 1,
  unvalidated_reference: 2,
  anomaly_review: 3,
  corroborated_evidence: 4
});

export function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const LOGCAT_TS_PROC_RE = /^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(?:\S+\s+)?(\d+)\s+(\d+)\s+([VDIWEFS])\s+([^:]+):/;
const ISO_TS_RE = /\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\b/;

export function extractLineMeta(line) {
  let timestamp = '';
  let process = '';
  const mLog = LOGCAT_TS_PROC_RE.exec(line);
  if (mLog) {
    timestamp = mLog[1];
    process = mLog[5].trim();
  } else {
    const mIso = ISO_TS_RE.exec(line);
    if (mIso) timestamp = mIso[1];
  }
  return { timestamp, process };
}

function buildBoundaryRegex(items) {
  if (!items || items.length === 0) return null;
  const sorted = [...items].sort((a, b) => b.length - a.length);
  const alts = sorted.map(escapeRegex).join('|');
  return new RegExp(`(?<![A-Za-z0-9_.-])(?:${alts})(?![A-Za-z0-9_.-])`, 'gi');
}

function buildItemMap(items) {
  const m = new Map();
  for (const it of (items || [])) {
    m.set(it.toLowerCase(), it);
  }
  return m;
}

export function createMatcher(catalog) {
  const groupsMap = new Map();
  for (const g of (catalog && catalog.groups) || []) {
    groupsMap.set(g.id, g);
  }

  const getActiveItems = (groupId) => {
    const g = groupsMap.get(groupId);
    if (!g) return [];
    if (g.match_policy === 'disabled' || g.default_status === 'inactive_research_only') {
      return [];
    }
    return g.items || [];
  };

  let inactiveTokensCount = 0;
  const inactiveGroupIds = [];
  for (const g of (catalog && catalog.groups) || []) {
    if (g.match_policy === 'disabled' || g.default_status === 'inactive_research_only') {
      inactiveGroupIds.push(g.id);
      inactiveTokensCount += (g.items || []).length;
    }
  }

  const iosJailbreakItems = getActiveItems('IOS_JAILBREAK_TERMS');
  const iosDopamineItems = getActiveItems('IOS_DOPAMINE_TWEAKS');
  const iosBackupItems = getActiveItems('IOS_BACKUP_RESTORE');
  const androidPackageItems = getActiveItems('ANDROID_PACKAGE_CANDIDATES');
  const androidRootItems = getActiveItems('ANDROID_ROOT_MODULE_NAMES');
  const proxyNamedItems = getActiveItems('PROXY_NAMED_CANDIDATES');
  const androidTelemetryItems = getActiveItems('ANDROID_TELEMETRY_USB_ADB_NET');
  const androidLogDiagItems = getActiveItems('ANDROID_LOGGING_DIAGNOSTICS');

  const baselines = (catalog && catalog.baselines) || {};
  const freeFirePackages = new Set(
    (baselines.android_freefire_packages || ['com.dts.freefireth', 'com.dts.freefiremax']).map(p => p.toLowerCase())
  );

  // Separar itens que têm sintaxe especial (= ou /) de tokens simples em PROXY / ROOT / DOPAMINE
  const rootManagerPackages = new Set(
    androidRootItems.filter(it => it.includes('.')).map(it => it.toLowerCase())
  );

  return {
    catalogMeta: (catalog && catalog.meta) || { version: '5.0-clean' },
    baselines,
    freeFirePackages,
    inactiveTokensCount,
    inactiveGroupIds,

    // Sets exatos (lowercase -> canonical item)
    androidPackageMap: buildItemMap(androidPackageItems),
    proxyNamedMap: buildItemMap(proxyNamedItems),
    androidRootMap: buildItemMap(androidRootItems),
    rootManagerPackages,

    // Regexes pré-compiladas uma única vez no boot
    iosJailbreakRe: buildBoundaryRegex(iosJailbreakItems),
    iosDopamineRe: buildBoundaryRegex(iosDopamineItems),
    iosBackupRe: buildBoundaryRegex(iosBackupItems),
    androidRootModuleRe: buildBoundaryRegex(androidRootItems),
    proxyNamedRe: buildBoundaryRegex(proxyNamedItems),
    androidTelemetryRe: buildBoundaryRegex(androidTelemetryItems),
    androidLoggingDiagRe: buildBoundaryRegex(androidLogDiagItems),

    // Caminhos canônicos Free Fire (normal + MAX) sempre comparados em lowercase
    gameArtifactPaths: {
      shGpp2Targets: [
        '/data/user/0/com.dts.freefiremax/files/contentcache/compulsory/android/gameassetbundles/font/sh-gpp2',
        '/data/user/0/com.dts.freefireth/files/contentcache/compulsory/android/gameassetbundles/font/sh-gpp2'
      ],
      jarTargets: [
        '/data/user/0/com.dts.freefiremax/cache/app_resources_lib.jar',
        '/data/user/0/com.dts.freefiremax/cache/google_api_resources_lib.jar',
        '/data/user/0/com.dts.freefireth/cache/app_resources_lib.jar',
        '/data/user/0/com.dts.freefireth/cache/google_api_resources_lib.jar'
      ]
    },

    findAllMatches(re, line) {
      if (!re || !line) return [];
      re.lastIndex = 0;
      const found = [];
      let m;
      while ((m = re.exec(line)) !== null) {
        found.push(m[0]);
        if (m[0].length === 0) re.lastIndex++;
      }
      return found;
    }
  };
}

export function buildCanonicalEvent({
  ruleId,
  ruleVersion = RULE_VERSION,
  domain,
  title,
  source,
  observed,
  evidenceLevel,
  corroboration = [],
  heuristicWeight = 0,
  interpretation,
  alternativeExplanations = [],
  recommendedAction,
  snippet = null,
  dedupKey = null
}) {
  const pkg = observed && observed.package ? observed.package : '';
  const op = observed && observed.operation ? observed.operation : '';
  const obj = observed && observed.object_path ? observed.object_path : '';
  return {
    rule_id: ruleId,
    rule_version: ruleVersion,
    domain,
    domain_label: DOMAIN_LABELS[domain] || domain,
    title: title || ruleId,
    source: {
      path: source && source.path ? source.path : 'unknown',
      format: source && source.format ? source.format : 'text',
      line: source && source.line ? source.line : 0
    },
    observed: {
      timestamp: (observed && observed.timestamp) || 'Não disponível',
      process: (observed && observed.process) || 'Não identificado',
      package: pkg || 'Não identificado',
      operation: op || '',
      outcome: (observed && observed.outcome) || '',
      object_path: obj || '',
      raw_detail: (observed && observed.raw_detail) || ''
    },
    evidence_level: evidenceLevel,
    evidence_level_label: EVIDENCE_LEVEL_LABELS[evidenceLevel] || evidenceLevel,
    corroboration: [...corroboration],
    occurrence_count: 1,
    heuristic_weight: heuristicWeight,
    interpretation,
    alternative_explanations: [...alternativeExplanations],
    recommended_action: recommendedAction,
    snippet,
    dedup_key: dedupKey || `${ruleId}|${source && source.path ? source.path : ''}|${pkg}|${op}|${obj}`
  };
}
