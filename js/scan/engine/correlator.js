/* ══════════════════════════════════════════════════════════════════
   CACIQUE SCAN v5.0 — CORRELACIONADOR DE EVIDÊNCIAS & VEREDITO
   - Exige >= 2 fontes técnicas independentes para EVIDÊNCIA CORROBORADA
   - Separa rigorosamente Cobertura de Índice Heurístico
   - Nunca declara "100% limpo" nem "Ban Direto"
   - Diante de lacunas / parser ausente, declara INCONCLUSIVO
   ══════════════════════════════════════════════════════════════════ */
import { DOMAIN_LABELS, EVIDENCE_LEVEL_LABELS, EVIDENCE_LEVEL_RANK } from './matcher.js';

const SIGNAL_FAMILY_MAP = Object.freeze({
  ff_sh_gpp2_exec: { family: 'selinux_gameasset', label: 'SELinux/auditd GameAsset' },
  ff_shgap_dir: { family: 'fs_gameasset', label: 'Diretório anômalo no jogo' },
  ff_jar_loaded: { family: 'classloader_jar', label: 'ClassLoader/execução de JAR' },
  ff_non_playstore: { family: 'packagemanager_origin', label: 'Origem de instalação fora da Play Store' },
  android_candidate_pkg: { family: 'packagemanager_pkg', label: 'Pacote candidato instalado' },
  android_root_env: { family: 'root_environment', label: 'Ambiente Root/Módulos' },
  android_boot_unlocked: { family: 'boot_properties', label: 'Propriedades de Boot/SELinux' },
  android_setedit_anomaly: { family: 'settings_provider', label: 'Alteração via SetEdit' },
  injected_backtrace: { family: 'crash_backtrace', label: 'Biblioteca externa em backtrace' },
  android_adb_remote: { family: 'adb_network', label: 'ADB remoto via rede' },
  android_proxy_tool: { family: 'network_proxy', label: 'Proxy/MITM configurado' },
  proxy_named_domain: { family: 'network_dns', label: 'Domínio/perfil proxy em contexto de rede' },
  proxy_package_installed: { family: 'packagemanager_proxy', label: 'Pacote proxy instalado' },
  ios_usedimage_injection: { family: 'ios_crash_ips', label: 'usedImages .ips com dylib suspeita' },
  ios_ff_non_appstore: { family: 'ios_ips_origin', label: 'Metadados App Store divergentes em .ips' },
  ios_proxy_profile: { family: 'ios_profile_plist', label: 'Perfil/Proxy estruturado em .plist' },
  ios_dopamine_runtime: { family: 'ios_runtime_dopamine', label: 'Runtime Dopamine/Tweak em log decodificado' },
  ios_jailbreak_runtime: { family: 'ios_runtime_jailbreak', label: 'Evento decodificado de jailbreak' }
});

// Regras elegíveis para promoção a EVIDÊNCIA CORROBORADA quando sustentadas por >= 2 fontes independentes
const CORROBORATABLE_RULES = new Set([
  'ANDROID_GAME_SH_GPP2_EXEC_001',
  'ANDROID_GAME_SHGAP_DIR_001',
  'ANDROID_GAME_JAR_LOADED_001',
  'ANDROID_FF_NON_PLAYSTORE_001',
  'ANDROID_PKG_CANDIDATE_001',
  'ANDROID_PROFILE_PKG_001',
  'ANDROID_CRASH_INJECTED_BACKTRACE_001',
  'ANDROID_NET_PROXY_TOOL_001',
  'PROXY_NAMED_DOMAIN_001',
  'ANDROID_SETTINGS_SETEDIT_ANOMALY_001',
  'IOS_IPS_USEDIMAGE_DYLIB_001',
  'IOS_IPS_FF_SIDELOAD_001',
  'IOS_PLIST_PROXY_PROFILE_001',
  'IOS_DOPAMINE_EVENT_001',
  'IOS_JAILBREAK_EVENT_001'
]);

const RULE_SIGNAL_KEY = Object.freeze({
  ANDROID_GAME_SH_GPP2_EXEC_001: 'ff_sh_gpp2_exec',
  ANDROID_GAME_SHGAP_DIR_001: 'ff_shgap_dir',
  ANDROID_GAME_JAR_LOADED_001: 'ff_jar_loaded',
  ANDROID_FF_NON_PLAYSTORE_001: 'ff_non_playstore',
  ANDROID_PKG_CANDIDATE_001: 'android_candidate_pkg',
  ANDROID_PROFILE_PKG_001: 'proxy_package_installed',
  ANDROID_CRASH_INJECTED_BACKTRACE_001: 'injected_backtrace',
  ANDROID_NET_PROXY_TOOL_001: 'android_proxy_tool',
  PROXY_NAMED_DOMAIN_001: 'proxy_named_domain',
  ANDROID_SETTINGS_SETEDIT_ANOMALY_001: 'android_setedit_anomaly',
  IOS_IPS_USEDIMAGE_DYLIB_001: 'ios_usedimage_injection',
  IOS_IPS_FF_SIDELOAD_001: 'ios_ff_non_appstore',
  IOS_PLIST_PROXY_PROFILE_001: 'ios_proxy_profile',
  IOS_DOPAMINE_EVENT_001: 'ios_dopamine_runtime',
  IOS_JAILBREAK_EVENT_001: 'ios_jailbreak_runtime'
});

function summarizeIndependentFamilies(signalsMap) {
  const familyDescriptions = new Map();
  for (const [sigKey, desc] of signalsMap.entries()) {
    const info = SIGNAL_FAMILY_MAP[sigKey] || { family: sigKey, label: sigKey };
    if (!familyDescriptions.has(info.family)) {
      familyDescriptions.set(info.family, `${info.label}: ${desc}`);
    }
  }
  return familyDescriptions;
}

export function correlateAndBuildReport({
  events,
  rawOccurrences,
  signals,
  coverage,
  deviceInfo,
  osDetected,
  durationMs,
  catalogMeta,
  inactiveRulesCount
}) {
  const familyMap = summarizeIndependentFamilies(signals);

  // 1. Correlação estrita: 2+ fontes técnicas independentes sustentam anomalia específica
  if (familyMap.size >= 2) {
    for (const ev of events) {
      if (ev.evidence_level !== 'anomaly_review') continue;
      if (!CORROBORATABLE_RULES.has(ev.rule_id)) continue;

      const ownSigKey = RULE_SIGNAL_KEY[ev.rule_id];
      const ownFamily = ownSigKey && SIGNAL_FAMILY_MAP[ownSigKey]
        ? SIGNAL_FAMILY_MAP[ownSigKey].family
        : ev.source.format;

      const otherSources = [];
      for (const [fam, desc] of familyMap.entries()) {
        if (fam !== ownFamily) otherSources.push(desc);
      }

      if (otherSources.length >= 1) {
        ev.evidence_level = 'corroborated_evidence';
        ev.evidence_level_label = EVIDENCE_LEVEL_LABELS.corroborated_evidence;
        ev.corroboration = otherSources;
        ev.heuristic_weight = Math.max(ev.heuristic_weight || 0, 50);
        ev.recommended_action = 'Revisão especializada recomendada com base em múltiplas fontes independentes (nunca aplicar punição automática apenas por logs).';
      }
    }
  }

  // Reordenar após possíveis promoções de nível
  events.sort((a, b) => {
    const lvlDiff = (EVIDENCE_LEVEL_RANK[b.evidence_level] || 0) - (EVIDENCE_LEVEL_RANK[a.evidence_level] || 0);
    if (lvlDiff !== 0) return lvlDiff;
    return (b.heuristic_weight || 0) - (a.heuristic_weight || 0);
  });

  // 2. Avaliar lacunas de cobertura (ausência de dados NUNCA vira alerta nem "100% limpo")
  if (osDetected === 'ANDROID' && coverage.saw_bugreport && coverage.boot_keys_seen.size === 0 && coverage.analyzed_files > 0) {
    coverage.gaps.push({
      file: 'bugreport (getprop)',
      reason: 'Bug report Android parcial: chaves de integridade de boot/getprop (verifiedbootstate, flash.locked, build.tags) ausentes no recorte.'
    });
  }

  if (coverage.analyzed_files === 0 && (coverage.unsupported_files.length > 0 || coverage.rejected_limits.length > 0 || coverage.rejected_security.length > 0 || coverage.ignored_auxiliary.length > 0)) {
    coverage.status = 'insuficiente';
  } else if (coverage.unsupported_files.length > 0 || coverage.rejected_limits.length > 0 || coverage.rejected_security.length > 0 || coverage.gaps.length > 0) {
    coverage.status = 'parcial';
  } else if (coverage.analyzed_files === 0) {
    coverage.status = 'insuficiente';
  } else {
    coverage.status = 'completa';
  }

  // 3. Contadores separados (Cobertura x Risco x Domínios)
  const uniqueEvents = events.length;
  const corroboratedCount = events.filter(e => e.evidence_level === 'corroborated_evidence').length;
  const reviewCount = events.filter(e => e.evidence_level === 'anomaly_review').length;
  const unvalidatedCount = events.filter(e => e.evidence_level === 'unvalidated_reference').length;
  const informationalCount = events.filter(e => e.evidence_level === 'informational').length;

  const domainCounts = {};
  for (const key of Object.keys(DOMAIN_LABELS)) {
    domainCounts[key] = 0;
  }
  for (const ev of events) {
    domainCounts[ev.domain] = (domainCounts[ev.domain] || 0) + 1;
  }

  const rawHeuristicSum = events.reduce((acc, ev) => acc + (ev.heuristic_weight || 0), 0);
  const heuristicIndex = Math.min(100, rawHeuristicSum);

  // 4. Veredito honesto nos 5 estados oficiais
  let verdict;
  if (corroboratedCount > 0) {
    verdict = {
      code: 'corroborated_evidence',
      status: 'EVIDÊNCIA CORROBORADA',
      color: 'red',
      summary: 'Múltiplas fontes técnicas independentes sustentam a mesma hipótese técnica. Requer revisão humana especializada.'
    };
  } else if (reviewCount > 0) {
    verdict = {
      code: 'anomaly_review',
      status: 'ANOMALIA PARA REVISÃO',
      color: 'yellow',
      summary: 'Evento(s) técnico(s) específico(s) com hipóteses alternativas detectados. Necessária revisão humana contextual.'
    };
  } else if (coverage.status !== 'completa') {
    verdict = {
      code: 'inconclusive',
      status: 'INCONCLUSIVO',
      color: 'yellow',
      summary: 'Cobertura parcial, arquivo incompleto ou formato sem parser nativo (.tracev3). Solicite coleta completa padronizada.'
    };
  } else if (unvalidatedCount > 0) {
    verdict = {
      code: 'unvalidated_reference',
      status: 'REFERÊNCIA NÃO VALIDADA',
      color: 'yellow',
      summary: 'Termos ou caminhos candidatos sem evento estruturado de execução/carregamento. Apenas referência de pesquisa.'
    };
  } else {
    verdict = {
      code: 'informational',
      status: 'INFORMATIVO',
      color: 'green',
      summary: 'Nenhuma anomalia técnica observada nos arquivos analisados (análise passiva de logs não garante ausência absoluta de interferência).'
    };
  }

  const cleanCoverage = {
    status: coverage.status,
    total_container_entries: coverage.total_container_entries,
    analyzed_files: coverage.analyzed_files,
    skipped_ignored: coverage.skipped_ignored,
    checked_lines: coverage.checked_lines,
    checked_bytes: coverage.checked_bytes,
    unsupported_files: coverage.unsupported_files,
    ignored_auxiliary: coverage.ignored_auxiliary,
    rejected_limits: coverage.rejected_limits,
    rejected_security: coverage.rejected_security,
    gaps: coverage.gaps,
    logging_diagnostics: Array.from(coverage.logging_diagnostics),
    boot_keys_seen: Array.from(coverage.boot_keys_seen)
  };

  return {
    engine_version: '5.0.0',
    catalog_version: (catalogMeta && catalogMeta.version) || '5.0-clean',
    os_detected: osDetected,
    duration_ms: Math.round(durationMs),
    verdict,
    heuristic_index: heuristicIndex,
    coverage: cleanCoverage,
    counters: {
      raw_occurrences: rawOccurrences,
      unique_events: uniqueEvents,
      corroborated_evidence: corroboratedCount,
      anomaly_review: reviewCount,
      unvalidated_reference: unvalidatedCount,
      informational: informationalCount,
      inactive_short_tokens: inactiveRulesCount
    },
    domains: domainCounts,
    device_info: deviceInfo,
    events
  };
}
