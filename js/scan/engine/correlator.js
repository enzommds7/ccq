/* ══════════════════════════════════════════════════════════════════
   ccq scan — CORRELACIONADOR DE EVIDÊNCIAS & VEREDITO
   - Exige >= 2 fontes técnicas efetivamente independentes para EVIDÊNCIA CORROBORADA
   - Impede inflação artificial de pontuação (teto por família + bônus limitado)
   - Separa rigorosamente Cobertura de Índice Heurístico
   - Nunca declara "100% limpo" nem "Ban Direto"
   - Diante de lacunas / parser ausente, declara INCONCLUSIVO
   ══════════════════════════════════════════════════════════════════ */
import { DOMAIN_LABELS, EVIDENCE_LEVEL_LABELS, EVIDENCE_LEVEL_RANK } from './matcher.js';

const SIGNAL_FAMILY_MAP = Object.freeze({
  ff_sh_gpp2_exec: { family: 'selinux_gameasset', label: 'SELinux/auditd GameAsset', corroborationEligible: true },
  ff_sh_gpp2_mismatch: { family: 'selinux_gameasset', label: 'SELinux/auditd GameAsset (inconsistência contextual)', corroborationEligible: true },
  ff_shgap_dir: { family: 'fs_gameasset', label: 'Diretório anômalo no jogo', corroborationEligible: true },
  ff_jar_loaded: { family: 'classloader_jar', label: 'ClassLoader/execução de JAR', corroborationEligible: true },
  ff_non_playstore: { family: 'packagemanager_origin', label: 'Origem de instalação fora da Play Store', corroborationEligible: true },
  android_candidate_pkg: { family: 'packagemanager_pkg', label: 'Pacote candidato instalado', corroborationEligible: true },
  android_root_env: { family: 'root_environment', label: 'Ambiente Root/Módulos', corroborationEligible: true },
  android_boot_unlocked: { family: 'boot_properties', label: 'Propriedades de Boot/SELinux', corroborationEligible: true },
  android_setedit_anomaly: { family: 'settings_provider', label: 'Alteração via SetEdit', corroborationEligible: true },
  android_shell_settings_anomaly: { family: 'settings_provider', label: 'Alteração de Settings via Android Shell', corroborationEligible: false },
  injected_backtrace: { family: 'crash_backtrace', label: 'Biblioteca externa em backtrace', corroborationEligible: true },
  android_adb_tcp_port: { family: 'adb_config', label: 'Porta ADB TCP configurada (compatível com Brevent/Shizuku)', corroborationEligible: false },
  android_adb_remote: { family: 'adb_network', label: 'ADB remoto via rede', corroborationEligible: true },
  android_adb_forward: { family: 'adb_network', label: 'Encaminhamento de porta ADB', corroborationEligible: false },
  android_overlay_active: { family: 'window_overlay', label: 'Janela sobreposta (WindowManager/SurfaceFlinger)', corroborationEligible: true },
  android_proxy_tool: { family: 'network_proxy', label: 'Proxy/MITM configurado', corroborationEligible: true },
  proxy_named_domain: { family: 'network_dns', label: 'Domínio/perfil proxy em contexto de rede', corroborationEligible: true },
  proxy_alias_candidate: { family: 'network_dns', label: 'Alias textual de proxy/bypass em contexto de rede', corroborationEligible: true },
  network_ip_candidate: { family: 'network_ip', label: 'Endereço IP candidato (sem reputação permanente)', corroborationEligible: false },
  profile_ref_candidate: { family: 'profile_reference', label: 'Referência de perfil candidata', corroborationEligible: true },
  tool_indicator_detected: { family: 'debug_tool', label: 'Ferramenta candidata em contexto operacional', corroborationEligible: true },
  proxy_package_installed: { family: 'packagemanager_proxy', label: 'Pacote proxy instalado', corroborationEligible: true },
  ios_usedimage_injection: { family: 'ios_crash_ips', label: 'usedImages .ips com dylib suspeita', corroborationEligible: true },
  ios_ff_non_appstore: { family: 'ios_ips_origin', label: 'Metadados App Store divergentes em .ips', corroborationEligible: true },
  ios_proxy_profile: { family: 'ios_profile_plist', label: 'Perfil/Proxy estruturado em .plist', corroborationEligible: true },
  ios_dopamine_runtime: { family: 'ios_runtime_dopamine', label: 'Runtime Dopamine/Tweak em log decodificado', corroborationEligible: true },
  ios_jailbreak_runtime: { family: 'ios_runtime_jailbreak', label: 'Evento decodificado de jailbreak', corroborationEligible: true }
});

// Regras elegíveis para promoção a EVIDÊNCIA CORROBORADA quando sustentadas por >= 2 fontes técnicas independentes
const CORROBORATABLE_RULES = new Set([
  'ANDROID_GAME_SH_GPP2_EXEC_001',
  'ANDROID_GAME_SH_GPP2_CTX_MISMATCH_001',
  'ANDROID_GAME_SHGAP_DIR_001',
  'ANDROID_GAME_JAR_LOADED_001',
  'ANDROID_FF_NON_PLAYSTORE_001',
  'ANDROID_PKG_CANDIDATE_001',
  'ANDROID_PROFILE_PKG_001',
  'ANDROID_CRASH_INJECTED_BACKTRACE_001',
  'ANDROID_NET_PROXY_TOOL_001',
  'ANDROID_OVERLAY_ACTIVE_001',
  'PROXY_NAMED_DOMAIN_001',
  'PROXY_ALIAS_CANDIDATE_001',
  'PROFILE_REFERENCE_CANDIDATE_001',
  'TOOL_INDICATOR_CANDIDATE_001',
  'ANDROID_SETTINGS_SETEDIT_ANOMALY_001',
  'IOS_IPS_USEDIMAGE_DYLIB_001',
  'IOS_IPS_FF_SIDELOAD_001',
  'IOS_PLIST_PROXY_PROFILE_001',
  'IOS_DOPAMINE_EVENT_001',
  'IOS_JAILBREAK_EVENT_001'
]);

const RULE_SIGNAL_KEY = Object.freeze({
  ANDROID_GAME_SH_GPP2_EXEC_001: 'ff_sh_gpp2_exec',
  ANDROID_GAME_SH_GPP2_CTX_MISMATCH_001: 'ff_sh_gpp2_mismatch',
  ANDROID_GAME_SHGAP_DIR_001: 'ff_shgap_dir',
  ANDROID_GAME_JAR_LOADED_001: 'ff_jar_loaded',
  ANDROID_FF_NON_PLAYSTORE_001: 'ff_non_playstore',
  ANDROID_PKG_CANDIDATE_001: 'android_candidate_pkg',
  ANDROID_PROFILE_PKG_001: 'proxy_package_installed',
  ANDROID_ROOT_ENV_001: 'android_root_env',
  ANDROID_BOOT_UNLOCKED_001: 'android_boot_unlocked',
  ANDROID_CRASH_INJECTED_BACKTRACE_001: 'injected_backtrace',
  ANDROID_ADB_TCP_PORT_CONFIGURED_001: 'android_adb_tcp_port',
  ANDROID_ADB_REMOTE_001: 'android_adb_remote',
  ANDROID_ADB_FORWARD_001: 'android_adb_forward',
  ANDROID_OVERLAY_ACTIVE_001: 'android_overlay_active',
  ANDROID_NET_PROXY_TOOL_001: 'android_proxy_tool',
  PROXY_NAMED_DOMAIN_001: 'proxy_named_domain',
  PROXY_ALIAS_CANDIDATE_001: 'proxy_alias_candidate',
  NETWORK_IP_CANDIDATE_001: 'network_ip_candidate',
  PROFILE_REFERENCE_CANDIDATE_001: 'profile_ref_candidate',
  TOOL_INDICATOR_CANDIDATE_001: 'tool_indicator_detected',
  ANDROID_SETTINGS_SETEDIT_ANOMALY_001: 'android_setedit_anomaly',
  ANDROID_SETTINGS_SHELL_ANOMALY_001: 'android_shell_settings_anomaly',
  IOS_IPS_USEDIMAGE_DYLIB_001: 'ios_usedimage_injection',
  IOS_IPS_FF_SIDELOAD_001: 'ios_ff_non_appstore',
  IOS_PLIST_PROXY_PROFILE_001: 'ios_proxy_profile',
  IOS_DOPAMINE_EVENT_001: 'ios_dopamine_runtime',
  IOS_JAILBREAK_EVENT_001: 'ios_jailbreak_runtime'
});

const MAX_SINGLE_FAMILY_SCORE = 35;
const EXTRA_EVENT_SAME_FAMILY_STEP = 5;
const MAX_EXTRA_EVENT_SAME_FAMILY = 10;
const CORROBORATION_BONUS_PER_FAMILY = 15;
const MAX_CORROBORATION_BONUS = 25;

function summarizeIndependentFamilies(signalsMap) {
  const eligibleFamilies = new Map();
  for (const [sigKey, desc] of signalsMap.entries()) {
    const info = SIGNAL_FAMILY_MAP[sigKey] || { family: sigKey, label: sigKey, corroborationEligible: false };
    if (!info.corroborationEligible) continue;
    if (!eligibleFamilies.has(info.family)) {
      eligibleFamilies.set(info.family, `${info.label}: ${desc}`);
    }
  }
  return eligibleFamilies;
}

function resolveEventFamily(ev) {
  const sigKey = RULE_SIGNAL_KEY[ev.rule_id];
  if (sigKey && SIGNAL_FAMILY_MAP[sigKey]) {
    return SIGNAL_FAMILY_MAP[sigKey].family;
  }
  return (ev.source && ev.source.format) || ev.rule_id;
}

/**
 * Calcula o índice heurístico de forma calibrada e resistente à inflação artificial:
 * - Eventos da mesma família técnica sofrem amortecimento e teto (MAX_SINGLE_FAMILY_SCORE = 35)
 * - Corroboração real (>= 2 famílias elegíveis) adiciona bônus único limitado (máx +25),
 *   sem multiplicar ou sobrescrever os pesos individuais de cada evento.
 */
function computeCalibratedHeuristicIndex(events, eligibleFamilyCount, corroboratedCount) {
  const familyBuckets = new Map();

  for (const ev of events) {
    const w = Number(ev.heuristic_weight) || 0;
    if (w <= 0) continue;
    const fam = resolveEventFamily(ev);
    if (!familyBuckets.has(fam)) {
      familyBuckets.set(fam, []);
    }
    familyBuckets.get(fam).push(w);
  }

  let familyScoreSum = 0;
  for (const weights of familyBuckets.values()) {
    weights.sort((a, b) => b - a);
    const maxWeight = weights[0];
    const extraContribution = Math.min(
      MAX_EXTRA_EVENT_SAME_FAMILY,
      (weights.length - 1) * EXTRA_EVENT_SAME_FAMILY_STEP
    );
    const familyCap = Math.max(MAX_SINGLE_FAMILY_SCORE, maxWeight);
    familyScoreSum += Math.min(familyCap, maxWeight + extraContribution);
  }

  const corroborationBonus = (corroboratedCount > 0 && eligibleFamilyCount >= 2)
    ? Math.min(MAX_CORROBORATION_BONUS, (eligibleFamilyCount - 1) * CORROBORATION_BONUS_PER_FAMILY)
    : 0;

  return Math.min(100, familyScoreSum + corroborationBonus);
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
  const eligibleFamilyMap = summarizeIndependentFamilies(signals);

  // 1. Correlação estrita: >= 2 fontes técnicas independentes e elegíveis sustentam anomalia específica
  if (eligibleFamilyMap.size >= 2) {
    for (const ev of events) {
      if (ev.evidence_level !== 'anomaly_review') continue;
      if (!CORROBORATABLE_RULES.has(ev.rule_id)) continue;

      const ownFamily = resolveEventFamily(ev);
      const otherSources = [];
      for (const [fam, desc] of eligibleFamilyMap.entries()) {
        if (fam !== ownFamily) otherSources.push(desc);
      }

      if (otherSources.length >= 1) {
        ev.evidence_level = 'corroborated_evidence';
        ev.evidence_level_label = EVIDENCE_LEVEL_LABELS.corroborated_evidence;
        ev.corroboration = otherSources;
        // Preserva o peso individual calibrado do evento (sem inflar todos para 50)
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

  const heuristicIndex = computeCalibratedHeuristicIndex(
    events,
    eligibleFamilyMap.size,
    corroboratedCount
  );

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
    engine_version: '5.1.0',
    catalog_version: (catalogMeta && catalogMeta.version) || '5.1-clean',
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
