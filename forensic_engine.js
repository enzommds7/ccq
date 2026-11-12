/**
 * Cacique SCAN — Motor de Análise Forense Baseado em Evidências (v4.0)
 * =====================================================================
 * Compatível com Browser (window.CaciqueForensicEngine) e Node.js (module.exports).
 *
 * Elimina buscas genéricas por substring/hífen e aplica:
 * - Modelo formal de regras (id, os, category, fileTypes, allowedFields, matchType,
 *   requiredConditions, exclusionConditions, confidence, evidenceTier, status, version, provenance).
 * - Parsers dedicados: SELinux/auditd, Crashes/Tombstones, Hex Dumps, iOS Backup/Restore,
 *   Unified Logs (.tracev3), Rede/Proxy/DNS/Perfis e Origem de Instalação.
 * - Deduplicação de ocorrências repetidas e correlação de evidências independentes.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.CaciqueForensicEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const ENGINE_VERSION = '4.0.0';

  const EVIDENCE_TIERS = {
    textual_reference: 0,      // Referência textual — sem pontuação de ameaça
    contextual_event: 1,       // Evento contextual — baixa confiança
    specific_anomaly: 2,       // Anomalia específica — exige revisão
    corroborated_evidence: 3,  // Evidências independentes correlacionadas — confiança elevada
    confirmed_interference: 4  // Interferência tecnicamente confirmada
  };

  const CONFIDENCE_LABELS = {
    none: 'Nenhuma (Informativo)',
    low: 'Baixa',
    medium: 'Média',
    high: 'Alta',
    confirmed: 'Confirmada'
  };

  const TIER_LABELS = {
    textual_reference: 'Referência Textual',
    contextual_event: 'Evento Contextual',
    specific_anomaly: 'Anomalia Específica (Revisão Necessária)',
    corroborated_evidence: 'Evidências Corroboradas',
    confirmed_interference: 'Interferência Confirmada'
  };

  const CATEGORY_LABELS = {
    gameasset_anomaly: 'Anomalia em GameAsset (Free Fire)',
    suspicious_jar: 'Arquivos JAR em Cache (Free Fire)',
    stability_crash: 'Diagnóstico de Estabilidade & Crashes',
    github_hexdump: 'Referência em Hex Dump / Memória',
    casino_activity: 'Atividade de Cassino / Apostas',
    ios_backup_restore: 'iOS — Backup & Restauração',
    proxy_domain: 'Domínios & Indicadores de Proxy',
    profile_package_id: 'Identificadores de Pacotes & Perfis',
    proxy_experimental: 'Referências Experimentais Inativas (Proxy)',
    unified_log: 'iOS — Unified Logs (.tracev3)',
    ff_cheat: 'Cheats & Offsets Free Fire',
    ff_regedit: 'Regedits & Macros',
    overlay: 'Janelas Sobrepostas (Overlay)',
    injection: 'Injeção & Hooking',
    root_bypass: 'Root, Jailbreak & Bypass',
    installer_origin: 'Origem de Instalação',
    log_audit: 'Auditoria de Logging (Infraestrutura)',
    uncategorized: 'Não Categorizado'
  };

  // 8. Indicadores curtos/hexadecimais -> OBRIGATORIAMENTE experimental_inactive (sem alertas!)
  const EXPERIMENTAL_SHORT_HEX_TOKENS = [
    '06', '03', '051', '06a', '0af', '0b', '0E', 'od', '140', '1ea', '14', '105e', '15d', '1b69',
    '2c', '28a', '2bb', '3c', '3c4', '439', '40e', '4e', '4a', '4c', '4cf', '4d', '47', '51', '550',
    '5b', '5c10', '59ac', '60a', '60af', '62', '62d', '6b', '6dd', '69', '78f', '70a', '704114', '704',
    '70d', '739', '76d', '7d', '80', '84', '87', '9d', '90eb', '96f', 'a00', 'a1fc', 'a4', 'a9', 'a4c',
    'a48', 'a5', 'a64', 'ae7', 'b0', 'b9', 'b4', 'bc', 'bd', 'bd32', 'bd32d', 'c17', 'c25', 'c9', 'd14',
    'd03090', 'd141', 'd03', 'd5', 'd7319', 'dd4f0', 'dd4fa', 'd4f0', 'e0', 'e3', 'f54', 'f6', 'f6c',
    'f9', 'ff32', 'ff6'
  ];

  const PROXY_DOMAINS_TEXTUAL = [
    { pattern: 'authproxyxff.up', matchType: 'domain', desc: 'Domínio de Proxy AuthProxyXFF' },
    { pattern: 'dash.proxy', matchType: 'domain', desc: 'Domínio de Proxy Dash' },
    { pattern: 'freefireproxy.xyz', matchType: 'domain', desc: 'Domínio FreeFireProxy' },
    { pattern: 'vip.uncover', matchType: 'domain', desc: 'Domínio/Repo VIP Unc0ver' },
    { pattern: 'vip.uncOver', matchType: 'domain', desc: 'Domínio/Repo VIP Unc0ver' },
    { pattern: 'to.appdb.C2D9F2', matchType: 'domain', desc: 'Identificador/Domínio AppDB C2D9F2' },
    { pattern: 'to.appdb.certs1', matchType: 'domain', desc: 'Certificado/Domínio AppDB 1' },
    { pattern: 'to.appdb.certs2', matchType: 'domain', desc: 'Certificado/Domínio AppDB 2' },
    { pattern: 'iMac.EFB7D714', matchType: 'exact', desc: 'Hostname/Perfil iMac Proxy' },
    { pattern: 'proxyady', matchType: 'exact', desc: 'Indicador ProxyAdy' },
    { pattern: 'khoindvn', matchType: 'exact', desc: 'Indicador Khoindvn' },
    { pattern: 'TRONGHIEU', matchType: 'exact', desc: 'Perfil/Identificador TRONGHIEU' },
    { pattern: 'XITADO', matchType: 'exact', desc: 'Perfil/Identificador XITADO' },
    { pattern: 'mitm', matchType: 'exact', desc: 'Termo Genérico MITM (Requer contexto de rede/certificado)' },
    { pattern: 'Regedit', matchType: 'exact', desc: 'Termo Genérico Regedit (Requer contexto de configuração)' }
  ];

  const PACKAGE_AND_PROFILE_IDS = [
    { id: 'com.xtremo.mobile', desc: 'Pacote Xtremo Mobile' },
    { id: 'com.luxebypass', desc: 'Pacote/Perfil LuxeBypass' },
    { id: 'com.thanhcongregedit', desc: 'Pacote/Perfil ThanhCong Regedit' },
    { id: 'com.thanhcongregedit.apple.dns', desc: 'Perfil DNS ThanhCong Apple' },
    { id: 'com.congdatregedit', desc: 'Pacote/Perfil CongDat Regedit' },
    { id: 'com.headshot', desc: 'Pacote Headshot' },
    { id: 'com.apple.mgmt.External', desc: 'Perfil MDM Externo Apple (com.apple.mgmt.External)' },
    { id: 'com.antijudas.dns', desc: 'Perfil DNS AntiJudas' },
    { id: 'com.antijudas.ios', desc: 'Perfil/Bundle AntiJudas iOS' },
    { id: 'com.criperlegend', desc: 'Pacote/Perfil CriperLegend' },
    { id: 'com.giahuyregedit', desc: 'Pacote/Perfil GiaHuy Regedit' },
    { id: 'com.sensi.fluida.pro', desc: 'Pacote Sensi Fluida Pro' },
    { id: 'com.giahuyregedit.apple', desc: 'Perfil GiaHuy Regedit Apple' },
    { id: 'com.ngocsonregedit.apple', desc: 'Perfil NgocSon Regedit Apple' },
    { id: 'com.krarosxvenuxapple', desc: 'Perfil Kraros x Venux Apple' },
    { id: 'com.peligroff.input.redzone', desc: 'Perfil PeligroFF Input RedZone' },
    { id: 'com.solitude.profile.v12', desc: 'Perfil Solitude v12' },
    { id: 'com.demon.engine', desc: 'Pacote/Perfil Demon Engine' },
    { id: 'com.Vluv.lockprofile', desc: 'Perfil Vluv LockProfile' }
  ];

  const LEGACY_CHEAT_RULES = [
    { id: 'LEGACY_MAGISK_1', pattern: 'top.johnwu.magisk', os: 'android', cat: 'root_bypass', mtype: 'package_id', weight: 45, tier: 'corroborated_evidence', conf: 'high' },
    { id: 'LEGACY_MAGISK_2', pattern: 'com.topjohnwu.magisk', os: 'android', cat: 'root_bypass', mtype: 'package_id', weight: 45, tier: 'corroborated_evidence', conf: 'high' },
    { id: 'LEGACY_MAGISK_DELTA', pattern: 'io.github.huskydg.magisk', os: 'android', cat: 'root_bypass', mtype: 'package_id', weight: 45, tier: 'corroborated_evidence', conf: 'high' },
    { id: 'LEGACY_ZYGISK', pattern: 'zygisk', os: 'android', cat: 'root_bypass', mtype: 'exact', weight: 35, tier: 'specific_anomaly', conf: 'medium' },
    { id: 'LEGACY_FRIDA_SERVER', pattern: 'frida-server', os: 'both', cat: 'injection', mtype: 'exact', weight: 55, tier: 'corroborated_evidence', conf: 'high' },
    { id: 'LEGACY_FRIDA_GADGET', pattern: 'frida-gadget', os: 'both', cat: 'injection', mtype: 'exact', weight: 55, tier: 'corroborated_evidence', conf: 'high' },
    { id: 'LEGACY_LSPOSED', pattern: 'lsposed', os: 'android', cat: 'injection', mtype: 'exact', weight: 40, tier: 'specific_anomaly', conf: 'medium' },
    { id: 'LEGACY_XPOSED', pattern: 'de.robv.android.xposed', os: 'android', cat: 'injection', mtype: 'package_id', weight: 45, tier: 'corroborated_evidence', conf: 'high' },
    { id: 'LEGACY_GAMEGUARDIAN', pattern: 'gameguardian', os: 'android', cat: 'ff_cheat', mtype: 'exact', weight: 50, tier: 'corroborated_evidence', conf: 'high' },
    { id: 'LEGACY_LUCKYPATCHER', pattern: 'com.chelpus.lackypatch', os: 'android', cat: 'ff_cheat', mtype: 'package_id', weight: 45, tier: 'corroborated_evidence', conf: 'high' },
    { id: 'LEGACY_IL2CPP_DUMPER', pattern: 'il2cppdumper', os: 'both', cat: 'ff_cheat', mtype: 'exact', weight: 50, tier: 'corroborated_evidence', conf: 'high' },
    { id: 'LEGACY_DRIPWIRE', pattern: 'dripwire.cc', os: 'both', cat: 'overlay', mtype: 'domain', weight: 45, tier: 'specific_anomaly', conf: 'medium' },
    { id: 'LEGACY_LETUNIA', pattern: 'LetuniaProxy.ff', os: 'both', cat: 'proxy_domain', mtype: 'domain', weight: 45, tier: 'specific_anomaly', conf: 'medium' },
    { id: 'LEGACY_IOS_CYDIA', pattern: 'cydia', os: 'ios', cat: 'root_bypass', mtype: 'exact', weight: 40, tier: 'specific_anomaly', conf: 'medium' },
    { id: 'LEGACY_IOS_SILEO', pattern: 'sileo', os: 'ios', cat: 'root_bypass', mtype: 'exact', weight: 40, tier: 'specific_anomaly', conf: 'medium' },
    { id: 'LEGACY_IOS_TROLLSTORE', pattern: 'com.opa334.trollstore', os: 'ios', cat: 'root_bypass', mtype: 'package_id', weight: 45, tier: 'corroborated_evidence', conf: 'high' },
    { id: 'LEGACY_IOS_DOPAMINE', pattern: 'dopamine', os: 'ios', cat: 'root_bypass', mtype: 'exact', weight: 40, tier: 'specific_anomaly', conf: 'medium' },
    { id: 'LEGACY_IOS_FILZA', pattern: 'com.tigisoftware.filza', os: 'ios', cat: 'root_bypass', mtype: 'package_id', weight: 40, tier: 'specific_anomaly', conf: 'medium' }
  ];

  function buildRuleRegistry() {
    const rules = [];

    rules.push({
      id: 'FF_GAMEASSET_SH_GPP2_AUDITD',
      name: 'Anomalia em arquivo do Free Fire (SH-Gpp2)',
      os: 'android',
      category: 'gameasset_anomaly',
      fileTypes: ['auditd', 'logcat', 'bugreport', 'generic_text'],
      allowedFields: ['path', 'comm', 'app', 'avc_action', 'operations'],
      matchType: 'path',
      pattern: '/data/user/0/com.dts.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2',
      requiredConditions: { package: 'com.dts.freefiremax' },
      exclusionConditions: { ignoreUnrelatedContext: true },
      confidence: 'medium',
      evidenceTier: 'specific_anomaly',
      corroboratingEvidence: ['installer_non_playstore', 'gameasset_tampering'],
      status: 'active',
      version: '4.0.0',
      provenance: 'Cacique Forensics Lab — SELinux Auditd Policy',
      baseWeight: 30
    });

    rules.push({
      id: 'FF_UNVERIFIED_FOLDER_SHGAP',
      name: 'Anomalia em arquivo do Free Fire — Pasta -SHgap-',
      os: 'android',
      category: 'gameasset_anomaly',
      fileTypes: ['auditd', 'logcat', 'bugreport', 'generic_text'],
      allowedFields: ['path'],
      matchType: 'path',
      pattern: '-SHgap-',
      requiredConditions: { mustBePathComponent: true },
      exclusionConditions: { mustNotMatchGenericHyphen: true },
      confidence: 'medium',
      evidenceTier: 'specific_anomaly',
      corroboratingEvidence: ['gameasset_tampering', 'installer_non_playstore'],
      status: 'active',
      version: '4.0.0',
      provenance: 'Cacique Forensics Lab — Free Fire Directory Verification',
      baseWeight: 25
    });

    ['app_resources_lib.jar', 'google_api_resources_lib.jar'].forEach((jarName) => {
      rules.push({
        id: jarName === 'app_resources_lib.jar' ? 'FF_CACHE_JAR_APP_RESOURCES' : 'FF_CACHE_JAR_GOOGLE_API',
        name: `Arquivo JAR em Cache Free Fire (${jarName})`,
        os: 'android',
        category: 'suspicious_jar',
        fileTypes: ['auditd', 'logcat', 'bugreport', 'dumpsys', 'generic_text'],
        allowedFields: ['path', 'classloader', 'process'],
        matchType: 'path',
        pattern: `/data/user/0/com.dts.freefiremax/cache/${jarName}`,
        requiredConditions: { package: 'com.dts.freefiremax', mustNotMatchExtensionOnly: true },
        exclusionConditions: {},
        confidence: 'low',
        evidenceTier: 'contextual_event',
        corroboratingEvidence: ['classloader_execution'],
        status: 'active',
        version: '4.0.0',
        provenance: 'Cacique Forensics Lab — Cache JAR Inspection',
        baseWeight: 15
      });
    });

    rules.push({
      id: 'STABILITY_LOW_MEMORY',
      name: 'Encerramento por Memória (LOW_MEMORY)',
      os: 'android',
      category: 'stability_crash',
      fileTypes: ['logcat', 'bugreport', 'crash_tombstone', 'generic_text'],
      allowedFields: ['reason', 'raw_line'],
      matchType: 'regex_contextual',
      pattern: 'LOW_MEMORY',
      requiredConditions: {},
      exclusionConditions: {},
      confidence: 'none',
      evidenceTier: 'textual_reference',
      corroboratingEvidence: [],
      status: 'reclassified',
      version: '4.0.0',
      provenance: 'Android ActivityManager — Reclassificado para stability_crash',
      baseWeight: 0
    });

    rules.push({
      id: 'STABILITY_NATIVE_SIGSEGV',
      name: 'Crash Nativo / Falha de Memória (SIGSEGV / SEGV_MAPERR)',
      os: 'both',
      category: 'stability_crash',
      fileTypes: ['crash_tombstone', 'logcat', 'bugreport', 'ios_ips_crash', 'generic_text'],
      allowedFields: ['signal', 'cause', 'raw_line'],
      matchType: 'regex_contextual',
      pattern: 'SIGSEGV|SEGV_MAPERR',
      requiredConditions: {},
      exclusionConditions: {},
      confidence: 'none',
      evidenceTier: 'textual_reference',
      corroboratingEvidence: ['suspicious_loaded_library_in_backtrace'],
      status: 'reclassified',
      version: '4.0.0',
      provenance: 'Crash/Tombstone Analyzer — Reclassificado para stability_crash',
      baseWeight: 0
    });

    rules.push({
      id: 'HEXDUMP_GITHUB_REFERENCE',
      name: 'URL GitHub Reconstruída em Hex Dump',
      os: 'both',
      category: 'github_hexdump',
      fileTypes: ['crash_tombstone', 'bugreport', 'generic_text'],
      allowedFields: ['hexdump_ascii', 'url'],
      matchType: 'regex_contextual',
      pattern: 'https?://github\\.com/',
      requiredConditions: {},
      exclusionConditions: {},
      confidence: 'none',
      evidenceTier: 'textual_reference',
      corroboratingEvidence: [],
      status: 'reclassified',
      version: '4.0.0',
      provenance: 'Hex Dump Reconstructor — Reclassificado para github_hexdump',
      baseWeight: 0
    });

    rules.push({
      id: 'CASINO_DOMAIN_OR_APP',
      name: 'Indicador Estruturado de Cassino / Apostas',
      os: 'both',
      category: 'casino_activity',
      fileTypes: ['network_proxy', 'packages', 'logcat', 'bugreport', 'ios_unified_log'],
      allowedFields: ['domain', 'url', 'package', 'bundle_id'],
      matchType: 'domain',
      pattern: 'blaze.com|betano.com|bet365.com|sportingbet.com|estrelabet.com|pixbet.com|stake.com|1xbet.com',
      requiredConditions: {},
      exclusionConditions: { mustNotMatchHyphenOnly: true },
      confidence: 'low',
      evidenceTier: 'contextual_event',
      corroboratingEvidence: [],
      status: 'active',
      version: '4.0.0',
      provenance: 'Cacique Forensics Lab — Substitui regra inválida de hífen',
      baseWeight: 0
    });

    EXPERIMENTAL_SHORT_HEX_TOKENS.forEach((tok) => {
      rules.push({
        id: `PROXY_EXP_${tok.toUpperCase()}`,
        name: `Referência Experimental Inativa: ${tok}`,
        os: 'both',
        category: 'proxy_experimental',
        fileTypes: [],
        allowedFields: [],
        matchType: 'exact',
        pattern: tok,
        requiredConditions: {},
        exclusionConditions: {},
        confidence: 'none',
        evidenceTier: 'textual_reference',
        corroboratingEvidence: [],
        status: 'experimental_inactive',
        version: '4.0.0',
        provenance: 'Lista Proxy 09/08/2026 — Desativada até documentação de formato',
        baseWeight: 0
      });
    });

    PROXY_DOMAINS_TEXTUAL.forEach((d) => {
      rules.push({
        id: `PROXY_TEXT_${d.pattern.replace(/[^A-Za-z0-9]+/g, '_').toUpperCase()}`,
        name: d.desc,
        os: 'both',
        category: 'proxy_domain',
        fileTypes: ['network_proxy', 'ios_plist', 'packages', 'auditd', 'logcat', 'bugreport', 'ios_unified_log'],
        allowedFields: ['domain', 'url', 'dns', 'proxy_host'],
        matchType: d.matchType,
        pattern: d.pattern,
        requiredConditions: {},
        exclusionConditions: {},
        confidence: 'medium',
        evidenceTier: 'specific_anomaly',
        corroboratingEvidence: ['active_proxy_config'],
        status: 'active',
        version: '4.0.0',
        provenance: 'Lista Proxy 09/08/2026 — Pesquisa restrita a campos de rede/perfil',
        baseWeight: 20
      });
    });

    PACKAGE_AND_PROFILE_IDS.forEach((p) => {
      rules.push({
        id: `PKG_PROFILE_${p.id.replace(/[^A-Za-z0-9]+/g, '_').toUpperCase()}`,
        name: `${p.desc} (${p.id})`,
        os: 'both',
        category: 'profile_package_id',
        fileTypes: ['packages', 'ios_plist', 'network_proxy', 'logcat', 'bugreport', 'ios_unified_log'],
        allowedFields: ['package', 'bundle_id', 'profile_id'],
        matchType: 'package_id',
        pattern: p.id,
        requiredConditions: {},
        exclusionConditions: {},
        confidence: p.id === 'com.apple.mgmt.External' ? 'low' : 'medium',
        evidenceTier: p.id === 'com.apple.mgmt.External' ? 'contextual_event' : 'specific_anomaly',
        corroboratingEvidence: ['profile_installed', 'active_proxy_config'],
        status: 'active',
        version: '4.0.0',
        provenance: 'Lista Perfis/Pacotes 09/08/2026 — Match exato',
        baseWeight: p.id === 'com.apple.mgmt.External' ? 5 : 25
      });
    });

    LEGACY_CHEAT_RULES.forEach((r) => {
      rules.push({
        id: r.id,
        name: `Indicador: ${r.pattern}`,
        os: r.os,
        category: r.cat,
        fileTypes: ['packages', 'auditd', 'logcat', 'bugreport', 'crash_tombstone', 'ios_plist', 'ios_unified_log', 'generic_text'],
        allowedFields: ['package', 'process', 'path', 'domain'],
        matchType: r.mtype,
        pattern: r.pattern,
        requiredConditions: {},
        exclusionConditions: {},
        confidence: r.conf,
        evidenceTier: r.tier,
        corroboratingEvidence: [],
        status: 'active',
        version: '4.0.0',
        provenance: 'Lista de assinaturas clássicas (reclassificada com fronteira exata)',
        baseWeight: r.weight
      });
    });

    return rules;
  }

  const RULE_REGISTRY = buildRuleRegistry();

  // ── Utilitários & Parsers ──

  function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function canonicalizeAndroidPath(p) {
    if (!p) return '';
    const clean = p.replace(/\\/g, '/').trim();
    if (clean.startsWith('/data/data/')) {
      return '/data/user/0/' + clean.slice('/data/data/'.length);
    }
    return clean;
  }

  function classifyFileType(filename, contentHead) {
    const low = (filename || '').replace(/\\/g, '/').toLowerCase();
    const base = low.split('/').pop() || '';

    if (low.endsWith('.tracev3')) return 'ios_tracev3';
    if (low.endsWith('.ips') || low.includes('crashreporter')) return 'ios_ips_crash';
    if (low.endsWith('.plist') || low.endsWith('.mobileconfig')) return 'ios_plist';
    if (base.includes('audit') || base.includes('selinux')) return 'auditd';
    if (low.includes('tombstone') || low.includes('anr') || low.includes('crash')) return 'crash_tombstone';
    if (base.includes('packages') && (low.endsWith('.xml') || low.endsWith('.list') || !base.includes('.'))) return 'packages';
    if (['network', 'connectivity', 'netstats', 'proxy', 'vpn', 'dns', 'hosts', 'wifi'].some(k => base.includes(k))) return 'network_proxy';
    if (base.includes('logcat')) return 'logcat';
    if (base.includes('bugreport') || base.includes('dumpsys')) return 'bugreport';
    if (low.includes('sysdiagnose') || base.includes('unified') || low.includes('system_logs')) return 'ios_unified_log';

    if (contentHead) {
      const h = contentHead.slice(0, 4000).toLowerCase();
      if (h.includes('avc:') && h.includes('audit(')) return 'auditd';
      if (h.includes('signal 11 (sigsegv)') || h.includes('backtrace:')) return 'crash_tombstone';
      if (h.includes('installerpackagename=')) return 'packages';
    }
    return 'generic_text';
  }

  const AUDITD_AVC_RE = /audit\(([^)]+)\):\s*avc:\s*(granted|denied)\s*\{\s*([^}]+)\s*\}\s*for\s+(.+)/i;

  function parseAuditdLine(line) {
    const m = AUDITD_AVC_RE.exec(line);
    if (!m) return null;
    const body = m[4];
    const fields = {
      timestamp: m[1].trim(),
      avc_action: m[2].toLowerCase(),
      operations: m[3].trim().toLowerCase().split(/\s+/)
    };
    const keys = ['comm', 'path', 'dev', 'ino', 'scontext', 'tcontext', 'tclass', 'app', 'name'];
    for (const k of keys) {
      const km = new RegExp(`\\b${k}=(?:"([^"]+)"|([^\\s]+))`).exec(body);
      if (km) {
        fields[k] = km[1] !== undefined ? km[1] : km[2];
      }
    }
    if (fields.path) {
      fields.canonical_path = canonicalizeAndroidPath(fields.path);
    }
    return fields;
  }

  const HEXDUMP_LINE_RE = /^\s*([0-9a-fA-F]{8,16})\s+((?:[0-9a-fA-F]{2,16}\s+){1,8})\s*(.{1,32})?\s*$/;

  function parseHexDumpLines(lines) {
    const chunks = [];
    let currentBytes = [];
    let startLine = -1;
    let startAddr = '';

    function flush(endIdx) {
      if (currentBytes.length > 0) {
        const ascii = currentBytes.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
        const urls = ascii.match(/https?:\/\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]+/g) || [];
        chunks.push({
          startLine,
          endLine: endIdx,
          startAddr,
          byteCount: currentBytes.length,
          reconstructedAscii: ascii,
          urls
        });
        currentBytes = [];
        startLine = -1;
        startAddr = '';
      }
    }

    for (let idx = 0; idx < lines.length; idx++) {
      const m = HEXDUMP_LINE_RE.exec(lines[idx]);
      if (!m) {
        flush(idx - 1);
        continue;
      }
      if (startLine === -1) {
        startLine = idx;
        startAddr = m[1];
      }
      const groups = m[2].trim().split(/\s+/);
      const asciiCol = (m[3] || '').trim();
      for (const grp of groups) {
        if (grp.length % 2 !== 0) continue;
        const rawBytes = [];
        for (let i = 0; i < grp.length; i += 2) {
          rawBytes.push(parseInt(grp.slice(i, i + 2), 16));
        }
        const revBytes = rawBytes.slice().reverse();
        const revStr = revBytes.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
        const rawStr = rawBytes.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
        if (asciiCol && (asciiCol.includes(revStr.slice(0, 4)) || asciiCol.includes(revStr.slice(-4)))) {
          currentBytes.push(...revBytes);
        } else if (asciiCol && (asciiCol.includes(rawStr.slice(0, 4)) || asciiCol.includes(rawStr.slice(-4)))) {
          currentBytes.push(...rawBytes);
        } else {
          currentBytes.push(...((rawBytes.length === 4 || rawBytes.length === 8) ? revBytes : rawBytes));
        }
      }
    }
    flush(lines.length - 1);
    return chunks;
  }

  function isTraceV3Binary(uint8) {
    if (!uint8 || uint8.length < 16) return false;
    const tag = (uint8[0]) | (uint8[1] << 8) | (uint8[2] << 16) | (uint8[3] << 24);
    if (tag === 0x00001000 || tag === 0x00006001 || tag === 0x00006002 || tag === 0x00006003) return true;
    // Check 'hdb' signature in first 64 bytes
    for (let i = 0; i < Math.min(61, uint8.length - 3); i++) {
      if (uint8[i] === 104 && uint8[i + 1] === 100 && uint8[i + 2] === 98) return true;
    }
    return false;
  }

  const LOGCAT_TS_PROC_RE = /^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(?:\S+\s+)?(\d+)\s+(\d+)\s+([VDIWEFS])\s+([^:]+):/;
  const ISO_TS_RE = /(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?)/;

  function getLineContext(lines, idx) {
    const prevLine = idx > 0 ? lines[idx - 1].replace(/\r$/, '').slice(0, 200) : '';
    const currentLine = lines[idx].replace(/\r$/, '').slice(0, 240);
    const nextLine = idx + 1 < lines.length ? lines[idx + 1].replace(/\r$/, '').slice(0, 200) : '';
    let timestamp = '';
    let process = '';
    const mLog = LOGCAT_TS_PROC_RE.exec(currentLine);
    if (mLog) {
      timestamp = mLog[1];
      process = mLog[5].trim();
    } else {
      const mIso = ISO_TS_RE.exec(currentLine);
      if (mIso) timestamp = mIso[1];
    }
    return { prevLine, currentLine, nextLine, timestamp, process };
  }

  function makeAlert({
    signatureId,
    signatureName,
    category,
    sourceFile,
    process,
    timestamp,
    contextualSnippet,
    observedEvent,
    technicalInterpretation,
    corroboratingEvidence,
    confidence,
    evidenceTier,
    classificationReason,
    recommendedAction,
    limitation,
    weight,
    ruleVersion = '4.0.0',
    provenance = 'Cacique Forensics Lab',
    dedupKey = null
  }) {
    return {
      signature_id: signatureId,
      signature_name: signatureName,
      category,
      category_label: CATEGORY_LABELS[category] || category,
      source_file: sourceFile,
      process: process || 'Não identificado',
      timestamp: timestamp || 'Não disponível',
      contextual_snippet: contextualSnippet,
      observed_event: observedEvent,
      technical_interpretation: technicalInterpretation,
      corroborating_evidence: corroboratingEvidence || [],
      confidence,
      confidence_label: CONFIDENCE_LABELS[confidence] || confidence,
      evidence_tier: evidenceTier,
      evidence_tier_label: TIER_LABELS[evidenceTier] || evidenceTier,
      classification_reason: classificationReason,
      recommended_action: recommendedAction,
      limitation,
      weight,
      raw_occurrences: 1,
      rule_version: ruleVersion,
      provenance,
      _dedupKey: dedupKey || `${signatureId}|${sourceFile}|${process}`
    };
  }

  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  class ForensicEngine {
    constructor(rules) {
      this.rules = rules || RULE_REGISTRY;
      this.activeRules = this.rules.filter(r => r.status !== 'experimental_inactive');
    }

    detectOS(files) {
      const joined = files.map(f => (f.path || '').toLowerCase()).join(' ');
      const iosScore = ['sysdiagnose', '.plist', '.tracev3', '.ips', 'mobilebackup'].filter(k => joined.includes(k)).length;
      const androidScore = ['bugreport', 'logcat', 'dumpsys', 'audit', 'packages'].filter(k => joined.includes(k)).length;
      return iosScore > androidScore ? 'ios' : 'android';
    }

    async analyzeFiles(files, options = {}) {
      const osHint = (options.osHint || 'auto').toLowerCase();
      const onProgress = options.onProgress || null;
      const detectedOS = (osHint === 'android' || osHint === 'ios') ? osHint : this.detectOS(files);

      const rawAlerts = [];
      const unanalyzedFiles = [];
      const signals = new Set();
      let analyzedFiles = 0;
      let totalLines = 0;

      for (let fIdx = 0; fIdx < files.length; fIdx++) {
        const entry = files[fIdx];
        const fpath = entry.path || 'unknown';
        const rawBytes = entry.bytes || null;
        let text = entry.text;

        if (fpath.toLowerCase().endsWith('.tracev3')) {
          const isBin = rawBytes ? isTraceV3Binary(rawBytes) : false;
          unanalyzedFiles.push({
            file: fpath,
            reason: isBin
              ? "Não analisado — formato binário Unified Log (.tracev3) requer conversão via ferramenta compatível (ex: macOS 'log show')."
              : 'Não analisado — arquivo .tracev3 sem parser binário nativo disponível.'
          });
          continue;
        }

        if (text == null && rawBytes) {
          text = new TextDecoder('utf-8', { fatal: false }).decode(rawBytes);
        }
        if (!text) continue;

        analyzedFiles++;
        const lines = text.split(/\r?\n/);
        if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
        totalLines += lines.length;
        const ftype = classifyFileType(fpath, text.slice(0, 4000));

        // Processar em blocos de linhas para manter a UI responsiva em logs grandes (50k+ linhas)
        const BATCH = 5000;
        for (let start = 0; start < lines.length; start += BATCH) {
          const end = Math.min(lines.length, start + BATCH);
          this._analyzeAuditdAndGameasset(lines, start, end, fpath, rawAlerts, signals);
          this._analyzeSuspiciousJars(lines, start, end, fpath, rawAlerts, signals);
          this._analyzeCrashesAndStability(lines, start, end, fpath, rawAlerts, signals);
          this._analyzeCasinoActivity(lines, start, end, fpath, ftype, rawAlerts);
          if (detectedOS === 'ios' || ['ios_unified_log', 'ios_plist', 'ios_ips_crash'].includes(ftype)) {
            this._analyzeIosBackupRestore(lines, start, end, fpath, rawAlerts, signals);
          }
          this._analyzeProxiesAndProfiles(lines, start, end, fpath, ftype, rawAlerts, signals);
          this._analyzeLegacyContextual(lines, start, end, fpath, ftype, detectedOS, rawAlerts, signals);

          if (lines.length > BATCH && typeof setTimeout === 'function' && options.yieldAsync !== false) {
            if (onProgress) onProgress(fIdx / files.length, fpath);
            await sleep(0);
          }
        }

        this._analyzeHexdumpsAndGithub(lines, fpath, rawAlerts);
        if (detectedOS === 'android') {
          this._analyzeInstallerOrigins(text, lines, fpath, rawAlerts, signals);
        }
      }

      const { dedupedAlerts, rawOccurrencesCount } = this._deduplicateAlerts(rawAlerts);
      this._correlateEvidence(dedupedAlerts, signals);

      const uniqueEvents = dedupedAlerts.length;
      const validatedEvidence = dedupedAlerts.filter(a => ['corroborated_evidence', 'confirmed_interference'].includes(a.evidence_tier)).length;
      const reviewAlerts = dedupedAlerts.filter(a => a.evidence_tier === 'specific_anomaly').length;
      const informativeEvents = dedupedAlerts.filter(a => ['textual_reference', 'contextual_event'].includes(a.evidence_tier)).length;

      const threatScore = dedupedAlerts.reduce((acc, a) => acc + (a.weight || 0), 0);
      const integrityScore = Math.max(0, 100 - Math.min(100, threatScore));

      const hasGameassetAnomaly = dedupedAlerts.some(a =>
        (a.signature_id === 'FF_UNVERIFIED_FOLDER_SHGAP' || a.signature_id === 'FF_GAMEASSET_SH_GPP2_AUDITD') &&
        ['specific_anomaly', 'corroborated_evidence', 'confirmed_interference'].includes(a.evidence_tier)
      );

      const verdict = this._computeVerdict(dedupedAlerts, unanalyzedFiles, threatScore);

      return {
        engine_version: ENGINE_VERSION,
        os_detected: detectedOS.toUpperCase(),
        verdict,
        threat_score: threatScore,
        integrity_score: integrityScore,
        has_gameasset_anomaly: hasGameassetAnomaly,
        counters: {
          raw_occurrences: rawOccurrencesCount,
          unique_events: uniqueEvents,
          validated_evidence: validatedEvidence,
          review_alerts: reviewAlerts,
          informative_events: informativeEvents,
          unanalyzed_files: unanalyzedFiles.length,
          analyzed_files: analyzedFiles,
          checked_lines: totalLines,
          inactive_experimental_rules: this.rules.filter(r => r.status === 'experimental_inactive').length
        },
        alerts: dedupedAlerts,
        unanalyzed_files: unanalyzedFiles
      };
    }

    _analyzeAuditdAndGameasset(lines, start, end, fpath, alerts, signals) {
      const targetCanon = '/data/user/0/com.dts.freefiremax/files/contentcache/compulsory/android/gameassetbundles/font/sh-gpp2';
      for (let idx = start; idx < end; idx++) {
        const line = lines[idx];
        const low = line.toLowerCase();
        if (!low.includes('sh-gpp2') && !low.includes('-shgap-')) continue;

        const ctx = getLineContext(lines, idx);
        const audit = parseAuditdLine(line);

        if (audit && audit.canonical_path && audit.canonical_path.toLowerCase().includes('sh-gpp2')) {
          const cpath = audit.canonical_path;
          const isExact = cpath.toLowerCase() === targetCanon;
          const comm = audit.comm || '';
          const app = audit.app || '';
          const action = audit.avc_action || '';
          const ops = audit.operations || [];

          if (isExact && app === 'com.dts.freefiremax') {
            if (action === 'granted' && ops.includes('execute') && comm === 'UnityMain') {
              signals.add('avc_granted_execute_sh_gpp2');
              alerts.push(makeAlert({
                signatureId: 'FF_GAMEASSET_SH_GPP2_AUDITD',
                signatureName: 'Anomalia em arquivo do Free Fire (SH-Gpp2)',
                category: 'gameasset_anomaly',
                sourceFile: fpath,
                process: comm,
                timestamp: audit.timestamp || ctx.timestamp,
                contextualSnippet: ctx,
                observedEvent: `SELinux avc: granted { ${ops.join(', ')} } para comm="${comm}" em ${audit.path} (app=${app}).`,
                technicalInterpretation: 'SELinux permitiu (granted) uma operação de execução no caminho de recurso font/SH-Gpp2 associado ao pacote com.dts.freefiremax.',
                corroboratingEvidence: [],
                confidence: 'medium',
                evidenceTier: 'specific_anomaly',
                classificationReason: 'Execução registrada pelo kernel/SELinux em caminho de recurso sujeito à validação de integridade.',
                recommendedAction: 'Verificar integridade do recurso, versão do jogo e outros eventos relacionados; recomendar reinstalação oficial caso haja indícios consistentes de adulteração.',
                limitation: 'Esse registro isolado não comprova injeção de código nem autoriza punição automática.',
                weight: 30,
                dedupKey: `FF_GAMEASSET_SH_GPP2_AUDITD|${cpath}|${action}|${ops.join('_')}`
              }));
            } else if (action === 'denied') {
              alerts.push(makeAlert({
                signatureId: 'FF_GAMEASSET_SH_GPP2_DENIED',
                signatureName: 'Tentativa SELinux Negada em GameAsset (SH-Gpp2)',
                category: 'gameasset_anomaly',
                sourceFile: fpath,
                process: comm || ctx.process,
                timestamp: audit.timestamp || ctx.timestamp,
                contextualSnippet: ctx,
                observedEvent: `SELinux avc: denied { ${ops.join(', ')} } em ${audit.path} (app=${app}).`,
                technicalInterpretation: 'O SELinux bloqueou (denied) a operação no arquivo SH-Gpp2; não houve execução permitida neste evento.',
                corroboratingEvidence: [],
                confidence: 'low',
                evidenceTier: 'contextual_event',
                classificationReason: "Operação negada pelo SELinux (diferenciada de 'granted').",
                recommendedAction: 'Apenas registrar para contexto; verificar se há outros eventos permitidos.',
                limitation: 'Operação bloqueada pelo sistema.',
                weight: 5,
                dedupKey: `FF_GAMEASSET_SH_GPP2_DENIED|${cpath}`
              }));
            }
            continue;
          }
        }

        if (/\/data\/(?:user\/0|data)\/com\.dts\.freefiremax\/files\/contentcache\/Compulsory\/android\/gameassetbundles\/font\/SH-Gpp2\b/.test(line)) {
          alerts.push(makeAlert({
            signatureId: 'FF_GAMEASSET_SH_GPP2_PATH_REF',
            signatureName: 'Referência ao caminho SH-Gpp2 do Free Fire',
            category: 'gameasset_anomaly',
            sourceFile: fpath,
            process: ctx.process,
            timestamp: ctx.timestamp,
            contextualSnippet: ctx,
            observedEvent: 'Caminho específico de SH-Gpp2 citado em log.',
            technicalInterpretation: 'Referência textual ao caminho do arquivo SH-Gpp2 sem evento de execução SELinux confirmado nesta linha.',
            corroboratingEvidence: [],
            confidence: 'low',
            evidenceTier: 'contextual_event',
            classificationReason: 'Caminho compatível encontrado, mas sem confirmação de execução nesta linha.',
            recommendedAction: 'Verificar se existe evento auditd/execução correspondente.',
            limitation: 'Citação do caminho isolada não comprova execução ou adulteração.',
            weight: 10,
            dedupKey: `FF_GAMEASSET_SH_GPP2_PATH_REF|${fpath}`
          }));
        } else if (low.includes('sh-gpp2')) {
          alerts.push(makeAlert({
            signatureId: 'FF_GAMEASSET_SH_GPP2_UNRELATED',
            signatureName: 'Menção textual a SH-Gpp2 fora do contexto do Free Fire',
            category: 'uncategorized',
            sourceFile: fpath,
            process: ctx.process,
            timestamp: ctx.timestamp,
            contextualSnippet: ctx,
            observedEvent: "Termo 'SH-Gpp2' encontrado fora do caminho/pacote com.dts.freefiremax.",
            technicalInterpretation: 'Referência textual sem associação ao diretório gameassetbundles do Free Fire.',
            corroboratingEvidence: [],
            confidence: 'none',
            evidenceTier: 'textual_reference',
            classificationReason: 'Ausência de caminho do Free Fire e de evento SELinux/execução.',
            recommendedAction: 'Nenhuma ação necessária.',
            limitation: 'Coincidência textual fora do contexto do jogo.',
            weight: 0,
            dedupKey: `FF_GAMEASSET_SH_GPP2_UNRELATED|${fpath}`
          }));
        }

        if (/(?:^|[\\/])-SHgap-(?:$|[\\/])/.test(line)) {
          signals.add('unverified_folder_shgap');
          alerts.push(makeAlert({
            signatureId: 'FF_UNVERIFIED_FOLDER_SHGAP',
            signatureName: 'Anomalia em arquivo do Free Fire — Pasta -SHgap-',
            category: 'gameasset_anomaly',
            sourceFile: fpath,
            process: ctx.process,
            timestamp: ctx.timestamp,
            contextualSnippet: ctx,
            observedEvent: "Componente de diretório '-SHgap-' detectado em caminho de arquivo.",
            technicalInterpretation: "A pasta '-SHgap-' não pertence à árvore padrão verificada do Free Fire.",
            corroboratingEvidence: [],
            confidence: 'medium',
            evidenceTier: 'specific_anomaly',
            classificationReason: 'Identificado como componente explícito de caminho, não por simples presença de hífen.',
            recommendedAction: 'Verificar integridade dos arquivos do Free Fire e recomendar reinstalação oficial caso haja indícios consistentes de adulteração.',
            limitation: 'Registro isolado exige revisão técnica e não determina punição automática.',
            weight: 25,
            dedupKey: `FF_UNVERIFIED_FOLDER_SHGAP|${fpath}`
          }));
        }
      }
    }

    _analyzeSuspiciousJars(lines, start, end, fpath, alerts, signals) {
      const jars = [
        { name: 'app_resources_lib.jar', id: 'FF_CACHE_JAR_APP_RESOURCES' },
        { name: 'google_api_resources_lib.jar', id: 'FF_CACHE_JAR_GOOGLE_API' }
      ];
      const loaderRe = /DexClassLoader|PathClassLoader|InMemoryDexClassLoader|dalvik\.system|Opening dex|avc:\s*granted\s*\{\s*execute/i;

      for (let idx = start; idx < end; idx++) {
        const line = lines[idx];
        const low = line.toLowerCase();
        for (const j of jars) {
          if (!low.includes(j.name)) continue;
          const fullRe = new RegExp(`/data/(?:user/0|data)/com\\.dts\\.freefiremax/cache/${escapeRegex(j.name)}\\b`, 'i');
          if (!fullRe.test(line)) continue;

          const ctx = getLineContext(lines, idx);
          const hasLoader = loaderRe.test(line) || loaderRe.test(ctx.prevLine) || loaderRe.test(ctx.nextLine);
          if (hasLoader) {
            signals.add(`jar_loaded_${j.name}`);
            alerts.push(makeAlert({
              signatureId: j.id,
              signatureName: `Carregamento/Execução de JAR em Cache (${j.name})`,
              category: 'suspicious_jar',
              sourceFile: fpath,
              process: ctx.process || 'com.dts.freefiremax',
              timestamp: ctx.timestamp,
              contextualSnippet: ctx,
              observedEvent: `Evento de carregamento/ClassLoader associado a ${j.name} no cache do Free Fire Max.`,
              technicalInterpretation: 'Arquivo JAR específico no diretório de cache com evidência contextual de carregamento ou execução.',
              corroboratingEvidence: ['Evento de ClassLoader/execução no contexto imediato'],
              confidence: 'medium',
              evidenceTier: 'specific_anomaly',
              classificationReason: 'Caminho completo associado a com.dts.freefiremax + indício de carregamento.',
              recommendedAction: 'Elevar para revisão técnica: verificar origem, assinatura e integridade do pacote.',
              limitation: 'Nome do arquivo não comprova finalidade maliciosa sem análise do conteúdo do JAR.',
              weight: 25,
              dedupKey: `${j.id}|loaded`
            }));
          } else {
            alerts.push(makeAlert({
              signatureId: j.id,
              signatureName: `Referência a JAR em Cache (${j.name})`,
              category: 'suspicious_jar',
              sourceFile: fpath,
              process: ctx.process || 'com.dts.freefiremax',
              timestamp: ctx.timestamp,
              contextualSnippet: ctx,
              observedEvent: `Caminho completo de ${j.name} presente no log sem evento de carregamento.`,
              technicalInterpretation: 'Arquivo presente em listagem/caminho, sem registro de execução ou ClassLoader nesta entrada.',
              corroboratingEvidence: [],
              confidence: 'low',
              evidenceTier: 'contextual_event',
              classificationReason: 'Distinção entre arquivo presente e arquivo efetivamente carregado.',
              recommendedAction: 'Manter como referência a investigar caso surjam eventos de carregamento.',
              limitation: 'Extensão .jar ou nome do arquivo isolado não comprova malícia.',
              weight: 5,
              dedupKey: `${j.id}|present`
            }));
          }
        }
      }
    }

    _analyzeCrashesAndStability(lines, start, end, fpath, alerts, signals) {
      for (let idx = start; idx < end; idx++) {
        const line = lines[idx];
        if (line.includes('LOW_MEMORY') || line.includes('OutOfMemoryError')) {
          const ctx = getLineContext(lines, idx);
          const procM = /process=([^\s]+)/.exec(line);
          const proc = procM ? procM[1] : ctx.process;
          alerts.push(makeAlert({
            signatureId: 'STABILITY_LOW_MEMORY',
            signatureName: 'Encerramento por Memória (LOW_MEMORY)',
            category: 'stability_crash',
            sourceFile: fpath,
            process: proc,
            timestamp: ctx.timestamp,
            contextualSnippet: ctx,
            observedEvent: line.trim().slice(0, 200),
            technicalInterpretation: 'Classificação de crash: Crash comum. Encerramento normal do processo por pressão de memória RAM.',
            corroboratingEvidence: [],
            confidence: 'none',
            evidenceTier: 'textual_reference',
            classificationReason: 'Evento padrão do ActivityManager/LMK do sistema operacional.',
            recommendedAction: 'Nenhuma ação anti-cheat. Diagnóstico apenas de estabilidade.',
            limitation: 'LOW_MEMORY nunca indica cheating ou injeção.',
            weight: 0,
            dedupKey: `STABILITY_LOW_MEMORY|${proc}`
          }));
          continue;
        }

        if (line.includes('SIGSEGV') || line.includes('SEGV_MAPERR')) {
          const ctx = getLineContext(lines, idx);
          const block = lines.slice(Math.max(0, idx - 5), Math.min(lines.length, idx + 15)).join('\n');
          const cmdM = /Cmdline:\s*([^\r\n]+)/.exec(block);
          const nameM = /name:\s*([^\s>]+)/.exec(block);
          const causeM = /Cause:\s*([^\r\n]+)/.exec(block);
          const proc = (cmdM ? cmdM[1].trim() : '') || (nameM ? nameM[1].trim() : ctx.process);
          const cause = causeM ? causeM[1].trim() : 'Não especificada';

          const suspBt = /backtrace:[\s\S]{0,600}(?:frida|gadget|substrate|lsposed|xposed|modmenu)/i.exec(block);
          if (suspBt) {
            signals.add('crash_with_suspicious_backtrace_lib');
            alerts.push(makeAlert({
              signatureId: 'STABILITY_SIGSEGV_CORROBORATED',
              signatureName: 'Crash SIGSEGV com Biblioteca Suspeita em Backtrace',
              category: 'stability_crash',
              sourceFile: fpath,
              process: proc,
              timestamp: ctx.timestamp,
              contextualSnippet: ctx,
              observedEvent: `Crash SIGSEGV/SEGV_MAPERR (Causa: ${cause}) com biblioteca de hooking no backtrace.`,
              technicalInterpretation: 'Classificação de crash: Indício técnico corroborado de interferência — crash associado a biblioteca suspeita carregada.',
              corroboratingEvidence: [`Biblioteca suspeita no backtrace: ${suspBt[0].slice(-60)}`],
              confidence: 'high',
              evidenceTier: 'corroborated_evidence',
              classificationReason: 'SIGSEGV isolado não basta, mas houve correlação direta no backtrace.',
              recommendedAction: 'Revisar mapa de memória e módulos carregados no processo.',
              limitation: 'Requer preservação do tombstone completo para auditoria.',
              weight: 45,
              dedupKey: `STABILITY_SIGSEGV_CORROBORATED|${proc}`
            }));
          } else {
            alerts.push(makeAlert({
              signatureId: 'STABILITY_NATIVE_SIGSEGV',
              signatureName: 'Crash Nativo / Falha de Memória (SIGSEGV)',
              category: 'stability_crash',
              sourceFile: fpath,
              process: proc,
              timestamp: ctx.timestamp,
              contextualSnippet: ctx,
              observedEvent: `Crash nativo SIGSEGV/SEGV_MAPERR (Causa: ${cause}).`,
              technicalInterpretation: 'Classificação de crash: Falha não determinada. Falha de acesso à memória sem evidência de injeção.',
              corroboratingEvidence: [],
              confidence: 'none',
              evidenceTier: 'textual_reference',
              classificationReason: 'SIGSEGV, endereços hex e registradores ARM64 isolados não comprovam wallhack ou injeção.',
              recommendedAction: 'Exigir evidências adicionais (backtrace, mapas /proc/pid/maps, bibliotecas carregadas) antes de investigar adulteração.',
              limitation: 'Crash nativo comum em engines Unity/C++; não indica trapaça.',
              weight: 0,
              dedupKey: `STABILITY_NATIVE_SIGSEGV|${proc}|${cause}`
            }));
          }
        }
      }
    }

    _analyzeHexdumpsAndGithub(lines, fpath, alerts) {
      const chunks = parseHexDumpLines(lines);
      for (const ch of chunks) {
        for (const url of ch.urls) {
          if (url.toLowerCase().includes('github.com')) {
            const ctx = getLineContext(lines, Math.max(0, ch.startLine));
            alerts.push(makeAlert({
              signatureId: 'HEXDUMP_GITHUB_REFERENCE',
              signatureName: 'URL GitHub Reconstruída em Dump de Memória',
              category: 'github_hexdump',
              sourceFile: fpath,
              process: ctx.process || 'Dump de Memória',
              timestamp: ctx.timestamp,
              contextualSnippet: ctx,
              observedEvent: `URL reconstruída a partir de ${ch.byteCount} bytes reais do dump (${ch.startAddr}): ${url}`,
              technicalInterpretation: 'String presente em memória estática/dump (ex: metadados de biblioteca como Newtonsoft.Json). Não representa operação executada nem causa comprovada de crash.',
              corroboratingEvidence: [],
              confidence: 'none',
              evidenceTier: 'textual_reference',
              classificationReason: 'Reconstrução fiel de bytes disponíveis sem atribuição causal de crash ou cheat.',
              recommendedAction: 'Nenhuma ação punitiva. Apenas referência contextual de string em memória.',
              limitation: 'Presença de github.com em dump de memória não é indício de trapaça.',
              weight: 0,
              dedupKey: `HEXDUMP_GITHUB_REFERENCE|${url}`
            }));
          }
        }
      }
    }

    _analyzeCasinoActivity(lines, start, end, fpath, ftype, alerts) {
      if (!['network_proxy', 'packages', 'ios_unified_log', 'logcat', 'bugreport'].includes(ftype)) return;
      const casinoRe = /\b(?:blaze\.com|betano\.com|bet365\.com|sportingbet\.com|estrelabet\.com|pixbet\.com|stake\.com|1xbet\.com)\b/i;
      const structRe = /(?:https?:\/\/|dns|host=|domain=|package:|url=|referer|visit)/i;
      for (let idx = start; idx < end; idx++) {
        const line = lines[idx];
        const m = casinoRe.exec(line);
        if (!m || !structRe.test(line)) continue;
        const ctx = getLineContext(lines, idx);
        alerts.push(makeAlert({
          signatureId: 'CASINO_DOMAIN_OR_APP',
          signatureName: `Domínio de Apostas/Cassino (${m[0]})`,
          category: 'casino_activity',
          sourceFile: fpath,
          process: ctx.process,
          timestamp: ctx.timestamp,
          contextualSnippet: ctx,
          observedEvent: `Domínio estruturado de apostas encontrado: ${m[0]}`,
          technicalInterpretation: 'Indicador explícito de domínio de apostas/cassino em registro de rede ou pacote.',
          corroboratingEvidence: [],
          confidence: 'low',
          evidenceTier: 'contextual_event',
          classificationReason: 'Correspondência exata em domínio conhecido (hífens isolados são ignorados).',
          recommendedAction: 'Verificar se é relevante para a auditoria solicitada.',
          limitation: 'Acesso ou menção a site de apostas não implica cheat no Free Fire.',
          weight: 0,
          dedupKey: `CASINO_DOMAIN_OR_APP|${m[0].toLowerCase()}`
        }));
      }
    }

    _analyzeIosBackupRestore(lines, start, end, fpath, alerts, signals) {
      const terms = [
        'MobileBackup', 'BackupAgent', 'BackupRestore', 'RestoreFromBackup',
        'Restored', 'mobilebackupd', 'restore_type', 'SetupAssistant',
        'iCloudRestore', 'itunesstored'
      ];
      const startRe = /\b(start|started|begin|initiating|iniciando)\b/i;
      const progRe = /\b(progress|restoring|downloading|transferring)\b/i;
      const doneRe = /\b(complete|completed|finished|succeeded|done)\b/i;
      const availRe = /\b(registered|available|loaded|plist|service|daemon|idle)\b/i;

      for (let idx = start; idx < end; idx++) {
        const line = lines[idx];
        for (const term of terms) {
          if (!new RegExp(`\\b${escapeRegex(term)}\\b`).test(line)) continue;
          const ctx = getLineContext(lines, idx);

          if (term === 'itunesstored') {
            alerts.push(makeAlert({
              signatureId: 'IOS_ITUNESSTORED',
              signatureName: 'Serviço App Store (itunesstored)',
              category: 'ios_backup_restore',
              sourceFile: fpath,
              process: 'itunesstored',
              timestamp: ctx.timestamp,
              contextualSnippet: ctx,
              observedEvent: 'Registro padrão do serviço itunesstored.',
              technicalInterpretation: 'itunesstored é o daemon legítimo da App Store; não comprova restauração de backup.',
              corroboratingEvidence: [],
              confidence: 'none',
              evidenceTier: 'textual_reference',
              classificationReason: 'Serviço nativo da App Store.',
              recommendedAction: 'Nenhuma ação necessária.',
              limitation: 'Não é evidência de restauração nem de cheating.',
              weight: 0,
              dedupKey: 'IOS_ITUNESSTORED'
            }));
            continue;
          }

          if (term === 'SetupAssistant' && !/restore/i.test(line)) {
            alerts.push(makeAlert({
              signatureId: 'IOS_SETUP_ASSISTANT',
              signatureName: 'SetupAssistant (Configuração do Sistema)',
              category: 'ios_backup_restore',
              sourceFile: fpath,
              process: 'SetupAssistant',
              timestamp: ctx.timestamp,
              contextualSnippet: ctx,
              observedEvent: 'Registro do SetupAssistant sem menção a restauração.',
              technicalInterpretation: 'SetupAssistant ocorre normalmente após atualizações do iOS ou configuração inicial legítima.',
              corroboratingEvidence: [],
              confidence: 'none',
              evidenceTier: 'textual_reference',
              classificationReason: 'Evento legítimo de configuração sem ciclo de restauração.',
              recommendedAction: 'Nenhuma ação necessária sem eventos de restauração correlatos.',
              limitation: 'Não comprova restauração nem trapaça.',
              weight: 0,
              dedupKey: 'IOS_SETUP_ASSISTANT'
            }));
            continue;
          }

          const isStage = startRe.test(line) || progRe.test(line) || doneRe.test(line);
          const isAvail = availRe.test(line) && !isStage;

          if (isStage && ['RestoreFromBackup', 'iCloudRestore', 'BackupRestore', 'restore_type', 'mobilebackupd'].includes(term)) {
            signals.add('ios_restore_lifecycle_event');
            const stage = startRe.test(line) ? 'início' : (progRe.test(line) ? 'progresso' : 'conclusão');
            alerts.push(makeAlert({
              signatureId: `IOS_RESTORE_${term.toUpperCase()}`,
              signatureName: `Possível atividade de restauração de backup (${term})`,
              category: 'ios_backup_restore',
              sourceFile: fpath,
              process: ctx.process || term,
              timestamp: ctx.timestamp,
              contextualSnippet: ctx,
              observedEvent: `Evento de ciclo de restauração (estágio: ${stage}) envolvendo ${term}.`,
              technicalInterpretation: 'Possível atividade de restauração de backup — verificar contexto e timestamps.',
              corroboratingEvidence: [`Estágio observado: ${stage}`],
              confidence: 'low',
              evidenceTier: 'contextual_event',
              classificationReason: 'Evento com indicação de execução/estágio de restauração.',
              recommendedAction: 'Verificar timestamps e correlacionar outros eventos de restauração. Não presumir cheat.',
              limitation: 'Restauração de backup é funcionalidade legítima do iOS e não comprova utilização de cheat.',
              weight: 10,
              dedupKey: `IOS_RESTORE_${term.toUpperCase()}|${stage}`
            }));
          } else {
            alerts.push(makeAlert({
              signatureId: `IOS_BACKUP_REF_${term.toUpperCase()}`,
              signatureName: `Referência de Backup/Serviço iOS (${term})`,
              category: 'ios_backup_restore',
              sourceFile: fpath,
              process: ctx.process || term,
              timestamp: ctx.timestamp,
              contextualSnippet: ctx,
              observedEvent: `Termo ${term} citado${isAvail ? ' como serviço disponível' : ''} sem estágio ativo de restauração.`,
              technicalInterpretation: 'Referência textual ou serviço disponível; não comprova restauração executada.',
              corroboratingEvidence: [],
              confidence: 'none',
              evidenceTier: 'textual_reference',
              classificationReason: 'Ausência de eventos de início, progresso ou conclusão de restauração.',
              recommendedAction: 'Apenas informativo; não comprova restauração.',
              limitation: 'MobileBackup ou daemons listados isoladamente não comprovam restauração.',
              weight: 0,
              dedupKey: `IOS_BACKUP_REF_${term.toUpperCase()}`
            }));
          }
        }
      }
    }

    _analyzeProxiesAndProfiles(lines, start, end, fpath, ftype, alerts, signals) {
      const domainFieldRe = /(?:https?:\/\/|host=|domain=|dns|query|proxy|server=|url=|cn=|san=)/i;
      const pkgFieldRe = /(?:package\s*[:=\[]|bundleid|bundle_id|payloadidentifier|profile|app=|installerpackagename=|cmd package|pm list)/i;

      for (let idx = start; idx < end; idx++) {
        const line = lines[idx];
        for (const d of PROXY_DOMAINS_TEXTUAL) {
          if (d.matchType === 'domain') {
            if (!domainFieldRe.test(line) && !['network_proxy', 'ios_plist'].includes(ftype)) continue;
            const patRe = new RegExp(`(?<![A-Za-z0-9_-])${escapeRegex(d.pattern)}(?![A-Za-z0-9_-])`, 'i');
            if (patRe.test(line)) {
              const ctx = getLineContext(lines, idx);
              signals.add(`proxy_domain_${d.pattern.toLowerCase()}`);
              alerts.push(makeAlert({
                signatureId: `PROXY_TEXT_${d.pattern.replace(/[^A-Za-z0-9]+/g, '_').toUpperCase()}`,
                signatureName: d.desc,
                category: 'proxy_domain',
                sourceFile: fpath,
                process: ctx.process,
                timestamp: ctx.timestamp,
                contextualSnippet: ctx,
                observedEvent: `Domínio '${d.pattern}' encontrado em campo de rede/DNS/proxy.`,
                technicalInterpretation: 'Indicador de domínio associado a proxy/bypass encontrado em contexto de rede ou perfil.',
                corroboratingEvidence: [],
                confidence: 'medium',
                evidenceTier: 'specific_anomaly',
                classificationReason: 'Match exato de domínio em campo compatível (rede/DNS/proxy).',
                recommendedAction: 'Correlacionar com proxy configurado, estado de VPN e conexões ativas.',
                limitation: 'Domínio em lista ou consulta não comprova uso ativo sem evidência de conexão/roteamento.',
                weight: 20,
                dedupKey: `PROXY_DOMAIN|${d.pattern.toLowerCase()}`
              }));
            }
          } else {
            if (['mitm', 'regedit'].includes(d.pattern.toLowerCase())) {
              if (!['network_proxy', 'ios_plist', 'packages'].includes(ftype) && !domainFieldRe.test(line)) continue;
            }
            const patRe = new RegExp(`(?<![A-Za-z0-9_])${escapeRegex(d.pattern)}(?![A-Za-z0-9_])`);
            if (patRe.test(line)) {
              const ctx = getLineContext(lines, idx);
              alerts.push(makeAlert({
                signatureId: `PROXY_TEXT_${d.pattern.replace(/[^A-Za-z0-9]+/g, '_').toUpperCase()}`,
                signatureName: d.desc,
                category: 'proxy_domain',
                sourceFile: fpath,
                process: ctx.process,
                timestamp: ctx.timestamp,
                contextualSnippet: ctx,
                observedEvent: `Indicador '${d.pattern}' detectado em contexto compatível.`,
                technicalInterpretation: 'Identificador/hostname de perfil ou ferramenta listado.',
                corroboratingEvidence: [],
                confidence: 'low',
                evidenceTier: 'contextual_event',
                classificationReason: 'Match exato com fronteira de palavra em campo apropriado.',
                recommendedAction: 'Verificar se há perfil instalado ou proxy configurado associado.',
                limitation: 'Presença textual isolada não comprova trapaça.',
                weight: 10,
                dedupKey: `PROXY_TEXT|${d.pattern}`
              }));
            }
          }
        }

        if (['packages', 'ios_plist', 'network_proxy'].includes(ftype) || pkgFieldRe.test(line)) {
          for (const p of PACKAGE_AND_PROFILE_IDS) {
            const flags = p.id === 'com.Vluv.lockprofile' ? '' : 'i';
            const exactPkgRe = new RegExp(`(?<![A-Za-z0-9_.-])${escapeRegex(p.id)}(?![A-Za-z0-9_.-])`, flags);
            if (exactPkgRe.test(line)) {
              const ctx = getLineContext(lines, idx);
              const isMdm = p.id === 'com.apple.mgmt.External';
              signals.add(`pkg_profile_${p.id.toLowerCase()}`);
              alerts.push(makeAlert({
                signatureId: `PKG_PROFILE_${p.id.replace(/[^A-Za-z0-9]+/g, '_').toUpperCase()}`,
                signatureName: p.desc,
                category: 'profile_package_id',
                sourceFile: fpath,
                process: ctx.process,
                timestamp: ctx.timestamp,
                contextualSnippet: ctx,
                observedEvent: `Identificador exato '${p.id}' detectado em campo de pacote/bundle/perfil.`,
                technicalInterpretation: isMdm ? 'Identificador MDM externo legítimo ou perfil corporativo.' : 'Identificador de pacote ou perfil de configuração associado a proxy/regedit.',
                corroboratingEvidence: [],
                confidence: isMdm ? 'low' : 'medium',
                evidenceTier: isMdm ? 'contextual_event' : 'specific_anomaly',
                classificationReason: 'Correspondência exata em campo de pacote/perfil (sem substring match).',
                recommendedAction: 'Diferenciar perfil citado de perfil efetivamente instalado e verificar configuração de proxy.',
                limitation: 'A presença do ID em arquivo ou lista não comprova utilização de proxy.',
                weight: isMdm ? 5 : 25,
                dedupKey: `PKG_PROFILE|${p.id}`
              }));
            }
          }
        }
      }
    }

    _analyzeInstallerOrigins(text, lines, fpath, alerts, signals) {
      if (!text.includes('installerPackageName=')) return;
      const pkgRe = /Package\s+\[([a-zA-Z0-9_.]+)\]/g;
      let m;
      while ((m = pkgRe.exec(text)) !== null) {
        const appPkg = m[1];
        let block = text.slice(m.index, Math.min(text.length, m.index + 1800));
        const nextPkg = block.indexOf('Package [', 10);
        if (nextPkg !== -1) block = block.slice(0, nextPkg);
        const instM = /installerPackageName=([^\s,}]+)/.exec(block);
        if (!instM) continue;
        const inst = instM[1].trim();
        if (inst === 'com.android.vending') continue;
        const isFf = appPkg.toLowerCase().includes('freefire');
        if (!isFf && inst === 'null' && /^(com\.android\.|android$|com\.google\.android\.|com\.samsung\.|com\.miui\.)/i.test(appPkg)) continue;

        const lineIdx = text.slice(0, m.index).split('\n').length - 1;
        const ctx = getLineContext(lines, Math.min(lineIdx, lines.length - 1));
        if (isFf) signals.add('ff_installed_outside_playstore');
        alerts.push(makeAlert({
          signatureId: 'ANDROID_INSTALLER_ORIGIN',
          signatureName: `Origem de Instalação Externa: ${appPkg} (via ${inst})`,
          category: 'installer_origin',
          sourceFile: fpath,
          process: 'PackageManager',
          timestamp: ctx.timestamp,
          contextualSnippet: ctx,
          observedEvent: `Package [${appPkg}] instalado com installerPackageName=${inst}.`,
          technicalInterpretation: 'Aplicativo instalado fora da Google Play Store oficial (com.android.vending).',
          corroboratingEvidence: [],
          confidence: isFf ? 'high' : 'low',
          evidenceTier: isFf ? 'corroborated_evidence' : 'contextual_event',
          classificationReason: 'Verificação oficial de installerPackageName no PackageManager.',
          recommendedAction: isFf ? 'Confirmar fonte do APK; para Free Fire, exigir instalação exclusivamente pela Play Store.' : 'Verificar se o aplicativo pertence a loja oficial do fabricante.',
          limitation: 'Lojas de fabricantes também usam instaladores distintos.',
          weight: isFf ? 45 : 10,
          dedupKey: `ANDROID_INSTALLER_ORIGIN|${appPkg}|${inst}`
        }));
      }
    }

    _analyzeLegacyContextual(lines, start, end, fpath, ftype, osType, alerts, signals) {
      for (const rule of this.activeRules) {
        if (!rule.id.startsWith('LEGACY_')) continue;
        if (rule.os !== 'both' && rule.os !== osType) continue;
        if (!rule.fileTypes.includes(ftype) && !rule.fileTypes.includes('generic_text')) continue;

        const patRe = new RegExp(`(?<![A-Za-z0-9_.-])${escapeRegex(rule.pattern)}(?![A-Za-z0-9_.-])`, 'i');
        for (let idx = start; idx < end; idx++) {
          if (patRe.test(lines[idx])) {
            const ctx = getLineContext(lines, idx);
            signals.add(`legacy_${rule.id}`);
            alerts.push(makeAlert({
              signatureId: rule.id,
              signatureName: rule.name,
              category: rule.category,
              sourceFile: fpath,
              process: ctx.process,
              timestamp: ctx.timestamp,
              contextualSnippet: ctx,
              observedEvent: `Assinatura '${rule.pattern}' encontrada em contexto compatível.`,
              technicalInterpretation: rule.name,
              corroboratingEvidence: [],
              confidence: rule.confidence,
              evidenceTier: rule.evidenceTier,
              classificationReason: 'Correspondência contextual com fronteira exata.',
              recommendedAction: 'Verificar processo associado, instalação ativa e evidências corroboradoras.',
              limitation: 'Requer contexto de pacote/processo compatível.',
              weight: rule.baseWeight,
              ruleVersion: rule.version,
              provenance: rule.provenance,
              dedupKey: `${rule.id}|${fpath}`
            }));
            break;
          }
        }
      }
    }

    _deduplicateAlerts(rawAlerts) {
      const grouped = new Map();
      for (const al of rawAlerts) {
        const key = al._dedupKey;
        if (!grouped.has(key)) {
          grouped.set(key, al);
        } else {
          grouped.get(key).raw_occurrences += 1;
        }
      }
      const dedupedAlerts = [];
      for (const al of grouped.values()) {
        delete al._dedupKey;
        dedupedAlerts.push(al);
      }
      dedupedAlerts.sort((a, b) => {
        const tierDiff = (EVIDENCE_TIERS[b.evidence_tier] || 0) - (EVIDENCE_TIERS[a.evidence_tier] || 0);
        return tierDiff !== 0 ? tierDiff : (b.weight || 0) - (a.weight || 0);
      });
      return { dedupedAlerts, rawOccurrencesCount: rawAlerts.length };
    }

    _correlateEvidence(alerts, signals) {
      const hasNonPlaystoreFf = signals.has('ff_installed_outside_playstore');
      const hasHooking = Array.from(signals).some(s => s.startsWith('legacy_LEGACY_FRIDA') || s.startsWith('legacy_LEGACY_LSPOSED') || s.startsWith('legacy_LEGACY_XPOSED'));

      for (const al of alerts) {
        if (al.signature_id === 'FF_GAMEASSET_SH_GPP2_AUDITD' || al.signature_id === 'FF_UNVERIFIED_FOLDER_SHGAP') {
          const corrob = [...al.corroborating_evidence];
          if (hasNonPlaystoreFf) corrob.push('Free Fire instalado fora da Google Play Store');
          if (hasHooking) corrob.push('Framework de hooking/injeção detectado nos logs');
          if (corrob.length > 0) {
            al.corroborating_evidence = corrob;
            al.evidence_tier = 'corroborated_evidence';
            al.evidence_tier_label = TIER_LABELS.corroborated_evidence;
            al.confidence = 'high';
            al.confidence_label = CONFIDENCE_LABELS.high;
            al.weight = Math.max(al.weight, 55);
            al.classification_reason += ' Elevado por evidências independentes correlacionadas.';
          }
        }
      }
    }

    _computeVerdict(alerts, unanalyzedFiles, threatScore) {
      const confirmed = alerts.some(a => a.evidence_tier === 'confirmed_interference');
      const corroborated = alerts.some(a => a.evidence_tier === 'corroborated_evidence');
      const anomalies = alerts.some(a => a.evidence_tier === 'specific_anomaly');

      if (confirmed || threatScore >= 80) {
        return { status: 'INTERFERÊNCIA CORROBORADA', color: 'red', summary: 'Evidências técnicas independentes correlacionadas detectadas.' };
      }
      if (corroborated || anomalies || threatScore >= 25) {
        return { status: 'REVISÃO TÉCNICA NECESSÁRIA', color: 'yellow', summary: 'Anomalias específicas detectadas que exigem análise contextual.' };
      }
      if (unanalyzedFiles.length > 0) {
        return { status: 'COBERTURA INCOMPLETA (LIMPO NO ANALISADO)', color: 'yellow', summary: 'Nenhuma ameaça nos arquivos analisados, porém existem arquivos não analisados.' };
      }
      return { status: 'LIMPO (SEM EVIDÊNCIAS DE INTERFERÊNCIA)', color: 'green', summary: 'Nenhuma evidência técnica de adulteração encontrada.' };
    }
  }

  return {
    ENGINE_VERSION,
    EVIDENCE_TIERS,
    CONFIDENCE_LABELS,
    TIER_LABELS,
    CATEGORY_LABELS,
    RULE_REGISTRY,
    EXPERIMENTAL_SHORT_HEX_TOKENS,
    ForensicEngine,
    canonicalizeAndroidPath,
    classifyFileType,
    parseAuditdLine,
    parseHexDumpLines,
    isTraceV3Binary
  };
}));
