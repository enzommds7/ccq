"""
Cacique SCAN — Motor de Análise Forense Baseado em Evidências (v4.0)
=====================================================================
Substitui a busca indiscriminada por substrings por um motor contextual com:
- Modelo formal de regras (ForensicRule) com procedência, versão, campos permitidos e exclusões.
- Parsers especializados: SELinux/auditd, Crashes/Tombstones, Hex Dumps, iOS Backup/Restore,
  Unified Logs (.tracev3 / texto convertido), Rede/Proxy/DNS/Perfis e Origem de Instalação.
- Deduplicação de ocorrências repetidas e correlação de evidências independentes.
- Pontuação baseada em qualidade da evidência, não em contagem bruta de palavras.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

ENGINE_VERSION = "4.0.0"

# Níveis de evidência (ordem crescente de força)
EVIDENCE_TIERS = {
    "textual_reference": 0,       # Referência textual — sem pontuação de ameaça
    "contextual_event": 1,        # Evento contextual — baixa confiança
    "specific_anomaly": 2,        # Anomalia específica — exige revisão
    "corroborated_evidence": 3,   # Evidências independentes correlacionadas — confiança elevada
    "confirmed_interference": 4,  # Interferência tecnicamente confirmada — requer comprovação explícita
}

CONFIDENCE_LABELS = {
    "none": "Nenhuma (Informativo)",
    "low": "Baixa",
    "medium": "Média",
    "high": "Alta",
    "confirmed": "Confirmada",
}

TIER_LABELS = {
    "textual_reference": "Referência Textual",
    "contextual_event": "Evento Contextual",
    "specific_anomaly": "Anomalia Específica (Revisão Necessária)",
    "corroborated_evidence": "Evidências Corroboradas",
    "confirmed_interference": "Interferência Confirmada",
}

CATEGORY_LABELS = {
    "gameasset_anomaly": "Anomalia em GameAsset (Free Fire)",
    "suspicious_jar": "Arquivos JAR em Cache (Free Fire)",
    "stability_crash": "Diagnóstico de Estabilidade & Crashes",
    "github_hexdump": "Referência em Hex Dump / Memória",
    "casino_activity": "Atividade de Cassino / Apostas",
    "ios_backup_restore": "iOS — Backup & Restauração",
    "proxy_domain": "Domínios & Indicadores de Proxy",
    "profile_package_id": "Identificadores de Pacotes & Perfis",
    "proxy_experimental": "Referências Experimentais Inativas (Proxy)",
    "unified_log": "iOS — Unified Logs (.tracev3)",
    "ff_cheat": "Cheats & Offsets Free Fire",
    "ff_regedit": "Regedits & Macros",
    "overlay": "Janelas Sobrepostas (Overlay)",
    "injection": "Injeção & Hooking",
    "root_bypass": "Root, Jailbreak & Bypass",
    "installer_origin": "Origem de Instalação",
    "log_audit": "Auditoria de Logging (Infraestrutura)",
    "uncategorized": "Não Categorizado",
}


@dataclass
class ForensicRule:
    id: str
    name: str
    os: str  # "android", "ios", "both"
    category: str
    file_types: List[str]
    allowed_fields: List[str]
    match_type: str  # "exact", "path", "domain", "package_id", "regex_contextual"
    pattern: str
    required_conditions: Dict[str, Any] = field(default_factory=dict)
    exclusion_conditions: Dict[str, Any] = field(default_factory=dict)
    confidence: str = "medium"
    evidence_tier: str = "specific_anomaly"
    corroborating_evidence: List[str] = field(default_factory=list)
    status: str = "active"  # "active", "experimental_inactive", "reclassified"
    version: str = "4.0.0"
    provenance: str = "Cacique Forensics Lab"
    base_weight: int = 0
    description: str = ""
    recommended_action: str = "Revisar contexto técnico completo."
    limitation: str = "Registro isolado requer verificação de evidências independentes."


def canonicalize_android_path(path: str) -> str:
    """Normaliza aliases legítimos /data/data/ e /data/user/0/ para comparação equivalente."""
    if not path:
        return ""
    p = path.replace("\\", "/").strip()
    if p.startswith("/data/data/"):
        p = "/data/user/0/" + p[len("/data/data/"):]
    return p


def classify_file_type(filename: str, content_head: str = "") -> str:
    """Classifica o tipo forense do arquivo para restringir regras compatíveis."""
    low = filename.replace("\\", "/").lower()
    base = os.path.basename(low)

    if low.endswith(".tracev3"):
        return "ios_tracev3"
    if low.endswith(".ips") or "crashreporter" in low:
        return "ios_ips_crash"
    if low.endswith(".plist") or low.endswith(".mobileconfig"):
        return "ios_plist"
    if "audit" in base or "selinux" in base:
        return "auditd"
    if "tombstone" in low or "anr" in low or "crash" in low:
        return "crash_tombstone"
    if "packages" in base and (low.endswith(".xml") or low.endswith(".list") or "." not in base):
        return "packages"
    if any(k in base for k in ("network", "connectivity", "netstats", "proxy", "vpn", "dns", "hosts", "wifi")):
        return "network_proxy"
    if "logcat" in base:
        return "logcat"
    if "bugreport" in base or "dumpsys" in base:
        return "bugreport"
    if "sysdiagnose" in low or "unified" in base or "system_logs" in low:
        return "ios_unified_log"

    # Heurística leve pelo cabeçalho quando arquivo solto
    if content_head:
        head_low = content_head[:4000].lower()
        if "avc:" in head_low and "audit(" in head_low:
            return "auditd"
        if "signal 11 (sigsegv)" in head_low or "backtrace:" in head_low:
            return "crash_tombstone"
        if "installerpackagename=" in head_low:
            return "packages"
    return "generic_text"


# ─────────────────────────────────────────────────────────────
# Registro Oficial de Regras e Assinaturas (v4.0)
# ─────────────────────────────────────────────────────────────

# 8. Indicadores curtos e hexadecimais -> OBRIGATORIAMENTE experimental_inactive (sem alertas!)
EXPERIMENTAL_SHORT_HEX_TOKENS = [
    "06", "03", "051", "06a", "0af", "0b", "0E", "od", "140", "1ea", "14", "105e", "15d", "1b69",
    "2c", "28a", "2bb", "3c", "3c4", "439", "40e", "4e", "4a", "4c", "4cf", "4d", "47", "51", "550",
    "5b", "5c10", "59ac", "60a", "60af", "62", "62d", "6b", "6dd", "69", "78f", "70a", "704114", "704",
    "70d", "739", "76d", "7d", "80", "84", "87", "9d", "90eb", "96f", "a00", "a1fc", "a4", "a9", "a4c",
    "a48", "a5", "a64", "ae7", "b0", "b9", "b4", "bc", "bd", "bd32", "bd32d", "c17", "c25", "c9", "d14",
    "d03090", "d141", "d03", "d5", "d7319", "dd4f0", "dd4fa", "d4f0", "e0", "e3", "f54", "f6", "f6c",
    "f9", "ff32", "ff6",
]

PROXY_DOMAINS_TEXTUAL = [
    ("authproxyxff.up", "domain", "Domínio de Proxy AuthProxyXFF"),
    ("dash.proxy", "domain", "Domínio de Proxy Dash"),
    ("freefireproxy.xyz", "domain", "Domínio FreeFireProxy"),
    ("vip.uncover", "domain", "Domínio/Repo VIP Unc0ver"),
    ("vip.uncOver", "domain", "Domínio/Repo VIP Unc0ver"),
    ("to.appdb.C2D9F2", "domain", "Identificador/Domínio AppDB C2D9F2"),
    ("to.appdb.certs1", "domain", "Certificado/Domínio AppDB 1"),
    ("to.appdb.certs2", "domain", "Certificado/Domínio AppDB 2"),
    ("iMac.EFB7D714", "exact", "Hostname/Perfil iMac Proxy"),
    ("proxyady", "exact", "Indicador ProxyAdy"),
    ("khoindvn", "exact", "Indicador Khoindvn"),
    ("TRONGHIEU", "exact", "Perfil/Identificador TRONGHIEU"),
    ("XITADO", "exact", "Perfil/Identificador XITADO"),
    ("mitm", "exact", "Termo Genérico MITM (Requer contexto de rede/certificado)"),
    ("Regedit", "exact", "Termo Genérico Regedit (Requer contexto de configuração)"),
]

PACKAGE_AND_PROFILE_IDS = [
    ("com.xtremo.mobile", "Pacote Xtremo Mobile"),
    ("com.luxebypass", "Pacote/Perfil LuxeBypass"),
    ("com.thanhcongregedit", "Pacote/Perfil ThanhCong Regedit"),
    ("com.thanhcongregedit.apple.dns", "Perfil DNS ThanhCong Apple"),
    ("com.congdatregedit", "Pacote/Perfil CongDat Regedit"),
    ("com.headshot", "Pacote Headshot"),
    ("com.apple.mgmt.External", "Perfil MDM Externo Apple (com.apple.mgmt.External)"),
    ("com.antijudas.dns", "Perfil DNS AntiJudas"),
    ("com.antijudas.ios", "Perfil/Bundle AntiJudas iOS"),
    ("com.criperlegend", "Pacote/Perfil CriperLegend"),
    ("com.giahuyregedit", "Pacote/Perfil GiaHuy Regedit"),
    ("com.sensi.fluida.pro", "Pacote Sensi Fluida Pro"),
    ("com.giahuyregedit.apple", "Perfil GiaHuy Regedit Apple"),
    ("com.ngocsonregedit.apple", "Perfil NgocSon Regedit Apple"),
    ("com.krarosxvenuxapple", "Perfil Kraros x Venux Apple"),
    ("com.peligroff.input.redzone", "Perfil PeligroFF Input RedZone"),
    ("com.solitude.profile.v12", "Perfil Solitude v12"),
    ("com.demon.engine", "Pacote/Perfil Demon Engine"),
    ("com.Vluv.lockprofile", "Perfil Vluv LockProfile"),
]

# Assinaturas clássicas preservadas e reclassificadas com contexto apropriado
LEGACY_CHEAT_RULES = [
    # Root / Magisk / Hooking / Dumpers (Android)
    ("LEGACY_MAGISK_1", "top.johnwu.magisk", "android", "root_bypass", "package_id", ["package", "process"], 45, "corroborated_evidence", "high", "Lista de assinaturas clássicas Android"),
    ("LEGACY_MAGISK_2", "com.topjohnwu.magisk", "android", "root_bypass", "package_id", ["package", "process"], 45, "corroborated_evidence", "high", "Lista de assinaturas clássicas Android"),
    ("LEGACY_MAGISK_DELTA", "io.github.huskydg.magisk", "android", "root_bypass", "package_id", ["package", "process"], 45, "corroborated_evidence", "high", "Lista de assinaturas clássicas Android"),
    ("LEGACY_ZYGISK", "zygisk", "android", "root_bypass", "exact", ["process", "raw_line"], 35, "specific_anomaly", "medium", "Lista de assinaturas clássicas Android"),
    ("LEGACY_FRIDA_SERVER", "frida-server", "both", "injection", "exact", ["process", "cmdline", "path"], 55, "corroborated_evidence", "high", "Lista de assinaturas clássicas"),
    ("LEGACY_FRIDA_GADGET", "frida-gadget", "both", "injection", "exact", ["path", "library", "raw_line"], 55, "corroborated_evidence", "high", "Lista de assinaturas clássicas"),
    ("LEGACY_LSPOSED", "lsposed", "android", "injection", "exact", ["process", "package", "raw_line"], 40, "specific_anomaly", "medium", "Lista de assinaturas clássicas Android"),
    ("LEGACY_XPOSED", "de.robv.android.xposed", "android", "injection", "package_id", ["package", "path"], 45, "corroborated_evidence", "high", "Lista de assinaturas clássicas Android"),
    ("LEGACY_GAMEGUARDIAN", "gameguardian", "android", "ff_cheat", "exact", ["package", "process", "raw_line"], 50, "corroborated_evidence", "high", "Lista de assinaturas clássicas Android"),
    ("LEGACY_LUCKYPATCHER", "com.chelpus.lackypatch", "android", "ff_cheat", "package_id", ["package"], 45, "corroborated_evidence", "high", "Lista de assinaturas clássicas Android"),
    ("LEGACY_IL2CPP_DUMPER", "il2cppdumper", "both", "ff_cheat", "exact", ["package", "process", "path"], 50, "corroborated_evidence", "high", "Lista de assinaturas clássicas"),
    ("LEGACY_DRIPWIRE", "dripwire.cc", "both", "overlay", "domain", ["domain", "url", "package", "raw_line"], 45, "specific_anomaly", "medium", "Lista de assinaturas clássicas FF"),
    ("LEGACY_LETUNIA", "LetuniaProxy.ff", "both", "proxy_domain", "domain", ["domain", "url", "package", "raw_line"], 45, "specific_anomaly", "medium", "Lista de assinaturas clássicas FF"),
    # iOS Jailbreak
    ("LEGACY_IOS_CYDIA", "cydia", "ios", "root_bypass", "exact", ["package", "bundle_id", "path", "process"], 40, "specific_anomaly", "medium", "Lista de assinaturas clássicas iOS"),
    ("LEGACY_IOS_SILEO", "sileo", "ios", "root_bypass", "exact", ["package", "bundle_id", "path", "process"], 40, "specific_anomaly", "medium", "Lista de assinaturas clássicas iOS"),
    ("LEGACY_IOS_TROLLSTORE", "com.opa334.trollstore", "ios", "root_bypass", "package_id", ["bundle_id", "package", "path"], 45, "corroborated_evidence", "high", "Lista de assinaturas clássicas iOS"),
    ("LEGACY_IOS_DOPAMINE", "dopamine", "ios", "root_bypass", "exact", ["process", "path", "bundle_id"], 40, "specific_anomaly", "medium", "Lista de assinaturas clássicas iOS"),
    ("LEGACY_IOS_FILZA", "com.tigisoftware.filza", "ios", "root_bypass", "package_id", ["bundle_id", "package"], 40, "specific_anomaly", "medium", "Lista de assinaturas clássicas iOS"),
]


def build_rule_registry() -> List[ForensicRule]:
    rules: List[ForensicRule] = []

    # 1) Regras Free Fire GameAsset (SH-Gpp2 e -SHgap-)
    rules.append(ForensicRule(
        id="FF_GAMEASSET_SH_GPP2_AUDITD",
        name="Execução SELinux em GameAsset (SH-Gpp2)",
        os="android",
        category="gameasset_anomaly",
        file_types=["auditd", "logcat", "bugreport", "generic_text"],
        allowed_fields=["path", "comm", "app", "avc_action", "operations"],
        match_type="path",
        pattern="/data/user/0/com.dts.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2",
        required_conditions={"package": "com.dts.freefiremax"},
        exclusion_conditions={"ignore_unrelated_context": True},
        confidence="medium",
        evidence_tier="specific_anomaly",
        corroborating_evidence=["installer_non_playstore", "gameasset_tampering", "suspicious_jar_loaded"],
        status="active",
        provenance="Cacique Forensics Lab — SELinux Auditd Policy",
        base_weight=30,
        description="Identifica evento SELinux ou acesso contextual ao caminho específico SH-Gpp2 do Free Fire Max.",
        recommended_action="Verificar integridade do recurso, versão do jogo e outros eventos relacionados; reinstalar o Free Fire pela loja oficial caso haja indícios consistentes de adulteração.",
        limitation="Esse registro isolado não comprova injeção de código nem justifica punição automática.",
    ))

    rules.append(ForensicRule(
        id="FF_UNVERIFIED_FOLDER_SHGAP",
        name="Pasta Não Verificada Free Fire (-SHgap-)",
        os="android",
        category="gameasset_anomaly",
        file_types=["auditd", "logcat", "bugreport", "generic_text"],
        allowed_fields=["path"],
        match_type="path",
        pattern="-SHgap-",
        required_conditions={"must_be_path_component": True},
        exclusion_conditions={"must_not_match_generic_hyphen": True},
        confidence="medium",
        evidence_tier="specific_anomaly",
        corroborating_evidence=["gameasset_tampering", "installer_non_playstore"],
        status="active",
        provenance="Cacique Forensics Lab — Free Fire Directory Verification",
        base_weight=25,
        description="Pasta -SHgap- identificada como componente de diretório em caminho de sistema/jogo.",
        recommended_action="Verificar integridade dos arquivos do Free Fire e recomendar reinstalação pela distribuição oficial se confirmada adulteração.",
        limitation="A presença do nome de diretório isolado exige revisão técnica e não comprova cheat por si só.",
    ))

    # 2) Regras JAR Suspeitos (app_resources_lib.jar, google_api_resources_lib.jar)
    for jar_id, jar_name in [
        ("FF_CACHE_JAR_APP_RESOURCES", "app_resources_lib.jar"),
        ("FF_CACHE_JAR_GOOGLE_API", "google_api_resources_lib.jar"),
    ]:
        rules.append(ForensicRule(
            id=jar_id,
            name=f"Arquivo JAR em Cache Free Fire ({jar_name})",
            os="android",
            category="suspicious_jar",
            file_types=["auditd", "logcat", "bugreport", "dumpsys", "generic_text"],
            allowed_fields=["path", "classloader", "process"],
            match_type="path",
            pattern=f"/data/user/0/com.dts.freefiremax/cache/{jar_name}",
            required_conditions={"package": "com.dts.freefiremax", "must_not_match_extension_only": True},
            confidence="low",
            evidence_tier="contextual_event",
            corroborating_evidence=["classloader_execution", "dex_load", "avc_granted_execute"],
            status="active",
            provenance="Cacique Forensics Lab — Cache JAR Inspection",
            base_weight=15,
            description=f"Monitora caminho completo de {jar_name} no cache do Free Fire Max, distinguindo presença de carregamento efetivo.",
            recommended_action="Verificar se houve carregamento por ClassLoader (DexClassLoader/PathClassLoader) e origem do arquivo.",
            limitation="O nome ou extensão .jar isolado não comprova finalidade maliciosa.",
        ))

    # 3) Estabilidade & Crashes (Reclassificados: 0 pontuação de cheat!)
    rules.append(ForensicRule(
        id="STABILITY_LOW_MEMORY",
        name="Encerramento de Processo por Memória (LOW_MEMORY)",
        os="android",
        category="stability_crash",
        file_types=["logcat", "bugreport", "crash_tombstone", "generic_text"],
        allowed_fields=["reason", "raw_line"],
        match_type="regex_contextual",
        pattern=r"reason=\d+\s*\(LOW_MEMORY\)",
        confidence="none",
        evidence_tier="textual_reference",
        status="reclassified",
        provenance="Android ActivityManager — Reclassificado de 'system' para 'stability_crash'",
        base_weight=0,
        description="Encerramento normal pelo gerenciador de memória do Android.",
        recommended_action="Nenhuma ação punitiva. Evento normal de gerenciamento de memória.",
        limitation="Não indica trapaça, injeção ou modificação.",
    ))

    rules.append(ForensicRule(
        id="STABILITY_NATIVE_SIGSEGV",
        name="Crash Nativo / Falha de Memória (SIGSEGV / SEGV_MAPERR)",
        os="both",
        category="stability_crash",
        file_types=["crash_tombstone", "logcat", "bugreport", "ios_ips_crash", "generic_text"],
        allowed_fields=["signal", "cause", "raw_line"],
        match_type="regex_contextual",
        pattern=r"signal\s+11\s*\(SIGSEGV\)|SEGV_MAPERR|null pointer dereference",
        confidence="none",
        evidence_tier="textual_reference",
        corroborating_evidence=["suspicious_loaded_library_in_backtrace", "hooking_framework_active"],
        status="reclassified",
        provenance="Crash/Tombstone Analyzer — Reclassificado de 'injection' para 'stability_crash'",
        base_weight=0,
        description="Falha nativa de segmentação ou desreferência de ponteiro nulo.",
        recommended_action="Analisar backtrace e mapas de bibliotecas apenas se houver indícios independentes de interferência.",
        limitation="SIGSEGV, SEGV_MAPERR e registradores ARM64 isolados não comprovam injeção de assembly ou wallhack.",
    ))

    # 4) Hex Dump & GitHub URLs
    rules.append(ForensicRule(
        id="HEXDUMP_GITHUB_REFERENCE",
        name="URL GitHub Reconstruída em Hex Dump",
        os="both",
        category="github_hexdump",
        file_types=["crash_tombstone", "bugreport", "generic_text"],
        allowed_fields=["hexdump_ascii", "url"],
        match_type="regex_contextual",
        pattern=r"https?://github\.com/[^\s\"'<>]+",
        confidence="none",
        evidence_tier="textual_reference",
        status="reclassified",
        provenance="Hex Dump Reconstructor — Reclassificado de 'injection' para 'github_hexdump'",
        base_weight=0,
        description="String de URL do GitHub reconstruída a partir de bytes reais em dump de memória.",
        recommended_action="Verificar se é biblioteca open-source legítima (ex: Newtonsoft.Json) antes de qualquer conclusão.",
        limitation="Presença de URL github.com em memória não comprova causa de crash nem cheating.",
    ))

    # 5) Cassino (Substitui filtro '-' por indicadores estruturados)
    rules.append(ForensicRule(
        id="CASINO_DOMAIN_OR_APP",
        name="Indicador Estruturado de Cassino / Apostas",
        os="both",
        category="casino_activity",
        file_types=["network_proxy", "packages", "logcat", "bugreport", "ios_unified_log"],
        allowed_fields=["domain", "url", "package", "bundle_id"],
        match_type="domain",
        pattern=r"(?:blaze\.com|betano\.com|bet365\.com|sportingbet\.com|estrelabet\.com|pixbet\.com|stake\.com|1xbet\.com|tigre|fortune\s*tiger)",
        exclusion_conditions={"must_not_match_hyphen_only": True},
        confidence="low",
        evidence_tier="contextual_event",
        status="active",
        provenance="Cacique Forensics Lab — Substitui regra inválida de hífen '-'",
        base_weight=0,
        description="Identifica domínios ou pacotes explícitos de casas de apostas/cassino em campos de rede ou pacotes.",
        recommended_action="Verificar contexto apenas se aplicável às regras do campeonato.",
        limitation="Hífens isolados, datas, paths ou IDs nunca são classificados como cassino.",
    ))

    # 6) iOS Backup & Restore
    ios_backup_specs = [
        ("IOS_BACKUP_MOBILEBACKUP", "MobileBackup", "Serviço/Framework MobileBackup", 0, "textual_reference", "none"),
        ("IOS_BACKUP_AGENT", "BackupAgent", "Agente de Backup (BackupAgent)", 0, "textual_reference", "none"),
        ("IOS_BACKUP_RESTORE", "BackupRestore", "Operação BackupRestore", 10, "contextual_event", "low"),
        ("IOS_RESTORE_FROM_BACKUP", "RestoreFromBackup", "Evento RestoreFromBackup", 15, "contextual_event", "low"),
        ("IOS_RESTORED_DAEMON", "Restored", "Serviço Restored", 0, "textual_reference", "none"),
        ("IOS_MOBILEBACKUPD", "mobilebackupd", "Daemon mobilebackupd", 5, "textual_reference", "none"),
        ("IOS_RESTORE_TYPE", "restore_type", "Campo restore_type", 10, "contextual_event", "low"),
        ("IOS_SETUP_ASSISTANT", "SetupAssistant", "SetupAssistant (Configuração Inicial / Update)", 0, "textual_reference", "none"),
        ("IOS_ICLOUD_RESTORE", "iCloudRestore", "Evento iCloudRestore", 15, "contextual_event", "low"),
        ("IOS_ITUNESSTORED", "itunesstored", "Serviço App Store (itunesstored)", 0, "textual_reference", "none"),
    ]
    for rid, term, desc, weight, tier, conf in ios_backup_specs:
        rules.append(ForensicRule(
            id=rid,
            name=f"iOS Backup/Restauração: {term}",
            os="ios",
            category="ios_backup_restore",
            file_types=["ios_unified_log", "ios_plist", "bugreport", "generic_text"],
            allowed_fields=["process", "subsystem", "category", "message", "raw_line"],
            match_type="exact",
            pattern=term,
            confidence=conf,
            evidence_tier=tier,
            corroborating_evidence=["restore_lifecycle_start_progress_complete"],
            status="active",
            provenance="iOS Sysdiagnose Backup/Restore Analyzer",
            base_weight=weight,
            description=desc,
            recommended_action="Verificar timestamps e estágio do ciclo (início/progresso/conclusão). Não presumir cheat após restauração.",
            limitation="itunesstored e SetupAssistant ocorrem normalmente em operações legítimas da App Store e sistema.",
        ))

    # 7) Indicadores experimentais inativos (Lista curta / hexadecimal)
    for tok in EXPERIMENTAL_SHORT_HEX_TOKENS:
        rules.append(ForensicRule(
            id=f"PROXY_EXP_{tok.upper()}",
            name=f"Referência Experimental Inativa: {tok}",
            os="both",
            category="proxy_experimental",
            file_types=[],
            allowed_fields=[],
            match_type="exact",
            pattern=tok,
            confidence="none",
            evidence_tier="textual_reference",
            status="experimental_inactive",
            provenance="Lista Proxy 09/08/2026 — Desativada até documentação de formato e campo",
            base_weight=0,
            description=f"Token curto/hexadecimal '{tok}' armazenado apenas como referência inativa.",
            recommended_action="Não gera alertas. Aguarda formato documentado para ativação.",
            limitation="Altamente genérico; buscar em texto livre gera falsos positivos em hex dumps e timestamps.",
        ))

    # 8) Domínios e indicadores textuais de Proxy
    for dom, mtype, desc in PROXY_DOMAINS_TEXTUAL:
        is_generic = dom.lower() in ("mitm", "regedit")
        allowed = ["domain", "url", "dns", "proxy_host", "certificate"] if mtype == "domain" else ["domain", "url", "proxy_host", "profile_name", "package"]
        rules.append(ForensicRule(
            id=f"PROXY_TEXT_{re.sub(r'[^A-Za-z0-9]+', '_', dom).upper()}",
            name=desc,
            os="both",
            category="proxy_domain",
            file_types=["network_proxy", "ios_plist", "packages", "auditd", "logcat", "bugreport", "ios_unified_log"],
            allowed_fields=allowed,
            match_type=mtype,
            pattern=dom,
            exclusion_conditions={"must_not_match_generic_text_only": is_generic},
            confidence="low" if is_generic else "medium",
            evidence_tier="contextual_event" if is_generic else "specific_anomaly",
            corroborating_evidence=["active_proxy_config", "vpn_or_tun_active", "dns_query_or_connection"],
            status="active",
            provenance="Lista Proxy 09/08/2026 — Pesquisa restrita a campos de rede/perfil",
            base_weight=5 if is_generic else 20,
            description=f"{desc} pesquisado exclusivamente em campos apropriados (domínio/URL/DNS/proxy/perfil).",
            recommended_action="Correlacionar com configurações de rede ativas, endpoints de conexão e processos associados.",
            limitation="Presença do domínio em lista ou texto não comprova conexão ativa.",
        ))

    # 9) Identificadores de Pacotes e Perfis
    for pkg_id, desc in PACKAGE_AND_PROFILE_IDS:
        is_apple_mdm = pkg_id == "com.apple.mgmt.External"
        rules.append(ForensicRule(
            id=f"PKG_PROFILE_{re.sub(r'[^A-Za-z0-9]+', '_', pkg_id).upper()}",
            name=f"{desc} ({pkg_id})",
            os="both",
            category="profile_package_id",
            file_types=["packages", "ios_plist", "network_proxy", "logcat", "bugreport", "ios_unified_log"],
            allowed_fields=["package", "bundle_id", "profile_id"],
            match_type="package_id",
            pattern=pkg_id,
            confidence="low" if is_apple_mdm else "medium",
            evidence_tier="contextual_event" if is_apple_mdm else "specific_anomaly",
            corroborating_evidence=["profile_installed", "active_proxy_config", "vpn_or_tun_active"],
            status="active",
            provenance="Lista Perfis/Pacotes 09/08/2026 — Match exato em campos de pacote/perfil",
            base_weight=5 if is_apple_mdm else 25,
            description=f"Identificador exato {pkg_id} verificado em campos de pacotes, bundles ou perfis.",
            recommended_action="Diferenciar identificador citado de perfil instalado e de proxy/VPN efetivamente configurado.",
            limitation="A simples citação do ID em um arquivo de texto não comprova utilização de proxy ou cheat.",
        ))

    # 10) Regras Legadas Presenvadas e Reclassificadas
    for rid, pat, os_t, cat, mtype, fields, weight, tier, conf, prov in LEGACY_CHEAT_RULES:
        rules.append(ForensicRule(
            id=rid,
            name=f"Indicador: {pat}",
            os=os_t,
            category=cat,
            file_types=["packages", "auditd", "logcat", "bugreport", "crash_tombstone", "ios_plist", "ios_unified_log", "generic_text"],
            allowed_fields=fields,
            match_type=mtype,
            pattern=pat,
            confidence=conf,
            evidence_tier=tier,
            status="active",
            provenance=prov,
            base_weight=weight,
            description=f"Assinatura preservada '{pat}' aplicada com correspondência contextual.",
            recommended_action="Verificar processo associado, instalação ativa e evidências corroboradoras.",
            limitation="Requer contexto de pacote/processo compatível.",
        ))

    return rules


RULE_REGISTRY: List[ForensicRule] = build_rule_registry()


# ─────────────────────────────────────────────────────────────
# Parsers Forenses Especializados
# ─────────────────────────────────────────────────────────────

AUDITD_AVC_RE = re.compile(
    r'audit\((?P<ts>[^)]+)\):\s*avc:\s*(?P<action>granted|denied)\s*\{\s*(?P<ops>[^}]+)\s*\}\s*for\s+(?P<body>.+)',
    re.IGNORECASE,
)


def parse_auditd_line(line: str) -> Optional[Dict[str, Any]]:
    """Extrai campos estruturados de uma linha SELinux/auditd."""
    m = AUDITD_AVC_RE.search(line)
    if not m:
        return None
    body = m.group("body")
    fields: Dict[str, Any] = {
        "timestamp": m.group("ts").strip(),
        "avc_action": m.group("action").lower(),
        "operations": [op.strip().lower() for op in m.group("ops").split()],
    }
    for key in ("comm", "path", "dev", "ino", "scontext", "tcontext", "tclass", "app", "name"):
        km = re.search(rf'\b{key}=(?:"([^"]+)"|([^\s]+))', body)
        if km:
            val = km.group(1) if km.group(1) is not None else km.group(2)
            fields[key] = val
    if "path" in fields:
        fields["canonical_path"] = canonicalize_android_path(fields["path"])
    return fields


HEXDUMP_LINE_RE = re.compile(
    r'^\s*(?P<addr>[0-9a-fA-F]{8,16})\s+(?P<hex>(?:[0-9a-fA-F]{2,16}\s+){1,8})\s*(?P<ascii>.{1,32})?\s*$'
)


def parse_hex_dump_lines(lines: List[str]) -> List[Dict[str, Any]]:
    """
    Reconstrói bytes reais disponíveis de linhas de hex dump sem inventar caracteres ausentes.
    Distingue strings em memória de operações executadas.
    """
    reconstructed_chunks: List[Dict[str, Any]] = []
    current_bytes = bytearray()
    start_line_idx = -1
    start_addr = ""

    def flush_chunk(end_idx: int) -> None:
        nonlocal current_bytes, start_line_idx, start_addr
        if current_bytes:
            # Decodifica apenas bytes ASCII imprimíveis ou UTF-8 disponíveis
            text_ascii = "".join(chr(b) if 32 <= b <= 126 else "." for b in current_bytes)
            urls = re.findall(r'https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+', text_ascii)
            reconstructed_chunks.append({
                "start_line": start_line_idx,
                "end_line": end_idx,
                "start_addr": start_addr,
                "byte_count": len(current_bytes),
                "reconstructed_ascii": text_ascii,
                "urls": urls,
            })
            current_bytes = bytearray()
            start_line_idx = -1
            start_addr = ""

    for idx, line in enumerate(lines):
        m = HEXDUMP_LINE_RE.match(line)
        if not m:
            flush_chunk(idx - 1)
            continue
        if start_line_idx == -1:
            start_line_idx = idx
            start_addr = m.group("addr")
        hex_groups = m.group("hex").strip().split()
        for grp in hex_groups:
            if len(grp) % 2 != 0:
                continue
            try:
                raw_grp = bytes.fromhex(grp)
                # Em dumps ARM64 (ex: 64-bit little-endian words como 6e6f734a2e74666f -> oft.Json),
                # palavras de 8 bytes ou 4 bytes frequentemente vêm em little-endian na coluna hex.
                # Reconstruímos na ordem little-endian se a coluna ASCII adjacente confirmar, senão ordem bruta.
                ascii_col = (m.group("ascii") or "").strip()
                reversed_grp = raw_grp[::-1]
                rev_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in reversed_grp)
                raw_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_grp)
                if ascii_col and any(part in ascii_col for part in (rev_str[:4], rev_str[-4:]) if len(part) >= 3):
                    current_bytes.extend(reversed_grp)
                elif ascii_col and any(part in ascii_col for part in (raw_str[:4], raw_str[-4:]) if len(part) >= 3):
                    current_bytes.extend(raw_grp)
                else:
                    # Fallback seguro: usa apenas bytes reais na ordem little-endian de palavra quando >=4 bytes
                    current_bytes.extend(reversed_grp if len(raw_grp) in (4, 8) else raw_grp)
            except ValueError:
                continue

    flush_chunk(len(lines) - 1)
    return reconstructed_chunks


def is_tracev3_binary(data: bytes) -> bool:
    """Verifica se o buffer é um arquivo binário Apple Unified Log (.tracev3)."""
    if len(data) < 16:
        return False
    # TraceV3 chunk header tags típicos (0x00001000 header chunk ou 0x6001/0x6002)
    tag = int.from_bytes(data[0:4], "little")
    return tag in (0x00001000, 0x00006001, 0x00006002, 0x00006003) or b"hdb" in data[:64]


# ─────────────────────────────────────────────────────────────
# Funções Auxiliares de Contexto e Construção de Alertas
# ─────────────────────────────────────────────────────────────

LOGCAT_TS_PROC_RE = re.compile(
    r'^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(?:\S+\s+)?(\d+)\s+(\d+)\s+([VDIWEFS])\s+([^:]+):'
)
ISO_TS_RE = re.compile(r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?)')


def get_line_context(lines: List[str], idx: int) -> Dict[str, str]:
    prev_l = lines[idx - 1].rstrip("\r")[:200] if idx > 0 else ""
    curr_l = lines[idx].rstrip("\r")[:240]
    next_l = lines[idx + 1].rstrip("\r")[:200] if idx + 1 < len(lines) else ""
    ts = ""
    proc = ""
    m_log = LOGCAT_TS_PROC_RE.match(curr_l)
    if m_log:
        ts = m_log.group(1)
        proc = m_log.group(5).strip()
    else:
        m_iso = ISO_TS_RE.search(curr_l)
        if m_iso:
            ts = m_iso.group(1)
    return {
        "prev_line": prev_l,
        "current_line": curr_l,
        "next_line": next_l,
        "timestamp": ts,
        "process": proc,
    }


def make_alert(
    signature_id: str,
    signature_name: str,
    category: str,
    source_file: str,
    process: str,
    timestamp: str,
    contextual_snippet: Dict[str, str],
    observed_event: str,
    technical_interpretation: str,
    corroborating_evidence: List[str],
    confidence: str,
    evidence_tier: str,
    classification_reason: str,
    recommended_action: str,
    limitation: str,
    weight: int,
    rule_version: str = "4.0.0",
    provenance: str = "Cacique Forensics Lab",
    dedup_key: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "signature_id": signature_id,
        "signature_name": signature_name,
        "category": category,
        "category_label": CATEGORY_LABELS.get(category, category),
        "source_file": source_file,
        "process": process or "Não identificado",
        "timestamp": timestamp or "Não disponível",
        "contextual_snippet": contextual_snippet,
        "observed_event": observed_event,
        "technical_interpretation": technical_interpretation,
        "corroborating_evidence": corroborating_evidence,
        "confidence": confidence,
        "confidence_label": CONFIDENCE_LABELS.get(confidence, confidence),
        "evidence_tier": evidence_tier,
        "evidence_tier_label": TIER_LABELS.get(evidence_tier, evidence_tier),
        "classification_reason": classification_reason,
        "recommended_action": recommended_action,
        "limitation": limitation,
        "weight": weight,
        "raw_occurrences": 1,
        "rule_version": rule_version,
        "provenance": provenance,
        "_dedup_key": dedup_key or f"{signature_id}|{source_file}|{process}",
    }


# ─────────────────────────────────────────────────────────────
# Motor Principal de Análise Forense
# ─────────────────────────────────────────────────────────────

AUTORIZED_INSTALLERS = {"com.android.vending"}


class ForensicEngine:
    def __init__(self, rules: Optional[List[ForensicRule]] = None):
        self.rules = rules if rules is not None else RULE_REGISTRY
        self.active_rules = [r for r in self.rules if r.status != "experimental_inactive"]
        # Pré-compilar regexes para alto desempenho em grandes volumes (60k+ linhas < 1s)
        self._compiled_legacy = [
            (r, re.compile(rf'(?<![A-Za-z0-9_.-]){re.escape(r.pattern)}(?![A-Za-z0-9_.-])', re.IGNORECASE))
            for r in self.active_rules if r.id.startswith("LEGACY_")
        ]
        self._compiled_proxy_domains = [
            (
                dom, mtype, desc,
                re.compile(
                    rf'(?<![A-Za-z0-9_-]){re.escape(dom)}(?![A-Za-z0-9_-])' if mtype == "domain"
                    else rf'(?<![A-Za-z0-9_]){re.escape(dom)}(?![A-Za-z0-9_])',
                    re.IGNORECASE if mtype == "domain" else 0,
                ),
            )
            for dom, mtype, desc in PROXY_DOMAINS_TEXTUAL
        ]
        self._compiled_pkg_ids = [
            (
                pkg_id, desc,
                re.compile(
                    rf'(?<![A-Za-z0-9_.-]){re.escape(pkg_id)}(?![A-Za-z0-9_.-])',
                    0 if pkg_id == "com.Vluv.lockprofile" else re.IGNORECASE,
                ),
            )
            for pkg_id, desc in PACKAGE_AND_PROFILE_IDS
        ]

    def analyze_files(
        self,
        files: List[Dict[str, Any]],
        os_hint: str = "auto",
    ) -> Dict[str, Any]:
        """
        Analisa uma lista de arquivos:
          cada item: {"path": str, "text": Optional[str], "bytes": Optional[bytes], "size": int}
        """
        detected_os = os_hint.lower() if os_hint in ("android", "ios") else self._detect_os(files)

        raw_alerts: List[Dict[str, Any]] = []
        unanalyzed_files: List[Dict[str, str]] = []
        analyzed_files = 0
        total_lines = 0
        signals_bag: Set[str] = set()  # Sinais independentes para correlação global

        for entry in files:
            fpath = entry.get("path", "unknown")
            raw_bytes = entry.get("bytes")
            text = entry.get("text")

            # 9. iOS Unified Logs (.tracev3) — NUNCA ler binário como texto simples!
            if fpath.lower().endswith(".tracev3"):
                if raw_bytes is not None and is_tracev3_binary(raw_bytes):
                    unanalyzed_files.append({
                        "file": fpath,
                        "reason": "Não analisado — formato binário Unified Log (.tracev3) requer conversão via ferramenta compatível (ex: macOS 'log show').",
                    })
                else:
                    unanalyzed_files.append({
                        "file": fpath,
                        "reason": "Não analisado — arquivo .tracev3 sem parser/conversor binário nativo disponível.",
                    })
                continue

            if text is None and raw_bytes is not None:
                text = raw_bytes.decode("utf-8", errors="ignore")
            if not text:
                continue

            analyzed_files += 1
            lines = text.splitlines()
            total_lines += len(lines)
            ftype = classify_file_type(fpath, text[:4000])

            # Executar analisadores contextuais especializados
            self._analyze_auditd_and_gameasset(lines, fpath, ftype, raw_alerts, signals_bag)
            self._analyze_suspicious_jars(lines, fpath, ftype, raw_alerts, signals_bag)
            self._analyze_crashes_and_stability(lines, fpath, ftype, raw_alerts, signals_bag)
            self._analyze_hexdumps_and_github(lines, fpath, raw_alerts)
            self._analyze_casino_activity(lines, fpath, ftype, raw_alerts)

            if detected_os == "ios" or ftype in ("ios_unified_log", "ios_plist", "ios_ips_crash"):
                self._analyze_ios_backup_restore(lines, fpath, raw_alerts, signals_bag)

            self._analyze_proxies_and_profiles(lines, fpath, ftype, detected_os, raw_alerts, signals_bag)
            if detected_os == "android":
                self._analyze_installer_origins(text, lines, fpath, raw_alerts, signals_bag)

            self._analyze_legacy_contextual(lines, fpath, ftype, detected_os, raw_alerts, signals_bag)

        # Deduplicação (12. Eventos repetidos não multiplicam risco)
        deduped_alerts, raw_occurrences_count = self._deduplicate_alerts(raw_alerts)

        # Correlação de evidências independentes
        self._correlate_evidence(deduped_alerts, signals_bag)

        # Contadores separados (Seção 10)
        unique_events = len(deduped_alerts)
        validated_evidence = sum(
            1 for a in deduped_alerts
            if a["evidence_tier"] in ("corroborated_evidence", "confirmed_interference")
        )
        review_alerts = sum(
            1 for a in deduped_alerts
            if a["evidence_tier"] == "specific_anomaly"
        )
        informative_events = sum(
            1 for a in deduped_alerts
            if a["evidence_tier"] in ("textual_reference", "contextual_event")
        )

        # Pontuação baseada exclusivamente na qualidade das evidências únicas
        threat_score = sum(a["weight"] for a in deduped_alerts)
        integrity_score = max(0, 100 - min(100, threat_score))

        has_shgap_anomaly = any(
            a["signature_id"] == "FF_UNVERIFIED_FOLDER_SHGAP" and a["evidence_tier"] in ("specific_anomaly", "corroborated_evidence", "confirmed_interference")
            for a in deduped_alerts
        )
        has_shgpp2_anomaly = any(
            a["signature_id"] == "FF_GAMEASSET_SH_GPP2_AUDITD" and a["evidence_tier"] in ("specific_anomaly", "corroborated_evidence", "confirmed_interference")
            for a in deduped_alerts
        )

        verdict = self._compute_verdict(deduped_alerts, unanalyzed_files, threat_score)

        return {
            "engine_version": ENGINE_VERSION,
            "os_detected": detected_os.upper(),
            "verdict": verdict,
            "threat_score": threat_score,
            "integrity_score": integrity_score,
            "has_gameasset_anomaly": has_shgap_anomaly or has_shgpp2_anomaly,
            "counters": {
                "raw_occurrences": raw_occurrences_count,
                "unique_events": unique_events,
                "validated_evidence": validated_evidence,
                "review_alerts": review_alerts,
                "informative_events": informative_events,
                "unanalyzed_files": len(unanalyzed_files),
                "analyzed_files": analyzed_files,
                "checked_lines": total_lines,
                "inactive_experimental_rules": sum(1 for r in self.rules if r.status == "experimental_inactive"),
            },
            "alerts": deduped_alerts,
            "unanalyzed_files": unanalyzed_files,
        }

    def _detect_os(self, files: List[Dict[str, Any]]) -> str:
        joined = " ".join(f.get("path", "").lower() for f in files)
        ios_score = sum(1 for k in ("sysdiagnose", ".plist", ".tracev3", ".ips", "mobilebackup") if k in joined)
        android_score = sum(1 for k in ("bugreport", "logcat", "dumpsys", "audit", "packages") if k in joined)
        return "ios" if ios_score > android_score else "android"

    # ── 2. Free Fire GameAsset (SH-Gpp2 & -SHgap-) ──
    def _analyze_auditd_and_gameasset(
        self, lines: List[str], fpath: str, ftype: str, alerts: List[Dict[str, Any]], signals: Set[str]
    ) -> None:
        target_canon = "/data/user/0/com.dts.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2"
        for idx, line in enumerate(lines):
            low = line.lower()
            if "sh-gpp2" not in low and "-shgap-" not in low:
                continue

            ctx = get_line_context(lines, idx)
            audit = parse_auditd_line(line)

            if audit and "sh-gpp2" in (audit.get("canonical_path") or "").lower():
                cpath = audit["canonical_path"]
                is_exact_ff_path = cpath.lower() == target_canon.lower()
                comm = audit.get("comm", "")
                app = audit.get("app", "")
                action = audit.get("avc_action", "")
                ops = audit.get("operations", [])

                if is_exact_ff_path and app == "com.dts.freefiremax":
                    if action == "granted" and "execute" in ops and comm == "UnityMain":
                        signals.add("avc_granted_execute_sh_gpp2")
                        alerts.append(make_alert(
                            signature_id="FF_GAMEASSET_SH_GPP2_AUDITD",
                            signature_name="Anomalia em arquivo do Free Fire (SH-Gpp2)",
                            category="gameasset_anomaly",
                            source_file=fpath,
                            process=comm,
                            timestamp=audit.get("timestamp") or ctx["timestamp"],
                            contextual_snippet=ctx,
                            observed_event=f"SELinux avc: granted {{ {', '.join(ops)} }} para comm=\"{comm}\" em {audit.get('path')} (app={app}).",
                            technical_interpretation="SELinux permitiu (granted) uma operação de execução no caminho de recurso font/SH-Gpp2 associado ao pacote com.dts.freefiremax.",
                            corroborating_evidence=[],
                            confidence="medium",
                            evidence_tier="specific_anomaly",
                            classification_reason="Execução registrada pelo kernel/SELinux em caminho de recurso sujeito à validação de integridade.",
                            recommended_action="Verificar integridade do recurso, versão do jogo e outros eventos relacionados; recomendar reinstalação oficial caso haja indícios consistentes de adulteração.",
                            limitation="Esse registro isolado não comprova injeção de código nem autoriza punição automática.",
                            weight=30,
                            dedup_key=f"FF_GAMEASSET_SH_GPP2_AUDITD|{cpath}|{action}|{'_'.join(ops)}",
                        ))
                    elif action == "denied":
                        alerts.append(make_alert(
                            signature_id="FF_GAMEASSET_SH_GPP2_DENIED",
                            signature_name="Tentativa SELinux Negada em GameAsset (SH-Gpp2)",
                            category="gameasset_anomaly",
                            source_file=fpath,
                            process=comm or ctx["process"],
                            timestamp=audit.get("timestamp") or ctx["timestamp"],
                            contextual_snippet=ctx,
                            observed_event=f"SELinux avc: denied {{ {', '.join(ops)} }} em {audit.get('path')} (app={app}).",
                            technical_interpretation="O SELinux bloqueou (denied) a operação no arquivo SH-Gpp2; não houve execução permitida neste evento.",
                            corroborating_evidence=[],
                            confidence="low",
                            evidence_tier="contextual_event",
                            classification_reason="Operação negada pelo SELinux (diferenciada de 'granted').",
                            recommended_action="Apenas registrar para contexto; verificar se há outros eventos permitidos.",
                            limitation="Operação bloqueada pelo sistema.",
                            weight=5,
                            dedup_key=f"FF_GAMEASSET_SH_GPP2_DENIED|{cpath}",
                        ))
                    continue

            # SH-Gpp2 em caminho exato do jogo fora de auditd
            if re.search(r'/data/(?:user/0|data)/com\.dts\.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2\b', line):
                alerts.append(make_alert(
                    signature_id="FF_GAMEASSET_SH_GPP2_PATH_REF",
                    signature_name="Referência ao caminho SH-Gpp2 do Free Fire",
                    category="gameasset_anomaly",
                    source_file=fpath,
                    process=ctx["process"],
                    timestamp=ctx["timestamp"],
                    contextual_snippet=ctx,
                    observed_event="Caminho específico de SH-Gpp2 citado em log.",
                    technical_interpretation="Referência textual ao caminho do arquivo SH-Gpp2 sem evento de execução SELinux confirmado nesta linha.",
                    corroborating_evidence=[],
                    confidence="low",
                    evidence_tier="contextual_event",
                    classification_reason="Caminho compatível encontrado, mas sem confirmação de execução nesta linha.",
                    recommended_action="Verificar se existe evento auditd/execução correspondente.",
                    limitation="Citação do caminho isolada não comprova execução ou adulteração.",
                    weight=10,
                    dedup_key=f"FF_GAMEASSET_SH_GPP2_PATH_REF|{fpath}",
                ))
            elif "sh-gpp2" in low:
                # 12.4: SH-Gpp2 em mensagem não relacionada ao jogo -> não gera alerta relevante!
                alerts.append(make_alert(
                    signature_id="FF_GAMEASSET_SH_GPP2_UNRELATED",
                    signature_name="Menção textual a SH-Gpp2 fora do contexto do Free Fire",
                    category="uncategorized",
                    source_file=fpath,
                    process=ctx["process"],
                    timestamp=ctx["timestamp"],
                    contextual_snippet=ctx,
                    observed_event="Termo 'SH-Gpp2' encontrado fora do caminho/pacote com.dts.freefiremax.",
                    technical_interpretation="Referência textual sem associação ao diretório gameassetbundles do Free Fire.",
                    corroborating_evidence=[],
                    confidence="none",
                    evidence_tier="textual_reference",
                    classification_reason="Ausência de caminho do Free Fire e de evento SELinux/execução.",
                    recommended_action="Nenhuma ação necessária.",
                    limitation="Coincidência textual fora do contexto do jogo.",
                    weight=0,
                    dedup_key=f"FF_GAMEASSET_SH_GPP2_UNRELATED|{fpath}",
                ))

            # -SHgap- como componente explícito de caminho/diretório
            if re.search(r'(?:^|[\\/])-SHgap-(?:$|[\\/])', line):
                signals.add("unverified_folder_shgap")
                alerts.append(make_alert(
                    signature_id="FF_UNVERIFIED_FOLDER_SHGAP",
                    signature_name="Anomalia em arquivo do Free Fire — Pasta -SHgap-",
                    category="gameasset_anomaly",
                    source_file=fpath,
                    process=ctx["process"],
                    timestamp=ctx["timestamp"],
                    contextual_snippet=ctx,
                    observed_event="Componente de diretório '-SHgap-' detectado em caminho de arquivo.",
                    technical_interpretation="A pasta '-SHgap-' não pertence à árvore padrão verificada do Free Fire.",
                    corroborating_evidence=[],
                    confidence="medium",
                    evidence_tier="specific_anomaly",
                    classification_reason="Identificado como componente explícito de caminho, não por simples presença de hífen.",
                    recommended_action="Verificar integridade dos arquivos do Free Fire e recomendar reinstalação oficial caso haja indícios consistentes de arquivos adulterados.",
                    limitation="Registro isolado exige revisão técnica e não determina punição automática.",
                    weight=25,
                    dedup_key=f"FF_UNVERIFIED_FOLDER_SHGAP|{fpath}",
                ))

    # ── 3. Arquivos JAR Suspeitos ──
    def _analyze_suspicious_jars(
        self, lines: List[str], fpath: str, ftype: str, alerts: List[Dict[str, Any]], signals: Set[str]
    ) -> None:
        jar_targets = {
            "app_resources_lib.jar": "FF_CACHE_JAR_APP_RESOURCES",
            "google_api_resources_lib.jar": "FF_CACHE_JAR_GOOGLE_API",
        }
        loader_re = re.compile(r'DexClassLoader|PathClassLoader|InMemoryDexClassLoader|dalvik\.system|Opening dex|avc:\s*granted\s*\{\s*execute', re.IGNORECASE)

        for idx, line in enumerate(lines):
            low = line.lower()
            for jar_name, rule_id in jar_targets.items():
                if jar_name not in low:
                    continue
                # Exigir caminho completo do pacote com.dts.freefiremax/cache/
                full_path_re = re.compile(
                    rf'/data/(?:user/0|data)/com\.dts\.freefiremax/cache/{re.escape(jar_name)}\b',
                    re.IGNORECASE,
                )
                if not full_path_re.search(line):
                    continue

                ctx = get_line_context(lines, idx)
                has_loader = bool(loader_re.search(line) or loader_re.search(ctx["prev_line"]) or loader_re.search(ctx["next_line"]))
                if has_loader:
                    signals.add(f"jar_loaded_{jar_name}")
                    alerts.append(make_alert(
                        signature_id=rule_id,
                        signature_name=f"Carregamento/Execução de JAR em Cache ({jar_name})",
                        category="suspicious_jar",
                        source_file=fpath,
                        process=ctx["process"] or "com.dts.freefiremax",
                        timestamp=ctx["timestamp"],
                        contextual_snippet=ctx,
                        observed_event=f"Evento de carregamento/ClassLoader associado a {jar_name} no cache do Free Fire Max.",
                        technical_interpretation="Arquivo JAR específico no diretório de cache com evidência contextual de carregamento ou execução.",
                        corroborating_evidence=["Evento de ClassLoader/execução no contexto imediato"],
                        confidence="medium",
                        evidence_tier="specific_anomaly",
                        classification_reason="Caminho completo associado a com.dts.freefiremax + indício de carregamento.",
                        recommended_action="Elevar para revisão técnica: verificar origem, assinatura e integridade do pacote.",
                        limitation="Nome do arquivo não comprova finalidade maliciosa sem análise do conteúdo do JAR.",
                        weight=25,
                        dedup_key=f"{rule_id}|loaded",
                    ))
                else:
                    alerts.append(make_alert(
                        signature_id=rule_id,
                        signature_name=f"Referência a JAR em Cache ({jar_name})",
                        category="suspicious_jar",
                        source_file=fpath,
                        process=ctx["process"] or "com.dts.freefiremax",
                        timestamp=ctx["timestamp"],
                        contextual_snippet=ctx,
                        observed_event=f"Caminho completo de {jar_name} presente no log sem evento de carregamento.",
                        technical_interpretation="Arquivo presente em listagem/caminho, sem registro de execução ou ClassLoader nesta entrada.",
                        corroborating_evidence=[],
                        confidence="low",
                        evidence_tier="contextual_event",
                        classification_reason="Distinção entre arquivo presente e arquivo efetivamente carregado.",
                        recommended_action="Manter como referência a investigar caso surjam eventos de carregamento.",
                        limitation="Extensão .jar ou nome do arquivo isolado não comprova malícia.",
                        weight=5,
                        dedup_key=f"{rule_id}|present",
                    ))

    # ── 4. Interpretação de Crashes & Estabilidade ──
    def _analyze_crashes_and_stability(
        self, lines: List[str], fpath: str, ftype: str, alerts: List[Dict[str, Any]], signals: Set[str]
    ) -> None:
        for idx, line in enumerate(lines):
            # LOW_MEMORY / OOM
            if "LOW_MEMORY" in line or "OutOfMemoryError" in line:
                ctx = get_line_context(lines, idx)
                proc_m = re.search(r'process=([^\s]+)', line)
                proc = proc_m.group(1) if proc_m else ctx["process"]
                alerts.append(make_alert(
                    signature_id="STABILITY_LOW_MEMORY",
                    signature_name="Encerramento por Memória (LOW_MEMORY)",
                    category="stability_crash",
                    source_file=fpath,
                    process=proc,
                    timestamp=ctx["timestamp"],
                    contextual_snippet=ctx,
                    observed_event=line.strip()[:200],
                    technical_interpretation="Classificação de crash: Crash comum. Encerramento normal do processo por pressão de memória RAM no sistema.",
                    corroborating_evidence=[],
                    confidence="none",
                    evidence_tier="textual_reference",
                    classification_reason="Evento padrão do ActivityManager/LMK do sistema operacional.",
                    recommended_action="Nenhuma ação anti-cheat. Diagnóstico apenas de estabilidade.",
                    limitation="LOW_MEMORY nunca indica cheating ou injeção.",
                    weight=0,
                    dedup_key=f"STABILITY_LOW_MEMORY|{proc}",
                ))
                continue

            # SIGSEGV / SEGV_MAPERR
            if "SIGSEGV" in line or "SEGV_MAPERR" in line:
                ctx = get_line_context(lines, idx)
                block = "\n".join(lines[max(0, idx - 5):min(len(lines), idx + 15)])
                cmd_m = re.search(r'Cmdline:\s*([^\r\n]+)', block)
                name_m = re.search(r'name:\s*([^\s>]+)', block)
                cause_m = re.search(r'Cause:\s*([^\r\n]+)', block)
                proc = (cmd_m.group(1).strip() if cmd_m else "") or (name_m.group(1).strip() if name_m else ctx["process"])
                cause = cause_m.group(1).strip() if cause_m else "Não especificada"

                # Verifica se há biblioteca suspeita explícita no backtrace
                suspicious_bt = re.search(r'backtrace:[\s\S]{0,600}(?:frida|gadget|substrate|lsposed|xposed|modmenu)', block, re.IGNORECASE)
                if suspicious_bt:
                    signals.add("crash_with_suspicious_backtrace_lib")
                    alerts.append(make_alert(
                        signature_id="STABILITY_SIGSEGV_CORROBORATED",
                        signature_name="Crash SIGSEGV com Biblioteca Suspeita em Backtrace",
                        category="stability_crash",
                        source_file=fpath,
                        process=proc,
                        timestamp=ctx["timestamp"],
                        contextual_snippet=ctx,
                        observed_event=f"Crash SIGSEGV/SEGV_MAPERR (Causa: {cause}) com referência a biblioteca de hooking no backtrace.",
                        technical_interpretation="Classificação de crash: Indício técnico corroborado de interferência — crash associado a biblioteca suspeita carregada.",
                        corroborating_evidence=[f"Biblioteca suspeita no backtrace: {suspicious_bt.group(0)[-60:]}"],
                        confidence="high",
                        evidence_tier="corroborated_evidence",
                        classification_reason="SIGSEGV isolado não basta, mas houve correlação direta no backtrace.",
                        recommended_action="Revisar mapa de memória e módulos carregados no processo.",
                        limitation="Requer preservação do tombstone completo para auditoria.",
                        weight=45,
                        dedup_key=f"STABILITY_SIGSEGV_CORROBORATED|{proc}",
                    ))
                else:
                    alerts.append(make_alert(
                        signature_id="STABILITY_NATIVE_SIGSEGV",
                        signature_name="Crash Nativo / Falha de Memória (SIGSEGV)",
                        category="stability_crash",
                        source_file=fpath,
                        process=proc,
                        timestamp=ctx["timestamp"],
                        contextual_snippet=ctx,
                        observed_event=f"Crash nativo SIGSEGV/SEGV_MAPERR (Causa: {cause}).",
                        technical_interpretation="Classificação de crash: Falha não determinada. Falha de acesso à memória (ex: null pointer dereference) sem evidência de injeção.",
                        corroborating_evidence=[],
                        confidence="none",
                        evidence_tier="textual_reference",
                        classification_reason="SIGSEGV, endereços hex e registradores ARM64 isolados não comprovam wallhack ou injeção.",
                        recommended_action="Exigir evidências adicionais (backtrace, mapas /proc/pid/maps, bibliotecas carregadas) antes de investigar adulteração.",
                        limitation="Crash nativo comum em engines Unity/C++; não indica trapaça.",
                        weight=0,
                        dedup_key=f"STABILITY_NATIVE_SIGSEGV|{proc}|{cause}",
                    ))

    # ── 5. Referências a GitHub e Hex Dumps ──
    def _analyze_hexdumps_and_github(
        self, lines: List[str], fpath: str, alerts: List[Dict[str, Any]]
    ) -> None:
        chunks = parse_hex_dump_lines(lines)
        for ch in chunks:
            for url in ch["urls"]:
                if "github.com" in url.lower():
                    idx = ch["start_line"]
                    ctx = get_line_context(lines, max(0, idx))
                    alerts.append(make_alert(
                        signature_id="HEXDUMP_GITHUB_REFERENCE",
                        signature_name="URL GitHub Reconstruída em Dump de Memória",
                        category="github_hexdump",
                        source_file=fpath,
                        process=ctx["process"] or "Dump de Memória",
                        timestamp=ctx["timestamp"],
                        contextual_snippet=ctx,
                        observed_event=f"URL reconstruída a partir de {ch['byte_count']} bytes reais do dump ({ch['start_addr']}): {url}",
                        technical_interpretation="String presente em memória estática/dump (ex: metadados de biblioteca como Newtonsoft.Json). Não representa operação executada nem causa comprovada de crash.",
                        corroborating_evidence=[],
                        confidence="none",
                        evidence_tier="textual_reference",
                        classification_reason="Reconstrução fiel de bytes disponíveis sem atribuição causal de crash ou cheat.",
                        recommended_action="Nenhuma ação punitiva. Apenas referência contextual de string em memória.",
                        limitation="Presença de github.com em dump de memória não é indício de trapaça.",
                        weight=0,
                        dedup_key=f"HEXDUMP_GITHUB_REFERENCE|{url}",
                    ))

    # ── 6. Categoria Cassino (Sem hífen!) ──
    def _analyze_casino_activity(
        self, lines: List[str], fpath: str, ftype: str, alerts: List[Dict[str, Any]]
    ) -> None:
        if ftype not in ("network_proxy", "packages", "ios_unified_log", "logcat", "bugreport"):
            return
        casino_re = re.compile(
            r'\b(?:blaze\.com|betano\.com|bet365\.com|sportingbet\.com|estrelabet\.com|pixbet\.com|stake\.com|1xbet\.com)\b',
            re.IGNORECASE,
        )
        for idx, line in enumerate(lines):
            m = casino_re.search(line)
            if not m:
                continue
            # Exige contexto estruturado de URL, DNS, navegador ou pacote (não qualquer palavra/hífen)
            if not re.search(r'(?:https?://|dns|host=|domain=|package:|url=|referer|visit)', line, re.IGNORECASE):
                continue
            ctx = get_line_context(lines, idx)
            alerts.append(make_alert(
                signature_id="CASINO_DOMAIN_OR_APP",
                signature_name=f"Domínio de Apostas/Cassino ({m.group(0)})",
                category="casino_activity",
                source_file=fpath,
                process=ctx["process"],
                timestamp=ctx["timestamp"],
                contextual_snippet=ctx,
                observed_event=f"Domínio estruturado de apostas encontrado: {m.group(0)}",
                technical_interpretation="Indicador explícito de domínio de apostas/cassino em registro de rede ou pacote.",
                corroborating_evidence=[],
                confidence="low",
                evidence_tier="contextual_event",
                classification_reason="Correspondência exata em domínio conhecido (hífens isolados são ignorados).",
                recommended_action="Verificar se é relevante para a auditoria solicitada.",
                limitation="Acesso ou menção a site de apostas não implica cheat no Free Fire.",
                weight=0,
                dedup_key=f"CASINO_DOMAIN_OR_APP|{m.group(0).lower()}",
            ))

    # ── 7. iOS — Backup e Restauração ──
    def _analyze_ios_backup_restore(
        self, lines: List[str], fpath: str, alerts: List[Dict[str, Any]], signals: Set[str]
    ) -> None:
        terms = [
            "MobileBackup", "BackupAgent", "BackupRestore", "RestoreFromBackup",
            "Restored", "mobilebackupd", "restore_type", "SetupAssistant",
            "iCloudRestore", "itunesstored",
        ]
        lifecycle_start_re = re.compile(r'\b(start|started|begin|initiating|iniciando)\b', re.IGNORECASE)
        lifecycle_prog_re = re.compile(r'\b(progress|restoring|downloading|transferring)\b', re.IGNORECASE)
        lifecycle_done_re = re.compile(r'\b(complete|completed|finished|succeeded|done)\b', re.IGNORECASE)
        service_only_re = re.compile(r'\b(registered|available|loaded|plist|service|daemon|idle)\b', re.IGNORECASE)

        for idx, line in enumerate(lines):
            for term in terms:
                if not re.search(rf'\b{re.escape(term)}\b', line):
                    continue
                ctx = get_line_context(lines, idx)

                # Regra 7.7: itunesstored é serviço da App Store, NUNCA comprova restauração
                if term == "itunesstored":
                    alerts.append(make_alert(
                        signature_id="IOS_ITUNESSTORED",
                        signature_name="Serviço App Store (itunesstored)",
                        category="ios_backup_restore",
                        source_file=fpath,
                        process="itunesstored",
                        timestamp=ctx["timestamp"],
                        contextual_snippet=ctx,
                        observed_event="Registro padrão do serviço itunesstored.",
                        technical_interpretation="itunesstored é o daemon legítimo da App Store; não comprova restauração de backup.",
                        corroborating_evidence=[],
                        confidence="none",
                        evidence_tier="textual_reference",
                        classification_reason="Serviço nativo da App Store.",
                        recommended_action="Nenhuma ação necessária.",
                        limitation="Não é evidência de restauração nem de cheating.",
                        weight=0,
                        dedup_key="IOS_ITUNESSTORED",
                    ))
                    continue

                # Regra 7.6: SetupAssistant legítimo
                if term == "SetupAssistant" and not re.search(r'restore', line, re.IGNORECASE):
                    alerts.append(make_alert(
                        signature_id="IOS_SETUP_ASSISTANT",
                        signature_name="SetupAssistant (Configuração do Sistema)",
                        category="ios_backup_restore",
                        source_file=fpath,
                        process="SetupAssistant",
                        timestamp=ctx["timestamp"],
                        contextual_snippet=ctx,
                        observed_event="Registro do SetupAssistant sem menção a restauração.",
                        technical_interpretation="SetupAssistant ocorre normalmente após atualizações do iOS ou configuração inicial legítima.",
                        corroborating_evidence=[],
                        confidence="none",
                        evidence_tier="textual_reference",
                        classification_reason="Evento legítimo de configuração sem ciclo de restauração.",
                        recommended_action="Nenhuma ação necessária sem eventos de restauração correlatos.",
                        limitation="Não comprova restauração nem trapaça.",
                        weight=0,
                        dedup_key="IOS_SETUP_ASSISTANT",
                    ))
                    continue

                is_restore_stage = bool(lifecycle_start_re.search(line) or lifecycle_prog_re.search(line) or lifecycle_done_re.search(line))
                is_service_avail = bool(service_only_re.search(line)) and not is_restore_stage

                if is_restore_stage and term in ("RestoreFromBackup", "iCloudRestore", "BackupRestore", "restore_type", "mobilebackupd"):
                    signals.add("ios_restore_lifecycle_event")
                    stage = "início" if lifecycle_start_re.search(line) else ("progresso" if lifecycle_prog_re.search(line) else "conclusão")
                    alerts.append(make_alert(
                        signature_id=f"IOS_RESTORE_{term.upper()}",
                        signature_name=f"Possível atividade de restauração de backup ({term})",
                        category="ios_backup_restore",
                        source_file=fpath,
                        process=ctx["process"] or term,
                        timestamp=ctx["timestamp"],
                        contextual_snippet=ctx,
                        observed_event=f"Evento de ciclo de restauração (estágio: {stage}) envolvendo {term}.",
                        technical_interpretation="Possível atividade de restauração de backup — verificar contexto e timestamps.",
                        corroborating_evidence=[f"Estágio observado: {stage}"],
                        confidence="low",
                        evidence_tier="contextual_event",
                        classification_reason="Evento com indicação de execução/estágio de restauração.",
                        recommended_action="Verificar timestamps e correlacionar outros eventos de restauração. Não presumir cheat.",
                        limitation="Restauração de backup é funcionalidade legítima do iOS e não comprova utilização de cheat.",
                        weight=10,
                        dedup_key=f"IOS_RESTORE_{term.upper()}|{stage}",
                    ))
                else:
                    # Serviço disponível / referência isolada (ex: MobileBackup sozinho)
                    alerts.append(make_alert(
                        signature_id=f"IOS_BACKUP_REF_{term.upper()}",
                        signature_name=f"Referência de Backup/Serviço iOS ({term})",
                        category="ios_backup_restore",
                        source_file=fpath,
                        process=ctx["process"] or term,
                        timestamp=ctx["timestamp"],
                        contextual_snippet=ctx,
                        observed_event=f"Termo {term} citado{' como serviço disponível' if is_service_avail else ''} sem estágio ativo de restauração.",
                        technical_interpretation="Referência textual ou serviço disponível; não comprova restauração executada.",
                        corroborating_evidence=[],
                        confidence="none",
                        evidence_tier="textual_reference",
                        classification_reason="Ausência de eventos de início, progresso ou conclusão de restauração.",
                        recommended_action="Apenas informativo; não comprova restauração.",
                        limitation="MobileBackup ou daemons listados isoladamente não comprovam restauração.",
                        weight=0,
                        dedup_key=f"IOS_BACKUP_REF_{term.upper()}",
                    ))

    # ── 8. Proxies, Domínios e Perfis/Pacotes ──
    def _analyze_proxies_and_profiles(
        self, lines: List[str], fpath: str, ftype: str, os_type: str, alerts: List[Dict[str, Any]], signals: Set[str]
    ) -> None:
        # Campos estruturados onde domínios de proxy são válidos
        domain_field_re = re.compile(r'(?:https?://|host=|domain=|dns|query|proxy|server=|url=|cn=|san=)', re.IGNORECASE)
        # Campos estruturados onde package/profile IDs são válidos
        pkg_field_re = re.compile(r'(?:package\s*[:=\[]|bundleid|bundle_id|payloadidentifier|profile|app=|installerpackagename=|cmd package|pm list)', re.IGNORECASE)

        for idx, line in enumerate(lines):
            line_low = line.lower()
            has_domain_ctx = ftype in ("network_proxy", "ios_plist") or bool(domain_field_re.search(line))
            # A) Domínios e indicadores textuais
            for dom, mtype, desc, pat_re in self._compiled_proxy_domains:
                if dom.lower() not in line_low:
                    continue
                if mtype == "domain":
                    if not has_domain_ctx:
                        continue
                    if pat_re.search(line):
                        ctx = get_line_context(lines, idx)
                        signals.add(f"proxy_domain_{dom.lower()}")
                        alerts.append(make_alert(
                            signature_id=f"PROXY_TEXT_{re.sub(r'[^A-Za-z0-9]+', '_', dom).upper()}",
                            signature_name=desc,
                            category="proxy_domain",
                            source_file=fpath,
                            process=ctx["process"],
                            timestamp=ctx["timestamp"],
                            contextual_snippet=ctx,
                            observed_event=f"Domínio '{dom}' encontrado em campo de rede/DNS/proxy.",
                            technical_interpretation="Indicador de domínio associado a proxy/bypass encontrado em contexto de rede ou perfil.",
                            corroborating_evidence=[],
                            confidence="medium",
                            evidence_tier="specific_anomaly",
                            classification_reason="Match exato de domínio em campo compatível (rede/DNS/proxy).",
                            recommended_action="Correlacionar com proxy configurado, estado de VPN e conexões ativas.",
                            limitation="Domínio em lista ou consulta não comprova uso ativo sem evidência de conexão/roteamento.",
                            weight=20,
                            dedup_key=f"PROXY_DOMAIN|{dom.lower()}",
                        ))
                else:
                    if dom.lower() in ("mitm", "regedit"):
                        if ftype not in ("network_proxy", "ios_plist", "packages") and not has_domain_ctx:
                            continue
                    if pat_re.search(line):
                        ctx = get_line_context(lines, idx)
                        alerts.append(make_alert(
                            signature_id=f"PROXY_TEXT_{re.sub(r'[^A-Za-z0-9]+', '_', dom).upper()}",
                            signature_name=desc,
                            category="proxy_domain",
                            source_file=fpath,
                            process=ctx["process"],
                            timestamp=ctx["timestamp"],
                            contextual_snippet=ctx,
                            observed_event=f"Indicador '{dom}' detectado em contexto compatível.",
                            technical_interpretation="Identificador/hostname de perfil ou ferramenta listado.",
                            corroborating_evidence=[],
                            confidence="low",
                            evidence_tier="contextual_event",
                            classification_reason="Match exato com fronteira de palavra em campo apropriado.",
                            recommended_action="Verificar se há perfil instalado ou proxy configurado associado.",
                            limitation="Presença textual isolada não comprova trapaça.",
                            weight=10,
                            dedup_key=f"PROXY_TEXT|{dom}",
                        ))

            # B) Identificadores exatos de Pacotes e Perfis
            if "com." in line_low and (ftype in ("packages", "ios_plist", "network_proxy") or pkg_field_re.search(line)):
                for pkg_id, desc, exact_pkg_re in self._compiled_pkg_ids:
                    if exact_pkg_re.search(line):
                        ctx = get_line_context(lines, idx)
                        is_mdm = pkg_id == "com.apple.mgmt.External"
                        signals.add(f"pkg_profile_{pkg_id.lower()}")
                        alerts.append(make_alert(
                            signature_id=f"PKG_PROFILE_{re.sub(r'[^A-Za-z0-9]+', '_', pkg_id).upper()}",
                            signature_name=desc,
                            category="profile_package_id",
                            source_file=fpath,
                            process=ctx["process"],
                            timestamp=ctx["timestamp"],
                            contextual_snippet=ctx,
                            observed_event=f"Identificador exato '{pkg_id}' detectado em campo de pacote/bundle/perfil.",
                            technical_interpretation="Identificador MDM externo legítimo ou perfil corporativo." if is_mdm else "Identificador de pacote ou perfil de configuração associado a proxy/regedit.",
                            corroborating_evidence=[],
                            confidence="low" if is_mdm else "medium",
                            evidence_tier="contextual_event" if is_mdm else "specific_anomaly",
                            classification_reason="Correspondência exata em campo de pacote/perfil (sem substring match).",
                            recommended_action="Diferenciar perfil citado de perfil efetivamente instalado e verificar configuração de proxy.",
                            limitation="A presença do ID em arquivo ou lista não comprova utilização de proxy.",
                            weight=5 if is_mdm else 25,
                            dedup_key=f"PKG_PROFILE|{pkg_id}",
                        ))

    # ── Origem de Instalação (Android) ──
    def _analyze_installer_origins(
        self, text: str, lines: List[str], fpath: str, alerts: List[Dict[str, Any]], signals: Set[str]
    ) -> None:
        if "installerPackageName=" not in text:
            return
        pkg_re = re.compile(r'Package\s+\[([a-zA-Z0-9_.]+)\]')
        for m in pkg_re.finditer(text):
            app_pkg = m.group(1)
            block = text[m.start():min(len(text), m.start() + 1800)]
            next_pkg = block.find("Package [", 10)
            if next_pkg != -1:
                block = block[:next_pkg]
            inst_m = re.search(r'installerPackageName=([^\s,}]+)', block)
            if not inst_m:
                continue
            inst = inst_m.group(1).strip()
            if inst in AUTORIZED_INSTALLERS:
                continue
            is_ff = "freefire" in app_pkg.lower()
            if not is_ff and inst == "null" and re.match(r'^(com\.android\.|android$|com\.google\.android\.|com\.samsung\.|com\.miui\.)', app_pkg, re.I):
                continue

            line_idx = text[:m.start()].count("\n")
            ctx = get_line_context(lines, min(line_idx, len(lines) - 1))
            if is_ff:
                signals.add("ff_installed_outside_playstore")
            alerts.append(make_alert(
                signature_id="ANDROID_INSTALLER_ORIGIN",
                signature_name=f"Origem de Instalação Externa: {app_pkg} (via {inst})",
                category="installer_origin",
                source_file=fpath,
                process="PackageManager",
                timestamp=ctx["timestamp"],
                contextual_snippet=ctx,
                observed_event=f"Package [{app_pkg}] instalado com installerPackageName={inst}.",
                technical_interpretation="Aplicativo instalado fora da Google Play Store oficial (com.android.vending).",
                corroborating_evidence=[],
                confidence="high" if is_ff else "low",
                evidence_tier="corroborated_evidence" if is_ff else "contextual_event",
                classification_reason="Verificação oficial de installerPackageName no PackageManager.",
                recommended_action="Confirmar fonte do APK; para Free Fire, exigir instalação exclusivamente pela Play Store." if is_ff else "Verificar se o aplicativo pertence a loja oficial do fabricante.",
                limitation="Lojas de fabricantes (Galaxy Store, Xiaomi GetApps) também usam instaladores distintos.",
                weight=45 if is_ff else 10,
                dedup_key=f"ANDROID_INSTALLER_ORIGIN|{app_pkg}|{inst}",
            ))

    # ── Regras Legadas Contextuais ──
    def _analyze_legacy_contextual(
        self, lines: List[str], fpath: str, ftype: str, os_type: str, alerts: List[Dict[str, Any]], signals: Set[str]
    ) -> None:
        applicable = [
            (rule, pat_re, rule.pattern.lower())
            for rule, pat_re in self._compiled_legacy
            if (rule.os == "both" or rule.os == os_type)
            and (ftype in rule.file_types or "generic_text" in rule.file_types)
        ]
        if not applicable:
            return
        matched_ids: Set[str] = set()
        for idx, line in enumerate(lines):
            low = line.lower()
            for rule, pat_re, pat_low in applicable:
                if rule.id in matched_ids or pat_low not in low:
                    continue
                if pat_re.search(line):
                    matched_ids.add(rule.id)
                    ctx = get_line_context(lines, idx)
                    signals.add(f"legacy_{rule.id}")
                    alerts.append(make_alert(
                        signature_id=rule.id,
                        signature_name=rule.name,
                        category=rule.category,
                        source_file=fpath,
                        process=ctx["process"],
                        timestamp=ctx["timestamp"],
                        contextual_snippet=ctx,
                        observed_event=f"Assinatura '{rule.pattern}' encontrada em contexto compatível.",
                        technical_interpretation=rule.description,
                        corroborating_evidence=[],
                        confidence=rule.confidence,
                        evidence_tier=rule.evidence_tier,
                        classification_reason="Correspondência contextual com fronteira exata.",
                        recommended_action=rule.recommended_action,
                        limitation=rule.limitation,
                        weight=rule.base_weight,
                        rule_version=rule.version,
                        provenance=rule.provenance,
                        dedup_key=f"{rule.id}|{fpath}",
                    ))

    # ── Deduplicação & Correlação ──
    def _deduplicate_alerts(self, raw_alerts: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
        grouped: Dict[str, Dict[str, Any]] = {}
        for al in raw_alerts:
            key = al["_dedup_key"]
            if key not in grouped:
                grouped[key] = al
            else:
                grouped[key]["raw_occurrences"] += 1
        result = []
        for al in grouped.values():
            al.pop("_dedup_key", None)
            result.append(al)
        # Ordenar por força de evidência e peso decrescente
        result.sort(key=lambda x: (EVIDENCE_TIERS.get(x["evidence_tier"], 0), x["weight"]), reverse=True)
        return result, len(raw_alerts)

    def _correlate_evidence(self, alerts: List[Dict[str, Any]], signals: Set[str]) -> None:
        """Eleva confiança quando existem múltiplas evidências independentes corroboradas."""
        has_non_playstore_ff = "ff_installed_outside_playstore" in signals
        has_hooking = any(s.startswith("legacy_LEGACY_FRIDA") or s.startswith("legacy_LEGACY_LSPOSED") or s.startswith("legacy_LEGACY_XPOSED") for s in signals)

        for al in alerts:
            if al["signature_id"] in ("FF_GAMEASSET_SH_GPP2_AUDITD", "FF_UNVERIFIED_FOLDER_SHGAP"):
                corroborators = list(al["corroborating_evidence"])
                if has_non_playstore_ff:
                    corroborators.append("Free Fire instalado fora da Google Play Store")
                if has_hooking:
                    corroborators.append("Framework de hooking/injeção detectado nos logs")
                if corroborators:
                    al["corroborating_evidence"] = corroborators
                    al["evidence_tier"] = "corroborated_evidence"
                    al["evidence_tier_label"] = TIER_LABELS["corroborated_evidence"]
                    al["confidence"] = "high"
                    al["confidence_label"] = CONFIDENCE_LABELS["high"]
                    al["weight"] = max(al["weight"], 55)
                    al["classification_reason"] += " Elevado por evidências independentes correlacionadas."

    def _compute_verdict(
        self, alerts: List[Dict[str, Any]], unanalyzed_files: List[Dict[str, str]], threat_score: int
    ) -> Dict[str, str]:
        confirmed = any(a["evidence_tier"] == "confirmed_interference" for a in alerts)
        corroborated = any(a["evidence_tier"] == "corroborated_evidence" for a in alerts)
        anomalies = any(a["evidence_tier"] == "specific_anomaly" for a in alerts)

        if confirmed or threat_score >= 80:
            return {"status": "INTERFERÊNCIA CORROBORADA", "color": "red", "summary": "Evidências técnicas independentes correlacionadas detectadas."}
        if corroborated or anomalies or threat_score >= 25:
            return {"status": "REVISÃO TÉCNICA NECESSÁRIA", "color": "yellow", "summary": "Anomalias específicas detectadas que exigem análise contextual."}
        if unanalyzed_files:
            return {"status": "COBERTURA INCOMPLETA (LIMPO NO ANALISADO)", "color": "yellow", "summary": "Nenhuma ameaça nos arquivos analisados, porém existem arquivos não suportados/não analisados."}
        return {"status": "LIMPO (SEM EVIDÊNCIAS DE INTERFERÊNCIA)", "color": "green", "summary": "Nenhuma evidência técnica de adulteração encontrada."}
