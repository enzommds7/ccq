from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import zipfile
import tarfile
import io
import re
import os
import tempfile
import shutil

load_dotenv()

app = Flask(__name__)
# Permitir CORS para requisições do seu site
CORS(app)

ADMIN_USER = os.getenv("ADMIN_USER", "CACIQUE")
ADMIN_PASS = os.getenv("ADMIN_PASS", "g.indiopatrocina777")

TEMP_DIR = os.path.join(tempfile.gettempdir(), "cacique_scan_uploads")
os.makedirs(TEMP_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────
# Dicionários de termos maliciosos com pesos e risco
# ─────────────────────────────────────────────────────────────

SUSPICIOUS_TERMS_ANDROID = {
    # Root / Magisk
    "top.johnwu.magisk":          {"tipo": "Root/Magisk",               "peso": 100, "risco": "Baixo (Ban direto)"},
    "com.topjohnwu.magisk":       {"tipo": "Root/Magisk",               "peso": 100, "risco": "Baixo (Ban direto)"},
    "io.github.huskydg.magisk":   {"tipo": "Root/Magisk Delta",         "peso": 100, "risco": "Baixo (Ban direto)"},
    "zygisk":                     {"tipo": "Injeção Zygisk",            "peso": 80,  "risco": "Baixo (Ban direto)"},
    "superuser":                  {"tipo": "Root (Superuser app)",      "peso": 70,  "risco": "Médio (checar contexto)"},
    "su binary":                  {"tipo": "Root (SU Binary)",          "peso": 80,  "risco": "Baixo (Ban direto)"},
    "busybox":                    {"tipo": "Root (Busybox)",            "peso": 60,  "risco": "Médio"},
    "com.noshufou.android.su":    {"tipo": "Root App (Superuser)",      "peso": 100, "risco": "Baixo (Ban direto)"},
    "eu.chainfire.supersu":       {"tipo": "Root App (SuperSU)",        "peso": 100, "risco": "Baixo (Ban direto)"},
    "com.kingroot.kinguser":      {"tipo": "Root App (KingRoot)",       "peso": 100, "risco": "Baixo (Ban direto)"},
    "com.kingoapp.root":          {"tipo": "Root App (KingoRoot)",      "peso": 100, "risco": "Baixo (Ban direto)"},

    # Hooking / Injeção de memória
    "frida":                      {"tipo": "Hooking (Frida)",           "peso": 100, "risco": "Baixo (Ban direto)"},
    "frida-server":               {"tipo": "Hooking (Frida Server)",    "peso": 100, "risco": "Baixo (Ban direto)"},
    "frida-gadget":               {"tipo": "Hooking (Frida Gadget)",    "peso": 100, "risco": "Baixo (Ban direto)"},
    "lsposed":                    {"tipo": "LSPosed Framework",         "peso": 80,  "risco": "Baixo (Ban direto)"},
    "de.robv.android.xposed":     {"tipo": "Xposed Framework",         "peso": 100, "risco": "Baixo (Ban direto)"},
    "xposed":                     {"tipo": "Xposed Framework",         "peso": 80,  "risco": "Médio (checar contexto)"},
    "ptrace":                     {"tipo": "Injeção de Memória (ptrace)","peso": 50,  "risco": "Alto (Aparece em logs normais)"},
    "gdbserver":                  {"tipo": "Debugger (gdbserver)",      "peso": 70,  "risco": "Médio"},

    # Mod Menus / Cheats diretos
    "gameguardian":               {"tipo": "Memory Editor (GameGuardian)","peso": 100, "risco": "Baixo (Ban direto)"},
    "com.mod.menu":               {"tipo": "Mod Menu",                  "peso": 100, "risco": "Baixo (Ban direto)"},
    "catch_":                     {"tipo": "Possível Mod Menu",         "peso": 60,  "risco": "Médio (Verificar contexto)"},
    "auto_clicker":               {"tipo": "Macro/AutoClicker",         "peso": 60,  "risco": "Médio"},
    "lucky patcher":              {"tipo": "App Patcher (Lucky Patcher)","peso": 100, "risco": "Baixo (Ban direto)"},
    "com.chelpus.lackypatch":     {"tipo": "App Patcher (Lucky Patcher)","peso": 100, "risco": "Baixo (Ban direto)"},
    "com.android.vendinghack":    {"tipo": "Play Store Hack",           "peso": 90,  "risco": "Baixo (Ban direto)"},

    # Dump de jogos / Engenharia reversa
    "il2cppdumper":               {"tipo": "Unity Dumper (IL2CppDumper)","peso": 100, "risco": "Baixo (Ban direto)"},
    "il2cpp_dumper":              {"tipo": "Unity Dumper",              "peso": 100, "risco": "Baixo (Ban direto)"},
    "apkeditor":                  {"tipo": "APK Editor em runtime",     "peso": 80,  "risco": "Médio"},
    "mt manager":                 {"tipo": "APK Editor (MT Manager)",   "peso": 80,  "risco": "Médio"},
    "com.zane.mtweaker":          {"tipo": "APK Editor (MT Manager)",   "peso": 90,  "risco": "Baixo"},

    # Virtual Env / Emulação
    "com.lbe.parallel":           {"tipo": "Paralel Space (conta falsa)","peso": 70,  "risco": "Médio"},
    "com.bstk.android":           {"tipo": "BlueStacks Emulator",       "peso": 60,  "risco": "Médio"},
    "com.vphone.launcher":        {"tipo": "VMOS Virtual Android",      "peso": 80,  "risco": "Baixo"},
    "vmos":                       {"tipo": "VMOS Virtual Android",      "peso": 80,  "risco": "Baixo"},
}

SUSPICIOUS_TERMS_IOS = {
    # Jailbreak Tools
    "cydia":                      {"tipo": "Jailbreak (Cydia)",         "peso": 100, "risco": "Baixo (Ban direto)"},
    "sileo":                      {"tipo": "Jailbreak (Sileo)",         "peso": 100, "risco": "Baixo (Ban direto)"},
    "zebra":                      {"tipo": "Jailbreak (Zebra)",         "peso": 100, "risco": "Baixo (Ban direto)"},
    "unc0ver":                    {"tipo": "Jailbreak (unc0ver)",       "peso": 100, "risco": "Baixo (Ban direto)"},
    "checkra1n":                  {"tipo": "Jailbreak (checkra1n)",     "peso": 100, "risco": "Baixo (Ban direto)"},
    "palera1n":                   {"tipo": "Jailbreak (palera1n)",      "peso": 100, "risco": "Baixo (Ban direto)"},
    "dopamine":                   {"tipo": "Jailbreak (Dopamine)",      "peso": 100, "risco": "Baixo (Ban direto)"},
    "odyssey":                    {"tipo": "Jailbreak (Odyssey)",       "peso": 100, "risco": "Baixo (Ban direto)"},
    "taurine":                    {"tipo": "Jailbreak (Taurine)",       "peso": 100, "risco": "Baixo (Ban direto)"},

    # Paths típicos de jailbreak
    "/var/jb":                    {"tipo": "Path de Jailbreak Rootless","peso": 90,  "risco": "Baixo (Ban direto)"},
    "/private/var/jb":            {"tipo": "Path de Jailbreak Rootless","peso": 90,  "risco": "Baixo (Ban direto)"},
    "/var/mobile/library/cydiasubstrate": {"tipo": "Substrate Path",   "peso": 100, "risco": "Baixo (Ban direto)"},
    "apt.bingner.com":            {"tipo": "Repo Jailbreak (Elucubratus)","peso": 80,"risco": "Baixo"},
    "repo.chariz.com":            {"tipo": "Repo Tweak (Chariz)",       "peso": 70,  "risco": "Médio"},

    # Tweak Injectors
    "trollstore":                 {"tipo": "Sideloading (TrollStore)",  "peso": 100, "risco": "Baixo (Ban direto)"},
    "substituted":                {"tipo": "Tweak Injector (Substitute)","peso": 90, "risco": "Baixo"},
    "ellekit":                    {"tipo": "Tweak Injector (ElleKit)",  "peso": 90,  "risco": "Baixo"},
    "mobile substrate":           {"tipo": "Tweak Injector (MobileSubstrate)","peso": 90, "risco": "Baixo"},
    "mobilesubstrate":            {"tipo": "Tweak Injector (MobileSubstrate)","peso": 90, "risco": "Baixo"},
    "dylib_inject":               {"tipo": "Injeção de dylib",          "peso": 80,  "risco": "Médio"},

    # Hooking / RE
    "frida":                      {"tipo": "Hooking (Frida)",           "peso": 100, "risco": "Baixo (Ban direto)"},
    "flexdecrypt":                {"tipo": "IPA Decryptor",             "peso": 90,  "risco": "Baixo"},
    "bfdecrypt":                  {"tipo": "IPA Decryptor (bfdecrypt)", "peso": 90,  "risco": "Baixo"},
}

GENERAL_TERMS = {
    "proxy_host":         {"tipo": "Rede/Proxy",           "peso": 30, "risco": "Alto (Pode ser VPN normal)"},
    "127.0.0.1:8080":     {"tipo": "Proxy Local Aberto",   "peso": 40, "risco": "Médio"},
}

# Extensões de texto para scan completo (leitura e decode)
TEXT_EXTENSIONS = (
    '.txt', '.log', '.prop', '.plist', '.xml', '.json',
    '.csv', '.conf', '.cfg', '.properties', '.yaml', '.yml',
    '.html', '.htm', '.js', '.sh', '.py',
)

# Extensões de binário — scan apenas de strings legíveis (ASCII printable)
BINARY_EXTENSIONS = ('.so', '.dex', '.dylib', '.bin', '.elf')

# Arquivos sem extensão comuns em bugreports Android que devem ser lidos
NO_EXTENSION_ALLOWLIST = (
    'packages', 'services', 'dumpsys', 'logcat',
    'procrank', 'processes', 'bugreport', 'meminfo',
    'cpuinfo', 'batterystats', 'usage_stats',
)

MAX_TEXT_FILE_SIZE = 50 * 1024 * 1024   # 50 MB
MAX_BIN_FILE_SIZE  = 10 * 1024 * 1024   # 10 MB para binários


def extract_strings_from_binary(data: bytes, min_len: int = 6) -> str:
    """Extrai strings legíveis de dados binários (similar ao comando `strings`)."""
    pattern = rb'[ -~]{' + str(min_len).encode() + rb',}'
    matches = re.findall(pattern, data)
    return b'\n'.join(matches).decode('ascii', errors='ignore')


def detect_os_from_archive(namelist: list) -> str:
    """Tenta detectar o OS com base nos arquivos presentes no arquivo comprimido."""
    joined = '\n'.join(namelist).lower()
    ios_indicators   = ['sysdiagnose', '.plist', '/var/mobile', 'crashreporter', 'ips']
    android_indicators = ['bugreport', 'logcat', 'dumpsys', 'procrank', 'packages.xml', 'system/build.prop']

    ios_score     = sum(1 for i in ios_indicators if i in joined)
    android_score = sum(1 for a in android_indicators if a in joined)

    if ios_score > android_score:
        return 'ios'
    return 'android'


def should_scan_file(name: str) -> tuple[bool, str]:
    """
    Retorna (deve_escanear, modo) onde modo é 'text' ou 'binary'.
    """
    lower = name.lower()
    basename = os.path.basename(lower)
    _, ext = os.path.splitext(lower)

    if ext in TEXT_EXTENSIONS:
        return True, 'text'
    if ext in BINARY_EXTENSIONS:
        return True, 'binary'
    # Sem extensão — checar allowlist
    if not ext and basename in NO_EXTENSION_ALLOWLIST:
        return True, 'text'

    return False, ''


def analyze_content(content: str, filename: str, os_type: str) -> tuple[list, int]:
    findings = []
    score = 0

    terms_to_check = {**GENERAL_TERMS}
    if os_type == "android":
        terms_to_check.update(SUSPICIOUS_TERMS_ANDROID)
    elif os_type == "ios":
        terms_to_check.update(SUSPICIOUS_TERMS_IOS)

    content_lower = content.lower()
    for termo, info in terms_to_check.items():
        if termo.lower() in content_lower:
            score += info["peso"]
            findings.append({
                "arquivo":   filename,
                "termo":     termo,
                "categoria": info["tipo"],
                "risco_fp":  info["risco"]
            })
    return findings, score


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = data.get('user')
    password = data.get('pass')

    if user == ADMIN_USER and password == ADMIN_PASS:
        return jsonify({"status": "success", "message": "Login aprovado."}), 200
    else:
        return jsonify({"status": "error", "message": "Credenciais inválidas."}), 401


@app.route('/upload_chunk', methods=['POST'])
def upload_chunk():
    user = request.form.get('user')
    password = request.form.get('pass')
    if user != ADMIN_USER or password != ADMIN_PASS:
        return jsonify({"erro": "Acesso Negado."}), 401

    file_id = request.form.get('fileId')
    chunk = request.files.get('chunk')

    if not file_id or not chunk:
        return jsonify({"erro": "Parâmetros inválidos."}), 400

    chunk_path = os.path.join(TEMP_DIR, f"{file_id}.tmp")

    with open(chunk_path, "ab") as f:
        f.write(chunk.read())

    return jsonify({"status": "ok"}), 200


@app.route('/scan', methods=['POST'])
def scan_file():
    user = request.form.get('user')
    password = request.form.get('pass')
    file_id = request.form.get('fileId')
    filename = request.form.get('fileName')

    if user != ADMIN_USER or password != ADMIN_PASS:
        return jsonify({"erro": "Acesso Negado. Credenciais inválidas."}), 401

    if not filename or not (filename.endswith('.zip') or filename.endswith('.tar.gz') or filename.endswith('.gz')):
        return jsonify({"erro": "Envie um arquivo .zip ou .tar.gz válido."}), 400

    file_path = os.path.join(TEMP_DIR, f"{file_id}.tmp")
    if not os.path.exists(file_path):
        return jsonify({"erro": "Arquivo não encontrado no servidor."}), 400

    relatorio = []
    pontuacao_total = 0
    scan_logs = []          # logs reais que serão enviados ao frontend
    files_scanned = 0
    files_skipped = 0
    files_error = 0

    try:
        if filename.endswith('.zip'):
            with zipfile.ZipFile(file_path) as z:
                namelist = z.namelist()

                # Detectar OS pelo conteúdo do arquivo
                os_type = detect_os_from_archive(namelist)
                if 'sysdiagnose' in filename.lower():
                    os_type = 'ios'

                scan_logs.append(f"OS detectado: {os_type.upper()} ({len(namelist)} entradas no arquivo)")
                scan_logs.append(f"Assinaturas carregadas: {len(SUSPICIOUS_TERMS_ANDROID if os_type == 'android' else SUSPICIOUS_TERMS_IOS) + len(GENERAL_TERMS)} termos")

                for nome_arquivo in namelist:
                    deve_escanear, modo = should_scan_file(nome_arquivo)
                    if not deve_escanear:
                        files_skipped += 1
                        continue

                    try:
                        info = z.getinfo(nome_arquivo)
                        max_size = MAX_BIN_FILE_SIZE if modo == 'binary' else MAX_TEXT_FILE_SIZE

                        if info.file_size > max_size:
                            scan_logs.append(f"[SKIP] {nome_arquivo} — muito grande ({info.file_size // 1024 // 1024} MB)")
                            files_skipped += 1
                            continue

                        raw = z.read(nome_arquivo)

                        if modo == 'binary':
                            conteudo = extract_strings_from_binary(raw)
                            scan_logs.append(f"[BIN]  {nome_arquivo}")
                        else:
                            conteudo = raw.decode('utf-8', errors='ignore')
                            scan_logs.append(f"[TEXT] {nome_arquivo}")

                        findings, score = analyze_content(conteudo, nome_arquivo, os_type)
                        if findings:
                            relatorio.extend(findings)
                            pontuacao_total += score
                            for f_item in findings:
                                scan_logs.append(f"  ⚠ DETECTADO: [{f_item['categoria']}] → '{f_item['termo']}'")

                        files_scanned += 1

                    except Exception as ex:
                        scan_logs.append(f"[ERRO] {nome_arquivo}: {str(ex)[:80]}")
                        files_error += 1

        elif filename.endswith('.tar.gz') or filename.endswith('.gz'):
            with tarfile.open(name=file_path, mode="r:gz") as tar:
                members = tar.getmembers()
                namelist = [m.name for m in members]

                os_type = detect_os_from_archive(namelist)
                if 'sysdiagnose' in filename.lower():
                    os_type = 'ios'

                scan_logs.append(f"OS detectado: {os_type.upper()} ({len(namelist)} entradas no arquivo)")
                scan_logs.append(f"Assinaturas carregadas: {len(SUSPICIOUS_TERMS_ANDROID if os_type == 'android' else SUSPICIOUS_TERMS_IOS) + len(GENERAL_TERMS)} termos")

                for membro in members:
                    if not membro.isfile():
                        continue

                    deve_escanear, modo = should_scan_file(membro.name)
                    if not deve_escanear:
                        files_skipped += 1
                        continue

                    try:
                        max_size = MAX_BIN_FILE_SIZE if modo == 'binary' else MAX_TEXT_FILE_SIZE
                        if membro.size > max_size:
                            scan_logs.append(f"[SKIP] {membro.name} — muito grande ({membro.size // 1024 // 1024} MB)")
                            files_skipped += 1
                            continue

                        f = tar.extractfile(membro)
                        if not f:
                            continue

                        raw = f.read()

                        if modo == 'binary':
                            conteudo = extract_strings_from_binary(raw)
                            scan_logs.append(f"[BIN]  {membro.name}")
                        else:
                            conteudo = raw.decode('utf-8', errors='ignore')
                            scan_logs.append(f"[TEXT] {membro.name}")

                        findings, score = analyze_content(conteudo, membro.name, os_type)
                        if findings:
                            relatorio.extend(findings)
                            pontuacao_total += score
                            for f_item in findings:
                                scan_logs.append(f"  ⚠ DETECTADO: [{f_item['categoria']}] → '{f_item['termo']}'")

                        files_scanned += 1

                    except Exception as ex:
                        scan_logs.append(f"[ERRO] {membro.name}: {str(ex)[:80]}")
                        files_error += 1

        # Limpa o arquivo temp
        os.remove(file_path)

        scan_logs.append(f"─── Scan finalizado: {files_scanned} analisados | {files_skipped} ignorados | {files_error} erros ───")

        veredito = "Limpo"
        color = "green"
        if pontuacao_total >= 100:
            veredito = "DETECTADO (Cheater)"
            color = "red"
        elif pontuacao_total >= 30:
            veredito = "SUSPEITO (Revisão Manual)"
            color = "yellow"

        # Deduplica findings
        unique_reports = []
        seen = set()
        for r in relatorio:
            identifier = f"{r['arquivo']}-{r['termo']}"
            if identifier not in seen:
                seen.add(identifier)
                unique_reports.append(r)

        return jsonify({
            "status":            "sucesso",
            "veredito":          veredito,
            "color":             color,
            "pontuacao_suspeita": pontuacao_total,
            "os_detectado":      os_type.upper(),
            "detalhes":          unique_reports,
            "scan_logs":         scan_logs,
            "stats": {
                "arquivos_analisados": files_scanned,
                "arquivos_ignorados":  files_skipped,
                "erros":               files_error,
            }
        })

    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({"erro": f"Erro ao processar o arquivo: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
