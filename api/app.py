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
import os

load_dotenv()

app = Flask(__name__)
# Permitir CORS para requisições do seu site
CORS(app)

ADMIN_USER = os.getenv("ADMIN_USER", "CACIQUE")
ADMIN_PASS = os.getenv("ADMIN_PASS", "g.indiopatrocina777")

TEMP_DIR = os.path.join(tempfile.gettempdir(), "cacique_scan_uploads")
os.makedirs(TEMP_DIR, exist_ok=True)

# Dicionários de termos maliciosos com pesos e risco
SUSPICIOUS_TERMS_ANDROID = {
    "top.johnwu.magisk": {"tipo": "Root/Magisk", "peso": 100, "risco": "Baixo (Ban direto)"},
    "com.topjohnwu.magisk": {"tipo": "Root/Magisk", "peso": 100, "risco": "Baixo (Ban direto)"},
    "io.github.huskydg.magisk": {"tipo": "Root/Magisk Delta", "peso": 100, "risco": "Baixo (Ban direto)"},
    "zygisk": {"tipo": "Injeção Zygisk", "peso": 80, "risco": "Baixo (Ban direto)"},
    "lsposed": {"tipo": "LSPosed Framework", "peso": 80, "risco": "Baixo (Ban direto)"},
    "catch_": {"tipo": "Possível Mod Menu", "peso": 60, "risco": "Médio (Verificar contexto)"},
    "gameguardian": {"tipo": "Memory Editor (GameGuardian)", "peso": 100, "risco": "Baixo (Ban direto)"},
    "com.mod.menu": {"tipo": "Mod Menu", "peso": 100, "risco": "Baixo (Ban direto)"},
    "ptrace": {"tipo": "Injeção de Memória (ptrace)", "peso": 50, "risco": "Alto (Aparece em logs normais)"},
    "auto_clicker": {"tipo": "Macro/AutoClicker", "peso": 60, "risco": "Médio"}
    "não pega adm":{"tipo":"Noban", "peso": 100, "risco": "Alto"},,
}

SUSPICIOUS_TERMS_IOS = {
    "cydia": {"tipo": "Jailbreak (Cydia)", "peso": 100, "risco": "Baixo (Ban direto)"},
    "sileo": {"tipo": "Jailbreak (Sileo)", "peso": 100, "risco": "Baixo (Ban direto)"},
    "zebra": {"tipo": "Jailbreak (Zebra)", "peso": 100, "risco": "Baixo (Ban direto)"},
    "trollstore": {"tipo": "Sideloading (TrollStore)", "peso": 100, "risco": "Baixo (Ban direto)"},
    "dylib_inject": {"tipo": "Injeção de dylib", "peso": 80, "risco": "Médio"},
    "substituted": {"tipo": "Tweak Injector", "peso": 90, "risco": "Baixo"},
    "ellekit": {"tipo": "Tweak Injector", "peso": 90, "risco": "Baixo"},
    "mobile substrate": {"tipo": "Tweak Injector", "peso": 90, "risco": "Baixo"},
    "não pega adm":{"tipo":"Noban", "peso": 100, "risco": "Alto"},
}

GENERAL_TERMS = {
    "proxy_host": {"tipo": "Rede/Proxy", "peso": 30, "risco": "Alto (Pode ser VPN normal)"},
    "127.0.0.1:8080": {"tipo": "Proxy Local Aberto", "peso": 40, "risco": "Médio"},
}

def analyze_content(content, filename, os_type):
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
                "arquivo": filename,
                "termo": termo,
                "categoria": info["tipo"],
                "risco_fp": info["risco"]
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

    # Tenta descobrir o OS pelo nome do arquivo
    os_type = "android" # Padrão
    if 'sysdiagnose' in filename.lower():
        os_type = "ios"

    relatorio = []
    pontuacao_total = 0

    try:
        if filename.endswith('.zip'):
            with zipfile.ZipFile(file_path) as z:
                target_files = [n for n in z.namelist() if n.endswith(('.txt', '.log', '.prop', '.plist'))]
                
                for nome_arquivo in target_files:
                    info = z.getinfo(nome_arquivo)
                    if info.file_size > 50 * 1024 * 1024:
                        continue
                        
                    conteudo = z.read(nome_arquivo).decode('utf-8', errors='ignore')
                    findings, score = analyze_content(conteudo, nome_arquivo, os_type)
                    if findings:
                        relatorio.extend(findings)
                        pontuacao_total += score
                        
        elif filename.endswith('.tar.gz') or filename.endswith('.gz'):
            with tarfile.open(name=file_path, mode="r:gz") as tar:
                for membro in tar:
                    if membro.isfile() and membro.name.endswith(('.txt', '.log', '.prop', '.plist')):
                        if membro.size > 50 * 1024 * 1024:
                            continue
                        
                        f = tar.extractfile(membro)
                        if f:
                            conteudo = f.read().decode('utf-8', errors='ignore')
                            findings, score = analyze_content(conteudo, membro.name, os_type)
                            if findings:
                                relatorio.extend(findings)
                                pontuacao_total += score

        # Limpa o arquivo temp
        os.remove(file_path)

        veredito = "Limpo"
        color = "green"
        if pontuacao_total >= 100:
            veredito = "DETECTADO (Cheater)"
            color = "red"
        elif pontuacao_total >= 30:
            veredito = "SUSPEITO (Revisão Manual)"
            color = "yellow"

        unique_reports = []
        seen = set()
        for r in relatorio:
            identifier = f"{r['arquivo']}-{r['termo']}"
            if identifier not in seen:
                seen.add(identifier)
                unique_reports.append(r)

        return jsonify({
            "status": "sucesso",
            "veredito": veredito,
            "color": color,
            "pontuacao_suspeita": pontuacao_total,
            "os_detectado": os_type.upper(),
            "detalhes": unique_reports
        })

    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({"erro": f"Erro ao processar o arquivo: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
