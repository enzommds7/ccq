from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import zipfile
import tarfile
import io
import re
import os

load_dotenv()

app = Flask(__name__)
# Permitir CORS para requisições do seu site
CORS(app)

ADMIN_USER = os.getenv("ADMIN_USER", "CACIQUE")
ADMIN_PASS = os.getenv("ADMIN_PASS", "g.indiopatrocina777")

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
    "auto_clicker": {"tipo": "Macro/AutoClicker", "peso": 60, "risco": "Médio"},
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

    for termo, info in terms_to_check.items():
        pattern = re.escape(termo)
        if re.search(pattern, content, re.IGNORECASE):
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

@app.route('/scan', methods=['POST'])
def scan_file():
    user = request.form.get('user')
    password = request.form.get('pass')
    file = request.files.get('file')

    if user != ADMIN_USER or password != ADMIN_PASS:
        return jsonify({"erro": "Acesso Negado. Credenciais inválidas."}), 401

    if not file or not (file.filename.endswith('.zip') or file.filename.endswith('.tar.gz') or file.filename.endswith('.gz')):
        return jsonify({"erro": "Envie um arquivo .zip ou .tar.gz válido."}), 400

    # Tenta descobrir o OS pelo nome do arquivo
    os_type = "android" # Padrão
    if 'sysdiagnose' in file.filename.lower():
        os_type = "ios"

    relatorio = []
    pontuacao_total = 0

    try:
        file_bytes = file.read()
        
        if file.filename.endswith('.zip'):
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
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
        elif file.filename.endswith('.tar.gz') or file.filename.endswith('.gz'):
            with tarfile.open(fileobj=io.BytesIO(file_bytes), mode="r:gz") as tar:
                target_files = [m for m in tar.getmembers() if m.isfile() and m.name.endswith(('.txt', '.log', '.prop', '.plist'))]
                
                for membro in target_files:
                    if membro.size > 50 * 1024 * 1024:
                        continue
                    
                    f = tar.extractfile(membro)
                    if f:
                        conteudo = f.read().decode('utf-8', errors='ignore')
                        findings, score = analyze_content(conteudo, membro.name, os_type)
                        if findings:
                            relatorio.extend(findings)
                            pontuacao_total += score

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
        return jsonify({"erro": f"Erro ao processar o arquivo: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
