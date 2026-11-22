# CACIQUE SCAN v5.0 — Documentação Forense e Arquitetura Modular

Esta documentação descreve a arquitetura **CACIQUE SCAN v5.0** — modularizada em ES Modules nativos com processamento fora da UI via **Web Worker** em modo **streaming**, utilizando o catálogo limpo (`js/scan/catalog-rules.json`).

---

## 1. Princípios Forenses Obrigatórios

1. **Fonte ≠ evento ≠ evidência ≠ violação:** uma string isolada não prova execução; uma ferramenta instalada não comprova interferência na partida.
2. **Proibido varrer binários como texto:** arquivos `.tracev3` e catálogos auxiliares (`UUIDText`, `DSC`, `timesync`) de `system_logs.logarchive` nunca geram alertas por substring.
3. **Ausência de dados ≠ prova:** arquivo ausente, chave `getprop` faltando, permissão negada ou parser ausente geram lacuna de cobertura (`INCONCLUSIVO`), nunca `"100% limpo"` nem `"Ban Direto"`.
4. **Deduplicação obrigatória:** mil repetições do mesmo evento contam como **1 evento único** (`occurrence_count: 1000`), mantendo inalterado o peso heurístico.
5. **Separação de domínios:** `seguranca_do_dispositivo`, `depuracao`, `rede`, `estabilidade`, `integridade_do_jogo`, `cobertura_log` e `sistema_backup`.
6. **Cobertura independente de risco:** a cobertura (`completa` / `parcial` / `insuficiente`, arquivos lidos, `.tracev3` não suportados, `UUIDText`/`DSC` ignorados, lacunas e rejeições) é reportada separadamente do índice heurístico.

### Estados de Resultado

| Estado | Código | Significado |
| :--- | :--- | :--- |
| **INFORMATIVO** | `informational` | Metadado, evento normal de sistema ou estabilidade (peso `0`). |
| **REFERÊNCIA NÃO VALIDADA** | `unvalidated_reference` | Termo/caminho candidato sem evento estruturado de execução/carregamento. |
| **ANOMALIA PARA REVISÃO** | `anomaly_review` | Evento específico verificável com hipóteses alternativas (exige revisão humana). |
| **EVIDÊNCIA CORROBORADA** | `corroborated_evidence` | 2+ fontes técnicas independentes sustentam a mesma hipótese técnica (nunca ban automático). |
| **INCONCLUSIVO** | `inconclusive` | Parser ausente (ex.: `.tracev3`), `bugreport` parcial ou cobertura insuficiente. |

---

## 2. Arquitetura Modular e Anti-Travamento

```text
js/
├── core/
│   ├── sound.js              # Áudio Web API e feedback háptico
│   ├── ui-utils.js           # escapeHtml, showToast, performCopy, SHA-256, HeroCanvas, navegação
│   └── auth.js               # Autenticação ADM (/login + SHA-256 client-side)
├── arena/
│   ├── ranks.js              # Patentes e pesos editáveis
│   ├── roster.js             # Gestão e parse de elenco
│   ├── wheel-engine.js       # Canvas 2D + CSPRNG das roletas
│   ├── arena-controller.js   # Orquestração das 3 mesas, Telão, Card PNG e Auditoria
│   └── quick-sort.js         # Modo Rápido clássico
├── scan/
│   ├── scan-ui.js            # UI thread leve (lazy-loaded ao autenticar/abrir scanner)
│   ├── scan.worker.js        # Web Worker ES Module: streaming + orquestração fora da UI
│   ├── archive-reader.js     # Leitura streaming segura ZIP/TAR/GZ com limites e anti-path-traversal
│   ├── catalog-rules.json    # Catálogo v5.0-clean compilado no boot do Worker
│   ├── parsers/
│   │   ├── android-parser.js # getprop, PackageManager, Settings, auditd, GameAssets, crashes, ADB
│   │   ├── ios-parser.js     # .ips JSON, .plist XML + bplist00 binário, Sandbox deny, Backup/Restore
│   │   └── hexdump-parser.js # Reconstrução fiel da coluna ASCII em hex dumps
│   └── engine/
│       ├── matcher.js        # Regexes e Sets pré-compilados no boot do Worker
│       ├── deduplicator.js   # Agrupamento por chave estável (occurrence_count)
│       └── correlator.js     # Correlação de 2+ fontes independentes + cobertura/veredito
└── main.js                   # Inicialização leve da página
```

### Garantias de Desempenho & Segurança
- **Web Worker dedicado:** toda leitura de ZIP/TAR/GZ e varredura de linhas roda em `js/scan/scan.worker.js`.
- **Streaming por arquivo e chunks de 1 MB (`indexOf('\n')`):** nunca acumula `collectedFiles` em RAM e nunca usa `text.split(/\r?\n/)` em arquivos grandes.
- **Lazy Loading:** `js/scan/*`, `catalog-rules.json`, `JSZip` e o Worker só são carregados quando necessários.
- **Segurança (`archive-reader.js`):** bloqueia path traversal (`../`), caminhos absolutos, bytes nulos e symlinks/hardlinks; impõe limite de 500 entradas relevantes, 120 MB por entrada e 512 MB totais descomprimidos; ignora mídia, `.pb`/`.proto`, `.perfetto-trace` e `.apk` antes da descompactação; inclui `tombstone_*`, `anr_*`, `mountinfo` e `lsaw.csstoredump`.

---

## 3. Escopo de Parsers e Falsos Positivos Eliminados

- **Catálogo `PROXY_SHORT_TOKENS` (76 tokens hex curtos):** mantido explicitamente inativo (`match_policy: "disabled"`, `default_status: "inactive_research_only"`).
- **Android Free Fire (`com.dts.freefireth` e `com.dts.freefiremax`):** suporte completo a `PackageManager`, canonicalização `/data/data/` ↔ `/data/user/0/`, `SH-Gpp2` (`granted { execute }` vs `denied`), `-SHgap-` e cache JAR (`ClassLoader` vs presença estática).
- **Settings Android (`pkg:by4a.setedit22` e `pkg:com.android.shell`):** valores padrão benignos (`long_press_timeout=400`, `peak_refresh_rate=120`) são classificados como `informational` (peso `0`).
- **ADB e Rede:** `127.0.0.1:5555` / `localhost:5555` (loopback típico de Brevent/Shizuku) é separado de IP remoto real; `USB connected`, `MTP`, `PTP`, `DHCP`, `InputDispatcher`, `chatty`, `dropped logs`, `log_overrun` nunca pontuam risco.
- **iOS (`sysdiagnose`):** `.tracev3` vai para `unsupported_files`; `UUIDText`/`DSC` vão para `ignored_auxiliary`; `bplist00` usa decodificador binário nativo sem corrupção UTF-8; `.ips` valida `itemID` (`1300146617` / `1480516829`), `usedImages` e mantém `teamID: 98573T3W6L` como `pending_official_baseline`; `Sandbox: ... deny` e `itunesstored` / `SetupAssistant` / Screen Time / `HoldingTankManifest.plist` nunca geram risco.

---

## 4. Limitações Conhecidas

1. Sem conversor externo Apple (`log show` no macOS), arquivos binários `.tracev3` não podem ser decodificados dentro do navegador — o motor declara explicitamente `INCONCLUSIVO` por cobertura parcial quando faltam fontes decodificadas.
2. Logs estáticos registram ocorrências históricas ou momentâneas sem garantia de vínculo temporal contínuo com a partida; toda decisão disciplinar cabe à revisão humana.
