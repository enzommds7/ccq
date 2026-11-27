# ccq scan v5.1 — Documentação Forense e Arquitetura Modular

Esta documentação descreve o motor forense **ccq scan v5.1** — modularizado em ES Modules nativos com processamento fora da UI via **Web Worker** em modo **streaming**, utilizando o catálogo tipado (`js/scan/catalog-rules.json`, versão `5.1-clean`).

---

## 1. Princípios Forenses Obrigatórios

1. **Fonte ≠ evento ≠ evidência ≠ violação:** presença não comprova execução; execução não comprova interferência no jogo; ausência de registros não comprova integridade.
2. **Proibido varrer binários como texto:** arquivos `.tracev3` e catálogos auxiliares (`UUIDText`, `DSC`, `timesync`) de `system_logs.logarchive` nunca geram alertas por substring.
3. **Ausência de dados ≠ prova:** arquivo ausente, chave `getprop` faltando, arquivo corrompido ou parser ausente geram lacuna de cobertura (`INCONCLUSIVO`), nunca `"100% limpo"` nem punição automática.
4. **Deduplicação obrigatória:** repetições do mesmo evento contam como **1 evento único** (`occurrence_count`), sem multiplicar risco ou peso heurístico.
5. **Separação de domínios:** `seguranca_do_dispositivo`, `depuracao`, `rede`, `estabilidade`, `integridade_do_jogo`, `cobertura_log` e `sistema_backup`.
6. **Cobertura independente de risco:** a cobertura (`completa` / `parcial` / `insuficiente`, arquivos lidos, `.tracev3` não suportados, `UUIDText`/`DSC` ignorados, lacunas e rejeições) é reportada separadamente do índice heurístico.
7. **Corroboração real e índice anti-inflação:** `corroborated_evidence` exige `>= 2` famílias técnicas independentes e elegíveis; sinais compatíveis com ferramentas legítimas (como porta ADB TCP configurada para Brevent/Shizuku, alterações via `com.android.shell` ou IPs candidatos sem reputação permanente) não corroboram outros eventos sozinhos.

### Estados Canônicos de Resultado

| Estado | Código | Peso Heurístico | Significado |
| :--- | :--- | :--- | :--- |
| **INFORMATIVO** | `informational` | `0` | Metadado, perfil nativo, overlay legítimo ou evento normal de estabilidade/sistema. |
| **REFERÊNCIA NÃO VALIDADA** | `unvalidated_reference` | `0` | Termo, configuração desconhecida ou caminho isolado sem evento estruturado de execução. |
| **ANOMALIA PARA REVISÃO** | `anomaly_review` | Calibrado (`8`–`35`) | Evento específico verificável com hipóteses alternativas (exige revisão humana). |
| **EVIDÊNCIA CORROBORADA** | `corroborated_evidence` | Calibrado + bônus limitado | `>= 2` fontes técnicas efetivamente independentes sustentam a mesma hipótese técnica (nunca ban automático). |
| **INCONCLUSIVO** | `inconclusive` | `0` | Parser ausente (ex.: `.tracev3`), `bugreport` parcial, container corrompido ou cobertura insuficiente. |

---

## 2. Arquitetura Modular

```text
js/
├── core/
│   ├── sound.js              # Áudio Web API e feedback háptico (guardas idempotentes)
│   ├── ui-utils.js           # escapeHtml, showToast, performCopy, SHA-256, navegação
│   └── auth.js               # Autenticação ADM (/login + fallback SHA-256)
├── scan/
│   ├── scan-ui.js            # UI thread leve (lazy-loaded ao autenticar, reset de sessão/Worker)
│   ├── scan.worker.js        # Web Worker ES Module: streaming + cancelamento cooperativo
│   ├── archive-reader.js     # Leitura segura ZIP/TAR/GZ, limites, liberação de buffers e chunks 1 MB
│   ├── catalog-rules.json    # Catálogo 5.1-clean tipado com procedência e status de validação
│   ├── parsers/
│   │   ├── android-parser.js # Settings (=/:), 7 estados ADB, auditd SH-Gpp2, Overlays, PackageManager, getprop
│   │   ├── ios-parser.js     # .ips JSON (1 ou 2 docs), XML/bplist00, Screen Time ancorado, Sandbox deny
│   │   └── hexdump-parser.js # Reconstrução fiel da coluna ASCII em hex dumps
│   └── engine/
│       ├── matcher.js        # Regexes com fronteiras e Maps pré-compilados no boot do Worker
│       ├── deduplicator.js   # Agrupamento por chave estável (occurrence_count)
│       └── correlator.js     # Correlação independente + índice heurístico anti-inflação
└── main.js                   # Boot leve e coordenação segura login/logout <-> scan-ui
```

---

## 3. Evoluções Forenses da Versão 5.1

### 3.1. Android (`js/scan/parsers/android-parser.js`)

1. **`dumpsys settings` (`=` e `:`):**
   - `SETTINGS_NAME_RE = /\bname\s*[:=]\s*([^\s,}\]]+)/i` e `SETTINGS_VALUE_RE = /\bvalue\s*[:=]\s*([^\s,}\]]+)/i`.
   - Diferencia explicitamente configurações **padrão** (`informational`, peso `0`), **alteradas fora do baseline** (`ANDROID_SETTINGS_SETEDIT_ANOMALY_001` peso `15` ou `ANDROID_SETTINGS_SHELL_ANOMALY_001` peso `10`, nível `anomaly_review`) e **desconhecidas** (`ANDROID_SETTINGS_UNKNOWN_001`, nível `unvalidated_reference`, peso `0`).
   - Linhas malformadas ou com `name`/`value` ausentes são descartadas sem emitir anomalias.

2. **ADB TCP e Depuração (7 estados distintos):**
   - `ANDROID_ADB_TCP_PORT_CONFIGURED_001` (`anomaly_review`, peso `8`, não elegível para corroboração isolada): `[service.adb.tcp.port]: [5555]` — **nunca confundido com conexão remota estabelecida**.
   - `ANDROID_ADB_SERVICE_ACTIVE_001` (`informational`, peso `0`): `[init.svc.adbd]: [running]`.
   - `ANDROID_ADB_LOOPBACK_001` (`informational`, peso `0`): `127.0.0.1:5555` / `localhost:5555` (compatível com Brevent/Shizuku).
   - `ANDROID_ADB_REMOTE_001` (`anomaly_review`, peso `25`): conexão/sessão remota efetivamente registrada com IP externo.
   - `ANDROID_ADB_USB_DEBUG_001` (`informational`, peso `0`): depuração USB (`adb_enabled`, `persist.sys.usb.config=...adb`).
   - `ANDROID_ADB_WIRELESS_DEBUG_001` (`informational`, peso `0`): depuração sem fio (`adb_wifi_enabled`, `adb_tls_pairing`).
   - `ANDROID_ADB_FORWARD_001` (`anomaly_review`, peso `12`): encaminhamento de portas (`adb forward` / `adb reverse`).

3. **`SH-Gpp2` em `auditd`:**
   - Quando `app=` está ausente, extrai o pacote proprietário do arquivo diretamente de `canonical_path` (`FF_DATA_PATH_RE`), diferenciando **pacote proprietário do arquivo** (`file_owner_package`) de **processo/app atuante** (`process`, `acting_app`).
   - Classificação:
     - `granted` + `execute` + contexto compatível → `ANDROID_GAME_SH_GPP2_EXEC_001` (`anomaly_review`, peso `35`).
     - `granted` + `execute` + processo/app incompatível com o proprietário → `ANDROID_GAME_SH_GPP2_CTX_MISMATCH_001` (`anomaly_review`, peso `30`).
     - `denied` → `ANDROID_GAME_SH_GPP2_DENIED_001` (`informational`, peso `0`).
     - Caminho isolado ou registro sem `execute`/`comm` suficiente → `ANDROID_GAME_SH_GPP2_UNVALIDATED_001` (`unvalidated_reference`, peso `0`).

4. **Overlays Android (`WindowManager` / `dumpsys window` / `SurfaceFlinger`):**
   - Analisa blocos contendo `type=2038`, `TYPE_APPLICATION_OVERLAY` ou pacotes em `ANDROID_OVERLAY_CANDIDATES` (ex.: `com.zayon.optimize`).
   - Extrai: pacote proprietário, nome da janela, tipo, processo, estado de visibilidade, timestamp, contexto de execução e aplicativo em primeiro plano (`mCurrentFocus` / `mFocusedApp`).
   - Ignora silenciosamente componentes de sistema/OEM (`android`, `com.android.*`, `com.google.*`, `com.miui.*`, `com.transsion.*`, `ShellDropTarget`, `Shell Root Leash`).
   - Overlays de aplicativos comuns legítimos (ex.: `com.whatsapp`) geram `ANDROID_OVERLAY_LEGIT_001` (`informational`, peso `0`).
   - Pacotes candidatos (ex.: `com.zayon.optimize`) ou terceiros não classificados geram `ANDROID_OVERLAY_ACTIVE_001` (`anomaly_review`, peso `15` ou `12`), correlacionáveis com `PackageManager` e demais fontes independentes.

### 3.2. iOS (`js/scan/parsers/ios-parser.js`)

- **`SCREENTIME_NATIVE_RE` ancorado:** expandido para `system.dateandtime.force_date_time_configuration_<var>-restrictions`, `system.web.contentfilter.<var>digital_health_restrictions`, `com.apple.webcontentfilter.basic-restrictions` e variantes Apple de `familycontrols`/`applicationaccess`/`screentime`, exigindo contexto de chave de identificador de perfil (`PayloadIdentifier`, `ProfileIdentifier`, etc.). Perfis disfarçados (ex.: `freefireproxy.xyz.digital_health_restrictions`) não são aceitos como nativos e seguem para inspeção de proxy/IP.
- **`.ips` JSON:** corrigido parsing de arquivos `.ips` formatados como objeto JSON único multi-linha (pretty-printed), preservando suporte ao formato nativo Apple de 2 documentos JSON (header na linha 1 + body).
- **Novos indicadores v5.1 em plist e logs decodificados:** consome `NETWORK_IP_CANDIDATES`, `PROFILE_REFERENCE_CANDIDATES`, `TEXTUAL_ALIAS_CANDIDATES` e `TOOL_INDICATORS_CANDIDATES` sempre respeitando bloqueio de `.tracev3`, `UUIDText`/`DSC` e `Sandbox: deny`.

### 3.3. Catálogo Tipado (`js/scan/catalog-rules.json` — `5.1-clean`)

| Grupo | Natureza Técnica | Exemplos v5.1 | Política de Correspondência | Estado de Validação |
| :--- | :--- | :--- | :--- | :--- |
| `ANDROID_PACKAGE_CANDIDATES` | Pacote Android | `com.netflix.mediaclientxx`, `com.spotify.musicx` (`Proxyhandler` removido) | `exact_package_id` (PackageManager) | `candidate_requires_corroboration` |
| `ANDROID_OVERLAY_CANDIDATES` | Pacote de overlay | `com.zayon.optimize` | `exact_package_id` (WindowManager/SurfaceFlinger/PM) | `candidate_requires_corroboration` |
| `NETWORK_IP_CANDIDATES` | IPv4 transitório | `85.31.231.237` | `exact_ip_in_network_context` | `unverified_transient_ip` (sem reputação permanente) |
| `PROFILE_REFERENCE_CANDIDATES` | Referência de perfil | `Imazing.profile`, `139.Spotifyx`, `238.timx` | `exact_profile_or_reference` | `candidate_requires_corroboration` |
| `TOOL_INDICATORS_CANDIDATES` | Ferramenta operacional | `TNTADB` | `exact_tool_in_process_or_adb_context` | `candidate_requires_corroboration` |
| `TEXTUAL_ALIAS_CANDIDATES` | Alias textual hifenizado | `com-xtremo-mobile`, `dash-proxy`, `com-luxebypass`, `freefireproxy-xyz` | `exact_alias_in_network_or_profile_context` | `candidate_requires_corroboration` |
| `PROXY_SHORT_TOKENS` | Tokens hex/curtos (76) | `06`, `a4`, `b9`, ... | `disabled` | `inactive_research_only` |

### 3.4. Calibração Anti-Inflação (`js/scan/engine/correlator.js`)

Na v5.0, promover eventos para `corroborated_evidence` elevava o peso de **cada evento individual** para `50` e somava todos linearmente, fazendo 2 eventos atingirem `100/100` facilmente. Na v5.1:

- **Agrupamento por família técnica:** cada família contribui com `min(max(35, maxWeight), maxWeight + min(10, (n - 1) * 5))`. Assim, múltiplos eventos da mesma fonte (ex.: 5 pacotes no `PackageManager`) nunca ultrapassam o teto de `35` sozinhos.
- **Preservação do peso individual:** a corroboração mantém o peso calibrado de cada evento e soma um **bônus único de corroboração** (`min(25, (familiasElegiveis - 1) * 15)`), com índice final limitado a `100`.
- **Proteção contra falsos positivos Brevent/Shizuku:** sinais `android_adb_tcp_port`, `android_shell_settings_anomaly`, `android_adb_forward` e `network_ip_candidate` têm `corroborationEligible: false`, impedindo corroboração indevida apenas por porta ADB + settings ou por IP isolado.

---

## 4. Análise de Memória, Performance e JSZip 3.10.1

### Comportamento medido do JSZip 3.10.1 (`jszip.min.js`)

Inspeção direta do bundle local `jszip.min.js` (v3.10.1) confirmou que `JSZip.loadAsync(blobOrFile)` lê o `Blob`/`File` integralmente via `FileReader.readAsArrayBuffer` e o converte em `Uint8Array` em RAM. Portanto, **passar `File`/`Blob` diretamente ao JSZip não torna a leitura do ZIP incremental**; o benefício real obtido em `archive-reader.js` v5.1 é:

1. **Eliminar a cópia duplicada no chamador:** no browser Worker (`canPassBlobDirectlyToJSZip`), `item` é entregue diretamente ao `JSZip.loadAsync(item)` sem criar um `rawBuf` extra antes. Em Node.js, `rawBuf = null` é executado imediatamente em `finally`.
2. **Descompactação estritamente serial (1 entrada por vez) + descarte imediato:** após cada entrada ser analisada, `u8 = null`, `delete zip.files[entryKey]` e `entryKeys[i] = null` liberam a referência imediatamente para o GC.
3. **Resiliência a arquivos corrompidos:** ZIPs, entradas ZIP individuais, streams gzip e cabeçalhos TAR truncados/inválidos registram lacuna em `coverage.gaps` (veredito `INCONCLUSIVO`) em vez de abortar o Worker.
4. **Ciclo de vida do Web Worker:** cancelamento cooperativo (`CANCEL_SCAN`) no Worker + encerramento imediato (`worker.terminate()`) e limpeza de `currentReport` / DOM no logout (`resetScanSession`) e em "Nova Análise".

### Caminho futuro documentado (sem migração prematura)

Para pacotes `.zip` extremamente grandes (ex.: bugreports acima de 300–500 MB em dispositivos com pouca RAM), a limitação arquitetural do JSZip 3.10.1 (materialização do ZIP comprimido completo) poderá ser resolvida em uma versão futura (v5.2+) migrando a leitura ZIP para **`@zip.js/zip.js`** (`BlobReader` + `Blob.slice()` sob demanda, lendo o Central Directory no final do arquivo e descomprimindo cada entrada via `TransformStream` sem carregar o ZIP inteiro na RAM). Essa migração não foi aplicada na v5.1 para evitar dependências extras desnecessárias nesta etapa.

### Métricas Reais Medidas (Node.js v24.19.0)

| Cenário Medido | Volume | Tempo | Vazão / Memória |
| :--- | :--- | :--- | :--- |
| Streaming 1 MB (`forEachLineChunked` via `Blob`) | 54.526.032 bytes (626.736 linhas) | `3.174 ms` | `16,38 MB/s` · `heapUsed` `5,6 → 17,8 MB` · `RSS` `140,3 MB` |
| ZIP serializado (50 entradas, liberação por entrada) | 8.700.000 bytes (100.000 linhas, ZIP `8,5 MB`) | `602 ms` | `heapUsed` pós-scan `16,3 MB` · `RSS` `145,7 MB` |
| Suíte completa de regressão (38 testes) | 7 arquivos de teste | `~3,9–4,4 s` | `38/38` aprovados (`0` falhas) |

---

## 5. Limitações Remanescentes

1. **`.tracev3` (Apple Unified Log binário):** sem conversor externo (`log show` no macOS), arquivos `.tracev3` permanecem fora da decodificação no navegador e elevam o resultado para `INCONCLUSIVO` quando não há fontes decodificadas equivalentes.
2. **Materialização do ZIP comprimido no JSZip 3.10.1:** arquivos `.zip` muito extensos ainda ocupam em RAM aproximadamente o tamanho comprimido do ZIP durante a indexação, até eventual migração futura para `zip.js`.
3. **Autenticação client-side no GitHub Pages:** o modo estático usa validação por hash SHA-256 no navegador para controle básico de acesso à interface; controle de acesso forte exige backend autenticado (`/login`).
4. **Correlação temporal em logs estáticos:** logs exportados podem conter eventos históricos anteriores à partida; a validação disciplinar continua exigindo revisão humana qualificada.
