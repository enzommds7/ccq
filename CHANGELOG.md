# Changelog — ccq scan

Todas as alterações relevantes do motor forense **ccq scan** são documentadas neste arquivo.

## [5.1.0] — 2026-11-27

### Corrigido
- **Android Settings (`js/scan/parsers/android-parser.js`):** corrigidas `SETTINGS_NAME_RE` e `SETTINGS_VALUE_RE` para aceitar delimitadores `=` e `:`; ampliado suporte a alterações via `com.android.shell` com baselines dedicados, diferenciando valores padrão (`informational`), não padrão (`anomaly_review`), desconhecidos (`unvalidated_reference`) e ignorando linhas truncadas/sem campos sem gerar falsos positivos.
- **Android ADB (`js/scan/parsers/android-parser.js`):** corrigido reconhecimento de `[service.adb.tcp.port]: [5555]` e separação técnica dos 7 estados de depuração (porta configurada, serviço `adbd`, loopback local Brevent/Shizuku, conexão remota real, USB, wireless e forward), eliminando confusão entre porta configurada e sessão remota estabelecida.
- **Android `SH-Gpp2` em `auditd` (`js/scan/parsers/android-parser.js`):** removida dependência exclusiva do campo `app=` usando fallback via `canonical_path`; separação explícita entre proprietário do arquivo e processo/app atuante, registrando inconsistência contextual (`ANDROID_GAME_SH_GPP2_CTX_MISMATCH_001`) e não presumindo execução na ausência de `execute`/`comm`.
- **iOS `.ips` (`js/scan/parsers/ios-parser.js`):** corrigida falha silenciosa ao analisar arquivos `.ips` em JSON único multi-linha (pretty-printed), preservando suporte ao formato nativo Apple de 2 documentos JSON.
- **iOS Screen Time (`js/scan/parsers/ios-parser.js`):** ampliado `SCREENTIME_NATIVE_RE` com ancoragem estrita e validação de chave de perfil para reconhecer `system.dateandtime.force_date_time_configuration_*-restrictions`, `system.web.contentfilter.basic.digital_health_restrictions` e `com.apple.webcontentfilter.basic-restrictions` sem ignorar perfis suspeitos disfarçados.
- **Estabilidade & ciclo de vida (`js/main.js`, `js/core/auth.js`, `js/core/sound.js`, `js/core/ui-utils.js`, `js/scan/scan-ui.js`):**
  - Corrigida race condition no carregamento lazy da UI do scanner e inconsistência entre logout, re-login e Web Worker ativo (`resetScanSession` encerra o Worker, limpa `currentReport` e DOM).
  - Adicionados guardas idempotentes contra duplicação de listeners e `.catch()` em Promises assíncronas de login/logout/cópia/áudio.
  - Removido código morto herdado da antiga arena (`HeroCanvas`, `generateRandomSeedHex`, listeners `.rede-tab-btn`/`.rede-copy-btn`).
  - Corrigido tratamento de arquivos ZIP, entradas ZIP, gzip e cabeçalhos TAR corrompidos em `js/scan/archive-reader.js` (registram lacuna `coverage.gaps` em vez de travar).

### Adicionado
- **Overlays Android (`js/scan/parsers/android-parser.js`):** suporte a `WindowManager`, `dumpsys window` e `SurfaceFlinger` (`type=2038`, `TYPE_APPLICATION_OVERLAY`, `com.zayon.optimize`) com extração de pacote, janela, tipo, processo, visibilidade, timestamp e app em primeiro plano, ignorando overlays de sistema/OEM e tratando apps legítimos como informativos.
- **Catálogo tipado v5.1 (`js/scan/catalog-rules.json` & `js/scan/engine/matcher.js`):**
  - Adicionados `com.netflix.mediaclientxx` e `com.spotify.musicx` a `ANDROID_PACKAGE_CANDIDATES` e removido termo genérico `Proxyhandler`.
  - Criadas categorias separadas com procedência e estado de validação: `ANDROID_OVERLAY_CANDIDATES` (`com.zayon.optimize`), `NETWORK_IP_CANDIDATES` (`85.31.231.237`), `PROFILE_REFERENCE_CANDIDATES` (`Imazing.profile`, `139.Spotifyx`, `238.timx`), `TOOL_INDICATORS_CANDIDATES` (`TNTADB`) e `TEXTUAL_ALIAS_CANDIDATES` (`com-xtremo-mobile`, `dash-proxy`, `com-luxebypass`, `freefireproxy-xyz`).
- **Suíte modular de testes & CI:** adicionados testes nativos Node.js (`tests/android-parser.test.js`, `tests/ios-parser.test.js`, `tests/matcher.test.js`, `tests/deduplicator.test.js`, `tests/correlator.test.js`, `tests/archive-reader.test.js`), fixtures sintéticas em `tests/fixtures/`, comando `npm test` e workflow `.github/workflows/regression-tests.yml`.
- **Cancelamento cooperativo & acessibilidade:** suporte a `CANCEL_SCAN` no Worker e ativação por teclado (`Enter`/`Space`) na caixa de upload.

### Alterado
- **Calibração heurística anti-inflação (`js/scan/engine/correlator.js`):** substituída elevação uniforme de peso para `50` por teto por família técnica (`35`) e bônus único limitado de corroboração (`+15` por família extra elegível, máx. `+25`), evitando que combinações compatíveis com Brevent/Shizuku (ADB TCP + shell settings) ou IPs isolados promovam eventos a `corroborated_evidence`.
- **Gerenciamento de memória ZIP/TAR (`js/scan/archive-reader.js`):** passagem direta de `Blob`/`File` para `JSZip.loadAsync` no browser Worker para evitar cópia extra de buffer, descarte imediato de `zip.files[entryKey]` e `u8` após cada entrada, validação de `maxBinaryEntryBytes` e documentação da limitação arquitetural do JSZip 3.10.1 com caminho futuro para `zip.js`.
- **Nomenclatura & cache busting:** padronização para `ccq scan` em relatórios, logs, documentação e atualização de versão (`5.1.0` / `5.1-clean` / `?v=8` e `?v=5.1`).

## [5.0.0] — 2026-11-22

### Adicionado
- Reestruturação modular em ES Modules com Web Worker dedicado (`scan.worker.js`), streaming em chunks de 1 MB, contrato canônico de 5 estados, deduplicação (`deduplicator.js`), correlação por fontes independentes (`correlator.js`), decodificador nativo `bplist00`, parser de `.ips` JSON e proteção contra path traversal/symlinks/ZIP bombs.
- Separação do catálogo limpo `5.0-clean` com desativação definitiva de `PROXY_SHORT_TOKENS` (76 tokens hex curtos).
