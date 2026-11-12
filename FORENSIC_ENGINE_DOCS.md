# CACIQUE SCAN — Documentação Técnica do Motor Forense v4.0.0

Este documento descreve a arquitetura baseada em evidências do motor de análise forense **Cacique SCAN** (`4.0.0`), implementado de forma simétrica no backend Python ([`api/forensic_engine.py`](api/forensic_engine.py)) e no frontend JavaScript ([`forensic_engine.js`](forensic_engine.js)).

---

## 1. Modelo Formal de Regras (`ForensicRule` / `RULE_REGISTRY`)

O motor não executa mais buscas genéricas por substring ou caractere em todos os arquivos. Toda regra de detecção segue um esquema formal com escopo, contexto, condições e procedência:

| Campo | Tipo | Descrição |
| :--- | :--- | :--- |
| `id` | `string` | Identificador único e imutável da assinatura (ex: `FF_GAMEASSET_SH_GPP2_AUDITD`). |
| `name` | `string` | Título legível da assinatura. |
| `os` | `'android' \| 'ios' \| 'both'` | Sistema operacional aplicável. |
| `category` | `string` | Categoria técnica (`gameasset_anomaly`, `suspicious_jar`, `stability_crash`, `github_hexdump`, `casino_activity`, `ios_backup_restore`, `proxy_domain`, `profile_package_id`, `proxy_experimental`, `unified_log`, `injection`, `root_bypass`, `installer_origin`, `log_audit`, `uncategorized`, etc.). |
| `file_types` / `fileTypes` | `string[]` | Tipos de arquivo compatíveis (`auditd`, `crash_tombstone`, `packages`, `network_proxy`, `logcat`, `bugreport`, `ios_unified_log`, `ios_plist`, `ios_ips_crash`, `ios_tracev3`, `generic_text`). |
| `allowed_fields` / `allowedFields` | `string[]` | Campos permitidos para correspondência (`path`, `comm`, `app`, `domain`, `url`, `package`, `process`, `reason`, `signal`, `line`). |
| `match_type` / `matchType` | `string` | Estratégia de correspondência: `exact`, `path`, `domain`, `package_id`, `contextual_regex`, `token_boundary`. |
| `pattern` | `string` | Padrão ou assinatura a ser avaliada. |
| `required_conditions` / `requiredConditions` | `object` | Condições obrigatórias (ex: `avc_action: 'granted'`, `operation: 'execute'`, `comm: 'UnityMain'`, `app: 'com.dts.freefiremax'`). |
| `exclusion_conditions` / `exclusionConditions` | `object` | Condições que invalidam o alerta (ex: `chat_message`, `hex_address`, `denied_only`). |
| `confidence` | `'none' \| 'low' \| 'medium' \| 'high' \| 'confirmed'` | Nível de confiança técnica do achado. |
| `evidence_tier` / `evidenceTier` | `string` | Camada de evidência: `textual_reference`, `contextual_event`, `specific_anomaly`, `corroborated_evidence`, `confirmed_interference`. |
| `corroborating_evidence` / `corroboratingEvidence` | `string[]` | Lista de sinais independentes que podem elevar o nível de confiança durante a correlação. |
| `status` | `'active' \| 'experimental_inactive'` | Estado operacional da regra. Regras `experimental_inactive` nunca geram alertas nem pontuam risco. |
| `version` | `string` | Versão da regra (atualmente `4.0.0`). |
| `provenance` | `string` | Origem / curadoria da assinatura. |
| `base_weight` / `baseWeight` | `number` | Peso base na pontuação de risco (0 para referências textuais/estabilidade). |

### Como cadastrar uma nova assinatura

1. **Defina o tipo de arquivo e os campos permitidos**: Nunca use `generic_text` sem fronteiras (`token_boundary`) ou parser contextual para termos curtos.
2. **Adicione a regra em ambos os motores** (`RULE_REGISTRY` em `api/forensic_engine.py` e `buildRuleRegistry()` em `forensic_engine.js`) mantendo o mesmo `id`, `category`, `evidence_tier` e `base_weight`.
3. **Se exigir parser estruturado** (ex: novo formato de log do kernel ou campo específico de `dumpsys`), adicione o método dedicado na classe `ForensicEngine` em ambos os arquivos.
4. **Adicione um teste de regressão** positivo e negativo (falso positivo) em [`tests/test_forensic_engine.py`](tests/test_forensic_engine.py) e [`tests/test_forensic_engine.mjs`](tests/test_forensic_engine.mjs).

---

## 2. Assinaturas Reclassificadas e Desativadas

Nenhuma assinatura clássica foi apagada silenciosamente. Todas foram auditadas e reclassificadas conforme seu valor forense real:

### 2.1. Tokens curtos e hexadecimais (`status: experimental_inactive`, peso `0`)
89 tokens curtos ou hexadecimais (incluindo `06`, `03`, `051`, `06a`, `0af`, `0b`, `0E`, `od`, `140`, `1ea`, `14`, `105e`, `15d`, `1b69`, `2c`, `28a`, `2bb`, `3c`, `3c4`, `439`, `40e`, `4e`, `4a`, `4c`, `4cf`, `4d`, `47`, `51`, `550`, `5b`, `5c10`, `59ac`, `60a`, `60af`, `62`, `62d`, `6b`, `6dd`, `69`, `78f`, `70a`, `704114`, `704`, `70d`, `739`, `76d`, `7d`, `80`, `84`, `87`, `9d`, `90eb`, `96f`, `a00`, `a1fc`, `a4`, `a9`, `a4c`, `a48`, `a5`, `a64`, `ae7`, `b0`, `b9`, `b4`, `bc`, `bd`, `bd32`, `bd32d`, `c17`, `c25`, `c9`, `d14`, `d03090`, `d141`, `d03`, `d5`, `d7319`, `dd4f0`, `dd4fa`, `d4f0`, `e0`, `e3`, `f54`, `f6`, `f6c`, `f9`, `ff32`, `ff6`):
- **Motivo técnico**: Strings de 2 a 6 caracteres hexadecimais/numéricos ocorrem naturalmente milhares de vezes em endereços de memória (`0x7f1a4b20`), registradores ARM64 (`x0`..`x29`), timestamps, offsets legítimos de sistema e hashes. Usá-los como match por substring produzia falsos positivos em massa. Mantidos apenas no catálogo como `experimental_inactive` até que exista associação comprovada com campo estruturado de proxy/rede.

### 2.2. Regra de hífen (`-`) removida da detecção de cassino
- **Motivo técnico**: O caractere `-` aparece em praticamente qualquer log (datas ISO, flags CLI, pacotes, nomes compostos, separadores). A categoria `casino_activity` agora exige domínios ou termos explícitos de apostas/cassino em contexto de URL/domínio/pacote/processo (`bet365`, `blaze.com`, `stake.com`, `1win`, `estrelabet`, `betano`, `pixbet`, `sportingbet`, `tigrinho`, `fortune tiger`, `casino`).

### 2.3. Eventos de estabilidade e crashes (`LOW_MEMORY`, `SIGSEGV` / `SEGV_MAPERR`)
- **Reclassificação**: Movidos para a categoria `stability_crash` (`textual_reference` / `contextual_event`, peso `0`).
- **Motivo técnico**: `reason=3 (LOW_MEMORY)` é encerramento normal por pressão de memória do Android. `signal 11 (SIGSEGV), code 1 (SEGV_MAPERR)` é falha de ponteiro nulo que ocorre em bugs comuns de apps e engines Unity; só é elevado para investigação adicional se houver biblioteca injetada ou módulo anômalo explícito no backtrace.

### 2.4. URLs do GitHub em hex dumps (`github.com/...`)
- **Reclassificação**: Reconstruídos por parser de hex dump (`parse_hex_dump_lines` / `parseHexDumpLines`) na categoria `github_hexdump` (`textual_reference`, peso `0`).
- **Motivo técnico**: Bibliotecas open-source usadas legitimamente por jogos Unity (como cabeçalhos XML/JSON de `Newtonsoft.Json` apontando para `https://github.com/jilleJr/Newtonsoft.Json-for-Unity` ou licenças) aparecem na memória do processo durante execução normal.

### 2.5. Processos e daemons nativos de backup do iOS (`MobileBackup`, `BackupAgent`, `itunesstored`, `SetupAssistant`, `mobilebackupd`, `restored`)
- **Reclassificação**: Diferenciados em estágios na categoria `ios_backup_restore` (`textual_reference` com peso `0` para referências de sistema e `itunesstored`/`SetupAssistant`; `contextual_event` com peso `5` apenas para eventos explícitos de ciclo de vida como `RestoreFromBackup` ou `BackupRestore` ativo).
- **Motivo técnico**: A mera menção a `MobileBackup` ou presença de `itunesstored` (daemon padrão da App Store) e `SetupAssistant` não comprova restauração de backup durante partida.

### 2.6. Domínios de proxy e IDs de pacotes/perfis
- **Reclassificação**: Pesquisados exclusivamente em campos compatíveis (`domain`, `url`, `host`, `dns`, `proxy`, `package`, `bundle`, `profile`) com correspondência exata ou de fronteira (`domain` / `package_id` / `exact`).
- **Motivo técnico**: Evita que um nome de pacote ou domínio citado em log de texto livre ou relatório seja confundido com perfil instalado ou proxy ativo.

---

## 3. Contadores, Deduplicação e Correlação

- **Deduplicação**: Ocorrências repetidas do mesmo evento no mesmo arquivo/chave são agrupadas em **1 evento único** com o contador `raw_occurrences` preservado. Isso garante que 4.000 repetições de um log não multipliquem artificialmente o `threat_score`.
- **5 Contadores Separados** no relatório (`counters`):
  1. `raw_occurrences`: total de ocorrências brutas agrupadas.
  2. `unique_events`: total de alertas únicos exibidos.
  3. `validated_evidence`: eventos nos níveis `corroborated_evidence` ou `confirmed_interference`.
  4. `review_alerts`: eventos no nível `specific_anomaly` que exigem revisão humana.
  5. `informative_events`: eventos nos níveis `textual_reference` ou `contextual_event`.
  6. `unanalyzed_files`: arquivos que não puderam ser interpretados (ex: `.tracev3` binários).
- **Correlação Independente**: Um alerta `specific_anomaly` (como `FF_GAMEASSET_SH_GPP2_AUDITD` em `avc: granted { execute }` para `UnityMain`) só é elevado para `corroborated_evidence` (`confidence: high`) quando há pelo menos outra evidência técnica independente no conjunto de logs (ex: Free Fire instalado fora da Play Store via `installerPackageName != com.android.vending`, ou framework de hooking como `frida`/`lsposed`/`xposed`).

---

## 4. Limitações Conhecidas da Análise Forense

1. **Logs estáticos não provam execução em partida por si sós**: Um registro isolado em `logcat`, `dumpsys` ou `auditd` indica o evento técnico registrado no snapshot do dispositivo, mas não substitui verificação contextual do momento da partida nem prova autoria sem evidência corroboradora.
2. **Arquivos `.tracev3` (Apple Unified Log)**: O formato `.tracev3` é binário proprietário da Apple. Nem o navegador nem o backend Python leem `.tracev3` como texto puro (para evitar falsos positivos com bytes aleatórios). Quando presentes, são listados em `unanalyzed_files` e o veredito reflete cobertura incompleta (`COBERTURA INCOMPLETA`) caso não haja outras ameaças. Para inspeção completa desses arquivos, é necessário convertê-los previamente em macOS com `log show`.
3. **Lojas de fabricantes Android**: No Android, `installerPackageName` diferente de `com.android.vending` pode ocorrer em lojas oficiais de fabricantes (Samsung Galaxy Store, Xiaomi GetApps, etc.); por isso a origem do instalador deve ser verificada pelo analista, sendo crítica especificamente para o pacote do Free Fire.
4. **Correlação vs. Causalidade**: Crashes (`SIGSEGV`, `LOW_MEMORY`) e URLs em hex dump são preservados apenas para diagnóstico e contexto, nunca como prova de trapaça.

