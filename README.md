# ccq scan

Ferramenta web de análise forense mobile voltada à identificação contextual de indicadores de trapaça, manipulação e alterações suspeitas em dispositivos Android e iOS, com foco na integridade competitiva do Free Fire.

**[Acessar o scanner](https://enzommds7.github.io/ccq/)** · [Documentação técnica](FORENSIC_ENGINE_DOCS.md) · [Changelog](CHANGELOG.md)

## Funcionalidades (v5.1)

- Análise de Bugreport Android e Sysdiagnose iOS diretamente no navegador via Web Worker dedicado.
- Entrada por arquivos `.zip` / `.tar.gz`, pastas extraídas ou logs individuais (incluindo `tombstone_*`, `anr_*`, `mountinfo` e `lsaw.csstoredump`).
- Parsers forenses especializados:
  - **Android**: `dumpsys settings` (formatos `=` e `:`, baselines para `by4a.setedit22` e `com.android.shell`), diferenciação dos 7 estados de ADB/depuração (porta configurada, serviço ativo, loopback Brevent/Shizuku, conexão remota, USB, wireless e forward), `auditd` (`SH-Gpp2` com fallback por `canonical_path` e checagem proprietário vs processo), overlays (`WindowManager`/`SurfaceFlinger`, `type=2038`, `TYPE_APPLICATION_OVERLAY`), `PackageManager`, `getprop`, crashes e hex dumps.
  - **iOS**: XML `.plist` e `bplist00` binário nativo, perfis nativos de Tempo de Uso (Screen Time) validados com regex ancorada, `.ips` JSON (objeto único ou formato Apple de 2 documentos), `Sandbox: deny`, `usedImages` e bloqueio de leitura textual em `.tracev3` e `UUIDText`/`DSC`.
- Catálogo modular (`js/scan/catalog-rules.json`, `5.1-clean`) com categorias separadas por natureza técnica (pacotes, overlays, IPs candidatos sem reputação permanente, referências de perfil, ferramentas e aliases textuais), mantendo `PROXY_SHORT_TOKENS` inativo.
- Deduplicação de eventos, correlação estrita por fontes independentes com pontuação anti-inflação e separação explícita entre cobertura de log e índice heurístico.
- Acesso restrito preservando o mecanismo de autenticação existente (backend `/login` + fallback SHA-256 client-side) e encerramento seguro do Worker no logout.

## Arquitetura

JavaScript (ES Modules), HTML5, CSS e Web Workers. A aplicação é estática e compatível com GitHub Pages, sem etapa de compilação nem dependências externas de runtime além do `jszip.min.js` local.

```text
ccq/
├── index.html
├── styles.css
├── logo.jpg
├── logo.webp
├── jszip.min.js
├── package.json
├── .github/
│   └── workflows/
│       └── regression-tests.yml
├── js/
│   ├── main.js
│   ├── core/
│   │   ├── auth.js
│   │   ├── sound.js
│   │   └── ui-utils.js
│   └── scan/
│       ├── scan-ui.js
│       ├── scan.worker.js
│       ├── archive-reader.js
│       ├── catalog-rules.json
│       ├── engine/
│       │   ├── matcher.js
│       │   ├── deduplicator.js
│       │   └── correlator.js
│       └── parsers/
│           ├── android-parser.js
│           ├── ios-parser.js
│           └── hexdump-parser.js
├── tests/
│   ├── fixtures/
│   │   ├── android/
│   │   ├── ios/
│   │   └── archives/
│   ├── android-parser.test.js
│   ├── ios-parser.test.js
│   ├── matcher.test.js
│   ├── deduplicator.test.js
│   ├── correlator.test.js
│   ├── archive-reader.test.js
│   └── test_scan_v5.mjs
├── CHANGELOG.md
├── FORENSIC_ENGINE_DOCS.md
└── README.md
```

## Execução local

```bash
git clone https://github.com/enzommds7/ccq.git
cd ccq
python -m http.server 8000
```

Acesse `http://localhost:8000` em um navegador moderno. Utilize um servidor HTTP local em vez de abrir o HTML diretamente (`file://`), devido ao uso de ES Modules e Web Workers.

## Testes automatizados

O projeto possui suíte de regressão baseada no test runner nativo do Node.js (zero dependências externas):

```bash
npm test
```

Ou diretamente via Node.js:

```bash
node --test tests/*.test.js tests/test_scan_v5.mjs
```

A regressão automatizada também é executada via GitHub Actions em `.github/workflows/regression-tests.yml`.

## Critérios de análise

O motor v5.1 diferencia rigorosamente os cinco estados canônicos: `informational`, `unvalidated_reference`, `anomaly_review`, `corroborated_evidence` e `inconclusive`.

- Presença não comprova execução; execução não comprova interferência na partida; ausência de evidência não comprova integridade.
- Nenhuma detecção isolada deve ser utilizada como fundamento automático para punições; toda decisão exige revisão humana contextual.

## Privacidade e limitações

Os arquivos analisados são processados localmente no navegador. A autenticação estática por hash não substitui controle de acesso implementado no servidor. Arquivos binários Apple `.tracev3` não são decodificados pelo motor atual; essa limitação é registrada explicitamente na cobertura (`inconclusive`).

## Histórico

O ccq scan preserva a identidade visual original e o brasão do projeto. A versão histórica permanece preservada integralmente na branch [legacy-cacique](https://github.com/enzommds7/ccq/tree/legacy-cacique). A branch `main` é dedicada exclusivamente ao ccq scan.
