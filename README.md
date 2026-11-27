# ccq scan

Ferramenta web de análise forense mobile e identificação de indicadores de trapaça em dispositivos Android e iOS, com foco na integridade competitiva do Free Fire.

**[Acessar o scanner](https://enzommds7.github.io/ccq/)** · [Documentação técnica](FORENSIC_ENGINE_DOCS.md)

## Funcionalidades

- Análise de Bugreport Android e Sysdiagnose iOS.
- Entrada por arquivos ZIP/TAR.GZ, pastas extraídas ou logs individuais.
- Identificação de indicadores relacionados a alterações no dispositivo, depuração, rede e integridade do jogo.
- Correlação de evidências, deduplicação de eventos e avaliação da cobertura dos logs.
- Terminal de análise, filtros de resultados e cópia do relatório.
- Processamento dos arquivos no navegador, com Web Worker dedicado.
- Acesso restrito pela autenticação existente baseada em SHA-256.

## Arquitetura

JavaScript (ES Modules), HTML5, CSS e Web Workers. A aplicação é estática e publicada pelo GitHub Pages, sem etapa de compilação.

```text
ccq/
├── index.html
├── styles.css
├── logo.jpg
├── logo.webp
├── jszip.min.js
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
├── FORENSIC_ENGINE_DOCS.md
└── README.md
```

## Execução local

```bash
git clone https://github.com/enzommds7/ccq.git
cd ccq
python -m http.server 8000
```

Acesse http://localhost:8000 em um navegador moderno. Utilize um servidor HTTP local em vez de abrir o HTML diretamente, devido ao uso de módulos JavaScript e Web Workers.

## Critérios de análise

O motor v5.0 diferencia referências não validadas, eventos informativos, anomalias para revisão, evidências corroboradas e resultados inconclusivos.

Uma assinatura isolada não comprova execução de cheat. A ausência de registros não comprova integridade. Os resultados exigem revisão humana e não devem ser utilizados como fundamento exclusivo para punições.

## Privacidade e limitações

Os arquivos analisados são processados localmente no navegador. A autenticação estática por hash não substitui controle de acesso implementado no servidor. Arquivos binários Apple .tracev3 não são decodificados pelo motor atual; essa limitação é registrada na cobertura da análise.

## Histórico

O ccq scan preserva a identidade visual original da Cacique. A versão histórica do projeto permanece na branch [legacy-cacique](https://github.com/enzommds7/ccq/tree/legacy-cacique). A branch main é dedicada exclusivamente ao scanner.
