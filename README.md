# ⚔️ Cacique Apostas — A Tribo Mais Confiável do Free Fire

> Plataforma web oficial da **Tribo Cacique Apostas**: comunidade competitiva brasileira de Free Fire focada em duelos rápidos, pagamentos imediatos via Pix, integridade auditada e arbitragem forense.

[![Deploy](https://img.shields.io/badge/Deploy-GitHub%20Pages-success?style=for-the-badge&logo=github)](https://enzommds7.github.io/ccq/)
[![Engine](https://img.shields.io/badge/Engine-ccq--scan%203.1-red?style=for-the-badge)](https://enzommds7.github.io/ccq/#scan)
[![Auditoria](https://img.shields.io/badge/Auditoria-CSPRNG%20%7C%20SHA--256-gold?style=for-the-badge)](https://enzommds7.github.io/ccq/#sorteio)
[![Status](https://img.shields.io/badge/Status-100%25%20Client--Side-blue?style=for-the-badge)](#)

---

## 🎯 Visão Geral

O projeto **Cacique Apostas** foi reconstruído do zero com arquitetura moderna e design autoral (estilo arena competitiva industrial/editorial), fugindo de templates genéricos e clichês visuais de IA. 

O site reúne três pilares centrais de operação da Tribo:
1. **Regulamento & Confiança:** Transparência total de regras de duelos (X1, X2, X3, X4, modo Bate-Soco e Normal) e histórico comprovado de pagamento ágil via Pix.
2. **Arena de Roletas por Patente:** Sistema de sorteio com 3 mesas simultâneas, balanceamento matemático por peso de patente, auditoria criptográfica com *Seed/Hash* e exportação de card oficial em PNG.
3. **Cacique SCAN v3.1:** Motor forense para análise pericial de dumps de memória, logs do Android (*Bugreport*) e iOS (*Sysdiagnose*) executado 100% no navegador, sem tráfego de dados para servidores externos.

---

## 🚀 Principais Funcionalidades

### 🎰 1. Arena de Roletas (Fluxo em 4 Passos)
Substitui sorteios aleatórios desiguais por confrontos equilibrados através de patentes:
- **Passo 1 — Cadastro & Elenco:**
  - Reconhecimento inteligente de texto livre (`Nick - D2`, `Capitão | Mestre`, `Sniper P1`, `Lobo M`, etc.).
  - Filtros, busca em tempo real, detecção de nicks duplicados e contador de inscritos por patente.
  - Recurso de **Pin (☆)** para travar jogadores em posições estratégicas.
  - Importação e exportação de elenco em **JSON**, **CSV** e texto simples.
- **Passo 2 — Configuração das 3 Roletas (Mesas A, B e C):**
  - Mesas independentes com formatos customizáveis (`4v4 Normal`, `4v4 Bate-Soco`, `2v2`, `X1`, etc.).
  - Filtro de patentes permitidas por mesa e tolerância ajustável de desequilíbrio ($\pm 1$ a $\pm 8$ pts).
  - Bloqueio inteligente: jogador sorteado em uma mesa sai automaticamente das outras.
- **Passo 3 — Giro com Física & Animação 60fps:**
  - Roletas em **Canvas 2D de alta densidade** (*devicePixelRatio*) com desaceleração exponencial e inércia angular.
  - Ponteiro mecânico com física de impacto (*tick* visual, sonoro e háptico/vibração no celular).
  - **Giros escalonados:** a Mesa A para primeiro, depois a B e por fim a C, garantindo suspense máximo.
  - Preenchimento em tempo real das vagas do Time 1 e Time 2 ao lado da roleta.
- **Passo 4 — Confrontos & Auditoria:**
  - **Auto-Equilibrar:** algoritmo combinatório de partição que reorganiza os times para obter o menor desnível absoluto de pontos.
  - **Copiar para WhatsApp:** resumo pronto com listas de nicks, patentes, pontuação e hash.
  - **Baixar Imagem (Card PNG 1200x630):** gera instantaneamente o card oficial do duelo em alta resolução com o brasão e marca d'água da Tribo.
- **Modo Telão (Tecla `T`):** Modo de apresentação em tela cheia com contraste altíssimo para lives no YouTube e compartilhamento de tela no Discord.

---

### 🎲 2. Modo Rápido (1 Clique)
- Ferramenta clássica preservada para partidas casuais ou quando o tempo é curto:
  - Seleção de tamanho de time (2, 3, 4, 5 ou personalizado).
  - Animação de suspense de 1.4s com barra de progresso.
  - Exportação direta para o WhatsApp.

---

### 🛡️ 3. Cacique SCAN v3.1 (Anti-Cheat Forense)
- **Análise Client-Side Segura:** Nenhum arquivo sai da máquina do usuário.
- **Múltiplos Modos de Entrada:** Arquivo compactado `.zip` / `.tar.gz`, pasta descompactada ou logs soltos.
- **Base com +50 Assinaturas Reais:**
  - Offsets Coringa e injeções de memória (HS Cabeça, Aimbot, Wallhack, Telekill, No Recoil).
  - Configurações e cheats OB40 por arma.
  - Detecção de hooks em `libil2cpp.so`, Magisk, Zygisk, Frida e GameGuardian.
- **Terminal Interativo (`tty0`):** Simulação de terminal pericial com logs monoespaçados e alertas coloridos por severidade.
- **Relatório Forense:** Pontuação de integridade pericial (0 a 100) e botão para copiar relatório pericial completo.
- **Segurança de Acesso:** Login de ADM autenticado via **hash SHA-256**, sem senhas salvas em texto puro.

---

### 🔊 4. Áudio Mecânico Web Audio API & Hápticos
- Áudio sintetizado nativamente no navegador através da `Web Audio API` (zero arquivos `.mp3` externos para carregamento instantâneo).
- Bipes de fatias, acorde harmônico de finalização e alertas de ameaça.
- Suporte a vibração tátil em dispositivos móveis compatíveis (`navigator.vibrate`).
- Botão de alternância mudo/ativo no topo com persistência em `localStorage`.

---

## 🎨 Identidade Visual & Design Tokens

O projeto utiliza um design system escuro e industrial, sem degradês neon de IA:
- **Base Escura:** `--bg: #0d0e12`, `--bg-elevated: #121318`, `--surface: #16171d`.
- **Acentos:**
  - **Vermelho Coral (`#e5484d`):** Botões principais de conversão, Time 1 e alertas críticos.
  - **Dourado (`#d4af37`):** Selo *"PAGA GARANTIDO"*, troféus e patente Mestre.
  - **Verde Esmeralda (`#10b981`):** Indicador dinâmico de status *"AO VIVO"* e auditoria limpa.
- **Tipografia:**
  - Títulos: `Clash Display` (com tracking fechado editorial).
  - Leitura: `Geist`.
  - Dados Técnicos / Roleta: `Geist Mono` & `Share Tech Mono`.
- **Brasão Oficial:** Preservado integralmente sem corte circular ou distorções, com moldura técnica retangular e cantoneiras de precisão.

---

## 📂 Estrutura do Repositório

```text
cacique-apostas/
├── index.html        # Estrutura semântica HTML5, modais e templates
├── styles.css        # Design system, animações de física, telão e responsividade
├── script.js         # Orquestrador modular (Audio, Canvas 2D, Roleta, Forensics, CSPRNG)
├── jszip.min.js      # Biblioteca para descompressão client-side de arquivos .zip
├── favicon.svg       # Favicon vetorial com silhueta do guerreiro Cacique
├── logo.webp         # Brasão oficial em formato otimizado
├── logo.jpg          # Fallback do brasão oficial
└── README.md         # Documentação completa do projeto
```

---

## ⚙️ Como Executar Localmente

Como a aplicação é 100% estática e não requer compiladores nem dependências de backend:

1. **Clone o repositório:**
   ```bash
   git clone https://github.com/enzommds7/ccq.git
   cd ccq
   ```
2. **Execute um servidor local simples:**
   - Com Python:
     ```bash
     python -m http.server 8000
     ```
   - Com Node.js / `npx`:
     ```bash
     npx serve .
     ```
   - Ou abra o `index.html` diretamente em qualquer navegador moderno.
3. Acesse `http://localhost:8000`.

---

## ⌨️ Atalhos de Teclado (Operador / ADM)

| Tecla | Ação |
| :---: | :--- |
| **`Espaço`** | Gira todas as roletas ativas simultaneamente |
| **`R`** | Reseta as roletas e limpa os confrontos para nova rodada |
| **`T`** | Alterna para o **Modo Telão** (tela cheia para stream/call) |
| **`ESC`** | Fecha qualquer modal aberto ou sai do Modo Telão |

---

## ⚖️ Jogo Responsável (18+)

A Tribo Cacique Apostas é uma comunidade destinada exclusivamente ao entretenimento competitivo de maiores de 18 anos. Jogue com moderação e responsabilidade financeira.
