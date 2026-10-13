/* ═══════════════════════════════════════════════
   Cacique Apostas — Interactivity & Forensic Scan
   ═══════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {

  // ─────────────────────────────────────────────────────────────
  // 1. Web Audio API — Interface Sintetizada (Zero dependências)
  // ─────────────────────────────────────────────────────────────
  class SoundController {
    constructor() {
      this.ctx = null;
      this.enabled = localStorage.getItem('cacique_sfx_enabled') === 'true';
      this.toggleBtn = document.getElementById('soundToggle');
      this.updateBtnState();
      if (this.toggleBtn) {
        this.toggleBtn.addEventListener('click', () => this.toggle());
      }
    }

    init() {
      if (!this.ctx) {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (AudioCtx) this.ctx = new AudioCtx();
      }
      if (this.ctx && this.ctx.state === 'suspended') {
        this.ctx.resume();
      }
    }

    updateBtnState() {
      if (!this.toggleBtn) return;
      this.toggleBtn.setAttribute('aria-pressed', this.enabled ? 'true' : 'false');
      this.toggleBtn.title = this.enabled ? 'Sons da interface ativados' : 'Sons desativados (clique para ativar)';
    }

    toggle() {
      this.init();
      this.enabled = !this.enabled;
      localStorage.setItem('cacique_sfx_enabled', this.enabled ? 'true' : 'false');
      this.updateBtnState();
      if (this.enabled) {
        this.tick();
        showToast('info', 'Áudio ativado', 'Feedback sonoro mecânico habilitado.');
      } else {
        showToast('info', 'Áudio desativado', 'Interface silenciosa.');
      }
    }

    // Bipe mecânico ultra-curto (usado nos logs e sorteio)
    tick(freq = 1100) {
      if (!this.enabled) return;
      this.init();
      if (!this.ctx) return;
      const t = this.ctx.currentTime;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, t);
      osc.frequency.exponentialRampToValueAtTime(300, t + 0.03);
      gain.gain.setValueAtTime(0.045, t);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.03);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start(t);
      osc.stop(t + 0.03);
    }

    // Sucesso / Ação concluída (acorde harmônico mecânico)
    done() {
      if (!this.enabled) return;
      this.init();
      if (!this.ctx) return;
      const t = this.ctx.currentTime;
      [523.25, 659.25, 783.99].forEach((freq, idx) => {
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(freq, t + idx * 0.04);
        gain.gain.setValueAtTime(0.06, t + idx * 0.04);
        gain.gain.exponentialRampToValueAtTime(0.0001, t + idx * 0.04 + 0.16);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start(t + idx * 0.04);
        osc.stop(t + idx * 0.04 + 0.17);
      });
    }

    // Alerta de ameaça detectada
    alert(isSevere = false) {
      if (!this.enabled) return;
      this.init();
      if (!this.ctx) return;
      const t = this.ctx.currentTime;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = isSevere ? 'sawtooth' : 'square';
      osc.frequency.setValueAtTime(isSevere ? 220 : 380, t);
      osc.frequency.linearRampToValueAtTime(isSevere ? 110 : 260, t + 0.14);
      gain.gain.setValueAtTime(0.08, t);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.15);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start(t);
      osc.stop(t + 0.15);
    }

    // Erro / Validação falha
    error() {
      if (!this.enabled) return;
      this.init();
      if (!this.ctx) return;
      const t = this.ctx.currentTime;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(260, t);
      osc.frequency.linearRampToValueAtTime(140, t + 0.18);
      gain.gain.setValueAtTime(0.08, t);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.19);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start(t);
      osc.stop(t + 0.19);
    }
  }

  const sfx = new SoundController();

  // ─────────────────────────────────────────────────────────────
  // 2. Sistema de Notificações Toast (Sem alert() nativo)
  // ─────────────────────────────────────────────────────────────
  const toastRegion = document.getElementById('toastRegion');

  function showToast(type, title, message, duration = 3000) {
    if (!toastRegion) return;

    // Limita a 4 toasts na tela
    while (toastRegion.children.length >= 4) {
      toastRegion.firstElementChild.remove();
    }

    const toast = document.createElement('div');
    toast.className = `toast is-${type}`;

    let iconSvg = '';
    if (type === 'success') {
      iconSvg = `<svg class="toast-icon" viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg>`;
    } else if (type === 'error') {
      iconSvg = `<svg class="toast-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
    } else {
      iconSvg = `<svg class="toast-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
    }

    toast.innerHTML = `
      ${iconSvg}
      <div class="toast-body">
        <strong>${escapeHtml(title)}</strong>
        ${message ? `<span>${escapeHtml(message)}</span>` : ''}
      </div>
    `;

    toastRegion.appendChild(toast);

    let dismissed = false;
    const dismiss = () => {
      if (dismissed) return;
      dismissed = true;
      toast.classList.add('is-leaving');
      setTimeout(() => toast.remove(), 220);
    };

    setTimeout(dismiss, duration);
    toast.addEventListener('click', dismiss);
  }

  // ─────────────────────────────────────────────────────────────
  // 3. Microinterações de Cópia (Botões com Check Sutil)
  // ─────────────────────────────────────────────────────────────
  async function performCopy(text, btnElement, successLabel = 'Copiado!') {
    let ok = false;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        ok = true;
      } catch (_) {
        ok = fallbackCopy(text);
      }
    } else {
      ok = fallbackCopy(text);
    }

    if (ok) {
      sfx.tick(1400);
      const originalHtml = btnElement.innerHTML;
      btnElement.classList.add('is-copied');
      btnElement.innerHTML = `
        <svg class="copy-check" viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5"/></svg>
        <span class="copy-label">${escapeHtml(successLabel)}</span>
      `;
      setTimeout(() => {
        btnElement.classList.remove('is-copied');
        btnElement.innerHTML = originalHtml;
      }, 2000);
      showToast('success', 'Copiado', 'Texto copiado para a área de transferência.');
    } else {
      sfx.error();
      showToast('error', 'Erro ao copiar', 'Não foi possível acessar a área de transferência.');
    }
  }

  function fallbackCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    let success = false;
    try {
      success = document.execCommand('copy');
    } catch (_) {
      success = false;
    }
    document.body.removeChild(ta);
    return success;
  }

  // ─────────────────────────────────────────────────────────────
  // 4. Header & Navegação Mobile
  // ─────────────────────────────────────────────────────────────
  const header = document.getElementById('header');
  window.addEventListener('scroll', () => {
    if (window.scrollY > 20) {
      header.classList.add('scrolled');
    } else {
      header.classList.remove('scrolled');
    }
  }, { passive: true });

  const navToggle = document.getElementById('navToggle');
  const mobileMenu = document.getElementById('mobileMenu');
  if (navToggle && mobileMenu) {
    function toggleMenu() {
      navToggle.classList.toggle('active');
      mobileMenu.classList.toggle('open');
      const isExpanded = navToggle.classList.contains('active');
      navToggle.setAttribute('aria-expanded', isExpanded);
    }

    navToggle.addEventListener('click', toggleMenu);
    mobileMenu.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        if (mobileMenu.classList.contains('open')) toggleMenu();
      });
    });
  }

  // ─────────────────────────────────────────────────────────────
  // 5. Sorteio de Times (Com Sons Mecânicos e Ritmo)
  // ─────────────────────────────────────────────────────────────
  const namesInput = document.getElementById('namesInput');
  const sizeBtns = document.querySelectorAll('.size-btn');
  const customSizeInput = document.getElementById('customSize');
  const sortInfo = document.getElementById('sortInfo');
  const sortBtn = document.getElementById('sortBtn');
  const clearBtn = document.getElementById('clearBtn');
  const sorteioStage = document.getElementById('sorteioStage');

  let teamSize = 4;

  function updateTeamSize(size, btnElement) {
    teamSize = parseInt(size, 10);
    sizeBtns.forEach(btn => btn.classList.remove('active'));
    if (btnElement) {
      btnElement.classList.add('active');
      if (customSizeInput) customSizeInput.value = '';
    }
    updateSortInfo();
    sfx.tick(900);
  }

  sizeBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      updateTeamSize(e.currentTarget.dataset.size, e.currentTarget);
    });
  });

  if (customSizeInput) {
    customSizeInput.addEventListener('input', (e) => {
      const val = parseInt(e.target.value, 10);
      if (val >= 2) {
        teamSize = val;
        sizeBtns.forEach(btn => btn.classList.remove('active'));
        updateSortInfo();
      }
    });
  }

  function getValidNames() {
    if (!namesInput) return [];
    return namesInput.value
      .split('\n')
      .map(name => name.trim())
      .filter(name => name.length > 0);
  }

  function updateSortInfo() {
    if (!sortInfo) return;
    const namesCount = getValidNames().length;
    sortInfo.innerHTML = `<span class="hl">${namesCount}</span> jogadores válidos detectados`;

    if (namesCount > 0 && namesCount < teamSize) {
      sortInfo.innerHTML += ` <span style="color:var(--red); font-weight:500;">(Mínimo de ${teamSize} necessário)</span>`;
      if (sortBtn) sortBtn.disabled = true;
    } else if (namesCount === 0) {
      if (sortBtn) sortBtn.disabled = true;
    } else {
      if (sortBtn) sortBtn.disabled = false;
    }
  }

  if (namesInput) namesInput.addEventListener('input', updateSortInfo);

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (namesInput) namesInput.value = '';
      updateSortInfo();
      if (sorteioStage) {
        sorteioStage.innerHTML = `
          <div class="stage-empty">
            <svg viewBox="0 0 24 24"><path d="M16 3h5v5"/><path d="M4 20L21 3"/><path d="M21 16v5h-5"/><path d="M15 15l6 6"/><path d="M4 4l5 5"/></svg>
            <p>Adicione nomes e clique em sortear para gerar os times</p>
          </div>
        `;
      }
      sfx.tick(600);
    });
  }

  function shuffle(array) {
    let currentIndex = array.length, randomIndex;
    while (currentIndex !== 0) {
      randomIndex = Math.floor(Math.random() * currentIndex);
      currentIndex--;
      [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
    }
    return array;
  }

  const teamColors = ['#e5484d', '#3b82f6', '#3dd68c', '#f5a524', '#8b5cf6', '#ec4899', '#14b8a6', '#f97316'];

  if (sortBtn) {
    sortBtn.addEventListener('click', () => {
      const names = getValidNames();
      if (names.length < teamSize) return;

      sorteioStage.innerHTML = `
        <div class="rolling">
          <div class="rolling-label">Sorteando...</div>
          <div class="rolling-name" id="rollingName">···</div>
        </div>
      `;

      const rollingNameEl = document.getElementById('rollingName');
      let rollCount = 0;

      const rollInterval = setInterval(() => {
        rollingNameEl.textContent = names[Math.floor(Math.random() * names.length)];
        rollCount++;
        sfx.tick(800 + Math.random() * 400);

        if (rollCount > 16) {
          clearInterval(rollInterval);
          generateTeams(names);
          sfx.done();
        }
      }, 55);
    });
  }

  function generateTeams(names) {
    const shuffledNames = shuffle([...names]);
    const numTeams = Math.floor(shuffledNames.length / teamSize);
    const leftovers = shuffledNames.length % teamSize;

    let html = `
      <div class="teams-result">
        <div class="teams-header">Sorteio Concluído</div>
        <div class="teams-grid">
    `;

    for (let i = 0; i < numTeams; i++) {
      const color = teamColors[i % teamColors.length];
      html += `
        <div class="team-card" style="--team-color: ${color};">
          <div class="team-card-header">
            <div class="team-badge">${i + 1}</div>
            <div class="team-name">Time ${i + 1}</div>
          </div>
          <div class="team-members">
      `;

      for (let j = 0; j < teamSize; j++) {
        html += `<div class="team-member">${escapeHtml(shuffledNames[i * teamSize + j])}</div>`;
      }

      html += `
          </div>
        </div>
      `;
    }

    if (leftovers > 0) {
      html += `
        <div class="team-card" style="--team-color: #5d5d66;">
          <div class="team-card-header">
            <div class="team-badge">!</div>
            <div class="team-name">Ficaram de fora (${leftovers})</div>
          </div>
          <div class="team-members">
      `;

      for (let i = 0; i < leftovers; i++) {
        html += `<div class="team-member">${escapeHtml(shuffledNames[numTeams * teamSize + i])}</div>`;
      }

      html += `
          </div>
        </div>
      `;
    }

    html += `
        </div>
        <button class="btn btn-secondary resort-btn" id="resortBtn">Sortear Novamente</button>
      </div>
    `;

    sorteioStage.innerHTML = html;

    const resortBtn = document.getElementById('resortBtn');
    if (resortBtn) {
      resortBtn.addEventListener('click', () => {
        sortBtn.click();
      });
    }
  }

  updateSortInfo();

  /* ═══════════════════════════════════════════════
     6. Cacique SCAN Engine v3.1 — Forensic Anti-Cheat
     ═══════════════════════════════════════════════ */
  const scanLoginView = document.getElementById('scanLoginView');
  const scanDashboardView = document.getElementById('scanDashboardView');
  const scanUser = document.getElementById('scanUser');
  const scanPass = document.getElementById('scanPass');
  const scanBtnLogin = document.getElementById('scanBtnLogin');
  const scanBtnLogout = document.getElementById('scanBtnLogout');

  const scanUploadContainer = document.getElementById('scanUploadContainer');
  const scanUploadBox = document.getElementById('scanUploadBox');
  const scanUploadTitle = document.getElementById('scanUploadTitle');
  const scanUploadDesc = document.getElementById('scanUploadDesc');
  const scanFileInput = document.getElementById('scanFileInput');
  const scanFolderInput = document.getElementById('scanFolderInput');
  const scanLooseInput = document.getElementById('scanLooseInput');

  const modeZipBtn = document.getElementById('modeZipBtn');
  const modeFolderBtn = document.getElementById('modeFolderBtn');
  const modeLooseBtn = document.getElementById('modeLooseBtn');

  const scanTerminalWrap = document.getElementById('scanTerminalWrap');
  const terminalLines = document.getElementById('terminalLines');
  const scanProgressFill = document.getElementById('scanProgressFill');
  const scanProgressLabel = document.getElementById('scanProgressLabel');
  const scanProgressPercent = document.getElementById('scanProgressPercent');

  const scanResults = document.getElementById('scanResults');
  const resultSummary = document.getElementById('resultSummary');
  const scanDeviceCard = document.getElementById('scanDeviceCard');
  const scanFilters = document.getElementById('scanFilters');
  const resultDetails = document.getElementById('resultDetails');
  const scanBtnCopyReport = document.getElementById('scanBtnCopyReport');
  const scanBtnNew = document.getElementById('scanBtnNew');

  let currentScanMode = 'zip'; // 'zip', 'folder', 'loose'
  let currentScanReport = null;
  let activeFilterCategory = 'all';

  const ADMIN_USER_VAL = 'CACIQUE';
  const ADMIN_PASS_VAL = 'g.indiopatrocina777';
  const AUTH_STORAGE_KEY = 'cacique_scan_authenticated';

const CHEAT_SIGNATURES = [
    // --- CORINGA CODES & OFFSETS LIBIL2CPP (PDF 2) ---
    { term: 'd0264a54', name: 'HS Cabeça (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0264a55', name: 'Aimbot Direto (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd027a2b6', name: 'Aimbot FOV 0 a 180 (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd1aac609', name: 'Aim Ignorar Derrubados (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd1aac60a', name: 'Aim Lock Mira (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0264a56', name: 'Ghost Teleporte (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0264a57', name: 'Atravessar Paredes (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0264a58', name: 'Medkit em Movimento (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0264a59', name: 'Visão de Águia (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0264a5a', name: 'Dispersão de Tiro Zero (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0264a5b', name: 'Telekill (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0266618', name: 'Pulo 2x/4x Hack (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0266619', name: 'Antena Cabeça (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd026661a', name: 'Alcance Hack (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd026661b', name: 'Chuva de Balas (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd026661c', name: 'Personagem Gigante (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd026661d', name: 'Correr 2x/4x Speed (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd026661e', name: 'Remover Mira / No Recoil (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd026661f', name: 'Carro Fantasma (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd027a2b0', name: 'Céu Preto / Black Sky (Coringa Offset)', cat: 'ff_offset', weight: 90, risk: 'Ban Direto' },
    { term: 'd027a2b1', name: 'Sem Neblina / No Fog (Coringa Offset)', cat: 'ff_offset', weight: 90, risk: 'Ban Direto' },
    { term: 'd027a2b2', name: 'Personagem Branco / Chams (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd027a2b3', name: 'Desbloqueio IMEI / Anti-Ban (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd027a2b4', name: 'Wallhack (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd027a2b5', name: 'ESP Line / Linhas (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd027a2b7', name: 'Limpar Report Automático (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd1aac604', name: 'Soco Rápido Fast Punch (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd1aac605', name: 'No Recoil Sem Recuo (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd1aac607', name: 'Sem Dano Ao Cair (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd1aac608', name: 'Granada Infinita (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd1aac60b', name: 'Ícone Invisível Bypass (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'coringa|', name: 'Injeção Protocolo Coringa Mod Menu', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },

    // --- FREE FIRE OB40 & WEAPON CONFIG CHEATS (PDF 1) ---
    { term: 'aimlock_head_ob40_', name: 'Aimlock OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimbot_head_ob40_', name: 'Aimbot OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'no_recoil_ob40_', name: 'No Recoil OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimfov_ob40_', name: 'Aim FOV OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'sensi_ob40_', name: 'Sensi Hack OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimlock_head_ob', name: 'Aimlock OB FF Config', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimbot_head_ob', name: 'Aimbot OB FF Config', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'no_recoil_ob', name: 'No Recoil OB FF Config', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimfov_ob', name: 'Aim FOV OB FF Config', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'sensi_ob', name: 'Sensi OB FF Config', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'timetomaximumspeed: 9999', name: 'Sensibilidade Ilegal 9999 MaxSpeed', cat: 'ff_cheat', weight: 95, risk: 'Ban Direto' },
    { term: '"timetomaximumspeed": 9999', name: 'Sensibilidade Ilegal 9999 MaxSpeed', cat: 'ff_cheat', weight: 95, risk: 'Ban Direto' },
    { term: '"maximumspeed": 9999', name: 'Velocidade de Mira 9999', cat: 'ff_cheat', weight: 95, risk: 'Ban Direto' },
    { term: 'iphone ob40 editor', name: 'Editor de Sensi / Cheat iOS OB40', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'ipad ob40 editor', name: 'Editor de Sensi / Cheat iPad OB40', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimbot_head+aimlock_head+sem_recuo', name: 'Combo Cheat Aimbot/Aimlock/NoRecoil', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimbot_cabeça+aimlock_cabeça+sem_recuo', name: 'Combo Cheat Mira Cabeça', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'antiban 100%', name: 'Script com Bypass Anti-Ban', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },

    // --- REGEDITS, SMALI & MEMORY PATCHES (PDF 3) ---
    { term: 'fovbotautogame_regedit', name: 'APK FovBot Auto Regedit', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'fovbotautogame', name: 'FovBot Auto Game Cheat', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'memorypatch("libil2cpp.so"', name: 'MemoryPatch em Libil2cpp', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: '0x30665456', name: 'Offset de Patch Libil2cpp (Aimlock)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: '0xEA80100', name: 'Offset de Patch Libil2cpp (Auto HS)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: '0x1C74E08', name: 'Offset de Patch Libil2cpp (Anti-Ban Bypass)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: '0xA7D378', name: 'Offset de Patch Libil2cpp (Aimlock Eagle)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: '0xEB4570', name: 'Offset de Patch Libil2cpp (Tiros na Cabeça)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: '0x4060909', name: 'Patch de Memória FovBot', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'regeditruokff', name: 'Regedit Ruok FF Cheat', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'lcom/regeditruokff', name: 'Classe Injetada RegeditRuokFF', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'at_21_u_weapon_thompson_desc', name: 'Modificação de Descrição de Arma (Injeção Sketchware)', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'getauxaimhsoffreefiremanager', name: 'Auxiliar de Mira FreeFireManager Hook', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'getauxaimhsintentformodelconfiguration', name: 'Auxiliar de Mira Intent Hook', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'auxaimhs', name: 'Auxiliar Aim HS Hook', cat: 'ff_cheat', weight: 95, risk: 'Ban Direto' },
    { term: 'tc_25_todas_as_armas', name: 'Configuração Cheat TC_25 Todas as Armas', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 't_25_lc_todas as armas', name: 'Configuração Cheat T_25 Todas as Armas', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'centralizar_todos_os_tiros_no_meio_da_cabeça', name: 'Aimlock Tiro Centralizado na Cabeça', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'centralizar_no_meio_da_cabeça', name: 'Aimlock Mira Centralizada', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'grudar_na_cabeça_do_jogador_inimigo', name: 'Aimlock Grudar na Cabeça', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'não_desprender_a_qualquer_instante_da_cabeça', name: 'Aimlock Lock Permanente na Cabeça', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'tiros_não_espalhar_na_cabeça', name: 'No Spread Tiros Não Espalhar', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'tiros_seguir_a_cabeça', name: 'Magic Bullet Tiros Seguir Cabeça', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'não_passar_da_cabeça', name: 'Aimlock Não Passar da Cabeça', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'auxílio_para_os_tiros_irem_mais_rápidos', name: 'Fast Bullet / Speed Shot', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aim lock vip ativado', name: 'Aimlock VIP Mod Ativado', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'regedit v1', name: 'Regedit FF V1', cat: 'ff_regedit', weight: 90, risk: 'Ban Direto' },
    { term: 'regedit x', name: 'Regedit FF X', cat: 'ff_regedit', weight: 90, risk: 'Ban Direto' },
    { term: 'smartgaga\\projecttitan\\sensibilidade', name: 'Regedit SmartGaGa ProjectTitan Sensi', cat: 'ff_regedit', weight: 95, risk: 'Ban Direto' },
    { term: 'modelscale 900', name: 'Hitbox / ModelScale Expandido 900', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'modelscale 85%', name: 'Hitbox / ModelScale Adulterado', cat: 'ff_cheat', weight: 95, risk: 'Ban Direto' },
    { term: 'pacotesdeativosjogo/config', name: 'Adulteração de Pacotes de Ativos do FF', cat: 'ff_cheat', weight: 90, risk: 'Ban Direto' },
    { term: 'gameassetbundles/config/0', name: 'Adulteração de AssetBundle Config FF', cat: 'ff_cheat', weight: 90, risk: 'Ban Direto' },

    // --- GAMEGUARDIAN, INJETORES & MOD MENUS ---
    { term: 'gameguardian', name: 'GameGuardian (Editor de Memória)', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: 'catch_', name: 'GameGuardian Process Hook (catch_)', cat: 'injection', weight: 80, risk: 'Alto' },
    { term: 'com.gameguardian', name: 'GameGuardian Package', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: 'bin.mt.plus', name: 'MT Manager VIP', cat: 'mod_tools', weight: 90, risk: 'Alto' },
    { term: 'mt manager', name: 'MT Manager (Modificador de APKs)', cat: 'mod_tools', weight: 80, risk: 'Médio' },
    { term: 'com.zane.mtweaker', name: 'M-Tweaker / MT Manager Plugin', cat: 'mod_tools', weight: 90, risk: 'Alto' },
    { term: 'apkeditor', name: 'APK Editor (Modificador em Runtime)', cat: 'mod_tools', weight: 80, risk: 'Médio' },
    { term: 'lucky patcher', name: 'Lucky Patcher', cat: 'mod_tools', weight: 100, risk: 'Ban Direto' },
    { term: 'com.chelpus.lackypatch', name: 'Lucky Patcher Package', cat: 'mod_tools', weight: 100, risk: 'Ban Direto' },
    { term: 'il2cppdumper', name: 'IL2Cpp Dumper (Engenharia Reversa)', cat: 'mod_tools', weight: 100, risk: 'Ban Direto' },
    { term: 'il2cpp_dumper', name: 'IL2Cpp Dumper', cat: 'mod_tools', weight: 100, risk: 'Ban Direto' },
    { term: 'frida-server', name: 'Frida Server (Injetor de Funções)', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: 'frida-gadget', name: 'Frida Gadget (Injeção em Lib)', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: 'gdbserver', name: 'Debugger GDB Remoto', cat: 'injection', weight: 80, risk: 'Alto' },
    { term: 'auto_clicker', name: 'Macro / Auto Clicker Proibido', cat: 'mod_tools', weight: 65, risk: 'Médio' },

    // --- ROOT, MAGISK, KERNELSU, APATCH, XPOSED ---
    { term: 'top.johnwu.magisk', name: 'Magisk Root Oficial', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'com.topjohnwu.magisk', name: 'Magisk Root Package', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'io.github.huskydg.magisk', name: 'Magisk Delta / Kitsune Mask', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'me.weishu.kernelsu', name: 'KernelSU Root a Nível de Kernel', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'bmax.apatch', name: 'APatch Root / Kernel Patch', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'zygisk', name: 'Zygisk Injeção em Processos', cat: 'root_bypass', weight: 90, risk: 'Ban Direto' },
    { term: 'lsposed', name: 'LSPosed Xposed Framework', cat: 'root_bypass', weight: 90, risk: 'Ban Direto' },
    { term: 'de.robv.android.xposed', name: 'Xposed Framework Legado', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'shamiko', name: 'Módulo Shamiko (Root Hider)', cat: 'root_bypass', weight: 90, risk: 'Ban Direto' },
    { term: 'magiskhide', name: 'Módulo MagiskHide', cat: 'root_bypass', weight: 90, risk: 'Ban Direto' },
    { term: 'superuser', name: 'Superuser / Binário SU', cat: 'root_bypass', weight: 70, risk: 'Médio' },
    { term: 'com.noshufou.android.su', name: 'Superuser App', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'eu.chainfire.supersu', name: 'SuperSU Chainfire', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'com.kingroot.kinguser', name: 'KingRoot', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },

    // --- IOS JAILBREAK, TROLLSTORE & TWEAKS ---
    { term: 'cydia', name: 'Jailbreak Cydia', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'sileo', name: 'Jailbreak Sileo', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'zebra', name: 'Jailbreak Zebra Package Manager', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'unc0ver', name: 'Jailbreak unc0ver', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'checkra1n', name: 'Jailbreak checkra1n Bootrom', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'palera1n', name: 'Jailbreak palera1n Semi-Tethered', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'dopamine', name: 'Jailbreak Dopamine Rootless', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'trollstore', name: 'TrollStore (Instalador IPA com Permissões de Root)', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'com.opa334.trollstore', name: 'TrollStore App Identifier', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: '/var/jb', name: 'Caminho Rootless de Jailbreak (/var/jb)', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: '/private/var/jb', name: 'Caminho Rootless de Jailbreak (/private/var/jb)', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'cydiasubstrate', name: 'CydiaSubstrate Hook Injector', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'mobilesubstrate', name: 'MobileSubstrate Hook Injector', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'ellekit', name: 'ElleKit Tweak Injector', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'substituted', name: 'Substitute Tweak Injector', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'com.tigisoftware.filza', name: 'Filza File Manager (Root Explorer iOS)', cat: 'root_bypass', weight: 95, risk: 'Ban Direto' },
    { term: 'flexdecrypt', name: 'IPA Decryptor FlexDecrypt', cat: 'mod_tools', weight: 90, risk: 'Alto' },
    { term: 'bfdecrypt', name: 'IPA Decryptor bfdecrypt', cat: 'mod_tools', weight: 90, risk: 'Alto' },

    // --- PROXY & INTERCEPTADORES DE REDE ---
    { term: 'httpcanary', name: 'HttpCanary (Sniffer de Pacotes)', cat: 'proxy_net', weight: 95, risk: 'Ban Direto' },
    { term: 'com.guoshi.httpcanary', name: 'HttpCanary App Package', cat: 'proxy_net', weight: 100, risk: 'Ban Direto' },
    { term: 'charlesproxy', name: 'Charles Proxy', cat: 'proxy_net', weight: 90, risk: 'Alto' },
    { term: 'burpsuite', name: 'Burp Suite Interceptor', cat: 'proxy_net', weight: 90, risk: 'Alto' },
    { term: 'portswigger', name: 'PortSwigger Burp Proxy', cat: 'proxy_net', weight: 90, risk: 'Alto' },
    { term: 'proxyman', name: 'Proxyman Interceptor', cat: 'proxy_net', weight: 85, risk: 'Alto' },
    { term: 'mitmproxy', name: 'Mitmproxy Man-in-the-Middle', cat: 'proxy_net', weight: 90, risk: 'Alto' },
    { term: '127.0.0.1:8080', name: 'Proxy Local Aberto 8080', cat: 'proxy_net', weight: 65, risk: 'Médio' },
    { term: '127.0.0.1:8888', name: 'Proxy Fiddler/Charles 8888', cat: 'proxy_net', weight: 75, risk: 'Médio' },

    // --- EMULADORES & VIRTUAIS ---
    { term: 'com.vphone.launcher', name: 'VMOS Virtual Machine', cat: 'emulator_clone', weight: 80, risk: 'Alto' },
    { term: 'vphonegaga', name: 'VPhoneGaGa Virtual Android', cat: 'emulator_clone', weight: 80, risk: 'Alto' },
    { term: 'x8sandbox', name: 'X8 Sandbox Virtual Space', cat: 'emulator_clone', weight: 80, risk: 'Alto' },
    { term: 'f1vm', name: 'F1 VM Virtual Machine', cat: 'emulator_clone', weight: 80, risk: 'Alto' },
    { term: 'virtualxposed', name: 'VirtualXposed Container', cat: 'emulator_clone', weight: 85, risk: 'Alto' },
    { term: 'com.lbe.parallel', name: 'Parallel Space Cloner', cat: 'emulator_clone', weight: 60, risk: 'Médio' },
    { term: 'com.bstk.android', name: 'BlueStacks Android Subsystem', cat: 'emulator_clone', weight: 60, risk: 'Médio' },
    { term: 'projecttitan', name: 'SmartGaGa ProjectTitan Emulador', cat: 'emulator_clone', weight: 75, risk: 'Médio' }
  ];

  const CATEGORY_NAMES = {
    all: 'Todas',
    ff_cheat: '🎯 Cheats Free Fire',
    ff_offset: '⚡ Offsets de Memória',
    ff_regedit: '📝 Regedits & Macros',
    injection: '💉 Injeção & Hooking',
    root_bypass: '🔓 Root & Bypass',
    proxy_net: '🌐 Proxy & Rede',
    mod_tools: '🛠️ Ferramentas Mod',
    emulator_clone: '💻 Emuladores & Clones'
  };

  const SKIP_EXTENSIONS = [
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.ico', '.heic',
    '.mp4', '.mov', '.avi', '.mkv', '.mp3', '.wav', '.ogg', '.m4a',
    '.ttf', '.otf', '.woff', '.woff2'
  ];

  function isRelevantEntry(path) {
    const lower = path.toLowerCase().replace(/\\/g, '/');
    return !SKIP_EXTENSIONS.some(ext => lower.endsWith(ext));
  }

  function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  function clearFileInputs() {
    if (scanFileInput) scanFileInput.value = '';
    if (scanFolderInput) scanFolderInput.value = '';
    if (scanLooseInput) scanLooseInput.value = '';
  }

  // ─────────────────────────────────────────────────────────────
  // Autenticação com Toasts e Feedback Visual (Sem Alert)
  // ─────────────────────────────────────────────────────────────
  if (localStorage.getItem(AUTH_STORAGE_KEY) === 'true') {
    if (scanLoginView && scanDashboardView) {
      scanLoginView.style.display = 'none';
      scanDashboardView.style.display = 'block';
    }
  }

  if (scanBtnLogin) {
    scanBtnLogin.addEventListener('click', () => {
      const user = (scanUser.value || '').trim();
      const pass = (scanPass.value || '').trim();

      [scanUser, scanPass].forEach(input => input.classList.remove('is-invalid'));

      if (user === ADMIN_USER_VAL && pass === ADMIN_PASS_VAL) {
        localStorage.setItem(AUTH_STORAGE_KEY, 'true');
        scanLoginView.style.display = 'none';
        scanDashboardView.style.display = 'block';
        sfx.done();
        showToast('success', 'Acesso Autorizado', 'Sessão de ADM liberada para análise forense.');
      } else {
        sfx.error();
        [scanUser, scanPass].forEach(input => {
          input.classList.add('is-invalid');
          setTimeout(() => input.classList.remove('is-invalid'), 600);
        });
        showToast('error', 'Credenciais Inválidas', 'Usuário ou senha de ADM incorretos.');
      }
    });

    [scanUser, scanPass].forEach(input => {
      if (input) {
        input.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') scanBtnLogin.click();
        });
      }
    });
  }

  if (scanBtnLogout) {
    scanBtnLogout.addEventListener('click', () => {
      localStorage.removeItem(AUTH_STORAGE_KEY);
      if (scanUser) scanUser.value = '';
      if (scanPass) scanPass.value = '';
      scanDashboardView.style.display = 'none';
      scanLoginView.style.display = 'block';
      resetScan();
      sfx.tick(500);
      showToast('info', 'Sessão Encerrada', 'Scanner bloqueado com sucesso.');
    });
  }

  // ─────────────────────────────────────────────────────────────
  // Seletor de Modo (Zip, Pasta, Arquivos)
  // ─────────────────────────────────────────────────────────────
  function setScanMode(mode) {
    currentScanMode = mode;
    [modeZipBtn, modeFolderBtn, modeLooseBtn].forEach(b => {
      if (b) b.classList.remove('active');
    });

    if (mode === 'zip') {
      if (modeZipBtn) modeZipBtn.classList.add('active');
      if (scanUploadTitle) scanUploadTitle.textContent = 'Arraste o arquivo .zip aqui';
      if (scanUploadDesc) scanUploadDesc.textContent = 'Bugreport Android (.zip), Sysdiagnose iOS (.tar.gz) ou dump de cheat';
    } else if (mode === 'folder') {
      if (modeFolderBtn) modeFolderBtn.classList.add('active');
      if (scanUploadTitle) scanUploadTitle.textContent = 'Clique para selecionar uma Pasta Extraída';
      if (scanUploadDesc) scanUploadDesc.textContent = 'Selecione a pasta descompactada do dump ou diretório do jogo no PC/celular';
    } else {
      if (modeLooseBtn) modeLooseBtn.classList.add('active');
      if (scanUploadTitle) scanUploadTitle.textContent = 'Selecione arquivos soltos / logs';
      if (scanUploadDesc) scanUploadDesc.textContent = 'Selecione um ou vários arquivos de texto, logs, dumpsys, prop, etc.';
    }
    sfx.tick(900);
  }

  if (modeZipBtn) modeZipBtn.addEventListener('click', (e) => { e.stopPropagation(); setScanMode('zip'); });
  if (modeFolderBtn) modeFolderBtn.addEventListener('click', (e) => { e.stopPropagation(); setScanMode('folder'); });
  if (modeLooseBtn) modeLooseBtn.addEventListener('click', (e) => { e.stopPropagation(); setScanMode('loose'); });

  if (scanUploadBox) {
    scanUploadBox.addEventListener('click', () => {
      if (currentScanMode === 'zip') {
        scanFileInput.click();
      } else if (currentScanMode === 'folder') {
        scanFolderInput.click();
      } else {
        scanLooseInput.click();
      }
    });

    // Drag-and-drop interativo (borda contínua iluminada + leve escala)
    scanUploadBox.addEventListener('dragover', (e) => {
      e.preventDefault();
      scanUploadBox.classList.add('dragover');
    });

    scanUploadBox.addEventListener('dragleave', (e) => {
      e.preventDefault();
      scanUploadBox.classList.remove('dragover');
    });

    scanUploadBox.addEventListener('drop', (e) => {
      e.preventDefault();
      scanUploadBox.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files.length) {
        startScanProcess(e.dataTransfer.files);
      }
    });

    if (scanFileInput) {
      scanFileInput.addEventListener('change', () => {
        if (scanFileInput.files && scanFileInput.files.length) {
          startScanProcess(scanFileInput.files);
        }
      });
    }

    if (scanFolderInput) {
      scanFolderInput.addEventListener('change', () => {
        if (scanFolderInput.files && scanFolderInput.files.length) {
          startScanProcess(scanFolderInput.files);
        }
      });
    }

    if (scanLooseInput) {
      scanLooseInput.addEventListener('change', () => {
        if (scanLooseInput.files && scanLooseInput.files.length) {
          startScanProcess(scanLooseInput.files);
        }
      });
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Terminal forense: fila com timestamp real e atraso dinâmico
  // ─────────────────────────────────────────────────────────────
  const LOG_LEVELS = { info: 'INFO', parse: 'PARSE', analysis: 'ANALYSIS', ok: 'OK', warn: 'DETECT', error: 'ERROR' };
  let logQueue = [];
  let logPumpRunning = false;
  let logDrainWaiters = [];

  function formatClock(d) {
    const p = (n, l = 2) => String(n).padStart(l, '0');
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
  }

  function formatBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }

  function log(level, text) {
    logQueue.push({ level, text, time: new Date() });
    if (!logPumpRunning) pumpLogs();
  }

  async function pumpLogs() {
    logPumpRunning = true;
    while (logQueue.length) {
      renderLogLine(logQueue.shift());
      const backlog = logQueue.length;
      const delay = backlog > 30 ? 0 : backlog > 10 ? 6 : 18 + Math.random() * 55;
      if (delay) await sleep(delay);
    }
    logPumpRunning = false;
    logDrainWaiters.splice(0).forEach(fn => fn());
  }

  function waitLogsDrained() {
    if (!logPumpRunning && !logQueue.length) return Promise.resolve();
    return new Promise(r => logDrainWaiters.push(r));
  }

  function renderLogLine({ level, text, time }) {
    if (!terminalLines) return;
    const row = document.createElement('div');
    row.className = `terminal-line lvl-${level}`;
    const t = document.createElement('span');
    t.className = 't-time';
    t.textContent = `[${formatClock(time)}]`;
    const l = document.createElement('span');
    l.className = 't-lvl';
    l.textContent = `[${LOG_LEVELS[level] || 'INFO'}]`;
    const m = document.createElement('span');
    m.className = 't-msg';
    m.textContent = text;
    row.append(t, l, m);
    terminalLines.appendChild(row);
    terminalLines.scrollTop = terminalLines.scrollHeight;

    if (level === 'warn') sfx.alert();
    else if (level !== 'parse') sfx.tick(1200);
  }

  function setTerminalStatus(text, cls = '') {
    const el = document.getElementById('terminalStatus');
    if (!el) return;
    el.textContent = text;
    el.className = 'terminal-status-indicator ' + cls;
  }

  function setProgress(percent, label) {
    if (scanProgressFill) scanProgressFill.style.width = Math.min(100, Math.max(0, percent)) + '%';
    if (scanProgressPercent) scanProgressPercent.textContent = Math.round(percent) + '%';
    if (scanProgressLabel) scanProgressLabel.textContent = label;
  }

  // ─────────────────────────────────────────────────────────────
  // Motor de Extração de Strings & Informações
  // ─────────────────────────────────────────────────────────────
  const BINARY_EXT = /\.(so|dex|dylib|odex|vdex|oat|apk|arsc|db|sqlite|bin|dat)$/i;
  const ARCHIVE_RE = /\.(zip|tar\.gz|tgz|tar|gz)$/i;
  const latin1 = new TextDecoder('latin1');
  const utf8 = new TextDecoder('utf-8');

  function extractPrintableStrings(bytes, minLen = 5) {
    const out = [];
    let start = -1;
    for (let i = 0; i <= bytes.length; i++) {
      const c = i < bytes.length ? bytes[i] : 0;
      if (c >= 32 && c <= 126) {
        if (start < 0) start = i;
      } else if (start >= 0) {
        if (i - start >= minLen) out.push(latin1.decode(bytes.subarray(start, i)));
        start = -1;
      }
    }
    return out.join('\n');
  }

  function extractDeviceInfo(text, deviceInfo) {
    const mModel = text.match(/ro\.product\.model\s*[:=]\s*([^\r\n]+)/i) ||
                   text.match(/model\s*[:=]\s*([^\r\n]+)/i);
    if (mModel && !deviceInfo.model) deviceInfo.model = mModel[1].trim();

    const mBrand = text.match(/ro\.product\.manufacturer\s*[:=]\s*([^\r\n]+)/i) ||
                   text.match(/ro\.product\.brand\s*[:=]\s*([^\r\n]+)/i);
    if (mBrand && !deviceInfo.brand) deviceInfo.brand = mBrand[1].trim();

    const mVer = text.match(/ro\.build\.version\.release\s*[:=]\s*([^\r\n]+)/i) ||
                 text.match(/Android\s+Version\s*[:=]?\s*([0-9.]+)/i);
    if (mVer && !deviceInfo.osVersion) deviceInfo.osVersion = 'Android ' + mVer[1].trim();

    const mSerial = text.match(/ro\.serialno\s*[:=]\s*([^\r\n]+)/i) ||
                    text.match(/ro\.boot\.serialno\s*[:=]\s*([^\r\n]+)/i);
    if (mSerial && !deviceInfo.serial) deviceInfo.serial = mSerial[1].trim();

    const mKernel = text.match(/Linux\s+version\s+([0-9a-zA-Z._\-+]+)/i);
    if (mKernel && !deviceInfo.kernel) deviceInfo.kernel = 'Linux ' + mKernel[1].trim();

    const mIosProd = text.match(/<key>ProductType<\/key>\s*<string>([^<]+)<\/string>/i);
    if (mIosProd && !deviceInfo.model) deviceInfo.model = mIosProd[1].trim();

    const mIosVer = text.match(/<key>ProductVersion<\/key>\s*<string>([^<]+)<\/string>/i);
    if (mIosVer && !deviceInfo.osVersion) deviceInfo.osVersion = 'iOS ' + mIosVer[1].trim();

    const mIosSerial = text.match(/<key>SerialNumber<\/key>\s*<string>([^<]+)<\/string>/i);
    if (mIosSerial && !deviceInfo.serial) deviceInfo.serial = mIosSerial[1].trim();
  }

  async function readZipEntries(file) {
    let zip;
    try {
      zip = await JSZip.loadAsync(file);
    } catch (e) {
      throw new Error('O arquivo não é um .zip válido (corrompido ou incompleto).');
    }
    return Object.values(zip.files).filter(e => !e.dir).map(e => ({
      path: e.name,
      bytes: () => e.async('uint8array'),
      text: () => e.async('string')
    }));
  }

  async function gunzip(file) {
    if (typeof DecompressionStream === 'undefined') {
      throw new Error('Este navegador não descomprime .gz. Extraia o arquivo e use "Pasta extraída".');
    }
    const stream = file.stream().pipeThrough(new DecompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  function parseTar(buf) {
    if (buf.length < 512 || latin1.decode(buf.subarray(257, 262)) !== 'ustar') return null;
    const entries = [];
    const cstr = (b) => latin1.decode(b).replace(/\0[\s\S]*$/, '');
    let off = 0;
    let pendingName = null;

    while (off + 512 <= buf.length) {
      const h = buf.subarray(off, off + 512);
      if (h[0] === 0 && h.every(b => b === 0)) break;

      let name = cstr(h.subarray(0, 100));
      const prefix = cstr(h.subarray(345, 500));
      const size = parseInt(cstr(h.subarray(124, 136)).trim() || '0', 8) || 0;
      const type = String.fromCharCode(h[156] || 48);
      const dataStart = off + 512;
      const data = buf.subarray(dataStart, dataStart + size);

      if (type === 'L') {
        pendingName = cstr(data);
      } else if (type === 'x') {
        const m = utf8.decode(data).match(/\d+ path=([^\n]+)\n/);
        if (m) pendingName = m[1];
      } else if (type === '0' || type === '7') {
        if (pendingName) name = pendingName;
        else if (prefix) name = prefix + '/' + name;
        pendingName = null;
        entries.push({ path: name, bytes: async () => data, text: async () => utf8.decode(data) });
      } else if (type !== 'g') {
        pendingName = null;
      }
      off = dataStart + Math.ceil(size / 512) * 512;
    }
    return entries;
  }

  async function readTarLike(file) {
    const lower = file.name.toLowerCase();
    const raw = lower.endsWith('.tar') ? new Uint8Array(await file.arrayBuffer()) : await gunzip(file);
    const entries = parseTar(raw);
    if (entries) return entries;
    return [{ path: file.name.replace(/\.gz$/i, ''), bytes: async () => raw, text: async () => utf8.decode(raw) }];
  }

  function readFileListEntries(files) {
    return files.map(f => ({
      path: f.webkitRelativePath || f.name,
      bytes: async () => new Uint8Array(await f.arrayBuffer()),
      text: () => f.text()
    }));
  }

  // ─────────────────────────────────────────────────────────────
  // Execução do Scan (100% In-Browser)
  // ─────────────────────────────────────────────────────────────
  let scanBusy = false;

  async function startScanProcess(fileList) {
    if (!fileList || fileList.length === 0) return;
    if (scanBusy) {
      showToast('info', 'Análise em andamento', 'Aguarde o scan atual terminar.');
      return;
    }

    const files = Array.from(fileList);
    const first = files[0];
    const isArchive = files.length === 1 && ARCHIVE_RE.test(first.name);

    if (currentScanMode === 'zip' && !isArchive) {
      sfx.error();
      showToast('error', 'Arquivo inválido', 'Neste modo envie um único .zip, .tar.gz ou .tar. Para outros use "Logs soltos".');
      clearFileInputs();
      return;
    }
    if (files.every(f => f.size === 0)) {
      sfx.error();
      showToast('error', 'Arquivo vazio', 'O arquivo selecionado tem 0 bytes.');
      clearFileInputs();
      return;
    }

    scanBusy = true;
    scanUploadContainer.style.display = 'none';
    scanTerminalWrap.style.display = 'block';
    scanResults.style.display = 'none';
    terminalLines.innerHTML = '';
    logQueue = [];
    setTerminalStatus('ANALISANDO');
    sfx.tick(1200);

    const startTime = performance.now();
    log('info', 'ccq-scan 3.1 — motor local, nenhum dado sai do navegador');
    if (isArchive) {
      log('info', `Lendo cabeçalho do arquivo ${first.name} (${formatBytes(first.size)})...`);
    } else {
      log('info', `${files.length} arquivo(s) recebidos de ${currentScanMode === 'folder' ? 'pasta extraída' : 'seleção manual'}`);
    }
    setProgress(4, 'Preparando...');
    await sleep(40);

    const findings = [];
    const seen = new Set();
    let analyzedCount = 0;
    let skippedCount = 0;
    let totalScore = 0;
    let osDetected = 'ANDROID';
    let gamePkgSeen = false;
    const deviceInfo = { brand: '', model: '', osVersion: '', serial: '', kernel: '' };

    try {
      let entries;
      if (isArchive && /\.zip$/i.test(first.name)) {
        if (typeof JSZip === 'undefined') throw new Error('JSZip não carregou. Recarregue a página.');
        setProgress(10, 'Lendo índice do .zip...');
        entries = await readZipEntries(first);
      } else if (isArchive) {
        setProgress(10, 'Descomprimindo...');
        log('parse', 'Descomprimindo fluxo gzip/tar em memória...');
        entries = await readTarLike(first);
      } else {
        entries = readFileListEntries(files);
      }

      const totalRaw = entries.length;
      if (entries.some(e => /sysdiagnose|\.plist$|\.ips$/i.test(e.path))) osDetected = 'IOS';
      entries = entries.filter(e => isRelevantEntry(e.path));
      log('info', `Estrutura indexada: ${totalRaw} entradas, ${entries.length} relevantes (mídia ignorada)`);
      if (!entries.length) throw new Error('Nenhum arquivo analisável foi encontrado no pacote.');
      log('analysis', `Sistema alvo: ${osDetected === 'IOS' ? 'iOS (sysdiagnose)' : 'Android (bugreport/dump)'}`);

      const total = entries.length;
      for (let i = 0; i < total; i++) {
        const entry = entries[i];
        const name = entry.path.split('/').pop();

        if (i % 4 === 0 || i === total - 1) {
          setProgress(12 + Math.round(((i + 1) / total) * 84), `${name} (${i + 1}/${total})`);
        }

        try {
          let text = '';
          if (BINARY_EXT.test(entry.path)) {
            const bytes = await entry.bytes();
            if (bytes.length <= 24 * 1024 * 1024) text = extractPrintableStrings(bytes);
          } else {
            text = await entry.text();
          }

          if (!text) {
            skippedCount++;
            continue;
          }

          if (text.length > 1024 * 1024) log('parse', `Extraindo ${name} (${formatBytes(text.length)})`);

          extractDeviceInfo(text, deviceInfo);

          if (!gamePkgSeen && /com\.dts\.freefire(th|max)/i.test(text)) {
            gamePkgSeen = true;
            log('analysis', `Pacote com.dts.freefireth localizado em ${name} — verificando integridade...`);
          }

          for (const f of scanTextForCheats(text, entry.path)) {
            const key = f.name + '|' + f.file;
            if (seen.has(key)) continue;
            seen.add(key);
            findings.push(f);
            totalScore += f.weight;
            log('warn', `${f.name} → ${name}`);
          }
          analyzedCount++;
        } catch (e) {
          skippedCount++;
        }

        if (i % 10 === 0) await sleep(0);
      }

      const durationSec = ((performance.now() - startTime) / 1000).toFixed(1);
      log('info', `Varredura concluída: ${analyzedCount} lidos, ${skippedCount} ignorados em ${durationSec}s`);
      setProgress(98, 'Compilando relatório...');

      let veredito = '100% LIMPO (VERIFICADO)';
      let colorClass = 'green';
      const hasDirectBan = findings.some(f => f.risk.includes('Ban Direto') || f.weight >= 90);

      if (hasDirectBan || totalScore >= 100) {
        veredito = 'DETECTADO (CHEATER)';
        colorClass = 'red';
      } else if (totalScore >= 30 || findings.length > 0) {
        veredito = 'SUSPEITO (REVISÃO MANUAL)';
        colorClass = 'yellow';
      }

      log(colorClass === 'red' ? 'error' : colorClass === 'yellow' ? 'warn' : 'ok',
        findings.length ? `${findings.length} indicador(es) — veredito: ${veredito}` : `Nenhuma assinatura encontrada — ${veredito}`);

      currentScanReport = {
        targetName: isArchive ? first.name : (files.length + ' arquivos'),
        targetSizeMb: isArchive ? (first.size / 1024 / 1024).toFixed(2) : null,
        os: osDetected,
        veredito,
        colorClass,
        totalScore,
        analyzedCount,
        skippedCount,
        durationSec,
        deviceInfo,
        findings,
        timestamp: new Date().toLocaleString('pt-BR')
      };

      await waitLogsDrained();
      setTerminalStatus('CONCLUÍDO', 'is-done');
      setProgress(100, `Concluído em ${durationSec}s`);
      if (colorClass === 'red') sfx.alert(true);
      else sfx.done();
      await sleep(350);

      renderScanResults(currentScanReport);
    } catch (err) {
      log('error', err.message || String(err));
      await waitLogsDrained();
      setTerminalStatus('FALHOU', 'is-error');
      sfx.error();
      showToast('error', 'Falha na análise', err.message || 'Arquivo corrompido ou formato não suportado.', 4500);
      setTimeout(resetScan, 3500);
    } finally {
      scanBusy = false;
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Varredura de Texto por Assinaturas
  // ─────────────────────────────────────────────────────────────
  function scanTextForCheats(text, filePath) {
    const hits = [];
    const textLower = text.toLowerCase();

    for (const sig of CHEAT_SIGNATURES) {
      const idx = textLower.indexOf(sig.term.toLowerCase());
      if (idx !== -1) {
        const snippetStart = Math.max(0, idx - 40);
        const snippetEnd = Math.min(text.length, idx + sig.term.length + 50);
        const rawSnippet = text.substring(snippetStart, snippetEnd).replace(/\r?\n/g, ' ');

        hits.push({
          term: sig.term,
          name: sig.name,
          category: sig.cat,
          categoryLabel: CATEGORY_NAMES[sig.cat] || sig.cat,
          weight: sig.weight,
          risk: sig.risk,
          file: filePath,
          snippet: rawSnippet
        });
      }
    }
    return hits;
  }

  // ─────────────────────────────────────────────────────────────
  // Renderização Visual dos Resultados
  // ─────────────────────────────────────────────────────────────
  function renderScanResults(report) {
    scanTerminalWrap.style.display = 'none';
    scanResults.style.display = 'block';

    const colorHex = report.colorClass === 'red' ? '#e5484d' : (report.colorClass === 'yellow' ? '#f5a524' : '#3dd68c');

    resultSummary.innerHTML = `
      <h3 style="color:${colorHex}">${report.veredito}</h3>
      <p>Alvo: <strong>${escapeHtml(report.targetName)}</strong> &nbsp;|&nbsp; Pontuação de Risco: <strong>${report.totalScore}</strong></p>
      <div class="scan-stats-grid">
        <div class="scan-stat-card">
          <div class="scan-stat-val" style="color:var(--green);">${report.analyzedCount}</div>
          <div class="scan-stat-lbl">Arquivos Lidos</div>
        </div>
        <div class="scan-stat-card">
          <div class="scan-stat-val" style="color:${colorHex};">${report.findings.length}</div>
          <div class="scan-stat-lbl">Ameaças Detectadas</div>
        </div>
        <div class="scan-stat-card">
          <div class="scan-stat-val" style="color:var(--blue);">${report.durationSec}s</div>
          <div class="scan-stat-lbl">Tempo de Varredura</div>
        </div>
      </div>
    `;

    const dev = report.deviceInfo;
    const hasDeviceData = dev.brand || dev.model || dev.osVersion || dev.serial || dev.kernel;
    if (hasDeviceData) {
      scanDeviceCard.style.display = 'block';
      const deviceModel = [dev.brand, dev.model].filter(Boolean).join(' ') || 'Não identificado';
      scanDeviceCard.innerHTML = `
        <div class="scan-device-header">📱 Dispositivo Analisado (Prova Forense)</div>
        <div class="device-spec-grid">
          <div class="device-spec-item">Aparelho: <strong>${escapeHtml(deviceModel)}</strong></div>
          <div class="device-spec-item">Sistema: <strong>${escapeHtml(dev.osVersion || report.os)}</strong></div>
          ${dev.serial ? `<div class="device-spec-item">HWID/Serial: <strong>${escapeHtml(dev.serial)}</strong></div>` : ''}
          ${dev.kernel ? `<div class="device-spec-item">Kernel: <strong>${escapeHtml(dev.kernel)}</strong></div>` : ''}
        </div>
      `;
    } else {
      scanDeviceCard.style.display = 'none';
    }

    renderCategoryFilters(report.findings);
    renderThreatList(report.findings, activeFilterCategory);
  }

  function renderCategoryFilters(findings) {
    if (!scanFilters) return;
    if (!findings || findings.length === 0) {
      scanFilters.style.display = 'none';
      return;
    }

    scanFilters.style.display = 'flex';
    const categoriesPresent = new Set(findings.map(f => f.category));

    let html = `
      <button class="scan-filter-chip ${activeFilterCategory === 'all' ? 'active' : ''}" data-cat="all">
        Todas (${findings.length})
      </button>
    `;

    categoriesPresent.forEach(cat => {
      const count = findings.filter(f => f.category === cat).length;
      html += `
        <button class="scan-filter-chip ${activeFilterCategory === cat ? 'active' : ''}" data-cat="${cat}">
          ${CATEGORY_NAMES[cat] || cat} (${count})
        </button>
      `;
    });

    scanFilters.innerHTML = html;

    scanFilters.querySelectorAll('.scan-filter-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        activeFilterCategory = chip.dataset.cat;
        scanFilters.querySelectorAll('.scan-filter-chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        renderThreatList(currentScanReport.findings, activeFilterCategory);
        sfx.tick(1000);
      });
    });
  }

  function renderThreatList(findings, categoryFilter) {
    if (!resultDetails) return;

    if (!findings || findings.length === 0) {
      resultDetails.innerHTML = `
        <div class="result-card green">
          <div class="rc-type">Tudo Limpo ✓</div>
          <div class="rc-file">Nenhuma assinatura de cheat, offset ou modificador conhecido foi encontrado no dump.</div>
        </div>
      `;
      return;
    }

    const filtered = categoryFilter === 'all' ? findings : findings.filter(f => f.category === categoryFilter);

    if (filtered.length === 0) {
      resultDetails.innerHTML = `
        <div class="result-card green">
          <div class="rc-type">Nenhum item nesta categoria</div>
        </div>
      `;
      return;
    }

    let html = '';
    filtered.forEach(item => {
      const cardColor = item.weight >= 85 ? '' : 'yellow';
      const cleanSnippet = escapeHtml(item.snippet);
      const highlightedSnippet = cleanSnippet.replace(new RegExp(escapeRegExp(item.term), 'gi'), m => `<span class="hl">${m}</span>`);

      html += `
        <div class="result-card ${cardColor}">
          <div class="result-card-top">
            <div class="rc-type">${escapeHtml(item.name)}</div>
            <span class="threat-tag">${item.categoryLabel}</span>
          </div>
          <div class="threat-meta">
            Arquivo: <strong>${escapeHtml(item.file)}</strong> &bull; Severidade: <strong>${item.risk}</strong> (Peso: ${item.weight})
          </div>
          <div class="threat-evidence-code">
            ...${highlightedSnippet}...
          </div>
        </div>
      `;
    });

    resultDetails.innerHTML = html;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, m => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
    }[m]));
  }

  function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // ─────────────────────────────────────────────────────────────
  // 7. Copiar Relatório Oficial (Discord / WhatsApp)
  // ─────────────────────────────────────────────────────────────
  if (scanBtnCopyReport) {
    scanBtnCopyReport.addEventListener('click', () => {
      if (!currentScanReport) return;

      const r = currentScanReport;
      const dev = r.deviceInfo;
      const devStr = [dev.brand, dev.model].filter(Boolean).join(' ') || 'Não identificado';

      let text = `══════════════════════════════════════════\n`;
      text += `🛡️ CACIQUE ANTI-CHEAT — RELATÓRIO OFICIAL\n`;
      text += `══════════════════════════════════════════\n`;
      text += `📅 Data: ${r.timestamp}\n`;
      text += `🎯 Alvo: ${r.targetName}${r.targetSizeMb ? ' (' + r.targetSizeMb + ' MB)' : ''}\n`;
      text += `📱 Dispositivo: ${devStr} | ${dev.osVersion || r.os}\n`;
      if (dev.serial) text += `🔑 HWID/Serial: ${dev.serial}\n`;
      if (dev.kernel) text += `🐧 Kernel: ${dev.kernel}\n`;
      text += `📊 VEREDITO: ${r.veredito}\n`;
      text += `⚠️ Pontuação de Risco: ${r.totalScore} pontos\n`;
      text += `📁 Arquivos Analisados: ${r.analyzedCount}\n`;
      text += `⏱️ Tempo de Scan: ${r.durationSec}s\n`;
      text += `------------------------------------------\n`;

      if (r.findings.length > 0) {
        text += `🚨 AMEAÇAS ENCONTRADAS (${r.findings.length}):\n`;
        r.findings.forEach((f, idx) => {
          text += `\n${idx + 1}. [${f.categoryLabel}] ${f.name}\n`;
          text += `   - Termo: "${f.term}"\n`;
          text += `   - Arquivo: ${f.file}\n`;
          text += `   - Risco: ${f.risk}\n`;
        });
      } else {
        text += `✅ Nenhuma ameaça detectada. Dump 100% verificado.\n`;
      }

      text += `------------------------------------------\n`;
      text += `🔍 Cacique SCAN Engine v3.1 // Anti-Cheat Oficial\n`;
      text += `══════════════════════════════════════════`;

      performCopy(text, scanBtnCopyReport, 'Relatório copiado!');
    });
  }

  function resetScan() {
    clearFileInputs();
    if (scanTerminalWrap) scanTerminalWrap.style.display = 'none';
    if (scanResults) scanResults.style.display = 'none';
    if (scanUploadContainer) scanUploadContainer.style.display = 'block';
    currentScanReport = null;
    activeFilterCategory = 'all';
    logQueue = [];
    scanBusy = false;
  }

  if (scanBtnNew) {
    scanBtnNew.addEventListener('click', () => {
      resetScan();
      sfx.tick(900);
    });
  }

  // ─────────────────────────────────────────────────────────────
  // 8. Nossas Redes — Abas & Feedback de Cópia Ativo
  // ─────────────────────────────────────────────────────────────
  const tabBtns = document.querySelectorAll('.rede-tab-btn');
  const tabContents = document.querySelectorAll('.redes-tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;

      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetContent = document.getElementById('tab-' + target);
      if (targetContent) targetContent.classList.add('active');
      sfx.tick(1000);
    });
  });

  document.querySelectorAll('.rede-copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const url = btn.dataset.copy;
      if (!url) return;
      performCopy(url, btn, 'Copiado!');
    });
  });
});
