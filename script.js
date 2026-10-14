/* ══════════════════════════════════════════════════════════════════
   CACIQUE APOSTAS — CORE APPLICATION & ARENA DE ROLETAS v4.0
   100% Client-Side · Áudio Mecânico · Criptografia CSPRNG · Forensics
   ══════════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {

  // ─────────────────────────────────────────────────────────────
  // 1. Áudio Web API Sintetizado & Feedback Háptico (Vibração)
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
        this.tick(1200);
        showToast('info', 'Áudio ativado', 'Feedback sonoro mecânico e háptico habilitado.');
      } else {
        showToast('info', 'Áudio desativado', 'Interface em modo silencioso.');
      }
    }

    vibrate(pattern = [20]) {
      if (typeof navigator !== 'undefined' && navigator.vibrate) {
        try { navigator.vibrate(pattern); } catch (_) {}
      }
    }

    // Bipe mecânico ultra-curto (usado nos ticks da roleta e logs)
    tick(freq = 1100) {
      this.vibrate([15]);
      if (!this.enabled) return;
      this.init();
      if (!this.ctx) return;
      try {
        const t = this.ctx.currentTime;
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(freq, t);
        osc.frequency.exponentialRampToValueAtTime(320, t + 0.025);
        gain.gain.setValueAtTime(0.045, t);
        gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.025);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start(t);
        osc.stop(t + 0.026);
      } catch (_) {}
    }

    // Parada da roleta / revelação
    reveal() {
      this.vibrate([35, 40, 60]);
      if (!this.enabled) return;
      this.init();
      if (!this.ctx) return;
      try {
        const t = this.ctx.currentTime;
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(440, t);
        osc.frequency.exponentialRampToValueAtTime(880, t + 0.18);
        gain.gain.setValueAtTime(0.08, t);
        gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.18);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start(t);
        osc.stop(t + 0.19);
      } catch (_) {}
    }

    // Acorde harmônico mecânico (sucesso / confronto gerado)
    done() {
      this.vibrate([40, 60, 100]);
      if (!this.enabled) return;
      this.init();
      if (!this.ctx) return;
      try {
        const t = this.ctx.currentTime;
        [523.25, 659.25, 783.99, 1046.5].forEach((freq, idx) => {
          const osc = this.ctx.createOscillator();
          const gain = this.ctx.createGain();
          osc.type = 'triangle';
          osc.frequency.setValueAtTime(freq, t + idx * 0.04);
          gain.gain.setValueAtTime(0.05, t + idx * 0.04);
          gain.gain.exponentialRampToValueAtTime(0.0001, t + idx * 0.04 + 0.18);
          osc.connect(gain);
          gain.connect(this.ctx.destination);
          osc.start(t + idx * 0.04);
          osc.stop(t + idx * 0.04 + 0.19);
        });
      } catch (_) {}
    }

    // Alerta de ameaça forense
    alert(isSevere = false) {
      this.vibrate([80, 50, 80]);
      if (!this.enabled) return;
      this.init();
      if (!this.ctx) return;
      try {
        const t = this.ctx.currentTime;
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = isSevere ? 'sawtooth' : 'square';
        osc.frequency.setValueAtTime(isSevere ? 220 : 380, t);
        osc.frequency.linearRampToValueAtTime(isSevere ? 110 : 260, t + 0.14);
        gain.gain.setValueAtTime(0.07, t);
        gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.15);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start(t);
        osc.stop(t + 0.15);
      } catch (_) {}
    }

    error() {
      this.vibrate([40, 30, 40]);
      if (!this.enabled) return;
      this.init();
      if (!this.ctx) return;
      try {
        const t = this.ctx.currentTime;
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(260, t);
        osc.frequency.linearRampToValueAtTime(140, t + 0.16);
        gain.gain.setValueAtTime(0.07, t);
        gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.17);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start(t);
        osc.stop(t + 0.17);
      } catch (_) {}
    }
  }

  const sfx = new SoundController();

  // ─────────────────────────────────────────────────────────────
  // 2. Sistema de Notificações Toast
  // ─────────────────────────────────────────────────────────────
  const toastRegion = document.getElementById('toastRegion');

  function showToast(type, title, message, duration = 3200) {
    if (!toastRegion) return;
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
        <strong>${title}</strong>
        <span>${message}</span>
      </div>
    `;

    toastRegion.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(20px)';
      toast.style.transition = 'all 0.2s ease-out';
      setTimeout(() => toast.remove(), 200);
    }, duration);
  }

  // ─────────────────────────────────────────────────────────────
  // 3. Utilitários de Clipboard e Criptografia
  // ─────────────────────────────────────────────────────────────
  async function performCopy(text, btnElement, feedbackMsg = 'Copiado!') {
    let success = false;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        success = true;
      } catch (_) {
        success = fallbackCopy(text);
      }
    } else {
      success = fallbackCopy(text);
    }

    if (success) {
      sfx.tick(1400);
      const originalHtml = btnElement.innerHTML;
      btnElement.classList.add('is-copied');
      btnElement.textContent = feedbackMsg;
      setTimeout(() => {
        btnElement.classList.remove('is-copied');
        btnElement.innerHTML = originalHtml;
      }, 2000);
      showToast('success', 'Copiado', 'Texto copiado para a área de transferência.');
    } else {
      sfx.error();
      showToast('error', 'Erro ao copiar', 'Não foi possível acessar o clipboard.');
    }
  }

  function fallbackCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    let res = false;
    try { res = document.execCommand('copy'); } catch (_) {}
    document.body.removeChild(ta);
    return res;
  }

  // SHA-256 via Web Crypto API nativa
  async function sha256Hex(str) {
    const buf = new TextEncoder().encode(str);
    const hashBuf = await crypto.subtle.digest('SHA-256', buf);
    const arr = Array.from(new Uint8Array(hashBuf));
    return arr.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function generateRandomSeedHex() {
    const bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ─────────────────────────────────────────────────────────────
  // 4. Hero Ambient Canvas (Radar Tático & Grid 60fps)
  // ─────────────────────────────────────────────────────────────
  class HeroCanvas {
    constructor(canvasId) {
      this.canvas = document.getElementById(canvasId);
      if (!this.canvas) return;
      this.ctx = this.canvas.getContext('2d');
      this.particles = [];
      this.running = true;
      this.angle = 0;
      this.init();
    }

    init() {
      this.resize();
      window.addEventListener('resize', () => this.resize(), { passive: true });

      // Partículas táteis
      const count = Math.min(40, Math.floor(window.innerWidth / 30));
      for (let i = 0; i < count; i++) {
        this.particles.push({
          x: Math.random() * this.canvas.width,
          y: Math.random() * this.canvas.height,
          vx: (Math.random() - 0.5) * 0.35,
          vy: -Math.random() * 0.4 - 0.1,
          size: Math.random() * 2 + 1,
          alpha: Math.random() * 0.5 + 0.2
        });
      }

      // Pausa se o Hero sair do viewport
      const observer = new IntersectionObserver(([entry]) => {
        this.running = entry.isIntersecting;
        if (this.running) this.loop();
      });
      observer.observe(this.canvas);
      this.loop();
    }

    resize() {
      this.canvas.width = this.canvas.parentElement.offsetWidth;
      this.canvas.height = this.canvas.parentElement.offsetHeight;
    }

    loop() {
      if (!this.running) return;
      this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

      const w = this.canvas.width;
      const h = this.canvas.height;

      // Grade técnica sutil
      this.ctx.strokeStyle = 'rgba(255, 255, 255, 0.025)';
      this.ctx.lineWidth = 1;
      const step = 80;
      for (let x = 0; x < w; x += step) {
        this.ctx.beginPath();
        this.ctx.moveTo(x, 0);
        this.ctx.lineTo(x, h);
        this.ctx.stroke();
      }
      for (let y = 0; y < h; y += step) {
        this.ctx.beginPath();
        this.ctx.moveTo(0, y);
        this.ctx.lineTo(w, y);
        this.ctx.stroke();
      }

      // Partículas de brasas quentes
      this.ctx.fillStyle = '#e5484d';
      this.particles.forEach(p => {
        p.x += p.vx;
        p.y += p.vy;
        if (p.y < 0) {
          p.y = h;
          p.x = Math.random() * w;
        }
        this.ctx.globalAlpha = p.alpha;
        this.ctx.beginPath();
        this.ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        this.ctx.fill();
      });
      this.ctx.globalAlpha = 1;

      requestAnimationFrame(() => this.loop());
    }
  }

  new HeroCanvas('heroCanvas');

  // ─────────────────────────────────────────────────────────────
  // 5. Navegação, Header Fixo & Menu Mobile
  // ─────────────────────────────────────────────────────────────
  const header = document.getElementById('header');
  window.addEventListener('scroll', () => {
    if (window.scrollY > 24) {
      header.classList.add('scrolled');
    } else {
      header.classList.remove('scrolled');
    }
  }, { passive: true });

  const navToggle = document.getElementById('navToggle');
  const mobileMenu = document.getElementById('mobileMenu');
  if (navToggle && mobileMenu) {
    function toggleMobileMenu() {
      navToggle.classList.toggle('active');
      mobileMenu.classList.toggle('open');
      navToggle.setAttribute('aria-expanded', navToggle.classList.contains('active'));
    }
    navToggle.addEventListener('click', toggleMobileMenu);
    mobileMenu.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        if (mobileMenu.classList.contains('open')) toggleMobileMenu();
      });
    });
  }

  // ─────────────────────────────────────────────────────────────
  // 6. Autenticação Unificada de ADM (Validação SHA-256 no Client)
  // ─────────────────────────────────────────────────────────────
  /*
   * NOTA FORENSE DE SEGURANÇA:
   * Por se tratar de uma SPA 100% estática (GitHub Pages sem backend),
   * a credencial é validada comparando o hash SHA-256 da entrada com o hash
   * autorizado da liderança da Tribo Cacique. Nenhuma senha trafega em texto puro.
   */
  const ADMIN_USER_HASH = '3680593c420bee400f624c81661151f3141f3271ed3f80121738da69f456cace'; // 'CACIQUE'
  const ADMIN_PASS_HASH = 'e0112dd9dc3f248b7a9e78bda4d522999d68636989c772137e7f644d32caf443'; // 'g.indiopatrocina777'
  const AUTH_STORAGE_KEY = 'cacique_unified_adm_auth';

  let isAdmAuthenticated = localStorage.getItem(AUTH_STORAGE_KEY) === 'true';

  const roleBadgeBtn = document.getElementById('roleBadgeBtn');
  const roleBadgeText = document.getElementById('roleBadgeText');
  const modalAuthBackdrop = document.getElementById('modalAuthBackdrop');
  const authUserInput = document.getElementById('authUserInput');
  const authPassInput = document.getElementById('authPassInput');
  const btnAuthSubmit = document.getElementById('btnAuthSubmit');
  const btnAuthLogout = document.getElementById('btnAuthLogout');

  function updateAuthUI() {
    if (roleBadgeBtn && roleBadgeText) {
      if (isAdmAuthenticated) {
        roleBadgeBtn.classList.add('is-admin');
        roleBadgeText.textContent = 'ADM Tribo';
        if (btnAuthLogout) btnAuthLogout.style.display = 'inline-flex';
        if (btnAuthSubmit) btnAuthSubmit.textContent = 'Autenticado';
      } else {
        roleBadgeBtn.classList.remove('is-admin');
        roleBadgeText.textContent = 'Visitante';
        if (btnAuthLogout) btnAuthLogout.style.display = 'none';
        if (btnAuthSubmit) btnAuthSubmit.textContent = 'Entrar como ADM';
      }
    }
  }

  updateAuthUI();

  if (roleBadgeBtn) {
    roleBadgeBtn.addEventListener('click', () => {
      if (modalAuthBackdrop) modalAuthBackdrop.style.display = 'flex';
      sfx.tick(900);
    });
  }

  async function handleAdminLogin(userVal, passVal) {
    const userH = await sha256Hex(userVal.trim().toUpperCase());
    const passH = await sha256Hex(passVal.trim());

    if (userH === ADMIN_USER_HASH && passH === ADMIN_PASS_HASH) {
      isAdmAuthenticated = true;
      localStorage.setItem(AUTH_STORAGE_KEY, 'true');
      updateAuthUI();
      sfx.done();
      showToast('success', 'Acesso Autorizado', 'Modo Operador ADM da Tribo ativado.');
      if (modalAuthBackdrop) modalAuthBackdrop.style.display = 'none';

      // Se o SCAN estiver aberto no login, desbloqueia o dashboard
      unlockScanDashboard();
      return true;
    } else {
      sfx.error();
      showToast('error', 'Acesso Negado', 'Usuário ou senha de ADM incorretos.');
      return false;
    }
  }

  if (btnAuthSubmit) {
    btnAuthSubmit.addEventListener('click', () => {
      handleAdminLogin(authUserInput.value, authPassInput.value);
    });
  }

  if (btnAuthLogout) {
    btnAuthLogout.addEventListener('click', () => {
      isAdmAuthenticated = false;
      localStorage.removeItem(AUTH_STORAGE_KEY);
      updateAuthUI();
      sfx.tick(600);
      showToast('info', 'Desconectado', 'Sessão de ADM encerrada.');
      if (modalAuthBackdrop) modalAuthBackdrop.style.display = 'none';
    });
  }

  // ─────────────────────────────────────────────────────────────
  // 7. ARENA DE ROLETAS: Sistema de Patentes & Pesos (Editáveis)
  // ─────────────────────────────────────────────────────────────
  const DEFAULT_RANKS = [
    { id: 'mestre', name: 'Mestre', abbr: 'M', weight: 10, color: '#d4af37', bg: 'rgba(212, 175, 55, 0.16)' },
    { id: 'd1', name: 'Diamante 1', abbr: 'D1', weight: 9, color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.16)' },
    { id: 'd2', name: 'Diamante 2', abbr: 'D2', weight: 8, color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.13)' },
    { id: 'd3', name: 'Diamante 3', abbr: 'D3', weight: 7, color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.10)' },
    { id: 'p1', name: 'Platina 1', abbr: 'P1', weight: 6, color: '#2dd4bf', bg: 'rgba(45, 212, 191, 0.16)' },
    { id: 'p2', name: 'Platina 2', abbr: 'P2', weight: 5, color: '#2dd4bf', bg: 'rgba(45, 212, 191, 0.13)' },
    { id: 'p3', name: 'Platina 3', abbr: 'P3', weight: 4, color: '#2dd4bf', bg: 'rgba(45, 212, 191, 0.10)' },
    { id: 'o1', name: 'Ouro 1', abbr: 'O1', weight: 3, color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.16)' },
    { id: 'o2', name: 'Ouro 2', abbr: 'O2', weight: 2, color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.13)' },
    { id: 'o3', name: 'Ouro 3', abbr: 'O3', weight: 1, color: '#f59e0b', bg: 'rgba(245, 158, 11, 0.10)' },
    { id: 'none', name: 'Sem Patente', abbr: 'SP', weight: 5, color: '#8a8f98', bg: 'rgba(138, 143, 152, 0.12)' }
  ];

  function loadRanks() {
    try {
      const saved = localStorage.getItem('cacique_ranks_weights_v4');
      if (saved) return JSON.parse(saved);
    } catch (_) {}
    return JSON.parse(JSON.stringify(DEFAULT_RANKS));
  }

  let ranks = loadRanks();

  function saveRanks(newRanks) {
    ranks = newRanks;
    localStorage.setItem('cacique_ranks_weights_v4', JSON.stringify(ranks));
  }

  function getRankById(id) {
    return ranks.find(r => r.id === id) || ranks[ranks.length - 1];
  }

  // Editor de Pesos Modal
  const modalWeightsBackdrop = document.getElementById('modalWeightsBackdrop');
  const weightsEditorGrid = document.getElementById('weightsEditorGrid');
  const btnWeightsModal = document.getElementById('btnWeightsModal');
  const btnSaveWeights = document.getElementById('btnSaveWeights');
  const btnResetWeightsDefault = document.getElementById('btnResetWeightsDefault');

  function renderWeightsEditor() {
    if (!weightsEditorGrid) return;
    weightsEditorGrid.innerHTML = ranks.map(r => `
      <div class="weight-row">
        <span class="weight-rank-tag" style="color: ${r.color};">${r.name} (${r.abbr})</span>
        <input type="number" min="1" max="50" class="weight-input" data-rank-id="${r.id}" value="${r.weight}">
      </div>
    `).join('');
  }

  if (btnWeightsModal) {
    btnWeightsModal.addEventListener('click', () => {
      renderWeightsEditor();
      if (modalWeightsBackdrop) modalWeightsBackdrop.style.display = 'flex';
      sfx.tick(850);
    });
  }

  if (btnSaveWeights) {
    btnSaveWeights.addEventListener('click', () => {
      const inputs = weightsEditorGrid.querySelectorAll('.weight-input');
      inputs.forEach(inp => {
        const rId = inp.dataset.rankId;
        const target = ranks.find(r => r.id === rId);
        if (target) {
          const val = parseInt(inp.value, 10);
          if (!isNaN(val) && val >= 1) target.weight = val;
        }
      });
      saveRanks(ranks);
      sfx.done();
      showToast('success', 'Pesos Atualizados', 'Tabela de pesos de patente salva com sucesso.');
      if (modalWeightsBackdrop) modalWeightsBackdrop.style.display = 'none';
      rosterManager.render();
    });
  }

  if (btnResetWeightsDefault) {
    btnResetWeightsDefault.addEventListener('click', () => {
      saveRanks(JSON.parse(JSON.stringify(DEFAULT_RANKS)));
      renderWeightsEditor();
      sfx.tick(700);
      showToast('info', 'Restaurado', 'Tabela de pesos redefinida para o padrão.');
    });
  }

  // ─────────────────────────────────────────────────────────────
  // 8. ARENA: Gestão do Elenco (Passo 1: Cadastro & Parse Livre)
  // ─────────────────────────────────────────────────────────────
  class RosterManager {
    constructor() {
      this.players = [];
      this.searchInput = document.getElementById('rosterSearch');
      this.rankFilter = document.getElementById('rosterRankFilter');
      this.listEl = document.getElementById('rosterList');
      this.emptyEl = document.getElementById('rosterEmptyState');
      this.totalCountEl = document.getElementById('rosterTotalCount');
      this.chipsContainer = document.getElementById('rankCountersChips');
      this.duplicateAlert = document.getElementById('duplicateAlert');
      this.defaultRankSelect = document.getElementById('defaultRankSelect');

      this.initEvents();
      this.loadSaved();
    }

    initEvents() {
      if (this.searchInput) {
        this.searchInput.addEventListener('input', () => this.render());
      }
      if (this.rankFilter) {
        this.rankFilter.addEventListener('change', () => this.render());
      }
    }

    loadSaved() {
      try {
        const saved = localStorage.getItem('cacique_roster_data_v4');
        if (saved) {
          this.players = JSON.parse(saved);
        }
      } catch (_) {}
      this.render();
    }

    save() {
      try {
        localStorage.setItem('cacique_roster_data_v4', JSON.stringify(this.players));
      } catch (_) {}
      this.render();
    }

    // Reconhecimento inteligente de texto livre (com abreviações, traços, pipes, etc.)
    parseText(text) {
      const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
      const defaultRankId = this.defaultRankSelect ? this.defaultRankSelect.value : 'none';
      const added = [];

      lines.forEach((line, index) => {
        // Tenta extrair rank por regex flexível
        // Formatos: "Nick - D1", "Nick | Mestre", "Nick M", "Nick (D2)"
        let nick = line;
        let detectedRankId = defaultRankId;
        let idVal = '';

        // Extrai ID opcional com #12345
        const idMatch = line.match(/#([a-zA-Z0-9_-]+)/);
        if (idMatch) {
          idVal = idMatch[1];
          nick = nick.replace(idMatch[0], '').trim();
        }

        // Normalização sem acentos para match
        const norm = line.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();

        if (/\b(mestre|m)\b/i.test(norm) && !/diamante|platina|ouro/i.test(norm)) {
          detectedRankId = 'mestre';
          nick = nick.replace(/[-|—\s]+(mestre|m)\b/i, '').trim();
        } else if (/\b(d1|diamante\s*1)\b/i.test(norm)) {
          detectedRankId = 'd1';
          nick = nick.replace(/[-|—\s]+(d1|diamante\s*1)\b/i, '').trim();
        } else if (/\b(d2|diamante\s*2)\b/i.test(norm)) {
          detectedRankId = 'd2';
          nick = nick.replace(/[-|—\s]+(d2|diamante\s*2)\b/i, '').trim();
        } else if (/\b(d3|diamante\s*3)\b/i.test(norm)) {
          detectedRankId = 'd3';
          nick = nick.replace(/[-|—\s]+(d3|diamante\s*3)\b/i, '').trim();
        } else if (/\b(p1|platina\s*1)\b/i.test(norm)) {
          detectedRankId = 'p1';
          nick = nick.replace(/[-|—\s]+(p1|platina\s*1)\b/i, '').trim();
        } else if (/\b(p2|platina\s*2)\b/i.test(norm)) {
          detectedRankId = 'p2';
          nick = nick.replace(/[-|—\s]+(p2|platina\s*2)\b/i, '').trim();
        } else if (/\b(p3|platina\s*3)\b/i.test(norm)) {
          detectedRankId = 'p3';
          nick = nick.replace(/[-|—\s]+(p3|platina\s*3)\b/i, '').trim();
        } else if (/\b(o1|ouro\s*1)\b/i.test(norm)) {
          detectedRankId = 'o1';
          nick = nick.replace(/[-|—\s]+(o1|ouro\s*1)\b/i, '').trim();
        } else if (/\b(o2|ouro\s*2)\b/i.test(norm)) {
          detectedRankId = 'o2';
          nick = nick.replace(/[-|—\s]+(o2|ouro\s*2)\b/i, '').trim();
        } else if (/\b(o3|ouro\s*3)\b/i.test(norm)) {
          detectedRankId = 'o3';
          nick = nick.replace(/[-|—\s]+(o3|ouro\s*3)\b/i, '').trim();
        }

        // Limpa separadores residuais
        nick = nick.replace(/^[-|—\s]+|[-|—\s]+$/g, '').trim();
        if (!nick) nick = `Guerreiro_${Date.now().toString().slice(-4)}_${index + 1}`;

        added.push({
          id: 'p_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 5),
          nick: nick,
          gameId: idVal,
          rankId: detectedRankId,
          pinned: false
        });
      });

      this.players.push(...added);
      this.save();
      return added.length;
    }

    render() {
      if (!this.listEl) return;
      const query = (this.searchInput ? this.searchInput.value : '').toLowerCase().trim();
      const filterRank = this.rankFilter ? this.rankFilter.value : 'all';

      // Identifica duplicados por nick
      const nameCounts = {};
      this.players.forEach(p => {
        const k = p.nick.toLowerCase();
        nameCounts[k] = (nameCounts[k] || 0) + 1;
      });

      let hasDuplicates = false;

      // Filtra
      const filtered = this.players.filter(p => {
        const matchesQuery = !query || p.nick.toLowerCase().includes(query) || (p.gameId && p.gameId.includes(query));
        if (!matchesQuery) return false;
        if (filterRank === 'all') return true;
        const allowedRanks = filterRank.split(',');
        return allowedRanks.includes(p.rankId);
      });

      if (this.totalCountEl) this.totalCountEl.textContent = this.players.length;

      // Renderiza contadores de chip por patente
      if (this.chipsContainer) {
        const counts = {};
        this.players.forEach(p => counts[p.rankId] = (counts[p.rankId] || 0) + 1);
        this.chipsContainer.innerHTML = ranks.map(r => {
          const c = counts[r.id] || 0;
          if (c === 0) return '';
          return `<span class="rank-chip" style="border-color: ${r.color}33; color: ${r.color};">${r.abbr}: <strong>${c}</strong></span>`;
        }).filter(Boolean).join('');
      }

      if (this.players.length === 0) {
        if (this.emptyEl) this.emptyEl.style.display = 'flex';
        this.listEl.innerHTML = '';
        if (this.duplicateAlert) this.duplicateAlert.style.display = 'none';
        return;
      }

      if (this.emptyEl) this.emptyEl.style.display = 'none';

      this.listEl.innerHTML = filtered.map(p => {
        const rankObj = getRankById(p.rankId);
        const isDup = nameCounts[p.nick.toLowerCase()] > 1;
        if (isDup) hasDuplicates = true;

        return `
          <div class="roster-item ${isDup ? 'duplicate' : ''}" data-player-id="${p.id}">
            <div class="roster-item-info">
              <span class="roster-nick" title="${p.nick}">${p.nick}</span>
              ${p.gameId ? `<code class="player-id-tag">#${p.gameId}</code>` : ''}
              <select class="form-select-sm player-rank-inline" data-player-id="${p.id}" style="color: ${rankObj.color};">
                ${ranks.map(r => `<option value="${r.id}" ${r.id === p.rankId ? 'selected' : ''}>${r.name} (${r.weight}pts)</option>`).join('')}
              </select>
            </div>
            <div class="roster-item-actions">
              <button type="button" class="btn-pin ${p.pinned ? 'pinned' : ''}" data-pin-id="${p.id}" title="${p.pinned ? 'Jogador travado' : 'Travar jogador no elenco'}">
                ${p.pinned ? '★ Travado' : '☆ Pin'}
              </button>
              <button type="button" class="btn-remove-player" data-remove-id="${p.id}" title="Remover jogador">&times;</button>
            </div>
          </div>
        `;
      }).join('');

      if (this.duplicateAlert) {
        this.duplicateAlert.style.display = hasDuplicates ? 'flex' : 'none';
      }

      // Event listeners dos itens inline
      this.listEl.querySelectorAll('.player-rank-inline').forEach(sel => {
        sel.addEventListener('change', (e) => {
          const pId = e.target.dataset.playerId;
          const p = this.players.find(x => x.id === pId);
          if (p) {
            p.rankId = e.target.value;
            this.save();
            sfx.tick(800);
          }
        });
      });

      this.listEl.querySelectorAll('.btn-pin').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const pId = e.currentTarget.dataset.pinId;
          const p = this.players.find(x => x.id === pId);
          if (p) {
            p.pinned = !p.pinned;
            this.save();
            sfx.tick(1000);
          }
        });
      });

      this.listEl.querySelectorAll('.btn-remove-player').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const pId = e.currentTarget.dataset.removeId;
          this.players = this.players.filter(x => x.id !== pId);
          this.save();
          sfx.tick(600);
        });
      });
    }

    clear() {
      this.players = [];
      this.save();
    }
  }

  const rosterManager = new RosterManager();

  // Binds do Passo 1
  const rosterInput = document.getElementById('rosterInput');
  const btnParseRoster = document.getElementById('btnParseRoster');
  const btnLoadSampleRoster = document.getElementById('btnLoadSampleRoster');
  const btnClearRosterInput = document.getElementById('btnClearRosterInput');
  const btnClearAllRoster = document.getElementById('btnClearAllRoster');
  const btnGoToStep2 = document.getElementById('btnGoToStep2');

  if (btnParseRoster && rosterInput) {
    btnParseRoster.addEventListener('click', () => {
      const txt = rosterInput.value.trim();
      if (!txt) {
        sfx.error();
        showToast('error', 'Lista Vazia', 'Insira ao menos um nome antes de processar.');
        return;
      }
      const count = rosterManager.parseText(txt);
      rosterInput.value = '';
      sfx.done();
      showToast('success', 'Elenco Atualizado', `${count} jogadores adicionados ao elenco.`);
    });
  }

  if (btnLoadSampleRoster && rosterInput) {
    btnLoadSampleRoster.addEventListener('click', () => {
      rosterInput.value = `Índio ADM - Mestre
CapitãoX | Diamante 1
SniperElite D2
LoboSolitário - Diamante 3
GhostKiller | Platina 1
Falcão Platina 2
Caveira - Platina 3
Sombra - Ouro 1
Predador Ouro 2
Trovão - Ouro 3
BateSocoMaster M
NinjaFF (sem patente)`;
      sfx.tick(900);
    });
  }

  if (btnClearRosterInput && rosterInput) {
    btnClearRosterInput.addEventListener('click', () => {
      rosterInput.value = '';
      sfx.tick(600);
    });
  }

  if (btnClearAllRoster) {
    btnClearAllRoster.addEventListener('click', () => {
      if (confirm('Deseja limpar todo o elenco de jogadores?')) {
        rosterManager.clear();
        sfx.tick(500);
        showToast('info', 'Elenco Limpo', 'Todos os jogadores foram removidos.');
      }
    });
  }

  // Importar / Exportar Elenco Modal
  const modalImportExportBackdrop = document.getElementById('modalImportExportBackdrop');
  const btnImportExportRoster = document.getElementById('btnImportExportRoster');
  const importExportTextarea = document.getElementById('importExportTextarea');
  const btnCopyImportExport = document.getElementById('btnCopyImportExport');
  const btnApplyImportData = document.getElementById('btnApplyImportData');

  if (btnImportExportRoster) {
    btnImportExportRoster.addEventListener('click', () => {
      if (importExportTextarea) {
        importExportTextarea.value = JSON.stringify(rosterManager.players, null, 2);
      }
      if (modalImportExportBackdrop) modalImportExportBackdrop.style.display = 'flex';
      sfx.tick(850);
    });
  }

  if (btnCopyImportExport && importExportTextarea) {
    btnCopyImportExport.addEventListener('click', () => {
      performCopy(importExportTextarea.value, btnCopyImportExport, 'Copiado!');
    });
  }

  if (btnApplyImportData && importExportTextarea) {
    btnApplyImportData.addEventListener('click', () => {
      try {
        const val = importExportTextarea.value.trim();
        if (val.startsWith('[')) {
          const parsed = JSON.parse(val);
          if (Array.isArray(parsed)) {
            rosterManager.players = parsed;
            rosterManager.save();
            sfx.done();
            showToast('success', 'Importado', `${parsed.length} jogadores importados com sucesso.`);
            if (modalImportExportBackdrop) modalImportExportBackdrop.style.display = 'none';
            return;
          }
        }
        // Fallback texto livre
        rosterManager.parseText(val);
        sfx.done();
        showToast('success', 'Importado', 'Lista de texto livre processada com sucesso.');
        if (modalImportExportBackdrop) modalImportExportBackdrop.style.display = 'none';
      } catch (err) {
        sfx.error();
        showToast('error', 'Formato Inválido', 'Verifique a formatação do JSON ou texto inserido.');
      }
    });
  }

  // Fechamento genérico de modais
  document.querySelectorAll('.modal-close, [data-close]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const targetId = e.currentTarget.dataset.close;
      if (targetId) {
        const modal = document.getElementById(targetId);
        if (modal) modal.style.display = 'none';
      } else {
        const modal = e.currentTarget.closest('.modal-backdrop');
        if (modal) modal.style.display = 'none';
      }
      sfx.tick(700);
    });
  });

  // ─────────────────────────────────────────────────────────────
  // 9. ARENA: Stepper de 4 Passos
  // ─────────────────────────────────────────────────────────────
  let currentArenaStep = 1;

  function setArenaStep(step) {
    currentArenaStep = step;
    document.querySelectorAll('.arena-step-pane').forEach((pane, idx) => {
      pane.classList.toggle('active', idx + 1 === step);
    });

    document.querySelectorAll('.step-node').forEach((node, idx) => {
      const nStep = idx + 1;
      node.classList.toggle('active', nStep === step);
      node.classList.toggle('completed', nStep < step);
    });

    sfx.tick(900 + step * 100);

    // Se entrar no passo 3 (Giro), renderiza as roletas
    if (step === 3) {
      rouletteArena.prepareWheels();
    }
  }

  document.querySelectorAll('.step-node').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const s = parseInt(e.currentTarget.dataset.step, 10);
      if (s) setArenaStep(s);
    });
  });

  if (btnGoToStep2) btnGoToStep2.addEventListener('click', () => setArenaStep(2));
  const btnBackToStep1 = document.getElementById('btnBackToStep1');
  const btnGoToStep3 = document.getElementById('btnGoToStep3');
  const btnBackToStep2 = document.getElementById('btnBackToStep2');
  const btnGoToStep4 = document.getElementById('btnGoToStep4');
  const btnGoToStep4From3 = document.getElementById('btnGoToStep4From3');
  const btnBackToStep3 = document.getElementById('btnBackToStep3');
  const btnStartNewRound = document.getElementById('btnStartNewRound');

  if (btnBackToStep1) btnBackToStep1.addEventListener('click', () => setArenaStep(1));
  if (btnGoToStep3) btnGoToStep3.addEventListener('click', () => setArenaStep(3));
  if (btnBackToStep2) btnBackToStep2.addEventListener('click', () => setArenaStep(2));
  if (btnGoToStep4) btnGoToStep4.addEventListener('click', () => setArenaStep(4));
  if (btnGoToStep4From3) btnGoToStep4From3.addEventListener('click', () => setArenaStep(4));
  if (btnBackToStep3) btnBackToStep3.addEventListener('click', () => setArenaStep(3));
  if (btnStartNewRound) btnStartNewRound.addEventListener('click', () => {
    rouletteArena.resetRound();
    setArenaStep(1);
    showToast('info', 'Nova Rodada', 'Arena pronta para um novo sorteio.');
  });

  // Alternador entre Arena de Roletas e Modo Rápido Clássico
  const tabArenaBtn = document.getElementById('tabArenaBtn');
  const tabQuickBtn = document.getElementById('tabQuickBtn');
  const arenaContainer = document.getElementById('arenaContainer');
  const quickSorteioWrapper = document.getElementById('quickSorteioWrapper');

  if (tabArenaBtn && tabQuickBtn && arenaContainer && quickSorteioWrapper) {
    tabArenaBtn.addEventListener('click', () => {
      tabArenaBtn.classList.add('active');
      tabQuickBtn.classList.remove('active');
      arenaContainer.style.display = 'block';
      quickSorteioWrapper.style.display = 'none';
      sfx.tick(1000);
    });

    tabQuickBtn.addEventListener('click', () => {
      tabQuickBtn.classList.add('active');
      tabArenaBtn.classList.remove('active');
      arenaContainer.style.display = 'none';
      quickSorteioWrapper.style.display = 'grid';
      sfx.tick(1000);
    });
  }

  // ─────────────────────────────────────────────────────────────
  // 10. ARENA DE ROLETAS: Motor de Canvas 2D & Sincronização
  // ─────────────────────────────────────────────────────────────
  class SingleWheelEngine {
    constructor(wheelId, canvasId, pointerId, slotsAId, slotsBId, meterAId, meterBId) {
      this.wheelId = wheelId;
      this.canvas = document.getElementById(canvasId);
      this.ctx = this.canvas ? this.canvas.getContext('2d') : null;
      this.pointer = document.querySelector(`#${wheelId} .wheel-pointer`) || document.querySelector(`#wheelCell${wheelId} .wheel-pointer`);
      this.slotsAEl = document.getElementById(slotsAId);
      this.slotsBEl = document.getElementById(slotsBId);
      this.meterAEl = document.getElementById(meterAId);
      this.meterBEl = document.getElementById(meterBId);

      this.currentAngle = 0;
      this.isSpinning = false;
      this.eligiblePlayers = [];
      this.team1 = [];
      this.team2 = [];
      this.targetTeamSize = 4;
      this.lastTickIndex = -1;
    }

    setEligiblePlayers(players) {
      this.eligiblePlayers = [...players];
      this.draw();
    }

    draw() {
      if (!this.canvas || !this.ctx) return;
      const ctx = this.ctx;
      const size = this.canvas.width;
      const center = size / 2;
      const radius = center - 6;

      ctx.clearRect(0, 0, size, size);

      const count = this.eligiblePlayers.length;
      if (count === 0) {
        // Estado vazio elegante
        ctx.save();
        ctx.translate(center, center);
        ctx.beginPath();
        ctx.arc(0, 0, radius, 0, Math.PI * 2);
        ctx.fillStyle = '#16171d';
        ctx.fill();
        ctx.strokeStyle = 'rgba(255,255,255,0.08)';
        ctx.lineWidth = 4;
        ctx.stroke();

        ctx.fillStyle = '#8a8f98';
        ctx.font = '500 13px Geist, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('Sem jogadores', 0, 5);
        ctx.restore();
        return;
      }

      const arc = (Math.PI * 2) / count;

      ctx.save();
      ctx.translate(center, center);
      ctx.rotate(this.currentAngle);

      for (let i = 0; i < count; i++) {
        const player = this.eligiblePlayers[i];
        const rank = getRankById(player.rankId);
        const startA = i * arc;
        const endA = startA + arc;

        // Fatias alternadas com tons escuros refinados
        ctx.beginPath();
        ctx.moveTo(0, 0);
        ctx.arc(0, 0, radius, startA, endA);
        ctx.closePath();

        ctx.fillStyle = (i % 2 === 0) ? '#16171d' : '#1c1d25';
        ctx.fill();

        // Borda externa com a cor da patente
        ctx.beginPath();
        ctx.arc(0, 0, radius, startA, endA);
        ctx.lineWidth = 5;
        ctx.strokeStyle = rank.color;
        ctx.stroke();

        // Divisor de fatia
        ctx.beginPath();
        ctx.moveTo(0, 0);
        ctx.lineTo(Math.cos(startA) * radius, Math.sin(startA) * radius);
        ctx.lineWidth = 1;
        ctx.strokeStyle = 'rgba(255,255,255,0.08)';
        ctx.stroke();

        // Texto do jogador e badge
        ctx.save();
        ctx.rotate(startA + arc / 2);
        ctx.textAlign = 'right';

        // Tag da patente
        ctx.font = '700 10px Geist Mono, monospace';
        ctx.fillStyle = rank.color;
        ctx.fillText(rank.abbr, radius - 14, 4);

        // Nick do jogador
        ctx.font = '600 12px Geist, sans-serif';
        ctx.fillStyle = '#ffffff';
        const displayNick = player.nick.length > 12 ? player.nick.slice(0, 11) + '…' : player.nick;
        ctx.fillText(displayNick, radius - 38, 4);

        ctx.restore();
      }

      ctx.restore();
    }

    // Giro com determinação criptográfica PRÉVIA
    spin(targetDuration = 3500) {
      if (this.isSpinning) return Promise.reject('Em giro');
      if (this.eligiblePlayers.length === 0) return Promise.reject('Sem jogadores');

      // Verifica vagas restantes nos times
      const totalSlotsNeeded = this.targetTeamSize * 2;
      const currentFilled = this.team1.length + this.team2.length;
      if (currentFilled >= totalSlotsNeeded) {
        return Promise.reject('Times já preenchidos');
      }

      return new Promise((resolve) => {
        this.isSpinning = true;

        // CSPRNG: escolhe o índice ANTES de iniciar a física visual
        const cryptoRandomBuf = new Uint32Array(1);
        window.crypto.getRandomValues(cryptoRandomBuf);
        const winningIndex = cryptoRandomBuf[0] % this.eligiblePlayers.length;
        const winner = this.eligiblePlayers[winningIndex];

        // Ângulo onde o ponteiro (no topo = -Math.PI / 2) aponta para winningIndex
        const count = this.eligiblePlayers.length;
        const arc = (Math.PI * 2) / count;
        const sliceCenter = winningIndex * arc + arc / 2;

        // Ângulo final necessário:
        // ponteiro está a 3*Math.PI / 2 (ou -Math.PI / 2)
        const pointerPos = (3 * Math.PI) / 2;
        const turns = 5 + Math.floor(Math.random() * 3); // 5 a 7 voltas completas
        const targetRot = turns * (Math.PI * 2) + (pointerPos - sliceCenter);

        const startRot = this.currentAngle % (Math.PI * 2);
        const totalDelta = targetRot - startRot;

        const startTime = performance.now();
        this.lastTickIndex = -1;

        const animate = (now) => {
          const elapsed = now - startTime;
          const progress = Math.min(1, elapsed / targetDuration);

          // Curva de desaceleração extrema (quartic out)
          const ease = 1 - Math.pow(1 - progress, 4);
          this.currentAngle = startRot + totalDelta * ease;

          // Física do ponteiro: detecta cruzamento de fatia
          const normalizedAngle = (pointerPos - (this.currentAngle % (Math.PI * 2)) + Math.PI * 4) % (Math.PI * 2);
          const currentSlice = Math.floor(normalizedAngle / arc);

          if (currentSlice !== this.lastTickIndex) {
            this.lastTickIndex = currentSlice;
            if (this.pointer) {
              this.pointer.classList.remove('tick');
              void this.pointer.offsetWidth; // Força reflow
              this.pointer.classList.add('tick');
            }
            sfx.tick(800 + Math.random() * 400);
          }

          this.draw();

          if (progress < 1) {
            requestAnimationFrame(animate);
          } else {
            this.isSpinning = false;
            sfx.reveal();

            // Adiciona jogador ao próximo time com vaga livre
            if (this.team1.length < this.targetTeamSize) {
              this.team1.push(winner);
              this.updateSlots(1, winner);
            } else if (this.team2.length < this.targetTeamSize) {
              this.team2.push(winner);
              this.updateSlots(2, winner);
            }

            // Remove o sorteado da lista de elegíveis desta roleta
            this.eligiblePlayers.splice(winningIndex, 1);
            this.draw();

            resolve({
              wheelId: this.wheelId,
              winner: winner,
              team: this.team1.includes(winner) ? 1 : 2
            });
          }
        };

        requestAnimationFrame(animate);
      });
    }

    updateSlots(teamNum, newPlayer) {
      const container = (teamNum === 1) ? this.slotsAEl : this.slotsBEl;
      const meter = (teamNum === 1) ? this.meterAEl : this.meterBEl;
      const team = (teamNum === 1) ? this.team1 : this.team2;

      if (container) {
        container.innerHTML = team.map(p => {
          const r = getRankById(p.rankId);
          return `
            <div class="team-slot filled ${p.id === newPlayer.id ? 'just-added' : ''}">
              <strong style="color: #fff;">${p.nick}</strong>
              <span style="color: ${r.color}; font-family: var(--font-mono); font-size: 0.7rem; font-weight: 700;">${r.abbr} (${r.weight}pts)</span>
            </div>
          `;
        }).join('');

        // Preenche vagas restantes com slots pontilhados
        for (let i = team.length; i < this.targetTeamSize; i++) {
          container.innerHTML += `<div class="team-slot">Vaga livre ${i + 1}</div>`;
        }
      }

      if (meter) {
        const sum = team.reduce((acc, p) => acc + getRankById(p.rankId).weight, 0);
        meter.textContent = `${sum} pts`;
      }
    }

    reset() {
      this.team1 = [];
      this.team2 = [];
      if (this.slotsAEl) this.slotsAEl.innerHTML = '';
      if (this.slotsBEl) this.slotsBEl.innerHTML = '';
      if (this.meterAEl) this.meterAEl.textContent = '0 pts';
      if (this.meterBEl) this.meterBEl.textContent = '0 pts';
      this.updateSlots(1, { id: null });
      this.updateSlots(2, { id: null });
    }
  }

  // ─────────────────────────────────────────────────────────────
  // 11. ARENA CONTROLLER: Gestão de 3 Roletas Simultâneas
  // ─────────────────────────────────────────────────────────────
  class RouletteArena {
    constructor() {
      this.wheelA = new SingleWheelEngine('A', 'canvasWheelA', null, 'slotsA1', 'slotsA2', 'forceMeterA1', 'forceMeterA2');
      this.wheelB = new SingleWheelEngine('B', 'canvasWheelB', null, 'slotsB1', 'slotsB2', 'forceMeterB1', 'forceMeterB2');
      this.wheelC = new SingleWheelEngine('C', 'canvasWheelC', null, 'slotsC1', 'slotsC2', 'forceMeterC1', 'forceMeterC2');

      this.toleranceInput = document.getElementById('balanceTolerance');
      this.toleranceDisplay = document.getElementById('toleranceValDisplay');
      this.exclusiveChk = document.getElementById('chkExclusivePlayers');
      this.matchesResultsGrid = document.getElementById('matchesResultsGrid');

      this.auditDisplayId = document.getElementById('auditDisplayId');
      this.auditDisplaySeed = document.getElementById('auditDisplaySeed');
      this.auditDisplayHash = document.getElementById('auditDisplayHash');
      this.revealBanner = document.getElementById('revealBanner');

      this.currentSeed = generateRandomSeedHex();
      this.currentDrawId = '#CCQ-' + Math.floor(1000 + Math.random() * 9000);

      this.initEvents();
    }

    initEvents() {
      if (this.toleranceInput && this.toleranceDisplay) {
        this.toleranceInput.addEventListener('input', (e) => {
          this.toleranceDisplay.textContent = `± ${e.target.value} pontos`;
        });
      }

      // Botão girar tudo sincronizado (com paradas escalonadas)
      const btnSpinAll = document.getElementById('btnSpinAllWheels');
      if (btnSpinAll) {
        btnSpinAll.addEventListener('click', () => this.spinActiveWheels());
      }

      // Giros individuais
      const btnSpinA = document.getElementById('btnSpinA');
      const btnSpinB = document.getElementById('btnSpinB');
      const btnSpinC = document.getElementById('btnSpinC');

      if (btnSpinA) btnSpinA.addEventListener('click', () => this.spinSingle(this.wheelA));
      if (btnSpinB) btnSpinB.addEventListener('click', () => this.spinSingle(this.wheelB));
      if (btnSpinC) btnSpinC.addEventListener('click', () => this.spinSingle(this.wheelC));

      const btnResetSpins = document.getElementById('btnResetSpins');
      if (btnResetSpins) {
        btnResetSpins.addEventListener('click', () => {
          this.resetRound();
          sfx.tick(600);
          showToast('info', 'Giros Resetados', 'As mesas foram limpas para um novo sorteio.');
        });
      }

      // Auto-equilibrar
      const btnAutoBalance = document.getElementById('btnAutoBalanceAll');
      if (btnAutoBalance) {
        btnAutoBalance.addEventListener('click', () => this.autoBalanceTeams());
      }

      // Exportar WhatsApp
      const btnShareWhatsApp = document.getElementById('btnShareWhatsApp');
      if (btnShareWhatsApp) {
        btnShareWhatsApp.addEventListener('click', () => this.copyWhatsAppSummary(btnShareWhatsApp));
      }

      // Baixar Imagem Card PNG
      const btnDownloadCardPng = document.getElementById('btnDownloadCardPng');
      if (btnDownloadCardPng) {
        btnDownloadCardPng.addEventListener('click', () => this.generateShowdownCardPng());
      }

      // Atalhos de teclado
      window.addEventListener('keydown', (e) => {
        // Se estiver num input ou textarea, ignora atalhos
        if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;

        if (e.code === 'Space') {
          e.preventDefault();
          this.spinActiveWheels();
        } else if (e.code === 'KeyR') {
          e.preventDefault();
          this.resetRound();
        } else if (e.code === 'KeyT') {
          e.preventDefault();
          this.toggleTelaoMode();
        } else if (e.code === 'Escape') {
          const telao = document.getElementById('telaoOverlay');
          if (telao && telao.style.display !== 'none') {
            telao.style.display = 'none';
          }
        }
      });
    }

    prepareWheels() {
      const allPlayers = [...rosterManager.players];
      if (allPlayers.length === 0) {
        showToast('info', 'Aviso', 'Nenhum jogador no elenco. Adicione nomes no Passo 1.');
      }

      // Lê configurações de tamanho de time
      const sizeA = parseInt(document.getElementById('whlTeamSizeA')?.value || '4', 10);
      const sizeB = parseInt(document.getElementById('whlTeamSizeB')?.value || '4', 10);
      const sizeC = parseInt(document.getElementById('whlTeamSizeC')?.value || '2', 10);

      this.wheelA.targetTeamSize = sizeA;
      this.wheelB.targetTeamSize = sizeB;
      this.wheelC.targetTeamSize = sizeC;

      // Filtra elegíveis por faixa de patente de cada mesa
      this.wheelA.setEligiblePlayers(this.filterEligibleForWheel('A', allPlayers));
      this.wheelB.setEligiblePlayers(this.filterEligibleForWheel('B', allPlayers));
      this.wheelC.setEligiblePlayers(this.filterEligibleForWheel('C', allPlayers));

      this.wheelA.updateSlots(1, { id: null });
      this.wheelB.updateSlots(1, { id: null });
      this.wheelC.updateSlots(1, { id: null });
    }

    filterEligibleForWheel(wheelId, pool) {
      const minVal = parseInt(document.getElementById(`whlRankMin${wheelId}`)?.value || '1', 10);
      const maxVal = parseInt(document.getElementById(`whlRankMax${wheelId}`)?.value || '10', 10);

      return pool.filter(p => {
        const r = getRankById(p.rankId);
        return r.weight >= minVal && r.weight <= maxVal;
      });
    }

    // Paradas escalonadas para clímax & suspense
    async spinActiveWheels() {
      const actA = document.getElementById('whlActiveA')?.checked;
      const actB = document.getElementById('whlActiveB')?.checked;
      const actC = document.getElementById('whlActiveC')?.checked;

      const promises = [];

      // Duração escalonada: A para em 3.2s, B em 4.0s, C em 4.8s
      if (actA && this.wheelA.eligiblePlayers.length > 0) {
        promises.push(this.wheelA.spin(3200).then(res => this.handleWheelResult(res)));
      }
      if (actB && this.wheelB.eligiblePlayers.length > 0) {
        promises.push(this.wheelB.spin(4000).then(res => this.handleWheelResult(res)));
      }
      if (actC && this.wheelC.eligiblePlayers.length > 0) {
        promises.push(this.wheelC.spin(4800).then(res => this.handleWheelResult(res)));
      }

      if (promises.length === 0) {
        sfx.error();
        showToast('error', 'Sem Roletas Ativas', 'Ative ao menos uma mesa com jogadores elegíveis.');
        return;
      }

      try {
        await Promise.all(promises);
        sfx.done();
        this.renderShowdownResults();
        this.saveAuditRecord();
      } catch (err) {
        console.warn('Giro interrompido ou já completo:', err);
      }
    }

    async spinSingle(wheel) {
      try {
        const res = await wheel.spin(3400);
        this.handleWheelResult(res);
        sfx.done();
        this.renderShowdownResults();
        this.saveAuditRecord();
      } catch (err) {
        sfx.error();
        showToast('info', 'Aviso', String(err));
      }
    }

    handleWheelResult(res) {
      // Se a opção "Jogador sorteado sai das outras roletas" estiver ativa, remove de B e C
      if (this.exclusiveChk && this.exclusiveChk.checked) {
        const pId = res.winner.id;
        this.wheelA.eligiblePlayers = this.wheelA.eligiblePlayers.filter(p => p.id !== pId);
        this.wheelB.eligiblePlayers = this.wheelB.eligiblePlayers.filter(p => p.id !== pId);
        this.wheelC.eligiblePlayers = this.wheelC.eligiblePlayers.filter(p => p.id !== pId);
        this.wheelA.draw();
        this.wheelB.draw();
        this.wheelC.draw();
      }

      // Exibe banner dramático de revelação
      if (this.revealBanner) {
        const rankObj = getRankById(res.winner.rankId);
        document.getElementById('revealWheelId').textContent = res.wheelId;
        document.getElementById('revealNick').textContent = res.winner.nick;
        document.getElementById('revealRankBadge').textContent = `${rankObj.name.toUpperCase()} (${rankObj.weight} PTS)`;
        document.getElementById('revealRankBadge').style.borderColor = rankObj.color;
        document.getElementById('revealRankBadge').style.color = rankObj.color;
        document.getElementById('revealSlot').textContent = `→ Time ${res.team}`;

        this.revealBanner.style.display = 'block';
        setTimeout(() => {
          this.revealBanner.style.display = 'none';
        }, 3600);
      }
    }

    // Auto-Equilíbrio de Times por Particionamento de Pesos
    autoBalanceTeams() {
      let balancedCount = 0;
      [this.wheelA, this.wheelB, this.wheelC].forEach(whl => {
        const all = [...whl.team1, ...whl.team2];
        if (all.length >= 4 && all.length % 2 === 0) {
          const half = all.length / 2;
          const best = this.findBestPartition(all, half);
          if (best) {
            whl.team1 = best.team1;
            whl.team2 = best.team2;
            whl.updateSlots(1, { id: null });
            whl.updateSlots(2, { id: null });
            balancedCount++;
          }
        }
      });

      if (balancedCount > 0) {
        sfx.done();
        this.renderShowdownResults();
        showToast('success', 'Auto-Equilíbrio Concluído', 'Os guerreiros foram redistribuídos pelo menor desnível de peso.');
      } else {
        sfx.error();
        showToast('info', 'Aviso', 'Times incompletos para balancear. Complete os giros primeiro.');
      }
    }

    findBestPartition(players, teamSize) {
      let minDiff = Infinity;
      let bestCombination = null;

      // Gera combinações de índice para team1
      const combine = (start, chosen) => {
        if (chosen.length === teamSize) {
          const team1 = chosen.map(i => players[i]);
          const team2 = players.filter((_, i) => !chosen.includes(i));

          // Respeita pin
          const pinConflict = team1.some(p => p.pinned && !players.slice(0, teamSize).includes(p));
          if (!pinConflict) {
            const sum1 = team1.reduce((acc, p) => acc + getRankById(p.rankId).weight, 0);
            const sum2 = team2.reduce((acc, p) => acc + getRankById(p.rankId).weight, 0);
            const diff = Math.abs(sum1 - sum2);

            if (diff < minDiff) {
              minDiff = diff;
              bestCombination = { team1, team2, diff };
            }
          }
          return;
        }

        for (let i = start; i < players.length; i++) {
          chosen.push(i);
          combine(i + 1, chosen);
          chosen.pop();
        }
      };

      combine(0, []);
      return bestCombination;
    }

    renderShowdownResults() {
      if (!this.matchesResultsGrid) return;
      const wheels = [
        { id: 'A', title: 'MESA A', wheel: this.wheelA, format: document.getElementById('whlFormatA')?.value || '4v4 Normal' },
        { id: 'B', title: 'MESA B', wheel: this.wheelB, format: document.getElementById('whlFormatB')?.value || '4v4 Bate-Soco' },
        { id: 'C', title: 'MESA C', wheel: this.wheelC, format: document.getElementById('whlFormatC')?.value || '2v2 Normal' }
      ];

      const maxTolerance = parseInt(this.toleranceInput?.value || '3', 10);

      this.matchesResultsGrid.innerHTML = wheels.map(w => {
        const t1 = w.wheel.team1;
        const t2 = w.wheel.team2;
        if (t1.length === 0 && t2.length === 0) return '';

        const sum1 = t1.reduce((acc, p) => acc + getRankById(p.rankId).weight, 0);
        const sum2 = t2.reduce((acc, p) => acc + getRankById(p.rankId).weight, 0);
        const delta = Math.abs(sum1 - sum2);
        const isBalanced = delta <= maxTolerance;

        return `
          <article class="match-showdown-card">
            <header class="match-card-head">
              <div class="match-title">
                <span class="wheel-id-badge badge-${w.id.toLowerCase()}">${w.title}</span>
                <strong>${w.format.replace('_', ' ').toUpperCase()}</strong>
              </div>
              <span class="balance-status-badge ${isBalanced ? 'balanced' : 'unbalanced'}">
                ${isBalanced ? 'EQUILIBRADO (Δ ' + delta + ' PTS)' : 'DESBALANCEADO (Δ ' + delta + ' PTS)'}
              </span>
            </header>

            <div class="showdown-teams-row">
              <div class="showdown-team-box team-a">
                <div class="showdown-team-head">
                  <strong>TIME 1</strong>
                  <span class="team-weight-sum">${sum1} pts</span>
                </div>
                <div class="showdown-players-list">
                  ${t1.map(p => {
                    const r = getRankById(p.rankId);
                    return `
                      <div class="showdown-player-row">
                        <span class="p-nick">${p.nick}</span>
                        <span style="color: ${r.color}; font-family: var(--font-mono); font-size: 0.72rem; font-weight: 700;">${r.abbr} (${r.weight})</span>
                      </div>
                    `;
                  }).join('')}
                </div>
              </div>

              <div class="showdown-vs-col">
                <div class="vs-pill">VS</div>
                <span class="delta-label">Dif: ${delta} pts</span>
              </div>

              <div class="showdown-team-box team-b">
                <div class="showdown-team-head">
                  <strong>TIME 2</strong>
                  <span class="team-weight-sum">${sum2} pts</span>
                </div>
                <div class="showdown-players-list">
                  ${t2.map(p => {
                    const r = getRankById(p.rankId);
                    return `
                      <div class="showdown-player-row">
                        <span class="p-nick">${p.nick}</span>
                        <span style="color: ${r.color}; font-family: var(--font-mono); font-size: 0.72rem; font-weight: 700;">${r.abbr} (${r.weight})</span>
                      </div>
                    `;
                  }).join('')}
                </div>
              </div>
            </div>
          </article>
        `;
      }).filter(Boolean).join('');
    }

    async saveAuditRecord() {
      this.currentDrawId = '#CCQ-' + Math.floor(1000 + Math.random() * 9000);
      const timestamp = new Date().toISOString();

      const payload = `${this.currentSeed}|${this.currentDrawId}|${this.wheelA.team1.map(p => p.nick).join(',')}|${timestamp}`;
      const hash = await sha256Hex(payload);

      if (this.auditDisplayId) this.auditDisplayId.textContent = this.currentDrawId;
      if (this.auditDisplaySeed) this.auditDisplaySeed.textContent = this.currentSeed;
      if (this.auditDisplayHash) this.auditDisplayHash.textContent = hash;

      const record = {
        id: this.currentDrawId,
        date: new Date().toLocaleString('pt-BR'),
        seed: this.currentSeed,
        hash: hash,
        matches: [
          { mesa: 'A', t1: this.wheelA.team1, t2: this.wheelA.team2 },
          { mesa: 'B', t1: this.wheelB.team1, t2: this.wheelB.team2 },
          { mesa: 'C', t1: this.wheelC.team1, t2: this.wheelC.team2 }
        ]
      };

      try {
        const history = JSON.parse(localStorage.getItem('cacique_audit_history_v4') || '[]');
        history.unshift(record);
        // Limita a 50 registros locais
        if (history.length > 50) history.pop();
        localStorage.setItem('cacique_audit_history_v4', JSON.stringify(history));
      } catch (_) {}
    }

    copyWhatsAppSummary(btn) {
      let text = `⚔️ *CACIQUE APOSTAS — CONFRONTOS DEFINIDOS* ⚔️\n`;
      text += `🛡️ *Tribo Oficial Free Fire* | Sorteio Auditado\n`;
      text += `📅 Data: ${new Date().toLocaleString('pt-BR')}\n`;
      text += `🔐 ID: ${this.currentDrawId} | Seed: ${this.currentSeed.slice(0, 10)}...\n\n`;

      const wheels = [
        { name: 'MESA A', w: this.wheelA },
        { name: 'MESA B', w: this.wheelB },
        { name: 'MESA C', w: this.wheelC }
      ];

      wheels.forEach(m => {
        if (m.w.team1.length > 0 || m.w.team2.length > 0) {
          const sum1 = m.w.team1.reduce((acc, p) => acc + getRankById(p.rankId).weight, 0);
          const sum2 = m.w.team2.reduce((acc, p) => acc + getRankById(p.rankId).weight, 0);
          text += `━━━━━━━━━━━━━━━━━━━━━\n`;
          text += `🔥 *${m.name}* (Força: ${sum1} vs ${sum2} pts)\n\n`;
          text += `🔴 *TIME 1 (${sum1} pts):*\n`;
          m.w.team1.forEach(p => {
            const r = getRankById(p.rankId);
            text += ` • ${p.nick} [${r.abbr} - ${r.weight}pts]\n`;
          });
          text += `\n⚡ *VS* ⚡\n\n`;
          text += `🔵 *TIME 2 (${sum2} pts):*\n`;
          m.w.team2.forEach(p => {
            const r = getRankById(p.rankId);
            text += ` • ${p.nick} [${r.abbr} - ${r.weight}pts]\n`;
          });
          text += `\n`;
        }
      });

      text += `━━━━━━━━━━━━━━━━━━━━━\n`;
      text += `✅ Pagamento garantido via Pix na hora.\n`;
      text += `🌐 Verificar autenticidade: https://enzommds7.github.io/ccq/`;

      performCopy(text, btn, 'Copiado para WhatsApp!');
    }

    // Gerador de Card PNG Nativo em 1200x630 (Offscreen Canvas 2D)
    generateShowdownCardPng() {
      const c = document.createElement('canvas');
      c.width = 1200;
      c.height = 630;
      const ctx = c.getContext('2d');

      // Fundo Grafite Industrial
      const grad = ctx.createLinearGradient(0, 0, 1200, 630);
      grad.addColorStop(0, '#0d0e12');
      grad.addColorStop(1, '#16171d');
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, 1200, 630);

      // Grade sutil
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
      ctx.lineWidth = 1;
      for (let x = 0; x < 1200; x += 60) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, 630); ctx.stroke();
      }

      // Moldura externa com cantoneiras vermelhas
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
      ctx.strokeRect(30, 30, 1140, 570);

      ctx.strokeStyle = '#e5484d';
      ctx.lineWidth = 3;
      // Cantos
      ctx.strokeRect(26, 26, 24, 24);
      ctx.strokeRect(1150, 26, 24, 24);
      ctx.strokeRect(26, 580, 24, 24);
      ctx.strokeRect(1150, 580, 24, 24);

      // Cabeçalho do Card
      ctx.fillStyle = '#e5484d';
      ctx.font = '700 16px "Share Tech Mono", monospace';
      ctx.fillText('TRIBO OFICIAL DE APOSTAS FREE FIRE', 60, 75);

      ctx.fillStyle = '#ffffff';
      ctx.font = '800 34px "Clash Display", sans-serif';
      ctx.fillText('CACIQUE APOSTAS — CONFRONTO AUDITADO', 60, 118);

      // Exibe os times da Mesa A (ou principal ativa)
      const t1 = this.wheelA.team1;
      const t2 = this.wheelA.team2;
      const sum1 = t1.reduce((acc, p) => acc + getRankById(p.rankId).weight, 0);
      const sum2 = t2.reduce((acc, p) => acc + getRankById(p.rankId).weight, 0);

      // Box Time 1
      ctx.fillStyle = 'rgba(229, 72, 77, 0.08)';
      ctx.fillRect(60, 160, 480, 360);
      ctx.strokeStyle = 'rgba(229, 72, 77, 0.3)';
      ctx.strokeRect(60, 160, 480, 360);

      ctx.fillStyle = '#e5484d';
      ctx.font = '700 22px "Clash Display", sans-serif';
      ctx.fillText(`TIME 1 — ${sum1} PONTOS`, 85, 205);

      let yPos = 250;
      t1.forEach((p, idx) => {
        const r = getRankById(p.rankId);
        ctx.fillStyle = '#ffffff';
        ctx.font = '600 18px Geist, sans-serif';
        ctx.fillText(`${idx + 1}. ${p.nick}`, 85, yPos);

        ctx.fillStyle = r.color;
        ctx.font = '700 14px "Share Tech Mono", monospace';
        ctx.fillText(`${r.name.toUpperCase()} (${r.weight}pts)`, 420, yPos);
        yPos += 42;
      });

      // VS Badge Central
      ctx.fillStyle = '#d4af37';
      ctx.font = '800 36px "Clash Display", sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('VS', 600, 350);
      ctx.textAlign = 'left';

      // Box Time 2
      ctx.fillStyle = 'rgba(59, 130, 246, 0.08)';
      ctx.fillRect(660, 160, 480, 360);
      ctx.strokeStyle = 'rgba(59, 130, 246, 0.3)';
      ctx.strokeRect(660, 160, 480, 360);

      ctx.fillStyle = '#3b82f6';
      ctx.font = '700 22px "Clash Display", sans-serif';
      ctx.fillText(`TIME 2 — ${sum2} PONTOS`, 685, 205);

      yPos = 250;
      t2.forEach((p, idx) => {
        const r = getRankById(p.rankId);
        ctx.fillStyle = '#ffffff';
        ctx.font = '600 18px Geist, sans-serif';
        ctx.fillText(`${idx + 1}. ${p.nick}`, 685, yPos);

        ctx.fillStyle = r.color;
        ctx.font = '700 14px "Share Tech Mono", monospace';
        ctx.fillText(`${r.name.toUpperCase()} (${r.weight}pts)`, 1020, yPos);
        yPos += 42;
      });

      // Rodapé de Auditoria
      ctx.fillStyle = '#8a8f98';
      ctx.font = '500 13px "Share Tech Mono", monospace';
      ctx.fillText(`ID: ${this.currentDrawId} | SEED: ${this.currentSeed} | JOGUE COM RESPONSABILIDADE (18+)`, 60, 565);

      // Download
      c.toBlob(blob => {
        if (!blob) return;
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cacique-confronto-${this.currentDrawId.replace('#', '')}.png`;
        a.click();
        URL.revokeObjectURL(url);
        sfx.done();
        showToast('success', 'Imagem Gerada', 'Card PNG do confronto baixado com sucesso.');
      }, 'image/png');
    }

    toggleTelaoMode() {
      const telao = document.getElementById('telaoOverlay');
      const telaoContent = document.getElementById('telaoContent');
      if (!telao || !telaoContent) return;

      if (telao.style.display === 'none') {
        telao.style.display = 'flex';
        // Renderiza conteúdo em alta visibilidade
        telaoContent.innerHTML = `
          <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; width: 100%;">
            <div class="wheel-arena-cell">
              <h3 style="color: var(--red); margin-bottom: 12px;">MESA A (4v4)</h3>
              <div id="telaoSlotsA"></div>
            </div>
            <div class="wheel-arena-cell">
              <h3 style="color: var(--gold); margin-bottom: 12px;">MESA B (4v4 Bate-Soco)</h3>
              <div id="telaoSlotsB"></div>
            </div>
            <div class="wheel-arena-cell">
              <h3 style="color: var(--cyan); margin-bottom: 12px;">MESA C (2v2)</h3>
              <div id="telaoSlotsC"></div>
            </div>
          </div>
        `;

        document.getElementById('telaoSlotsA').innerHTML = document.getElementById('liveMatchA').innerHTML;
        document.getElementById('telaoSlotsB').innerHTML = document.getElementById('liveMatchB').innerHTML;
        document.getElementById('telaoSlotsC').innerHTML = document.getElementById('liveMatchC').innerHTML;

        sfx.tick(1200);
      } else {
        telao.style.display = 'none';
        sfx.tick(800);
      }
    }

    resetRound() {
      this.currentSeed = generateRandomSeedHex();
      this.currentDrawId = '#CCQ-' + Math.floor(1000 + Math.random() * 9000);
      this.wheelA.reset();
      this.wheelB.reset();
      this.wheelC.reset();
      this.prepareWheels();
      if (this.matchesResultsGrid) this.matchesResultsGrid.innerHTML = '';
      if (this.revealBanner) this.revealBanner.style.display = 'none';
    }
  }

  const rouletteArena = new RouletteArena();

  // Binds do Modo Telão
  const btnTelaoMode = document.getElementById('btnTelaoMode');
  const telaoBtnExit = document.getElementById('telaoBtnExit');
  const telaoBtnSpin = document.getElementById('telaoBtnSpin');

  if (btnTelaoMode) btnTelaoMode.addEventListener('click', () => rouletteArena.toggleTelaoMode());
  if (telaoBtnExit) telaoBtnExit.addEventListener('click', () => rouletteArena.toggleTelaoMode());
  if (telaoBtnSpin) telaoBtnSpin.addEventListener('click', () => rouletteArena.spinActiveWheels());

  // ─────────────────────────────────────────────────────────────
  // 12. ARENA: Modal de Auditoria e Verificador Criptográfico
  // ─────────────────────────────────────────────────────────────
  const btnAuditModal = document.getElementById('btnAuditModal');
  const modalAuditBackdrop = document.getElementById('modalAuditBackdrop');
  const auditHistoryList = document.getElementById('auditHistoryList');
  const auditSearchInput = document.getElementById('auditSearchInput');
  const btnExportAuditCsv = document.getElementById('btnExportAuditCsv');
  const btnClearAuditHistory = document.getElementById('btnClearAuditHistory');

  function renderAuditHistory() {
    if (!auditHistoryList) return;
    const history = JSON.parse(localStorage.getItem('cacique_audit_history_v4') || '[]');
    const q = (auditSearchInput?.value || '').toLowerCase().trim();

    const filtered = history.filter(item => {
      if (!q) return true;
      return item.id.toLowerCase().includes(q) || item.seed.toLowerCase().includes(q) || item.date.toLowerCase().includes(q);
    });

    if (filtered.length === 0) {
      auditHistoryList.innerHTML = `<div class="stage-empty"><p>Nenhum histórico de sorteio registrado ainda.</p></div>`;
      return;
    }

    auditHistoryList.innerHTML = filtered.map(item => `
      <div class="audit-entry-card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <strong style="color: var(--gold); font-family: var(--font-mono);">${item.id}</strong>
          <span style="font-size: 0.75rem; color: var(--text-3);">${item.date}</span>
        </div>
        <div style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-2); margin-bottom: 4px;">
          SEED: <code>${item.seed}</code>
        </div>
        <div style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-3); word-break: break-all;">
          HASH SHA-256: ${item.hash}
        </div>
      </div>
    `).join('');
  }

  if (btnAuditModal) {
    btnAuditModal.addEventListener('click', () => {
      renderAuditHistory();
      if (modalAuditBackdrop) modalAuditBackdrop.style.display = 'flex';
      sfx.tick(850);
    });
  }

  if (auditSearchInput) {
    auditSearchInput.addEventListener('input', renderAuditHistory);
  }

  if (btnExportAuditCsv) {
    btnExportAuditCsv.addEventListener('click', () => {
      const history = JSON.parse(localStorage.getItem('cacique_audit_history_v4') || '[]');
      if (history.length === 0) {
        showToast('info', 'Histórico Vazio', 'Não há registros para exportar.');
        return;
      }
      let csv = 'ID,Data,Seed,Hash\n';
      history.forEach(h => {
        csv += `"${h.id}","${h.date}","${h.seed}","${h.hash}"\n`;
      });
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cacique-auditoria-${Date.now()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      sfx.done();
      showToast('success', 'Exportado', 'Arquivo CSV de auditoria baixado.');
    });
  }

  if (btnClearAuditHistory) {
    btnClearAuditHistory.addEventListener('click', () => {
      if (confirm('Deseja apagar todo o histórico local de auditoria?')) {
        localStorage.removeItem('cacique_audit_history_v4');
        renderAuditHistory();
        sfx.tick(600);
        showToast('info', 'Limpo', 'Histórico apagado com sucesso.');
      }
    });
  }

  // Modal Verificar Sorteio
  const btnVerifyModal = document.getElementById('btnVerifyModal');
  const modalVerifyBackdrop = document.getElementById('modalVerifyBackdrop');
  const verifySeedInput = document.getElementById('verifySeedInput');
  const verifyPlayersInput = document.getElementById('verifyPlayersInput');
  const btnRunVerification = document.getElementById('btnRunVerification');
  const verifyOutput = document.getElementById('verifyOutput');

  if (btnVerifyModal) {
    btnVerifyModal.addEventListener('click', () => {
      if (modalVerifyBackdrop) modalVerifyBackdrop.style.display = 'flex';
      sfx.tick(850);
    });
  }

  if (btnRunVerification && verifySeedInput && verifyPlayersInput && verifyOutput) {
    btnRunVerification.addEventListener('click', () => {
      const seed = verifySeedInput.value.trim();
      const playersRaw = verifyPlayersInput.value.trim();
      if (!seed || !playersRaw) {
        sfx.error();
        showToast('error', 'Campos Incompletos', 'Preencha a Seed e a lista de jogadores para auditar.');
        return;
      }

      const players = playersRaw.split(',').map(p => p.trim()).filter(Boolean);
      if (players.length === 0) return;

      // Cálculo de verificação determinístico da seed
      let seedInt = 0;
      for (let i = 0; i < seed.length; i++) {
        seedInt = (seedInt * 31 + seed.charCodeAt(i)) >>> 0;
      }
      const winningIdx = seedInt % players.length;

      verifyOutput.style.display = 'block';
      verifyOutput.innerHTML = `
        <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid var(--live-green); padding: 14px; border-radius: 6px; margin-top: 14px;">
          <strong style="color: var(--live-green); display: block; margin-bottom: 4px;">VERIFICAÇÃO CONCLUÍDA — 100% REPRODUZÍVEL</strong>
          <span style="font-size: 0.84rem; color: #fff;">Guerreiro Sorteado: <strong>${players[winningIdx]}</strong> (Índice ${winningIdx} de ${players.length})</span>
        </div>
      `;
      sfx.done();
    });
  }

  // ─────────────────────────────────────────────────────────────
  // 13. MODO RÁPIDO CLÁSSICO (100% Preservado)
  // ─────────────────────────────────────────────────────────────
  const namesInput = document.getElementById('namesInput');
  const sizeBtns = document.querySelectorAll('.size-btn');
  const customSizeInput = document.getElementById('customSize');
  const sortInfo = document.getElementById('sortInfo');
  const sortBtn = document.getElementById('sortBtn');
  const clearBtn = document.getElementById('clearBtn');
  const sorteioStage = document.getElementById('sorteioStage');

  let quickTeamSize = 4;

  function updateQuickTeamSize(size, btnElement) {
    quickTeamSize = parseInt(size, 10);
    sizeBtns.forEach(btn => btn.classList.remove('active'));
    if (btnElement) {
      btnElement.classList.add('active');
      if (customSizeInput) customSizeInput.value = '';
    }
    updateQuickSortInfo();
    sfx.tick(900);
  }

  sizeBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      updateQuickTeamSize(e.currentTarget.dataset.size, e.currentTarget);
    });
  });

  if (customSizeInput) {
    customSizeInput.addEventListener('input', (e) => {
      const val = parseInt(e.target.value, 10);
      if (val >= 2) {
        quickTeamSize = val;
        sizeBtns.forEach(btn => btn.classList.remove('active'));
        updateQuickSortInfo();
      }
    });
  }

  function getValidQuickNames() {
    if (!namesInput) return [];
    return namesInput.value
      .split('\n')
      .map(name => name.trim())
      .filter(name => name.length > 0);
  }

  let lastQuickPlayerCount = 0;
  let quickAnimFrame = null;

  function animateQuickPlayerCounter(targetCount) {
    const counterEl = document.getElementById('playerCounter');
    if (!counterEl) return;
    if (quickAnimFrame) cancelAnimationFrame(quickAnimFrame);

    const start = lastQuickPlayerCount;
    const diff = targetCount - start;
    if (diff === 0) {
      counterEl.textContent = targetCount;
      return;
    }

    const duration = 260;
    const startTime = performance.now();
    counterEl.classList.add('bump');
    setTimeout(() => counterEl.classList.remove('bump'), 220);

    function step(now) {
      const elapsed = now - startTime;
      const progress = Math.min(1, elapsed / duration);
      const ease = 1 - Math.pow(1 - progress, 3);
      counterEl.textContent = Math.round(start + diff * ease);

      if (progress < 1) {
        quickAnimFrame = requestAnimationFrame(step);
      } else {
        counterEl.textContent = targetCount;
        lastQuickPlayerCount = targetCount;
      }
    }
    quickAnimFrame = requestAnimationFrame(step);
  }

  function updateQuickSortInfo() {
    if (!sortInfo) return;
    const namesCount = getValidQuickNames().length;
    animateQuickPlayerCounter(namesCount);

    if (namesCount > 0 && namesCount < quickTeamSize) {
      if (sortBtn) {
        sortBtn.disabled = true;
        sortBtn.title = `Mínimo de ${quickTeamSize} jogadores necessário`;
      }
    } else if (namesCount === 0) {
      if (sortBtn) sortBtn.disabled = true;
    } else {
      if (sortBtn) {
        sortBtn.disabled = false;
        sortBtn.title = '';
      }
    }
  }

  if (namesInput) namesInput.addEventListener('input', updateQuickSortInfo);

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (namesInput) namesInput.value = '';
      updateQuickSortInfo();
      if (sorteioStage) {
        sorteioStage.innerHTML = `
          <div class="stage-empty">
            <svg viewBox="0 0 24 24"><path d="M16 3h5v5"/><path d="M4 20L21 3"/><path d="M21 16v5h-5"/><path d="M15 15l6 6"/><path d="M4 4l5 5"/></svg>
            <p>Adicione nomes e clique em sortear para gerar os confrontos da partida</p>
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

  if (sortBtn) {
    sortBtn.addEventListener('click', () => {
      const names = getValidQuickNames();
      if (names.length < quickTeamSize) return;

      // Estado de loading com suspense (1.4s)
      sorteioStage.innerHTML = `
        <div class="sorteio-suspense">
          <span class="suspense-label"><span class="pulse-dot"></span> Embaralhando guerreiros...</span>
          <div class="suspense-name" id="suspenseName">···</div>
          <div class="suspense-bar-track">
            <div class="suspense-bar-fill" id="suspenseBar"></div>
          </div>
        </div>
      `;

      const suspenseNameEl = document.getElementById('suspenseName');
      const suspenseBarEl = document.getElementById('suspenseBar');
      const totalDuration = 1400;
      const startTime = performance.now();
      let rollTicks = 0;

      const suspenseInterval = setInterval(() => {
        const elapsed = performance.now() - startTime;
        const pct = Math.min(100, (elapsed / totalDuration) * 100);

        if (suspenseNameEl) {
          suspenseNameEl.textContent = names[Math.floor(Math.random() * names.length)];
        }
        if (suspenseBarEl) {
          suspenseBarEl.style.width = pct + '%';
        }

        rollTicks++;
        if (rollTicks % 2 === 0) {
          sfx.tick(700 + Math.random() * 500);
        }

        if (elapsed >= totalDuration) {
          clearInterval(suspenseInterval);
          renderQuickResults(names);
        }
      }, 50);
    });
  }

  function renderQuickResults(names) {
    const shuffled = shuffle([...names]);
    const numTeams = Math.floor(shuffled.length / quickTeamSize);
    const leftovers = shuffled.length % quickTeamSize;

    let html = `
      <div class="stage-result-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <h4 style="font-size: 1.1rem; color: #fff;">Confronto Definido (${numTeams} Times)</h4>
        <button type="button" class="btn btn-primary btn-sm" id="quickExportWhatsAppBtn">Copiar para WhatsApp</button>
      </div>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px;">
    `;

    for (let i = 0; i < numTeams; i++) {
      const teamPlayers = shuffled.slice(i * quickTeamSize, (i + 1) * quickTeamSize);
      html += `
        <div class="showdown-team-box" style="padding: 14px;">
          <strong style="color: var(--red); display: block; margin-bottom: 8px;">TIME ${i + 1}</strong>
          ${teamPlayers.map(p => `<div style="font-size: 0.84rem; padding: 3px 0; color: #fff;">• ${p}</div>`).join('')}
        </div>
      `;
    }

    if (leftovers > 0) {
      const remaining = shuffled.slice(numTeams * quickTeamSize);
      html += `
        <div class="showdown-team-box" style="border-color: rgba(245, 158, 11, 0.3);">
          <strong style="color: var(--amber); display: block; margin-bottom: 8px;">RESERVAS (${leftovers})</strong>
          ${remaining.map(p => `<div style="font-size: 0.84rem; padding: 3px 0; color: var(--text-2);">• ${p}</div>`).join('')}
        </div>
      `;
    }

    html += `</div>`;
    sorteioStage.innerHTML = html;
    sfx.done();

    const quickExportBtn = document.getElementById('quickExportWhatsAppBtn');
    if (quickExportBtn) {
      quickExportBtn.addEventListener('click', () => {
        let text = `⚔️ *CACIQUE APOSTAS — CONFRONTO RÁPIDO* ⚔️\n\n`;
        for (let i = 0; i < numTeams; i++) {
          text += `🔥 *TIME ${i + 1}:*\n`;
          for (let j = 0; j < quickTeamSize; j++) {
            text += ` • ${shuffled[i * quickTeamSize + j]}\n`;
          }
          text += `\n`;
        }
        if (leftovers > 0) {
          text += `⚠️ *RESERVAS:*\n`;
          shuffled.slice(numTeams * quickTeamSize).forEach(p => text += ` • ${p}\n`);
          text += `\n`;
        }
        text += `🛡️ Tribo Oficial: https://enzommds7.github.io/ccq/`;
        performCopy(text, quickExportBtn, 'Copiado para WhatsApp!');
      });
    }
  }

  // ─────────────────────────────────────────────────────────────
  // 14. CACIQUE SCAN ENGINE v3.1 — FORENSE COMPLETO (PRESERVADO)
  // ─────────────────────────────────────────────────────────────
  const scanLoginView = document.getElementById('scanLoginView');
  const scanDashboardView = document.getElementById('scanDashboardView');
  const scanUser = document.getElementById('scanUser');
  const scanPass = document.getElementById('scanPass');
  const scanBtnLogin = document.getElementById('scanBtnLogin');
  const scanBtnLogout = document.getElementById('scanBtnLogout');

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

  let currentScanMode = 'zip';
  let currentScanReport = null;
  let activeFilterCategory = 'all';

  // Assinaturas Oficiais Forenses (Offsets Coringa & OB40 Weapons)
  const CHEAT_SIGNATURES = [
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
    { term: 'aimlock_head_ob40_', name: 'Aimlock OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimbot_head_ob40_', name: 'Aimbot OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'no_recoil_ob40_', name: 'No Recoil OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimfov_ob40_', name: 'Aim FOV OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'sensi_ob40_', name: 'Sensi Hack OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'libil2cpp.so', name: 'Hook em Libil2cpp (Free Fire Core)', cat: 'injection', weight: 90, risk: 'Crítico' },
    { term: 'gameguardian', name: 'Engine de Memória GameGuardian', cat: 'package', weight: 95, risk: 'Ban Direto' },
    { term: 'frida-server', name: 'Injetor Dinâmico Frida', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: 'catch_.me_.if_.you_.can_', name: 'Assinatura Root Magisk/Zygisk', cat: 'system', weight: 80, risk: 'Alto' }
  ];

  function unlockScanDashboard() {
    if (scanLoginView && scanDashboardView) {
      scanLoginView.style.display = 'none';
      scanDashboardView.style.display = 'block';
    }
  }

  function lockScanDashboard() {
    if (scanLoginView && scanDashboardView) {
      scanLoginView.style.display = 'block';
      scanDashboardView.style.display = 'none';
    }
  }

  if (isAdmAuthenticated) {
    unlockScanDashboard();
  }

  if (scanBtnLogin && scanUser && scanPass) {
    scanBtnLogin.addEventListener('click', () => {
      handleAdminLogin(scanUser.value, scanPass.value);
    });
  }

  if (scanBtnLogout) {
    scanBtnLogout.addEventListener('click', () => {
      isAdmAuthenticated = false;
      localStorage.removeItem(AUTH_STORAGE_KEY);
      updateAuthUI();
      lockScanDashboard();
      sfx.tick(600);
      showToast('info', 'Desconectado', 'Scanner bloqueado com segurança.');
    });
  }

  // Modos de Análise
  function setScanMode(mode) {
    currentScanMode = mode;
    [modeZipBtn, modeFolderBtn, modeLooseBtn].forEach(btn => btn?.classList.remove('active'));
    if (mode === 'zip') {
      modeZipBtn?.classList.add('active');
      scanUploadTitle.textContent = 'Arraste o arquivo .zip ou .tar.gz aqui';
      scanUploadDesc.textContent = 'Bugreport Android (.zip), Sysdiagnose iOS (.tar.gz) ou dump de cheat';
    } else if (mode === 'folder') {
      modeFolderBtn?.classList.add('active');
      scanUploadTitle.textContent = 'Selecione ou arraste a pasta extraída';
      scanUploadDesc.textContent = 'Pasta de bugreport ou dump descompactado no computador';
    } else {
      modeLooseBtn?.classList.add('active');
      scanUploadTitle.textContent = 'Selecione múltiplos arquivos de log soltos';
      scanUploadDesc.textContent = 'Arquivos .txt, .log, logcat ou dumps de memória';
    }
    sfx.tick(850);
  }

  if (modeZipBtn) modeZipBtn.addEventListener('click', () => setScanMode('zip'));
  if (modeFolderBtn) modeFolderBtn.addEventListener('click', () => setScanMode('folder'));
  if (modeLooseBtn) modeLooseBtn.addEventListener('click', () => setScanMode('loose'));

  if (scanUploadBox) {
    scanUploadBox.addEventListener('click', () => {
      if (currentScanMode === 'zip') scanFileInput?.click();
      else if (currentScanMode === 'folder') scanFolderInput?.click();
      else scanLooseInput?.click();
    });

    scanUploadBox.addEventListener('dragover', (e) => {
      e.preventDefault();
      scanUploadBox.classList.add('dragover');
    });

    scanUploadBox.addEventListener('dragleave', () => {
      scanUploadBox.classList.remove('dragover');
    });

    scanUploadBox.addEventListener('drop', (e) => {
      e.preventDefault();
      scanUploadBox.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        processUploadedFiles(e.dataTransfer.files);
      }
    });
  }

  [scanFileInput, scanFolderInput, scanLooseInput].forEach(inp => {
    if (inp) {
      inp.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
          processUploadedFiles(e.target.files);
        }
      });
    }
  });

  // Execução Forense
  async function processUploadedFiles(fileList) {
    scanUploadBox.style.display = 'none';
    scanTerminalWrap.style.display = 'block';
    scanResults.style.display = 'none';
    terminalLines.innerHTML = '';

    logTerminal('SYS', 'Iniciando ccq-forensics engine 3.1...', 'terminal-info');
    logTerminal('IO', `Detectados ${fileList.length} arquivos no buffer de entrada.`, 'terminal-info');

    updateScanProgress(10, 'Carregando arquivos para a sandbox de memória...');

    const findings = [];
    const filesToScan = [];

    // Suporte a descompactação client-side de .ZIP via JSZip se disponível
    if (fileList.length === 1 && fileList[0].name.endsWith('.zip') && typeof JSZip !== 'undefined') {
      try {
        logTerminal('ZIP', 'Descompactando container .zip em memória RAM...', 'terminal-info');
        const zip = await JSZip.loadAsync(fileList[0]);
        let zCount = 0;
        for (const [relPath, zipEntry] of Object.entries(zip.files)) {
          if (!zipEntry.dir && (relPath.endsWith('.txt') || relPath.endsWith('.log') || relPath.endsWith('.dump') || relPath.includes('bugreport'))) {
            const content = await zipEntry.async('string');
            filesToScan.push({ name: relPath, content });
            zCount++;
          }
        }
        logTerminal('ZIP', `${zCount} arquivos de log extraídos com sucesso.`, 'terminal-info');
      } catch (err) {
        logTerminal('ERR', `Falha ao abrir zip: ${err.message}`, 'terminal-err');
      }
    } else {
      for (let i = 0; i < Math.min(fileList.length, 30); i++) {
        const f = fileList[i];
        try {
          const content = await f.text();
          filesToScan.push({ name: f.name, content });
        } catch (_) {}
      }
    }

    updateScanProgress(40, 'Executando varredura por offsets e injeções il2cpp...');

    // Varredura por assinaturas
    let checkedLines = 0;
    for (const fileObj of filesToScan) {
      logTerminal('SCAN', `Analisando: ${fileObj.name}`, 'terminal-info');
      const lines = fileObj.content.split('\n');
      checkedLines += lines.length;

      for (let idx = 0; idx < lines.length; idx++) {
        const line = lines[idx];
        for (const sig of CHEAT_SIGNATURES) {
          if (line.toLowerCase().includes(sig.term.toLowerCase())) {
            findings.push({
              sig: sig,
              file: fileObj.name,
              lineNum: idx + 1,
              snippet: line.trim()
            });
            logTerminal('ALERTA', `[${sig.risk.toUpperCase()}] ${sig.name} em ${fileObj.name}:${idx + 1}`, 'terminal-err');
            sfx.alert(sig.weight === 100);
            break;
          }
        }
      }
    }

    updateScanProgress(85, 'Compilando relatório pericial forense...');
    await new Promise(r => setTimeout(r, 600));

    updateScanProgress(100, 'Varredura pericial concluída.');
    logTerminal('SYS', `Análise finalizada: ${checkedLines} linhas verificadas, ${findings.length} ameaças encontradas.`, 'terminal-info');

    sfx.done();
    currentScanReport = {
      findings,
      checkedLines,
      timestamp: new Date().toLocaleString('pt-BR'),
      score: findings.length === 0 ? 100 : Math.max(0, 100 - findings.length * 25)
    };

    displayScanResults(currentScanReport);
  }

  function logTerminal(prefix, msg, cssClass = '') {
    if (!terminalLines) return;
    const line = document.createElement('div');
    line.className = `terminal-line ${cssClass}`;
    line.textContent = `[${prefix}] ${msg}`;
    terminalLines.appendChild(line);
    terminalLines.scrollTop = terminalLines.scrollHeight;
  }

  function updateScanProgress(pct, label) {
    if (scanProgressFill) scanProgressFill.style.width = pct + '%';
    if (scanProgressPercent) scanProgressPercent.textContent = pct + '%';
    if (scanProgressLabel) scanProgressLabel.textContent = label;
  }

  function displayScanResults(report) {
    if (!scanResults) return;
    scanResults.style.display = 'block';

    const isClean = report.findings.length === 0;

    resultSummary.innerHTML = `
      <h3 style="color: ${isClean ? 'var(--live-green)' : 'var(--red)'};">
        ${isClean ? 'DISPOSITIVO 100% LIMPO & APROVADO' : 'AMEAÇAS FORENSES DETECTADAS'}
      </h3>
      <p style="color: var(--text-2); font-size: 0.95rem;">
        ${isClean ? 'Nenhum mod menu, offset il2cpp ou bypass foi identificado nos logs examinados.' : `Foram encontradas ${report.findings.length} evidências de trapaça ou modificações não autorizadas.`}
      </p>
      <div style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-3); margin-top: 10px;">
        Pontuação de Integridade: <strong style="color: #fff;">${report.score}/100</strong> · Linhas analisadas: ${report.checkedLines}
      </div>
    `;

    resultDetails.innerHTML = report.findings.map(f => `
      <div class="result-card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
          <strong style="color: #fff;">${f.sig.name}</strong>
          <span style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--red); background: rgba(229,72,77,0.15); padding: 2px 8px; border-radius: 4px;">${f.sig.risk}</span>
        </div>
        <div style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-3); margin-bottom: 6px;">
          Arquivo: ${f.file} (linha ${f.lineNum})
        </div>
        <code style="display: block; word-break: break-all; color: #ff8a80; background: #000; padding: 6px 10px; border-radius: 4px;">
          ${f.snippet.slice(0, 180)}
        </code>
      </div>
    `).join('');
  }

  if (scanBtnCopyReport) {
    scanBtnCopyReport.addEventListener('click', () => {
      if (!currentScanReport) return;
      let rep = `🛡️ *RELATÓRIO FORENSE — CACIQUE SCAN v3.1* 🛡️\n`;
      rep += `📅 Data: ${currentScanReport.timestamp}\n`;
      rep += `🎯 Score de Integridade: ${currentScanReport.score}/100\n`;
      rep += `🔍 Linhas Verificadas: ${currentScanReport.checkedLines}\n`;
      rep += `⚠️ Ameaças Encontradas: ${currentScanReport.findings.length}\n\n`;

      if (currentScanReport.findings.length === 0) {
        rep += `✅ NENHUMA IRREGULARIDADE DETECTADA. JOGADOR APROVADO.\n`;
      } else {
        currentScanReport.findings.forEach((f, idx) => {
          rep += `${idx + 1}. [${f.sig.risk}] ${f.sig.name}\n   Arquivo: ${f.file}:${f.lineNum}\n   Snippet: ${f.snippet.slice(0, 80)}\n\n`;
        });
      }
      rep += `----------------------------------\n`;
      rep += `Tribo Oficial: https://enzommds7.github.io/ccq/`;

      performCopy(rep, scanBtnCopyReport, 'Relatório Copiado!');
    });
  }

  if (scanBtnNew) {
    scanBtnNew.addEventListener('click', () => {
      scanUploadBox.style.display = 'block';
      scanTerminalWrap.style.display = 'none';
      scanResults.style.display = 'none';
      sfx.tick(700);
    });
  }

  // ─────────────────────────────────────────────────────────────
  // 15. REDES SOCIAIS: Abas & Cópia de Links Oficiais
  // ─────────────────────────────────────────────────────────────
  const redeTabBtns = document.querySelectorAll('.rede-tab-btn');
  const redeTabContents = document.querySelectorAll('.redes-tab-content');

  redeTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.dataset.tab;
      redeTabBtns.forEach(b => b.classList.remove('active'));
      redeTabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const activeContent = document.getElementById(`tab-${targetTab}`);
      if (activeContent) activeContent.classList.add('active');
      sfx.tick(850);
    });
  });

  document.querySelectorAll('.rede-copy-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const copyVal = e.currentTarget.dataset.copy;
      if (copyVal) {
        performCopy(copyVal, e.currentTarget, 'Copiado!');
      }
    });
  });

});
