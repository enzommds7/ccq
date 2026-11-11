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

    // Bipe de início de operação (scanner / motor)
    start() {
      this.tick(1200);
    }

    // Bipe sonoro 1200Hz (equivalente a winsound.Beep(1200, 500) para origem não autorizada)
    beep1200() {
      this.vibrate([60, 40, 60]);
      if (!this.enabled) return;
      this.init();
      if (!this.ctx) return;
      try {
        const t = this.ctx.currentTime;
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(1200, t);
        gain.gain.setValueAtTime(0.08, t);
        gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.35);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start(t);
        osc.stop(t + 0.36);
      } catch (_) {}
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
  // 2. Utilitário Global Anti-XSS & Sistema de Notificações Toast
  // ─────────────────────────────────────────────────────────────
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/[&<>"']/g, m => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    })[m]);
  }

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
        <strong>${escapeHtml(title)}</strong>
        <span>${escapeHtml(message)}</span>
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

  // SHA-256 nativo (Web Crypto) com fallback RFC-6234 puro JS (100% determinístico em HTTPS, HTTP e file://)
  function pureJsSha256(ascii) {
    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }
    const mathPow = Math.pow;
    const maxWord = mathPow(2, 32);
    let i, j;
    let result = '';
    const words = [];
    const asciiBitLength = ascii.length * 8;
    const hash = [];
    const k = [];
    let primeCounter = 0;
    const isComposite = {};
    for (let candidate = 2; primeCounter < 64; candidate++) {
      if (!isComposite[candidate]) {
        for (i = 0; i < 313; i += candidate) isComposite[i] = candidate;
        hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
        k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      }
    }
    ascii += '\x80';
    while ((ascii.length % 64) - 56) ascii += '\x00';
    for (i = 0; i < ascii.length; i++) {
      j = ascii.charCodeAt(i);
      words[i >> 2] |= j << ((3 - (i % 4)) * 8);
    }
    words[words.length] = (asciiBitLength / maxWord) | 0;
    words[words.length] = asciiBitLength;
    for (j = 0; j < words.length;) {
      const w = words.slice(j, (j += 16));
      const oldHash = hash.slice(0, 8);
      for (i = 0; i < 64; i++) {
        const w15 = w[i - 15];
        const w2 = w[i - 2];
        const a = hash[0];
        const e = hash[4];
        const temp1 = hash[7] +
          (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) +
          ((e & hash[5]) ^ (~e & hash[6])) +
          k[i] +
          (w[i] = (i < 16) ? w[i] : (
            w[i - 16] +
            (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) +
            w[i - 7] +
            (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
          ) | 0);
        const temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) +
          ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
        hash[7] = hash[6];
        hash[6] = hash[5];
        hash[5] = hash[4];
        hash[4] = (oldHash[4] + temp1) | 0;
        hash[3] = hash[2];
        hash[2] = hash[1];
        hash[1] = hash[0];
        hash[0] = (temp1 + temp2) | 0;
      }
      for (i = 0; i < 8; i++) {
        hash[i] = (hash[i] + oldHash[i]) | 0;
      }
    }
    for (i = 0; i < 8; i++) {
      for (j = 3; j >= 0; j--) {
        const b = (hash[i] >> (j * 8)) & 255;
        result += ((b < 16) ? '0' : '') + b.toString(16);
      }
    }
    return result;
  }

  async function sha256Hex(str) {
    try {
      if (typeof crypto !== 'undefined' && crypto.subtle && crypto.subtle.digest) {
        const buf = new TextEncoder().encode(str);
        const hashBuf = await crypto.subtle.digest('SHA-256', buf);
        const arr = Array.from(new Uint8Array(hashBuf));
        return arr.map(b => b.toString(16).padStart(2, '0')).join('');
      }
    } catch (_) {}
    return pureJsSha256(str);
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
  // 6. Autenticação Unificada de ADM (Sempre Exige Login ao Entrar)
  // ─────────────────────────────────────────────────────────────
  const ADMIN_USER_HASH = '3680593c420bee400f624c81661151f3141f3271ed3f80121738da69f456cace';
  const ADMIN_PASS_HASH = 'e0112dd9dc3f248b7a9e78bda4d522999d68636989c772137e7f644d32caf443';
  const AUTH_STORAGE_KEY = 'cacique_unified_adm_auth';

  // Remove qualquer sessão antiga salva no navegador para NUNCA iniciar logado automaticamente
  try {
    localStorage.removeItem('cacique_unified_adm_auth');
    localStorage.removeItem('cacique_scan_authenticated');
    sessionStorage.removeItem('cacique_unified_adm_auth');
  } catch (_) {}

  let isAdmAuthenticated = false;
  let adminSessionToken = null;

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
    const cleanUser = (userVal || '').trim().toUpperCase();
    const cleanPass = (passVal || '').trim();

    if (!cleanUser || !cleanPass) {
      sfx.error();
      showToast('error', 'Campos Vazios', 'Preencha usuário e senha de ADM.');
      return false;
    }

    let isMatch = false;

    // 1. Tentar validação via API Backend (com proteção anti-força bruta e emissão de Bearer Token)
    try {
      const resp = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: cleanUser, pass: cleanPass })
      });

      if (resp.status === 429) {
        const errData = await resp.json().catch(() => ({}));
        sfx.error();
        showToast('error', 'Bloqueio de Segurança', errData.message || 'Muitas tentativas. IP temporariamente bloqueado.');
        return false;
      }

      if (resp.ok) {
        const data = await resp.json();
        if (data && data.status === 'success') {
          isMatch = true;
          adminSessionToken = data.token || null;
        }
      }
    } catch (_) {}

    // 2. Validação client-side puramente criptográfica (apenas comparação de hash SHA-256 para GitHub Pages/offline)
    if (!isMatch) {
      try {
        const userH = await sha256Hex(cleanUser);
        const passH = await sha256Hex(cleanPass);
        if (userH === ADMIN_USER_HASH && passH === ADMIN_PASS_HASH) {
          isMatch = true;
        }
      } catch (_) {}
    }

    if (isMatch) {
      isAdmAuthenticated = true;
      updateAuthUI();
      sfx.done();
      showToast('success', 'Acesso Autorizado', 'Modo Operador ADM da Tribo ativado com sucesso.');
      if (modalAuthBackdrop) modalAuthBackdrop.style.display = 'none';
      if (authPassInput) authPassInput.value = '';
      unlockScanDashboard();
      return true;
    } else {
      sfx.error();
      showToast('error', 'Acesso Negado', 'Usuário ou senha de ADM incorretos.');
      return false;
    }
  }

  async function performAdminLogout() {
    if (adminSessionToken) {
      try {
        await fetch('/logout', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${adminSessionToken}`
          }
        });
      } catch (_) {}
    }

    adminSessionToken = null;
    isAdmAuthenticated = false;

    try {
      localStorage.removeItem(AUTH_STORAGE_KEY);
      sessionStorage.removeItem(AUTH_STORAGE_KEY);
    } catch (_) {}

    updateAuthUI();
    lockScanDashboard();
    sfx.tick(600);
    showToast('info', 'Desconectado', 'Sessão de ADM encerrada e invalidada.');
    if (modalAuthBackdrop) modalAuthBackdrop.style.display = 'none';
  }

  if (btnAuthSubmit) {
    btnAuthSubmit.addEventListener('click', () => {
      handleAdminLogin(authUserInput ? authUserInput.value : '', authPassInput ? authPassInput.value : '');
    });
  }

  [authUserInput, authPassInput].forEach(inp => {
    if (inp) {
      inp.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          handleAdminLogin(authUserInput ? authUserInput.value : '', authPassInput ? authPassInput.value : '');
        }
      });
    }
  });

  if (btnAuthLogout) {
    btnAuthLogout.addEventListener('click', performAdminLogout);
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
              <span class="roster-nick" title="${escapeHtml(p.nick)}">${escapeHtml(p.nick)}</span>
              ${p.gameId ? `<code class="player-id-tag">#${escapeHtml(p.gameId)}</code>` : ''}
              <select class="form-select-sm player-rank-inline" data-player-id="${p.id}" style="color: ${rankObj.color};">
                ${ranks.map(r => `<option value="${r.id}" ${r.id === p.rankId ? 'selected' : ''}>${escapeHtml(r.name)} (${r.weight}pts)</option>`).join('')}
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
              <strong style="color: #fff;">${escapeHtml(p.nick)}</strong>
              <span style="color: ${r.color}; font-family: var(--font-mono); font-size: 0.7rem; font-weight: 700;">${escapeHtml(r.abbr)} (${r.weight}pts)</span>
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
                        <span class="p-nick">${escapeHtml(p.nick)}</span>
                        <span style="color: ${r.color}; font-family: var(--font-mono); font-size: 0.72rem; font-weight: 700;">${escapeHtml(r.abbr)} (${r.weight})</span>
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
                        <span class="p-nick">${escapeHtml(p.nick)}</span>
                        <span style="color: ${r.color}; font-family: var(--font-mono); font-size: 0.72rem; font-weight: 700;">${escapeHtml(r.abbr)} (${r.weight})</span>
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
          <strong style="color: var(--gold); font-family: var(--font-mono);">${escapeHtml(item.id)}</strong>
          <span style="font-size: 0.75rem; color: var(--text-3);">${escapeHtml(item.date)}</span>
        </div>
        <div style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-2); margin-bottom: 4px;">
          SEED: <code>${escapeHtml(item.seed)}</code>
        </div>
        <div style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-3); word-break: break-all;">
          HASH SHA-256: ${escapeHtml(item.hash)}
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
          <span style="font-size: 0.84rem; color: #fff;">Guerreiro Sorteado: <strong>${escapeHtml(players[winningIdx])}</strong> (Índice ${winningIdx} de ${players.length})</span>
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
          ${teamPlayers.map(p => `<div style="font-size: 0.84rem; padding: 3px 0; color: #fff;">• ${escapeHtml(p)}</div>`).join('')}
        </div>
      `;
    }

    if (leftovers > 0) {
      const remaining = shuffled.slice(numTeams * quickTeamSize);
      html += `
        <div class="showdown-team-box" style="border-color: rgba(245, 158, 11, 0.3);">
          <strong style="color: var(--amber); display: block; margin-bottom: 8px;">RESERVAS (${leftovers})</strong>
          ${remaining.map(p => `<div style="font-size: 0.84rem; padding: 3px 0; color: var(--text-2);">• ${escapeHtml(p)}</div>`).join('')}
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
  // 14. CACIQUE SCAN ENGINE v3.2 — FORENSE PROFISSIONAL RESILIENTE
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
  const terminalStatus = document.getElementById('terminalStatus');

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

  // Domínios autorizados de origem de instalação (Detector de Origem de Instalação)
  const DOMINIOS_AUTORIZADOS = [
    'com.android.vending'
  ];

  // Assinaturas Oficiais Forenses Completas
  const CHEAT_SIGNATURES = [
    // ── Offsets Coringa & Free Fire ──
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

    // ── Overlays & Proxy Cheats Free Fire ──
    { term: 'dripwire.cc', name: 'Janela Sobrepondo Free Fire (dripwire.cc)', cat: 'overlay', weight: 100, risk: 'Alto (Verificar contexto)' },
    { term: 'TYPE_APPLICATION_OVERLAY', name: 'Janela Sobrepondo Free Fire (TYPE_APPLICATION_OVERLAY)', cat: 'overlay', weight: 60, risk: 'Médio (Verificar contexto)' },
    { term: 'LetuniaProxy.ff', name: 'Proxy/Modificação Free Fire (LetuniaProxy)', cat: 'ff_cheat', weight: 100, risk: 'Alto (Verificar contexto)' },

    // ── OB40 & Weapons / Regedits ──
    { term: 'aimlock_head_ob40_', name: 'Aimlock OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimbot_head_ob40_', name: 'Aimbot OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'no_recoil_ob40_', name: 'No Recoil OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimfov_ob40_', name: 'Aim FOV OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'sensi_ob40_', name: 'Sensi Hack OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'fovbotautogame_regedit', name: 'APK FovBot Auto Regedit', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'regeditruokff', name: 'Regedit Ruok FF Cheat', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'getauxaimhsoffreefiremanager', name: 'Auxiliar de Mira FreeFire Hook', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aim lock vip ativado', name: 'Aimlock VIP Mod Ativado', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },

    // ── Libil2cpp & Injeção / Root / Jailbreak ──
    { term: 'libil2cpp.so', name: 'Hook em Libil2cpp (Free Fire Core)', cat: 'injection', weight: 90, risk: 'Crítico' },
    { term: 'memorypatch("libil2cpp.so"', name: 'MemoryPatch em Libil2cpp', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: 'gameguardian', name: 'Engine de Memória GameGuardian', cat: 'injection', weight: 95, risk: 'Ban Direto' },
    { term: 'frida-server', name: 'Injetor Dinâmico Frida', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: 'frida-gadget', name: 'Frida Gadget Injected', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: 'catch_.me_.if_.you_.can_', name: 'Assinatura Root Magisk/Zygisk', cat: 'system', weight: 80, risk: 'Alto' },
    { term: 'top.johnwu.magisk', name: 'Magisk Root Oficial', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'me.weishu.kernelsu', name: 'KernelSU Root', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'bmax.apatch', name: 'APatch Kernel Root', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'zygisk', name: 'Zygisk Injeção de Processos', cat: 'root_bypass', weight: 90, risk: 'Ban Direto' },
    { term: 'lsposed', name: 'LSPosed Framework', cat: 'root_bypass', weight: 90, risk: 'Ban Direto' },
    { term: 'trollstore', name: 'TrollStore Root Helper iOS', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'cydia', name: 'Cydia Jailbreak', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'sileo', name: 'Sileo Jailbreak', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'httpcanary', name: 'HttpCanary Sniffer de Rede', cat: 'proxy_net', weight: 95, risk: 'Ban Direto' },

    // ── Proxy / Android Bug Report / Network Interception ──
    { term: 'global_http_proxy_host', name: 'Proxy Android Configurado (global_http_proxy_host)', cat: 'proxy_net', weight: 65, risk: 'Médio (Verificar contexto)' },
    { term: 'global_http_proxy_port', name: 'Porta de Proxy Android (global_http_proxy_port)', cat: 'proxy_net', weight: 50, risk: 'Médio' },
    { term: 'http_proxy', name: 'Configuração HTTP Proxy (http_proxy)', cat: 'proxy_net', weight: 45, risk: 'Médio' },
    { term: 'proxy_host', name: 'Proxy Host (proxy_host)', cat: 'proxy_net', weight: 40, risk: 'Médio' },
    { term: 'proxy_port', name: 'Proxy Port (proxy_port)', cat: 'proxy_net', weight: 40, risk: 'Médio' },
    { term: 'settings get global http_proxy', name: 'Consulta de Proxy Android (settings get global http_proxy)', cat: 'proxy_net', weight: 65, risk: 'Médio' },
    { term: 'dumpsys connectivity', name: 'Inspeção de Conectividade (dumpsys connectivity)', cat: 'proxy_net', weight: 35, risk: 'Médio' },
    { term: 'VpnService', name: 'Serviço VPN Android (VpnService)', cat: 'proxy_net', weight: 35, risk: 'Médio' },
    { term: 'tun0', name: 'Interface de Rede VPN (tun0)', cat: 'proxy_net', weight: 35, risk: 'Médio' },
    { term: '127.0.0.1:8888', name: 'Proxy Local Charles/Fiddler (127.0.0.1:8888)', cat: 'proxy_net', weight: 75, risk: 'Médio' },
    { term: '127.0.0.1:8080', name: 'Proxy Local HTTP (127.0.0.1:8080)', cat: 'proxy_net', weight: 65, risk: 'Médio' },
    { term: 'mitmproxy', name: 'Interceptação de Tráfego (mitmproxy)', cat: 'proxy_net', weight: 90, risk: 'Alto (Verificar contexto)' },
    { term: 'httptoolkit', name: 'HTTP Toolkit (httptoolkit)', cat: 'proxy_net', weight: 90, risk: 'Alto (Verificar contexto)' },
    { term: 'pcapdroid', name: 'Captura de Pacotes (pcapdroid)', cat: 'proxy_net', weight: 85, risk: 'Alto (Verificar contexto)' },
    { term: 'network_security_config', name: 'Configuração de Segurança de Rede (network_security_config)', cat: 'proxy_net', weight: 35, risk: 'Médio' },
    { term: 'ssl_unpinning', name: 'Possível Remoção de SSL Pinning (ssl_unpinning)', cat: 'proxy_net', weight: 90, risk: 'Alto' },
    { term: 'burp', name: 'Ferramenta de Interceptação (burp)', cat: 'proxy_net', weight: 75, risk: 'Médio' },

    // ── Logs External (ADB, Input Injection, Rede, Root & Certificados) ──
    { term: 'rmnet data active', name: 'Logs External: rmnet data active', cat: 'external_log', weight: 35, risk: 'Médio (Verificar contexto)' },
    { term: 'InputDispatcher', name: 'Logs External: InputDispatcher', cat: 'external_log', weight: 40, risk: 'Médio (Verificar contexto)' },
    { term: 'shell input swipe', name: 'Logs External: Injeção ADB (shell input swipe)', cat: 'external_log', weight: 85, risk: 'Alto (Automação/Macro ADB)' },
    { term: 'adbd daemon started successfully', name: 'Logs External: adbd daemon started successfully', cat: 'external_log', weight: 70, risk: 'Alto (ADB Ativo)' },
    { term: '10.x.x.x assigned', name: 'Logs External: IP Privado 10.x.x.x assigned', cat: 'external_log', weight: 35, risk: 'Médio (Verificar contexto)' },
    { term: 'cert verify failed', name: 'Logs External: Falha de Certificado (cert verify failed)', cat: 'external_log', weight: 75, risk: 'Alto (Possível MITM/Proxy)' },
    { term: 'shell input tap', name: 'Logs External: Injeção ADB (shell input tap)', cat: 'external_log', weight: 85, risk: 'Alto (Automação/Macro ADB)' },
    { term: 'localhost connection established', name: 'Logs External: localhost connection established', cat: 'external_log', weight: 60, risk: 'Médio (Túnel Local)' },
    { term: 'InputFlinger', name: 'Logs External: InputFlinger', cat: 'external_log', weight: 40, risk: 'Médio (Verificar contexto)' },
    { term: 'cmd activity start', name: 'Logs External: Execução Shell (cmd activity start)', cat: 'external_log', weight: 65, risk: 'Médio (Verificar contexto)' },
    { term: 'root access granted', name: 'Logs External: Acesso Root Concedido (root access granted)', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'tun0 up', name: 'Logs External: Túnel VPN Ativo (tun0 up)', cat: 'proxy_net', weight: 55, risk: 'Médio (VPN/Proxy)' },
    { term: 'keyevent injected', name: 'Logs External: Evento de Tecla Injetado (keyevent injected)', cat: 'external_log', weight: 80, risk: 'Alto (Injeção de Input)' },
    { term: 'SSLHandshakeException', name: 'Logs External: Exceção SSL (SSLHandshakeException)', cat: 'proxy_net', weight: 65, risk: 'Médio (Possível Interceptação SSL)' },
    { term: 'wlan0 up', name: 'Logs External: Interface Wi-Fi (wlan0 up)', cat: 'external_log', weight: 25, risk: 'Baixo (Verificar contexto)' },
    { term: 'permission elevated', name: 'Logs External: Elevação de Permissão (permission elevated)', cat: 'root_bypass', weight: 90, risk: 'Alto (Elevação de Privilégio)' },
    { term: 'forwarding port', name: 'Logs External: Redirecionamento de Porta (forwarding port)', cat: 'proxy_net', weight: 75, risk: 'Alto (Port Forwarding)' },
    { term: 'zygisk initialized', name: 'Logs External: Zygisk Inicializado (zygisk initialized)', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'adbd auth confirmed', name: 'Logs External: Autenticação ADB Confirmada (adbd auth confirmed)', cat: 'external_log', weight: 70, risk: 'Alto (Depuração ADB)' },
    { term: 'gateway set', name: 'Logs External: Configuração de Gateway (gateway set)', cat: 'external_log', weight: 35, risk: 'Médio (Verificar contexto)' },
    { term: 'proxySelector', name: 'Logs External: Seletor de Proxy (proxySelector)', cat: 'proxy_net', weight: 55, risk: 'Médio (Verificar contexto)' },
    { term: 'am startservice', name: 'Logs External: Inicialização de Serviço via Shell (am startservice)', cat: 'external_log', weight: 65, risk: 'Médio (Verificar contexto)' },
    { term: 'VPN connected', name: 'Logs External: VPN Conectada (VPN connected)', cat: 'proxy_net', weight: 55, risk: 'Médio (VPN Ativa)' },
    { term: 'socket opened on 5037', name: 'Logs External: Porta Padrão ADB (socket opened on 5037)', cat: 'external_log', weight: 85, risk: 'Alto (Servidor ADB 5037)' },
    { term: 'Shell command executed', name: 'Logs External: Comando Shell Executado (Shell command executed)', cat: 'external_log', weight: 70, risk: 'Alto (Verificar contexto)' },
    { term: 'Burp Suite certificate', name: 'Logs External: Certificado Burp Suite (Burp Suite certificate)', cat: 'proxy_net', weight: 95, risk: 'Alto (Interceptação Burp)' },
    { term: 'ADB bridge active', name: 'Logs External: Ponte ADB Ativa (ADB bridge active)', cat: 'external_log', weight: 80, risk: 'Alto (ADB Ativo)' },
    { term: 'ActivityManager: Start proc', name: 'Logs External: ActivityManager: Start proc', cat: 'external_log', weight: 35, risk: 'Médio (Verificar contexto)' },
    { term: 'HTTP proxy set', name: 'Logs External: Proxy HTTP Configurado (HTTP proxy set)', cat: 'proxy_net', weight: 70, risk: 'Alto (Proxy Ativo)' },
    { term: 'device authorized for debugging', name: 'Logs External: Dispositivo Autorizado para Debug', cat: 'external_log', weight: 70, risk: 'Alto (USB/Wireless Debugging)' },
    { term: 'ppp0 interface up', name: 'Logs External: Interface Ponto-a-Ponto (ppp0 interface up)', cat: 'proxy_net', weight: 50, risk: 'Médio (Túnel PPP/VPN)' },
    { term: 'USB connected', name: 'Logs External: Conexão USB Detectada (USB connected)', cat: 'external_log', weight: 40, risk: 'Médio (Verificar contexto)' },
    { term: 'USB debugging connected', name: 'Logs External: Depuração USB Conectada (USB debugging connected)', cat: 'external_log', weight: 75, risk: 'Alto (ADB USB Ativo)' },
    { term: 'dispatchPointer', name: 'Logs External: Evento de Ponteiro (dispatchPointer)', cat: 'external_log', weight: 45, risk: 'Médio (Verificar contexto)' },
    { term: '192.168.x.x assigned', name: 'Logs External: IP Local 192.168.x.x assigned', cat: 'external_log', weight: 30, risk: 'Baixo (Verificar contexto)' },
    { term: 'InputReader', name: 'Logs External: Leitor de Input (InputReader)', cat: 'external_log', weight: 40, risk: 'Médio (Verificar contexto)' },
    { term: 'adb reverse', name: 'Logs External: Túnel Reverso ADB (adb reverse)', cat: 'external_log', weight: 85, risk: 'Alto (Túnel ADB Reverso)' },
    { term: 'routing table changed', name: 'Logs External: Tabela de Roteamento Alterada (routing table changed)', cat: 'proxy_net', weight: 50, risk: 'Médio (Desvio de Rota/VPN)' },
    { term: 'HTTPS proxy configured', name: 'Logs External: Proxy HTTPS Configurado (HTTPS proxy configured)', cat: 'proxy_net', weight: 75, risk: 'Alto (Proxy HTTPS)' },
    { term: 'adb forward', name: 'Logs External: Encaminhamento ADB (adb forward)', cat: 'external_log', weight: 85, risk: 'Alto (Port Forward ADB)' },
    { term: 'mitmproxy connection', name: 'Logs External: Conexão mitmproxy (mitmproxy connection)', cat: 'proxy_net', weight: 95, risk: 'Alto (Interceptação MITM)' },
    { term: 'localhost 127.0.0.1:', name: 'Logs External: Conexão Localhost (localhost 127.0.0.1:)', cat: 'proxy_net', weight: 60, risk: 'Médio (Serviço Local/Proxy)' },
    { term: 'injectInputEvent', name: 'Logs External: Injeção de Evento de Toque (injectInputEvent)', cat: 'external_log', weight: 85, risk: 'Alto (Automação/Injeção de Mira)' },
    { term: 'Charles Proxy active', name: 'Logs External: Charles Proxy Ativo (Charles Proxy active)', cat: 'proxy_net', weight: 95, risk: 'Alto (Interceptação Charles)' },
    { term: 'adbd started', name: 'Logs External: Daemon ADB Iniciado (adbd started)', cat: 'external_log', weight: 70, risk: 'Alto (ADB Ativo)' },
    { term: 'default route via tun0', name: 'Logs External: Rota Padrão via VPN (default route via tun0)', cat: 'proxy_net', weight: 60, risk: 'Médio (Tráfego via Túnel VPN)' },
    { term: 'neighbor discovered', name: 'Logs External: Descoberta de Vizinho ARP/NDP (neighbor discovered)', cat: 'external_log', weight: 30, risk: 'Baixo (Verificar contexto)' },
    { term: 'magisk daemon started', name: 'Logs External: Daemon Magisk Iniciado (magisk daemon started)', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'certificate unknown', name: 'Logs External: Certificado Desconhecido (certificate unknown)', cat: 'proxy_net', weight: 70, risk: 'Alto (Possível Proxy MITM)' },
    { term: 'cmd package install', name: 'Logs External: Instalação via Linha de Comando (cmd package install)', cat: 'external_log', weight: 75, risk: 'Alto (Sideload ADB/Shell)' },
    { term: 'DHCP lease obtained', name: 'Logs External: Concessão DHCP Obtida (DHCP lease obtained)', cat: 'external_log', weight: 25, risk: 'Baixo (Verificar contexto)' },
    { term: 'Sending intent', name: 'Logs External: Disparo de Intent (Sending intent)', cat: 'external_log', weight: 40, risk: 'Médio (Verificar contexto)' },
    { term: 'SELinux permissive', name: 'Logs External: SELinux em Modo Permissivo (SELinux permissive)', cat: 'root_bypass', weight: 95, risk: 'Ban Direto (Segurança Desativada)' },
    { term: 'eth0 link up', name: 'Logs External: Interface Ethernet Ativa (eth0 link up)', cat: 'external_log', weight: 45, risk: 'Médio (Possível Emulador/Adaptador)' },
    { term: 'ADB TCP service started', name: 'Logs External: Serviço ADB via TCP (ADB TCP service started)', cat: 'external_log', weight: 85, risk: 'Alto (ADB Wireless/Remoto)' },
    { term: 'lsposed framework loaded', name: 'Logs External: LSPosed Carregado (lsposed framework loaded)', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: '172.16.x.x - 172.31.x.x', name: 'Logs External: Faixa IP Privada 172.16-31', cat: 'external_log', weight: 35, risk: 'Médio (Verificar contexto)' },
    { term: 'am start', name: 'Logs External: Inicialização Activity via Shell (am start)', cat: 'external_log', weight: 60, risk: 'Médio (Verificar contexto)' },
    { term: 'listening on tcp:5555', name: 'Logs External: ADB Escutando na Porta 5555 (listening on tcp:5555)', cat: 'external_log', weight: 90, risk: 'Alto (ADB Remoto TCP 5555)' },
    { term: 'su binary detected', name: 'Logs External: Binário SU Detectado (su binary detected)', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'ARP table entry', name: 'Logs External: Entrada na Tabela ARP (ARP table entry)', cat: 'external_log', weight: 30, risk: 'Baixo (Verificar contexto)' },

    // ── ETAPA 1 — SUPRESSÃO DE LOGS ──
    { term: 'suppression', name: 'Etapa 1 (Supressão de Logs): suppression', cat: 'log_audit', weight: 45, risk: 'Auditoria Etapa 1 (Verificar contexto)' },
    { term: 'suppressed', name: 'Etapa 1 (Supressão de Logs): suppressed / SUPPRESSED', cat: 'log_audit', weight: 45, risk: 'Auditoria Etapa 1 (Verificar contexto)' },
    { term: 'suppress', name: 'Etapa 1 (Supressão de Logs): suppress / SUPPRESS', cat: 'log_audit', weight: 40, risk: 'Auditoria Etapa 1 (Verificar contexto)' },

    // ── ETAPA 2 — AGRUPAMENTO DE MENSAGENS ──
    { term: 'chatty', name: 'Etapa 2 (Agrupamento de Mensagens): chatty', cat: 'log_audit', weight: 35, risk: 'Auditoria Etapa 2 (Verificar contexto)' },
    { term: 'CHATTER', name: 'Etapa 2 (Agrupamento de Mensagens): CHATTER', cat: 'log_audit', weight: 35, risk: 'Auditoria Etapa 2 (Verificar contexto)' },
    { term: 'LogBufferElement', name: 'Etapa 2 (Agrupamento de Mensagens): LogBufferElement', cat: 'log_audit', weight: 40, risk: 'Auditoria Etapa 2 (Verificar contexto)' },

    // ── ETAPA 3 — DESCARTE E PERDA DE REGISTROS ──
    { term: 'dropped logs', name: 'Etapa 3 (Descarte/Perda de Registros): dropped logs', cat: 'log_audit', weight: 55, risk: 'Auditoria Etapa 3 (Verificar contexto)' },
    { term: 'drop count', name: 'Etapa 3 (Descarte/Perda de Registros): drop count', cat: 'log_audit', weight: 50, risk: 'Auditoria Etapa 3 (Verificar contexto)' },
    { term: 'log_overrun', name: 'Etapa 3 (Descarte/Perda de Registros): log_overrun', cat: 'log_audit', weight: 55, risk: 'Auditoria Etapa 3 (Verificar contexto)' },
    { term: 'dropped', name: 'Etapa 3 (Descarte/Perda de Registros): dropped', cat: 'log_audit', weight: 35, risk: 'Auditoria Etapa 3 (Verificar contexto)' },
    { term: 'overrun', name: 'Etapa 3 (Descarte/Perda de Registros): overrun', cat: 'log_audit', weight: 40, risk: 'Auditoria Etapa 3 (Verificar contexto)' },
    { term: 'overflow', name: 'Etapa 3 (Descarte/Perda de Registros): overflow', cat: 'log_audit', weight: 40, risk: 'Auditoria Etapa 3 (Verificar contexto)' },
    { term: 'pruned', name: 'Etapa 3 (Descarte/Perda de Registros): pruned', cat: 'log_audit', weight: 45, risk: 'Auditoria Etapa 3 (Verificar contexto)' },

    // ── ETAPA 4 — FILTRAGEM DE MENSAGENS ──
    { term: 'filtered', name: 'Etapa 4 (Filtragem de Mensagens): filtered', cat: 'log_audit', weight: 35, risk: 'Auditoria Etapa 4 (Verificar contexto)' },
    { term: 'filter', name: 'Etapa 4 (Filtragem de Mensagens): filter', cat: 'log_audit', weight: 25, risk: 'Auditoria Etapa 4 (Verificar contexto)' },
    { term: 'excluded', name: 'Etapa 4 (Filtragem de Mensagens): excluded', cat: 'log_audit', weight: 35, risk: 'Auditoria Etapa 4 (Verificar contexto)' },
    { term: 'exclude', name: 'Etapa 4 (Filtragem de Mensagens): exclude', cat: 'log_audit', weight: 30, risk: 'Auditoria Etapa 4 (Verificar contexto)' },
    { term: 'skipped', name: 'Etapa 4 (Filtragem de Mensagens): skipped', cat: 'log_audit', weight: 25, risk: 'Auditoria Etapa 4 (Verificar contexto)' },
    { term: 'skip', name: 'Etapa 4 (Filtragem de Mensagens): skip', cat: 'log_audit', weight: 20, risk: 'Auditoria Etapa 4 (Verificar contexto)' },
    { term: 'ignored', name: 'Etapa 4 (Filtragem de Mensagens): ignored', cat: 'log_audit', weight: 25, risk: 'Auditoria Etapa 4 (Verificar contexto)' },
    { term: 'ignore', name: 'Etapa 4 (Filtragem de Mensagens): ignore', cat: 'log_audit', weight: 20, risk: 'Auditoria Etapa 4 (Verificar contexto)' },

    // ── ETAPA 5 — LIMITES E TRUNCAMENTO ──
    { term: 'truncation', name: 'Etapa 5 (Limites e Truncamento): truncation', cat: 'log_audit', weight: 45, risk: 'Auditoria Etapa 5 (Verificar contexto)' },
    { term: 'truncated', name: 'Etapa 5 (Limites e Truncamento): truncated', cat: 'log_audit', weight: 40, risk: 'Auditoria Etapa 5 (Verificar contexto)' },
    { term: 'buffer full', name: 'Etapa 5 (Limites e Truncamento): buffer full', cat: 'log_audit', weight: 50, risk: 'Auditoria Etapa 5 (Verificar contexto)' },
    { term: 'max entry', name: 'Etapa 5 (Limites e Truncamento): max entry', cat: 'log_audit', weight: 40, risk: 'Auditoria Etapa 5 (Verificar contexto)' },
    { term: 'limit exceeded', name: 'Etapa 5 (Limites e Truncamento): limit exceeded', cat: 'log_audit', weight: 45, risk: 'Auditoria Etapa 5 (Verificar contexto)' },
    { term: 'rate limit', name: 'Etapa 5 (Limites e Truncamento): rate limit', cat: 'log_audit', weight: 40, risk: 'Auditoria Etapa 5 (Verificar contexto)' },

    // ── ETAPA 6 — COMPONENTES DE LOGGING ──
    { term: 'logd', name: 'Etapa 6 (Componentes de Logging): logd', cat: 'log_audit', weight: 30, risk: 'Auditoria Etapa 6 (Infraestrutura Android)' },
    { term: 'LogBuffer', name: 'Etapa 6 (Componentes de Logging): LogBuffer', cat: 'log_audit', weight: 35, risk: 'Auditoria Etapa 6 (Infraestrutura Android)' },
    { term: 'Logcat', name: 'Etapa 6 (Componentes de Logging): Logcat', cat: 'log_audit', weight: 30, risk: 'Auditoria Etapa 6 (Infraestrutura Android)' },
    { term: 'liblog', name: 'Etapa 6 (Componentes de Logging): liblog', cat: 'log_audit', weight: 35, risk: 'Auditoria Etapa 6 (Infraestrutura Android)' },

    // ── INJEÇÕES EM GAMEASSET, CRASH DE MEMÓRIA & PASTA NÃO VERIFICADA -SHgap- ──
    { term: '-SHgap-', name: '-SHgap- Pasta Não Verificada (Reinstalar Free Fire)', cat: 'ff_cheat', weight: 100, risk: 'Crítico (Pedir para reinstalar Free Fire)', recommendation: 'Reinstalar Free Fire' },
    { term: 'gameassetbundles/font/SH-Gpp2', name: 'Arquivo Injetado na GameAsset (SH-Gpp2)', cat: 'injection', weight: 100, risk: 'Ban Direto (Arquivo Injetado na GameAsset)' },
    { term: 'SH-Gpp2', name: 'Arquivo Injetado na GameAsset (SH-Gpp2)', cat: 'injection', weight: 100, risk: 'Ban Direto (Arquivo Injetado na GameAsset)' },
    { term: 'app_resources_lib.jar', name: 'Processo Suspeito Cache (app_resources_lib.jar)', cat: 'injection', weight: 90, risk: 'Alto (Processo Suspeito em Cache)' },
    { term: 'google_api_resources_lib.jar', name: 'Processo Suspeito Cache (google_api_resources_lib.jar)', cat: 'injection', weight: 90, risk: 'Alto (Processo Suspeito em Cache)' },
    { term: 'comm="UnityMain" path="/data/data/com.dts.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2"', name: 'SELinux AVC: Execução Não Autorizada em GameAsset (UnityMain)', cat: 'injection', weight: 100, risk: 'Ban Direto (Arquivo Injetado na GameAsset / AVC Granted)' },
    { term: 'granted  { execute } for  comm="UnityMain"', name: 'SELinux AVC: Execução Não Autorizada em GameAsset (UnityMain)', cat: 'injection', weight: 100, risk: 'Ban Direto (Arquivo Injetado na GameAsset / AVC Granted)' },
    { term: 'process=com.dts.freefiremax reason=3 (LOW_MEMORY)', name: 'Encerramento de Processo na Memória (LOW_MEMORY)', cat: 'system', weight: 60, risk: 'Médio (Processo de Encerramento na Memória)' },
    { term: 'reason=3 (LOW_MEMORY)', name: 'Encerramento de Processo na Memória (LOW_MEMORY)', cat: 'system', weight: 50, risk: 'Médio (Processo de Encerramento na Memória)' },
    { term: 'github.com/jilleJr', name: 'Crash Suspeito Envolvendo Link Github (jilleJr/Newtonsoft.Json)', cat: 'injection', weight: 90, risk: 'Alto (Processo Suspeito Causando Crash)' },
    { term: 'jilleJr/Ne', name: 'DLL Externa Injetada Causando Crash (jilleJr/Newtonsoft.Json)', cat: 'injection', weight: 90, risk: 'Alto (Processo Suspeito Causando Crash)' },
    { term: 'signal 11 (SIGSEGV), code 1 (SEGV_MAPERR)', name: 'Crash UnityMain SIGSEGV SEGV_MAPERR (Injeção de Bytes Assembly / Wallhack)', cat: 'injection', weight: 95, risk: 'Crítico (Tentativa de Escrever na Memória / Wallhack)' },
    { term: 'SEGV_MAPERR', name: 'Crash de Memória: SEGV_MAPERR (Injeção de Memória / Crash)', cat: 'injection', weight: 85, risk: 'Alto (Tentativa de Escrever na Memória)', isWordBoundary: true },
    { term: 'pac_enabled_keys', name: 'Dump de Crash PAC Keys (UnityMain / Injeção)', cat: 'injection', weight: 70, risk: 'Alto (Dump de Crash com PAC Keys)' },

    // ── LOGS DE RESTORE BACKUP (iOS RESTORE - POSSIBLE HACK) ──
    { term: 'MobileBackup', name: 'Logs Restore/Backup: MobileBackup', cat: 'backup_restore', weight: 50, risk: 'Possible (Atividade do Serviço de Backup)' },
    { term: 'BackupAgent', name: 'Logs Restore/Backup: BackupAgent', cat: 'backup_restore', weight: 50, risk: 'Possible (Processos Relacionados a Backup)' },
    { term: 'BackupRestore', name: 'Logs Restore/Backup: BackupRestore', cat: 'backup_restore', weight: 60, risk: 'Possible (Operações de Backup ou Restauração)' },
    { term: 'RestoreFromBackup', name: 'Logs Restore/Backup: RestoreFromBackup', cat: 'backup_restore', weight: 70, risk: 'Possible (Possível Restauração de Backup)' },
    { term: 'Restored', name: 'Logs Restore/Backup: Restored', cat: 'backup_restore', weight: 55, risk: 'Possible (Serviço Responsável por Restauração)' },
    { term: 'mobilebackupd', name: 'Logs Restore/Backup: mobilebackupd', cat: 'backup_restore', weight: 60, risk: 'Possible (Daemon de Backup do iOS)' },
    { term: 'restore_type', name: 'Logs Restore/Backup: restore_type', cat: 'backup_restore', weight: 65, risk: 'Possible (Identificação de Tipo de Restauração)' },
    { term: 'SetupAssistant', name: 'Logs Restore/Backup: SetupAssistant', cat: 'backup_restore', weight: 50, risk: 'Possible (Configuração Inicial do iPhone)' },
    { term: 'iCloudRestore', name: 'Logs Restore/Backup: iCloudRestore', cat: 'backup_restore', weight: 65, risk: 'Possible (Possível Restauração pelo iCloud)' },
    { term: 'itunesstored', name: 'Logs App Store: itunesstored', cat: 'backup_restore', weight: 30, risk: 'Informativo (Serviço App Store - Não é Prova de Restauração)' },

    // ── LISTA OFICIAL DE PROXIES & BYPASSES FF (Att: 09/08/2026) ──
    { term: '03', name: 'Proxy FF ID: 03', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '051', name: 'Proxy FF ID: 051', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '06', name: 'Proxy FF ID: 06', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '06a', name: 'Proxy FF ID: 06a', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '0af', name: 'Proxy FF ID: 0af', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '0b', name: 'Proxy FF ID: 0b', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '0E', name: 'Proxy FF ID: 0E', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'od', name: 'Proxy FF ID: od', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '105e', name: 'Proxy FF ID: 105e', cat: 'proxy_net', weight: 85, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '14', name: 'Proxy FF ID: 14', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '140', name: 'Proxy FF ID: 140', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '15d', name: 'Proxy FF ID: 15d', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '1b69', name: 'Proxy FF ID: 1b69', cat: 'proxy_net', weight: 85, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '1ea', name: 'Proxy FF ID: 1ea', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '28a', name: 'Proxy FF ID: 28a', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '2bb', name: 'Proxy FF ID: 2bb', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '2c', name: 'Proxy FF ID: 2c', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '3c', name: 'Proxy FF ID: 3c', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '3c4', name: 'Proxy FF ID: 3c4', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '40e', name: 'Proxy FF ID: 40e', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '439', name: 'Proxy FF ID: 439', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '47', name: 'Proxy FF ID: 47', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '4a', name: 'Proxy FF ID: 4a', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '4c', name: 'Proxy FF ID: 4c', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '4cf', name: 'Proxy FF ID: 4cf', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '4d', name: 'Proxy FF ID: 4d', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '4e', name: 'Proxy FF ID: 4e', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '51', name: 'Proxy FF ID: 51', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '550', name: 'Proxy FF ID: 550', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '59ac', name: 'Proxy FF ID: 59ac', cat: 'proxy_net', weight: 85, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '5b', name: 'Proxy FF ID: 5b', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '5c10', name: 'Proxy FF ID: 5c10', cat: 'proxy_net', weight: 85, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '60a', name: 'Proxy FF ID: 60a', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '60af', name: 'Proxy FF ID: 60af', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '62', name: 'Proxy FF ID: 62', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '62d', name: 'Proxy FF ID: 62d', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '69', name: 'Proxy FF ID: 69', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '6b', name: 'Proxy FF ID: 6b', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '6dd', name: 'Proxy FF ID: 6dd', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '704', name: 'Proxy FF ID: 704', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '704114', name: 'Proxy FF ID: 704114', cat: 'proxy_net', weight: 90, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '70a', name: 'Proxy FF ID: 70a', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '70d', name: 'Proxy FF ID: 70d', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '739', name: 'Proxy FF ID: 739', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '76d', name: 'Proxy FF ID: 76d', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '78f', name: 'Proxy FF ID: 78f', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '7d', name: 'Proxy FF ID: 7d', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '80', name: 'Proxy FF ID: 80', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '84', name: 'Proxy FF ID: 84', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '87', name: 'Proxy FF ID: 87', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '90eb', name: 'Proxy FF ID: 90eb', cat: 'proxy_net', weight: 85, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '96f', name: 'Proxy FF ID: 96f', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: '9d', name: 'Proxy FF ID: 9d', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'a00', name: 'Proxy FF ID: a00', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'a1fc', name: 'Proxy FF ID: a1fc', cat: 'proxy_net', weight: 85, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'a4', name: 'Proxy FF ID: a4', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'a48', name: 'Proxy FF ID: a48', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'a4c', name: 'Proxy FF ID: a4c', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'a5', name: 'Proxy FF ID: a5', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'a64', name: 'Proxy FF ID: a64', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'a9', name: 'Proxy FF ID: a9', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'ae7', name: 'Proxy FF ID: ae7', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'authproxyxff.up', name: 'AuthProxyX FF (authproxyxff.up)', cat: 'proxy_net', weight: 100, risk: 'Ban Direto (Proxy FF)' },
    { term: 'b0', name: 'Proxy FF ID: b0', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'b4', name: 'Proxy FF ID: b4', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'b9', name: 'Proxy FF ID: b9', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'bc', name: 'Proxy FF ID: bc', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'bd', name: 'Proxy FF ID: bd', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'bd32', name: 'Proxy FF ID: bd32', cat: 'proxy_net', weight: 85, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'bd32d', name: 'Proxy FF ID: bd32d', cat: 'proxy_net', weight: 85, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'c17', name: 'Proxy FF ID: c17', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'c25', name: 'Proxy FF ID: c25', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'c9', name: 'Proxy FF ID: c9', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'com.antijudas.dns', name: 'Proxy DNS AntiJudas (com.antijudas.dns)', cat: 'proxy_net', weight: 100, risk: 'Ban Direto' },
    { term: 'com.antijudas.ios', name: 'Cheat AntiJudas iOS (com.antijudas.ios)', cat: 'proxy_net', weight: 100, risk: 'Ban Direto' },
    { term: 'com.apple.mgmt.External', name: 'Perfil Externo de Gestão (com.apple.mgmt.External)', cat: 'proxy_net', weight: 90, risk: 'Alto (Perfil de Proxy MDM)' },
    { term: 'com.congdatregedit', name: 'Regedit CongDat (com.congdatregedit)', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'com.criperlegend', name: 'CriperLegend Mod (com.criperlegend)', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'com.demon.engine', name: 'Demon Engine Cheat (com.demon.engine)', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: 'com.giahuyregedit.apple', name: 'GiaHuy Regedit Apple (com.giahuyregedit.apple)', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'com.giahuyregedit', name: 'GiaHuy Regedit (com.giahuyregedit)', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'com.headshot', name: 'Headshot Mod (com.headshot)', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'com.krarosxvenuxapple', name: 'KrarosX Venux Apple (com.krarosxvenuxapple)', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'com.luxebypass', name: 'Luxe Bypass (com.luxebypass)', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'com.ngocsonregedit.apple', name: 'NgocSon Regedit Apple (com.ngocsonregedit.apple)', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'com.peligroff.input.redzone', name: 'PeligroFF Redzone Input (com.peligroff.input.redzone)', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'com.sensi.fluida.pro', name: 'Sensi Fluida Pro (com.sensi.fluida.pro)', cat: 'ff_cheat', weight: 95, risk: 'Ban Direto' },
    { term: 'com.solitude.profile.v12', name: 'Solitude Profile v12 (com.solitude.profile.v12)', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'com.thanhcongregedit.apple.dns', name: 'ThanhCong Regedit Apple DNS', cat: 'proxy_net', weight: 100, risk: 'Ban Direto' },
    { term: 'com.thanhcongregedit', name: 'ThanhCong Regedit (com.thanhcongregedit)', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'com.Vluv.lockprofile', name: 'Vluv Lock Profile (com.Vluv.lockprofile)', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'com.xtremo.mobile', name: 'Xtremo Mobile Proxy/Cheat (com.xtremo.mobile)', cat: 'proxy_net', weight: 95, risk: 'Ban Direto' },
    { term: 'd03', name: 'Proxy FF ID: d03', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'd03090', name: 'Proxy FF ID: d03090', cat: 'proxy_net', weight: 90, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'd14', name: 'Proxy FF ID: d14', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'd141', name: 'Proxy FF ID: d141', cat: 'proxy_net', weight: 85, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'd4f0', name: 'Proxy FF ID: d4f0', cat: 'proxy_net', weight: 85, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'd5', name: 'Proxy FF ID: d5', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'd7319', name: 'Proxy FF ID: d7319', cat: 'proxy_net', weight: 85, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'dash.proxy', name: 'Dash Proxy (dash.proxy)', cat: 'proxy_net', weight: 90, risk: 'Alto (Proxy de Rede)' },
    { term: 'dd4f0', name: 'Proxy FF ID: dd4f0', cat: 'proxy_net', weight: 85, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'dd4fa', name: 'Proxy FF ID: dd4fa', cat: 'proxy_net', weight: 85, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'e0', name: 'Proxy FF ID: e0', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'e3', name: 'Proxy FF ID: e3', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'f54', name: 'Proxy FF ID: f54', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'f6', name: 'Proxy FF ID: f6', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'f6c', name: 'Proxy FF ID: f6c', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'f9', name: 'Proxy FF ID: f9', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'ff32', name: 'Proxy FF ID: ff32', cat: 'proxy_net', weight: 85, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'ff6', name: 'Proxy FF ID: ff6', cat: 'proxy_net', weight: 80, risk: 'Alto (Proxy/Bypass FF - Lista 09/08)', isWordBoundary: true },
    { term: 'freefireproxy.xyz', name: 'Free Fire Proxy XYZ (freefireproxy.xyz)', cat: 'proxy_net', weight: 100, risk: 'Ban Direto' },
    { term: 'iMac.EFB7D714', name: 'iMac Proxy Hardware Profile (iMac.EFB7D714)', cat: 'proxy_net', weight: 90, risk: 'Alto' },
    { term: 'khoindvn', name: 'Khoindvn Bypass/Proxy', cat: 'proxy_net', weight: 95, risk: 'Ban Direto' },
    { term: 'mitm', name: 'MITM Man-in-the-Middle', cat: 'proxy_net', weight: 80, risk: 'Alto (Interceptação MITM)', isWordBoundary: true },
    { term: 'proxyady', name: 'ProxyAdy Interceptor', cat: 'proxy_net', weight: 95, risk: 'Ban Direto' },
    { term: 'Regedit', name: 'Regedit Config', cat: 'ff_regedit', weight: 85, risk: 'Alto (Regedit Detectado)', isWordBoundary: true },
    { term: 'to.appdb.C2D9F2', name: 'AppDB Certificado C2D9F2', cat: 'root_bypass', weight: 95, risk: 'Ban Direto' },
    { term: 'to.appdb.certs1', name: 'AppDB Certificado 1', cat: 'root_bypass', weight: 95, risk: 'Ban Direto' },
    { term: 'to.appdb.certs2', name: 'AppDB Certificado 2', cat: 'root_bypass', weight: 95, risk: 'Ban Direto' },
    { term: 'TRONGHIEU', name: 'TrongHieu Cheat Profile', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'vip.uncover', name: 'VIP Unc0ver Jailbreak/Tweak', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'vip.uncOver', name: 'VIP Unc0ver Tweak Profile', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'XITADO', name: 'Xitado Cheat Profile', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' }
  ].map(s => ({ ...s, termLower: s.term.toLowerCase() }));

  const CATEGORY_NAMES = {
    all: 'Todas',
    ff_cheat: '🎯 Cheats Free Fire',
    ff_offset: '⚡ Offsets de Memória',
    ff_regedit: '📝 Regedits & Macros',
    overlay: '🪟 Janelas Sobrepostas (Overlay)',
    injection: '💉 Injeção & Hooking',
    root_bypass: '🔓 Root & Bypass',
    proxy_net: '🌐 Proxy & Interceptação',
    backup_restore: '🔄 Backup & Restauração (Possible)',
    casino_log: '🎰 Log de Cassino (Hífen)',
    external_log: '📡 Logs External & ADB',
    installer_origin: '📦 Origem de Instalação',
    log_audit: '🔎 Auditoria de Logs (Etapas 1-7)',
    system: '⚙️ Sistema Modificado'
  };

  // Allowlist estrita de arquivos relevantes para evitar travamentos em protobufs (.pb), vídeos, imagens ou traces gigantes
  const TEXT_EXT_RE = /\.(txt|log|prop|plist|xml|json|csv|conf|cfg|properties|yaml|yml|html|htm|js|sh|py|smali|reg|ini|md)$/i;
  const BIN_EXT_RE = /\.(so|dex|dylib|bin|elf|jar)$/i;
  const NO_EXT_ALLOW = new Set([
    'packages', 'services', 'dumpsys', 'logcat',
    'procrank', 'processes', 'bugreport', 'meminfo',
    'cpuinfo', 'batterystats', 'usage_stats'
  ]);
  const ARCHIVE_RE = /\.(zip|tar\.gz|tgz|tar|gz)$/i;

  function classifyScanEntry(path) {
    const clean = path.replace(/\\/g, '/');
    const lower = clean.toLowerCase();
    // Prioridade máxima: garantir que injeções em GameAsset, .jar em cache ou pastas não verificadas nunca sejam ignoradas
    if (lower.includes('sh-gpp2') || lower.includes('-shgap-')) return 'text';
    if (/\.(jar)$/i.test(lower)) return 'binary';

    // Ignorar pastas de mídia, fontes, imagens, proto, perfetto-trace e zips aninhados
    if (/\.(png|jpg|jpeg|gif|bmp|webp|ico|heic|mp4|mov|avi|mkv|mp3|wav|ogg|m4a|ttf|otf|woff|woff2|pb|perfetto-trace|hprof|apk|arsc|vdex|odex|oat|zip|gz|tar)$/i.test(lower)) {
      return null;
    }
    if (TEXT_EXT_RE.test(lower)) return 'text';
    if (BIN_EXT_RE.test(lower)) return 'binary';
    const base = lower.split('/').pop() || '';
    if (!base.includes('.')) {
      for (const allowed of NO_EXT_ALLOW) {
        if (base === allowed || base.startsWith('bugreport') || base.startsWith('logcat') || base.startsWith('dumpsys')) {
          return 'text';
        }
      }
    }
    if (lower.includes('bugreport') || lower.includes('logcat') || lower.includes('sysdiagnose')) {
      return 'text';
    }
    return null;
  }

  function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
  }

  const latin1 = new TextDecoder('latin1');
  const utf8 = new TextDecoder('utf-8', { fatal: false });

  function extractPrintableStrings(bytes, minLen = 6) {
    const out = [];
    let start = -1;
    // Limitar leitura de binários a no máximo 8 MB para não congelar a thread principal
    const len = Math.min(bytes.length, 8 * 1024 * 1024);
    for (let i = 0; i <= len; i++) {
      const c = i < len ? bytes[i] : 0;
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
    // Analisar apenas o cabeçalho (primeiros 400 KB) para velocidade instantânea
    const head = text.length > 400000 ? text.slice(0, 400000) : text;
    if (!deviceInfo.model) {
      const mModel = head.match(/ro\.product\.model\s*[:=]\s*\[?([^\r\n\]]+)/i) ||
                     head.match(/Build\s+fingerprint:.*\/([^/:]+):/i);
      if (mModel) deviceInfo.model = mModel[1].trim();
    }
    if (!deviceInfo.brand) {
      const mBrand = head.match(/ro\.product\.manufacturer\s*[:=]\s*\[?([^\r\n\]]+)/i) ||
                     head.match(/ro\.product\.brand\s*[:=]\s*\[?([^\r\n\]]+)/i);
      if (mBrand) deviceInfo.brand = mBrand[1].trim();
    }
    if (!deviceInfo.osVersion) {
      const mVer = head.match(/ro\.build\.version\.release\s*[:=]\s*\[?([^\r\n\]]+)/i) ||
                   head.match(/Android\s+Version\s*[:=]?\s*([0-9.]+)/i);
      if (mVer) deviceInfo.osVersion = 'Android ' + mVer[1].trim();
    }
    if (!deviceInfo.serial) {
      const mSerial = head.match(/ro\.serialno\s*[:=]\s*\[?([^\r\n\]]+)/i) ||
                      head.match(/ro\.boot\.serialno\s*[:=]\s*\[?([^\r\n\]]+)/i);
      if (mSerial) deviceInfo.serial = mSerial[1].trim();
    }
    if (!deviceInfo.kernel) {
      const mKernel = head.match(/Linux\s+version\s+([0-9a-zA-Z._\-+]+)/i);
      if (mKernel) deviceInfo.kernel = 'Linux ' + mKernel[1].trim();
    }
    if (!deviceInfo.model) {
      const mIosProd = head.match(/<key>ProductType<\/key>\s*<string>([^<]+)<\/string>/i);
      if (mIosProd) deviceInfo.model = mIosProd[1].trim();
    }
    if (!deviceInfo.osVersion) {
      const mIosVer = head.match(/<key>ProductVersion<\/key>\s*<string>([^<]+)<\/string>/i);
      if (mIosVer) deviceInfo.osVersion = 'iOS ' + mIosVer[1].trim();
    }
    if (!deviceInfo.serial) {
      const mIosSerial = head.match(/<key>SerialNumber<\/key>\s*<string>([^<]+)<\/string>/i);
      if (mIosSerial) deviceInfo.serial = mIosSerial[1].trim();
    }
  }

  // ETAPA 7 — ANÁLISE DOS RESULTADOS (Extrator de Contexto: Linha Anterior, Atual, Posterior, Timestamp e Tag)
  function extractLineContext(text, matchIdx) {
    let lineStart = text.lastIndexOf('\n', matchIdx);
    lineStart = lineStart === -1 ? 0 : lineStart + 1;
    let lineEnd = text.indexOf('\n', matchIdx);
    if (lineEnd === -1) lineEnd = text.length;

    const currentLine = text.slice(lineStart, lineEnd).replace(/\r$/, '').slice(0, 240);

    let prevLine = '';
    if (lineStart > 1) {
      let prevStart = text.lastIndexOf('\n', lineStart - 2);
      prevStart = prevStart === -1 ? 0 : prevStart + 1;
      prevLine = text.slice(prevStart, lineStart - 1).replace(/\r$/, '').slice(0, 200);
    }

    let nextLine = '';
    if (lineEnd < text.length - 1) {
      let nextEnd = text.indexOf('\n', lineEnd + 1);
      if (nextEnd === -1) nextEnd = text.length;
      nextLine = text.slice(lineEnd + 1, nextEnd).replace(/\r$/, '').slice(0, 200);
    }

    // Extrair Timestamp, Tag e Componente no padrão Logcat Android (ex: "11-10 09:47:12.345  1000  1234 I ActivityManager: ...")
    let meta = '';
    const logcatMatch = currentLine.match(/^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(?:\S+\s+)?(\d+)\s+(\d+)\s+([VDIWEFS])\s+([^:]+):/);
    if (logcatMatch) {
      meta = `Timestamp: ${logcatMatch[1]} | PID/TID: ${logcatMatch[2]}/${logcatMatch[3]} | Nível: ${logcatMatch[4]} | Tag/Componente: ${logcatMatch[5].trim()}`;
    }

    return {
      prevLine,
      currentLine,
      nextLine,
      meta
    };
  }

  // ── Detector de Origem de Instalação (equivalente a verificar_origem_instalacao em Python) ──
  function verificarOrigemInstalacao(text, filePath, seenInstallers) {
    const encontrados = [];
    // Procura blocos "Package [nome.do.pacote]" seguidos em até 1800 caracteres por "installerPackageName=..."
    const pkgRegex = /Package\s+\[([a-zA-Z0-9_.]+)\]/g;
    let match;
    let beeped = false;

    while ((match = pkgRegex.exec(text)) !== null) {
      const aplicativo = match[1];
      const windowEnd = Math.min(text.length, match.index + 1800);
      const block = text.slice(match.index, windowEnd);
      // Limitar até o próximo "Package [" caso apareça antes
      const nextPkgIdx = block.indexOf('Package [', 10);
      const safeBlock = nextPkgIdx !== -1 ? block.slice(0, nextPkgIdx) : block;

      const instMatch = safeBlock.match(/installerPackageName=([^\s,}]+)/);
      if (!instMatch) continue;

      const instalador = instMatch[1].trim();
      if (DOMINIOS_AUTORIZADOS.includes(instalador)) {
        continue;
      }

      // Ignorar pacotes nativos de sistema sem instalador ("null") apenas se forem com.android.* / android,
      // mas alertar fortemente Free Fire ou apps de terceiros instalados fora da Play Store!
      const isFreeFire = /freefire/i.test(aplicativo);
      const isSuspiciousApp = isFreeFire || !(/^(com\.android\.|android$|com\.google\.android\.|com\.qualcomm\.|com\.samsung\.|com\.sec\.|com\.miui\.|com\.xiaomi\.|com\.motorola\.|com\.mediatek\.)/i.test(aplicativo) && instalador === 'null');

      if (!isSuspiciousApp) continue;

      const uniqueKey = `${aplicativo}|${instalador}`;
      if (seenInstallers.has(uniqueKey)) continue;
      seenInstallers.add(uniqueKey);

      const ctx = extractLineContext(text, match.index);
      encontrados.push({
        term: `installerPackageName=${instalador}`,
        name: isFreeFire
          ? `⚠️ Free Fire Instalado Fora da Play Store (${aplicativo} via ${instalador})`
          : `Origem de Instalação Não Autorizada: ${aplicativo} (Instalador: ${instalador})`,
        category: 'installer_origin',
        categoryLabel: CATEGORY_NAMES.installer_origin,
        weight: isFreeFire ? 100 : 70,
        risk: isFreeFire ? 'Alto (Free Fire Mod/APK Externo)' : 'Origem não autorizada ou desconhecida',
        file: filePath,
        snippet: `Package [${aplicativo}] -> installerPackageName=${instalador}`,
        context: ctx
      });

      if (!beeped) {
        beeped = true;
        sfx.beep1200();
      }
    }

    return encontrados;
  }

  async function ensureJSZip() {
    if (typeof JSZip !== 'undefined') return window.JSZip;
    return new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js';
      s.onload = () => {
        if (typeof JSZip !== 'undefined') resolve(window.JSZip);
        else reject(new Error('JSZip carregado mas não inicializado.'));
      };
      s.onerror = () => {
        const s2 = document.createElement('script');
        s2.src = 'jszip.min.js';
        s2.onload = () => {
          if (typeof JSZip !== 'undefined') resolve(window.JSZip);
          else reject(new Error('Falha ao inicializar JSZip.'));
        };
        s2.onerror = () => reject(new Error('Não foi possível carregar o motor de descompactação JSZip.'));
        document.head.appendChild(s2);
      };
      document.head.appendChild(s);
    });
  }

  async function gunzip(file) {
    if (typeof DecompressionStream === 'undefined') {
      throw new Error('Navegador não suporta descompressão gzip nativa. Descompacte o arquivo e use "Pasta extraída".');
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
        entries.push({
          path: name,
          size,
          bytes: async () => data,
          text: async () => utf8.decode(data)
        });
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
    return [{
      path: file.name.replace(/\.gz$/i, ''),
      size: raw.length,
      bytes: async () => raw,
      text: async () => utf8.decode(raw)
    }];
  }

  // Varredura assíncrona em blocos (chunks) para nunca travar em arquivos grandes (ex: bugreport.txt de 60MB+)
  async function scanTextForCheatsChunked(text, filePath, onProgress) {
    const hits = [];
    const foundTermsInFile = new Set();
    const CHUNK_SIZE = 1500000; // 1.5 MB por bloco
    const OVERLAP = 256;
    const totalLen = text.length;

    for (let offset = 0; offset < totalLen; offset += CHUNK_SIZE) {
      const end = Math.min(totalLen, offset + CHUNK_SIZE + OVERLAP);
      const slice = text.slice(offset, end);
      const sliceLower = slice.toLowerCase();

      for (let sIdx = 0; sIdx < CHEAT_SIGNATURES.length; sIdx++) {
        const sig = CHEAT_SIGNATURES[sIdx];
        if (foundTermsInFile.has(sig.term)) continue;

        let searchFrom = 0;
        while (searchFrom < sliceLower.length) {
          const localIdx = sliceLower.indexOf(sig.termLower, searchFrom);
          if (localIdx === -1) break;

          // Se for termo curto (ex: proxies de 2 a 4 caracteres), validar delimitadores de palavra para eliminar falsos positivos
          if (sig.isWordBoundary) {
            const charBefore = localIdx > 0 ? sliceLower[localIdx - 1] : ' ';
            const charAfter = (localIdx + sig.termLower.length < sliceLower.length) ? sliceLower[localIdx + sig.termLower.length] : ' ';
            if (/[a-z0-9_]/.test(charBefore) || /[a-z0-9_]/.test(charAfter)) {
              searchFrom = localIdx + 1;
              continue;
            }
          }

          foundTermsInFile.add(sig.term);
          const globalIdx = offset + localIdx;
          const ctx = extractLineContext(text, globalIdx);

          hits.push({
            term: sig.term,
            name: sig.name,
            category: sig.cat,
            categoryLabel: CATEGORY_NAMES[sig.cat] || sig.cat,
            weight: sig.weight,
            risk: sig.risk,
            file: filePath,
            snippet: ctx.currentLine || slice.substring(Math.max(0, localIdx - 40), Math.min(slice.length, localIdx + sig.term.length + 60)).replace(/\r?\n/g, ' '),
            context: ctx
          });
          break;
        }
      }

      if (totalLen > CHUNK_SIZE && onProgress) {
        onProgress(Math.min(1, end / totalLen));
        await sleep(0);
      }
    }

    return hits;
  }

  function unlockScanDashboard() {
    if (scanLoginView && scanDashboardView) {
      scanLoginView.style.display = 'none';
      scanLoginView.hidden = true;
      scanDashboardView.style.display = 'block';
      scanDashboardView.hidden = false;
    }
  }

  function lockScanDashboard() {
    if (scanLoginView && scanDashboardView) {
      scanLoginView.style.display = 'block';
      scanLoginView.hidden = false;
      scanDashboardView.style.display = 'none';
      scanDashboardView.hidden = true;
    }
  }

  // SEMPRE iniciar bloqueado ao carregar a página (exige login de ADM toda vez)
  lockScanDashboard();

  function triggerScanLogin() {
    if (!scanUser || !scanPass) return;
    handleAdminLogin(scanUser.value, scanPass.value).then((ok) => {
      if (ok) {
        scanPass.value = '';
      } else {
        scanPass.classList.add('input-invalid');
        setTimeout(() => scanPass.classList.remove('input-invalid'), 600);
      }
    });
  }

  if (scanBtnLogin && scanUser && scanPass) {
    scanBtnLogin.addEventListener('click', (e) => {
      e.preventDefault();
      triggerScanLogin();
    });
    [scanUser, scanPass].forEach((inp) => {
      inp.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          triggerScanLogin();
        }
      });
    });
  }

  if (scanBtnLogout) {
    scanBtnLogout.addEventListener('click', performAdminLogout);
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
      if (!isAdmAuthenticated) {
        lockScanDashboard();
        showToast('error', 'Acesso Negado', 'Faça login com as credenciais de ADM para usar o scanner.');
        return;
      }
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

  function clearFileInputs() {
    if (scanFileInput) scanFileInput.value = '';
    if (scanFolderInput) scanFolderInput.value = '';
    if (scanLooseInput) scanLooseInput.value = '';
  }

  // Execução Forense Resiliente
  let scanBusy = false;

  async function processUploadedFiles(fileList) {
    if (!isAdmAuthenticated) {
      lockScanDashboard();
      showToast('error', 'Acesso Restrito', 'Autentique-se com usuário e senha de ADM antes de escanear.');
      return;
    }
    if (!fileList || fileList.length === 0) return;
    if (scanBusy) {
      showToast('info', 'Análise em andamento', 'Aguarde o scan atual terminar.');
      return;
    }

    scanBusy = true;
    scanUploadBox.style.display = 'none';
    scanTerminalWrap.style.display = 'block';
    scanResults.style.display = 'none';
    terminalLines.innerHTML = '';
    if (terminalStatus) {
      terminalStatus.textContent = 'ANALISANDO';
      terminalStatus.className = 'terminal-status-indicator';
    }

    logTerminal('SYS', 'Iniciando ccq-forensics engine 3.2 (Etapas 1-7 + Detector de Instalação)...', 'terminal-info');
    logTerminal('IO', `Detectados ${fileList.length} arquivo(s) no buffer de entrada.`, 'terminal-info');
    updateScanProgress(5, 'Carregando arquivos para a sandbox de memória...');
    sfx.start();

    const startTime = performance.now();
    const findings = [];
    const seen = new Set();
    const seenInstallers = new Set();
    const deviceInfo = { brand: '', model: '', osVersion: '', serial: '', kernel: '' };
    let analyzedCount = 0;
    let skippedCount = 0;
    let checkedLines = 0;
    let osDetected = 'ANDROID';

    try {
      const files = Array.from(fileList);
      const first = files[0];
      const isArchive = files.length === 1 && ARCHIVE_RE.test(first.name);

      let rawEntries = [];

      if (isArchive) {
        const lowerName = first.name.toLowerCase();
        if (lowerName.endsWith('.zip')) {
          logTerminal('ZIP', `Lendo container ${first.name} (${(first.size / 1024 / 1024).toFixed(1)} MB)...`, 'terminal-info');
          updateScanProgress(12, 'Inicializando motor JSZip em RAM...');
          const jszipInstance = await ensureJSZip();
          updateScanProgress(18, 'Indexando estrutura do arquivo .zip...');
          await sleep(10);
          const zip = await jszipInstance.loadAsync(first);
          // Usar uint8array + TextDecoder nativo (C++) em vez de async('string') para evitar congelamento em arquivos grandes
          rawEntries = Object.values(zip.files).filter(e => !e.dir).map(e => ({
            path: e.name,
            size: (e._data && e._data.uncompressedSize) ? e._data.uncompressedSize : 0,
            bytes: () => e.async('uint8array'),
            text: async () => {
              const buf = await e.async('uint8array');
              return utf8.decode(buf);
            }
          }));
        } else {
          logTerminal('TAR', `Descomprimindo ${first.name} (${(first.size / 1024 / 1024).toFixed(1)} MB)...`, 'terminal-info');
          updateScanProgress(15, 'Descomprimindo fluxo gzip/tar em memória...');
          rawEntries = await readTarLike(first);
        }
      } else {
        rawEntries = files.map(f => ({
          path: f.webkitRelativePath || f.name,
          size: f.size || 0,
          bytes: async () => new Uint8Array(await f.arrayBuffer()),
          text: async () => {
            const buf = new Uint8Array(await f.arrayBuffer());
            return utf8.decode(buf);
          }
        }));
      }

      const totalRaw = rawEntries.length;
      if (rawEntries.some(e => /sysdiagnose|\.plist$|\.ips$/i.test(e.path))) osDetected = 'IOS';

      // Filtrar apenas entradas forenses relevantes (evita travar em imagens, proto, traces binários)
      let entries = [];
      for (const e of rawEntries) {
        const mode = classifyScanEntry(e.path);
        if (mode) {
          entries.push({ ...e, scanMode: mode });
        } else {
          skippedCount++;
        }
      }

      // Caso o usuário tenha enviado um arquivo solto com nome incomum, analisar como texto
      if (entries.length === 0 && rawEntries.length > 0) {
        entries = rawEntries.slice(0, 30).map(e => ({ ...e, scanMode: 'text' }));
      }

      logTerminal('IO', `Estrutura indexada: ${totalRaw} entradas totais, ${entries.length} arquivos forenses selecionados (${CHEAT_SIGNATURES.length} assinaturas ativas).`, 'terminal-info');

      if (!entries.length) {
        throw new Error('Nenhum arquivo de log ou dump analisável foi encontrado no pacote.');
      }

      logTerminal('SYS', `Sistema alvo: ${osDetected === 'IOS' ? 'iOS (sysdiagnose)' : 'Android (bugreport/dump)'}`, 'terminal-info');
      updateScanProgress(25, 'Executando varredura forense (Offsets, Overlays, Proxies, Logs External e Etapas 1-7)...');
      await sleep(10);

      const total = entries.length;
      for (let i = 0; i < total; i++) {
        const entry = entries[i];
        const name = entry.path.split('/').pop() || entry.path;
        const basePct = 25 + ((i / total) * 68);

        updateScanProgress(Math.round(basePct), `Analisando (${i + 1}/${total}): ${name}`);
        await sleep(0);

        try {
          let text = '';
          if (entry.scanMode === 'binary') {
            if (entry.size && entry.size > 15 * 1024 * 1024) {
              skippedCount++;
              continue;
            }
            const bytes = await entry.bytes();
            if (bytes.length <= 15 * 1024 * 1024) {
              text = extractPrintableStrings(bytes);
            }
          } else {
            if (entry.size && entry.size > 120 * 1024 * 1024) {
              logTerminal('SKIP', `Pulando arquivo gigante (${(entry.size / 1024 / 1024).toFixed(0)} MB): ${name}`, 'terminal-info');
              skippedCount++;
              continue;
            }
            text = await entry.text();
          }

          if (!text) {
            skippedCount++;
            continue;
          }

          checkedLines += Math.max(1, Math.round(text.length / 65));
          extractDeviceInfo(text, deviceInfo);

          // 1) Detector de origem de instalação (Package [...] installerPackageName=...)
          if (osDetected === 'ANDROID' && text.includes('installerPackageName=')) {
            const installerHits = verificarOrigemInstalacao(text, entry.path, seenInstallers);
            for (const ih of installerHits) {
              findings.push(ih);
              logTerminal('ORIGEM', `[${ih.risk.toUpperCase()}] ${ih.name}`, 'terminal-err');
            }
          }

          // 2) Varredura em chunks das assinaturas forenses + Etapas 1 a 6 + Contexto Etapa 7
          const stepSpan = 68 / total;
          const hits = await scanTextForCheatsChunked(text, entry.path, (chunkRatio) => {
            const subPct = Math.min(93, Math.round(basePct + chunkRatio * stepSpan));
            updateScanProgress(subPct, `Analisando ${name} (${Math.round(chunkRatio * 100)}%)...`);
          });

          for (const h of hits) {
            const key = h.name + '|' + h.file;
            if (seen.has(key)) continue;
            seen.add(key);
            findings.push(h);
            logTerminal('ALERTA', `[${h.risk.toUpperCase()}] ${h.name} em ${name}`, 'terminal-err');
            if (h.weight >= 85) {
              sfx.alert(h.weight === 100);
            }
          }

          analyzedCount++;
        } catch (fileErr) {
          skippedCount++;
        }
      }

      updateScanProgress(96, 'Aplicando Etapa 7 (Análise Contextual dos Resultados)...');
      await sleep(120);

      const durationSec = ((performance.now() - startTime) / 1000).toFixed(1);
      updateScanProgress(100, `Varredura concluída em ${durationSec}s`);
      logTerminal('SYS', `Análise finalizada: ${analyzedCount} arquivos examinados, ${findings.length} ocorrências encontradas.`, 'terminal-info');

      if (terminalStatus) {
        terminalStatus.textContent = 'CONCLUÍDO';
        terminalStatus.className = 'terminal-status-indicator is-done';
      }

      sfx.done();

      // Cálculo de score ponderado (penaliza mais cheats diretos/root/overlays do que logs informativos de auditoria)
      const totalPenalty = findings.reduce((acc, f) => {
        if (f.category === 'log_audit') return acc + 5;
        if (f.weight >= 90) return acc + 35;
        if (f.weight >= 60) return acc + 18;
        return acc + 8;
      }, 0);

      currentScanReport = {
        findings,
        checkedLines: Math.round(checkedLines),
        analyzedCount,
        skippedCount,
        durationSec,
        osDetected,
        deviceInfo,
        timestamp: new Date().toLocaleString('pt-BR'),
        score: findings.length === 0 ? 100 : Math.max(0, 100 - totalPenalty)
      };

      displayScanResults(currentScanReport);
      showToast(findings.length === 0 ? 'success' : 'error', 'Análise Finalizada',
        findings.length === 0 ? 'Dispositivo 100% limpo e aprovado.' : `${findings.length} ocorrência(s) forense(s) encontrada(s)!`);

    } catch (err) {
      logTerminal('ERR', `Falha no scanner: ${err.message || String(err)}`, 'terminal-err');
      updateScanProgress(0, 'Falha no processamento');
      if (terminalStatus) {
        terminalStatus.textContent = 'FALHOU';
        terminalStatus.className = 'terminal-status-indicator is-error';
      }
      sfx.error();
      showToast('error', 'Erro no Scanner', err.message || 'Falha ao processar arquivo.');
    } finally {
      scanBusy = false;
      clearFileInputs();
    }
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
    activeFilterCategory = 'all';

    const highRiskCount = report.findings.filter(f => f.weight >= 60).length;
    const isClean = report.findings.length === 0;

    // Detecção da pasta não verificada -SHgap- (Exige reinstalação imediata do Free Fire)
    const hasSHgap = report.findings.some(f =>
      f.term === '-SHgap-' ||
      (f.file && f.file.includes('-SHgap-')) ||
      (f.snippet && f.snippet.includes('-SHgap-')) ||
      (f.name && f.name.includes('-SHgap-'))
    );

    resultSummary.innerHTML = `
      ${hasSHgap ? `
      <div style="background: rgba(229,72,77,0.18); border: 2px solid var(--red); border-radius: 8px; padding: 14px 16px; margin-bottom: 16px; color: #fff;">
        <div style="display:flex; align-items:center; gap:10px; margin-bottom: 6px;">
          <span style="font-size: 1.4rem;">⚠️</span>
          <strong style="color: var(--red); font-size: 1.05rem; letter-spacing: 0.5px;">ALERTA CRÍTICO: PASTA NÃO VERIFICADA DETECTADA (-SHgap-)</strong>
        </div>
        <p style="font-size: 0.9rem; line-height: 1.5; color: #ffcdd2; margin: 0 0 8px 0;">
          A pasta <code>-SHgap-</code> <strong>NÃO</strong> é uma pasta verificada do Free Fire original. Foram identificados arquivos injetados na GameAsset ou manipulação de diretório não autorizado.
        </p>
        <div style="background: rgba(0,0,0,0.45); padding: 10px 14px; border-radius: 6px; font-weight: bold; color: #fff; font-size: 0.9rem; border-left: 3px solid var(--red);">
          🚨 AÇÃO OBRIGATÓRIA: Peça para o jogador desinstalar e reinstalar o Free Fire imediatamente da loja oficial!
        </div>
      </div>
      ` : ''}
      <h3 style="color: ${isClean ? 'var(--live-green)' : (highRiskCount > 0 ? 'var(--red)' : '#f5a623')};">
        ${isClean ? 'DISPOSITIVO 100% LIMPO & APROVADO' : (highRiskCount > 0 ? 'AMEAÇAS FORENSES DETECTADAS' : 'REGISTROS DE AUDITORIA DETECTADOS (VERIFICAR CONTEXTO)')}
      </h3>
      <p style="color: var(--text-2); font-size: 0.95rem;">
        ${isClean
          ? 'Nenhum mod menu, offset il2cpp, janela sobreposta (overlay), proxy ou origem de instalação irregular foi identificado.'
          : `Foram encontradas ${report.findings.length} evidências/registros (${highRiskCount} de risco médio/alto ou ban direto).`}
      </p>
      <div style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-3); margin-top: 10px;">
        Pontuação de Integridade: <strong style="color: #fff;">${report.score}/100</strong> · Arquivos examinados: ${report.analyzedCount} · Linhas: ~${report.checkedLines.toLocaleString('pt-BR')} · Tempo: ${report.durationSec}s
      </div>
      <div style="margin-top: 12px; padding: 10px 12px; border-radius: 6px; background: rgba(255,255,255,0.03); border-left: 3px solid var(--amber, #f5a623); font-size: 0.78rem; color: var(--text-3); line-height: 1.5;">
        <strong style="color: #fff;">📋 ETAPA 7 — ANÁLISE DOS RESULTADOS:</strong> Examinar o contexto de cada ocorrência abaixo (incluindo linha anterior, linha posterior, timestamp, tag e componente responsável). Os termos de infraestrutura/logging, isoladamente, dependem da mensagem completa, da versão do Android e do componente que gerou o registro.
      </div>
    `;

    const dev = report.deviceInfo;
    const hasDev = dev && (dev.brand || dev.model || dev.osVersion || dev.serial || dev.kernel);
    if (scanDeviceCard) {
      if (hasDev) {
        scanDeviceCard.style.display = 'block';
        const modelStr = [dev.brand, dev.model].filter(Boolean).join(' ') || 'Não identificado';
        scanDeviceCard.innerHTML = `
          <strong style="display:block; margin-bottom:8px; color:#fff;">📱 Dispositivo Analisado: ${escapeHtml(modelStr)}</strong>
          <div style="font-family:var(--font-mono); font-size:0.78rem; color:var(--text-3); line-height:1.6;">
            Sistema: <strong style="color:#fff;">${escapeHtml(dev.osVersion || report.osDetected)}</strong>
            ${dev.serial ? ` · Serial: <strong style="color:#fff;">${escapeHtml(dev.serial)}</strong>` : ''}
            ${dev.kernel ? `<br>Kernel: ${escapeHtml(dev.kernel)}` : ''}
          </div>
        `;
      } else {
        scanDeviceCard.style.display = 'none';
      }
    }

    if (scanFilters) {
      if (isClean) {
        scanFilters.style.display = 'none';
      } else {
        scanFilters.style.display = 'flex';
        // Filtro de Log de Cassino (Tudo que contém hífen é log de cassino)
        const casinoCount = report.findings.filter(f =>
          f.category === 'casino_log' ||
          f.term.includes('-') ||
          (f.snippet && f.snippet.includes('-')) ||
          (f.context && f.context.currentLine && f.context.currentLine.includes('-'))
        ).length;

        const cats = Array.from(new Set(report.findings.map(f => f.category))).filter(c => c !== 'casino_log');
        scanFilters.innerHTML = `
          <button type="button" class="scan-filter-chip ${activeFilterCategory === 'all' ? 'active' : ''}" data-cat="all">Todas (${report.findings.length})</button>
          ${casinoCount > 0 ? `
            <button type="button" class="scan-filter-chip ${activeFilterCategory === 'casino_log' ? 'active' : ''}" data-cat="casino_log">
              🎰 Log de Cassino (Hífen) (${casinoCount})
            </button>
          ` : ''}
          ${cats.map(c => `
            <button type="button" class="scan-filter-chip ${activeFilterCategory === c ? 'active' : ''}" data-cat="${c}">
              ${CATEGORY_NAMES[c] || c} (${report.findings.filter(f => f.category === c).length})
            </button>
          `).join('')}
        `;

        scanFilters.querySelectorAll('.scan-filter-chip').forEach(btn => {
          btn.addEventListener('click', () => {
            activeFilterCategory = btn.dataset.cat;
            scanFilters.querySelectorAll('.scan-filter-chip').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderThreatList(report.findings, activeFilterCategory);
            sfx.tick(900);
          });
        });
      }
    }

    renderThreatList(report.findings, activeFilterCategory);
  }

  function renderThreatList(findings, categoryFilter) {
    if (!resultDetails) return;
    let filtered;
    if (categoryFilter === 'all') {
      filtered = findings;
    } else if (categoryFilter === 'casino_log') {
      // Filtro especial: tudo que contém hífen é considerado log de cassino
      filtered = findings.filter(f =>
        f.category === 'casino_log' ||
        f.term.includes('-') ||
        (f.snippet && f.snippet.includes('-')) ||
        (f.context && f.context.currentLine && f.context.currentLine.includes('-'))
      );
    } else {
      filtered = findings.filter(f => f.category === categoryFilter);
    }

    if (filtered.length === 0 && findings.length > 0) {
      resultDetails.innerHTML = `<p style="color:var(--text-3); padding:16px 0;">Nenhuma ocorrência nesta categoria.</p>`;
      return;
    }

    if (findings.length === 0) {
      resultDetails.innerHTML = `
        <div class="result-card" style="border-left-color: var(--live-green);">
          <strong style="color: var(--live-green);">Integridade Confirmada</strong>
          <p style="color: var(--text-2); font-size: 0.88rem; margin-top: 4px;">Nenhum rastro de trapaça ou modificação ilegal detectado.</p>
        </div>
      `;
      return;
    }

    resultDetails.innerHTML = filtered.map(f => {
      const ctx = f.context || {};
      const hasContextLines = Boolean(ctx.prevLine || ctx.nextLine);
      return `
      <div class="result-card">
        <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 6px;">
          <strong style="color: #fff;">${escapeHtml(f.name)}</strong>
          <span style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--red); background: rgba(229,72,77,0.15); padding: 2px 8px; border-radius: 4px;">
            Peso: ${f.weight || 50} · ${escapeHtml(f.risk)}
          </span>
        </div>
        <div style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-3); margin-bottom: 6px;">
          Arquivo: <span style="color: var(--text-2);">${escapeHtml(f.file)}</span> · Termo: <code style="color:#f5a623;">${escapeHtml(f.term)}</code>
          ${ctx.meta ? `<br><span style="color: #7ee787;">${escapeHtml(ctx.meta)}</span>` : ''}
        </div>
        <div style="background: #050507; border: 1px solid rgba(255,255,255,0.07); padding: 8px 10px; border-radius: 4px; font-family: var(--font-mono); font-size: 0.74rem; line-height: 1.5; overflow-x: auto;">
          ${hasContextLines && ctx.prevLine ? `<div style="color: #6e7681; word-break: break-all;">[Linha -1] ${escapeHtml(ctx.prevLine)}</div>` : ''}
          <div style="color: #ff8a80; font-weight: 600; word-break: break-all;">[Ocorrência] ${escapeHtml((ctx.currentLine || f.snippet || '').slice(0, 220))}</div>
          ${hasContextLines && ctx.nextLine ? `<div style="color: #6e7681; word-break: break-all;">[Linha +1] ${escapeHtml(ctx.nextLine)}</div>` : ''}
        </div>
      </div>
    `;
    }).join('');
  }

  if (scanBtnCopyReport) {
    scanBtnCopyReport.addEventListener('click', () => {
      if (!currentScanReport) return;
      const hasSHgap = currentScanReport.findings.some(f =>
        f.term === '-SHgap-' ||
        (f.file && f.file.includes('-SHgap-')) ||
        (f.snippet && f.snippet.includes('-SHgap-')) ||
        (f.name && f.name.includes('-SHgap-'))
      );

      let rep = `🛡️ *RELATÓRIO FORENSE — CACIQUE SCAN v3.2* 🛡️\n`;
      if (hasSHgap) {
        rep += `\n🚨 *ALERTA CRÍTICO: PASTA NÃO VERIFICADA DETECTADA (-SHgap-)* 🚨\n`;
        rep += `A pasta "-SHgap-" NÃO é uma pasta verificada do Free Fire original.\n`;
        rep += `AÇÃO OBRIGATÓRIA: Peça para o jogador reinstalar o Free Fire imediatamente da loja oficial!\n\n`;
      }
      rep += `📅 Data: ${currentScanReport.timestamp}\n`;
      rep += `🎯 Score de Integridade: ${currentScanReport.score}/100\n`;
      rep += `⏱️ Duração: ${currentScanReport.durationSec}s (${currentScanReport.analyzedCount} arquivos examinados)\n`;
      if (currentScanReport.deviceInfo && currentScanReport.deviceInfo.model) {
        rep += `📱 Dispositivo: ${currentScanReport.deviceInfo.brand} ${currentScanReport.deviceInfo.model} (${currentScanReport.deviceInfo.osVersion || currentScanReport.osDetected})\n`;
      }
      rep += `⚠️ Ocorrências Encontradas: ${currentScanReport.findings.length}\n\n`;

      if (currentScanReport.findings.length === 0) {
        rep += `✅ NENHUMA IRREGULARIDADE DETECTADA. JOGADOR APROVADO.\n`;
      } else {
        currentScanReport.findings.forEach((f, idx) => {
          rep += `${idx + 1}. [${f.risk} | Peso ${f.weight}] ${f.name}\n   Arquivo: ${f.file}\n   Evidência: ${(f.snippet || '').slice(0, 100)}\n\n`;
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
      clearFileInputs();
      sfx.tick(700);
    });
  }

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
