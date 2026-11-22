/* ══════════════════════════════════════════════════════════════════
   CACIQUE CORE — UI UTILS, ANTI-XSS, CRIPTOGRAFIA & NAVEGAÇÃO
   ══════════════════════════════════════════════════════════════════ */

let boundSoundCtrl = null;

export function bindCopySound(soundCtrl) {
  boundSoundCtrl = soundCtrl || null;
}

export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[m]);
}

export function showToast(type, title, message, duration = 3200) {
  const toastRegion = document.getElementById('toastRegion');
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

export function fallbackCopy(text) {
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

export async function performCopy(text, btnElement, feedbackMsg = 'Copiado!', soundCtrl = boundSoundCtrl) {
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
    if (soundCtrl && soundCtrl.tick) soundCtrl.tick(1400);
    if (btnElement) {
      const originalHtml = btnElement.innerHTML;
      btnElement.classList.add('is-copied');
      btnElement.textContent = feedbackMsg;
      setTimeout(() => {
        btnElement.classList.remove('is-copied');
        btnElement.innerHTML = originalHtml;
      }, 2000);
    }
    showToast('success', 'Copiado', 'Texto copiado para a área de transferência.');
  } else {
    if (soundCtrl && soundCtrl.error) soundCtrl.error();
    showToast('error', 'Erro ao copiar', 'Não foi possível acessar o clipboard.');
  }
}

// SHA-256 nativo (Web Crypto) com fallback RFC-6234 puro JS (100% determinístico em HTTPS, HTTP e file://)
export function pureJsSha256(ascii) {
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

export async function sha256Hex(str) {
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

export function generateRandomSeedHex() {
  const bytes = new Uint8Array(16);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export class HeroCanvas {
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

export function initNavigationAndSocial(sfx) {
  const header = document.getElementById('header');
  if (header) {
    window.addEventListener('scroll', () => {
      if (window.scrollY > 24) {
        header.classList.add('scrolled');
      } else {
        header.classList.remove('scrolled');
      }
    }, { passive: true });
  }

  const navToggle = document.getElementById('navToggle');
  const mobileMenu = document.getElementById('mobileMenu');
  if (navToggle && mobileMenu) {
    const toggleMobileMenu = () => {
      navToggle.classList.toggle('active');
      mobileMenu.classList.toggle('open');
      navToggle.setAttribute('aria-expanded', navToggle.classList.contains('active'));
    };
    navToggle.addEventListener('click', toggleMobileMenu);
    mobileMenu.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        if (mobileMenu.classList.contains('open')) toggleMobileMenu();
      });
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
      if (sfx) sfx.tick(700);
    });
  });

  // Redes Sociais: Abas & Cópia de Links Oficiais
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
      if (sfx) sfx.tick(850);
    });
  });

  document.querySelectorAll('.rede-copy-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const copyVal = e.currentTarget.dataset.copy;
      if (copyVal) {
        performCopy(copyVal, e.currentTarget, 'Copiado!', sfx);
      }
    });
  });
}
