/* ══════════════════════════════════════════════════════════════════
   ccq scan — ÁUDIO WEB API & FEEDBACK HÁPTICO
   ══════════════════════════════════════════════════════════════════ */
import { showToast } from './ui-utils.js';

export class SoundController {
  constructor() {
    this.ctx = null;
    this.domBound = false;
    try {
      this.enabled = typeof localStorage !== 'undefined' && localStorage.getItem('cacique_sfx_enabled') === 'true';
    } catch (_) {
      this.enabled = false;
    }
    this.toggleBtn = null;
  }

  bindDom() {
    if (this.domBound) return;
    this.domBound = true;
    this.toggleBtn = document.getElementById('soundToggle');
    this.updateBtnState();
    if (this.toggleBtn) {
      this.toggleBtn.addEventListener('click', () => this.toggle());
    }
  }

  init() {
    if (!this.ctx && typeof window !== 'undefined') {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (AudioCtx) this.ctx = new AudioCtx();
    }
    if (this.ctx && this.ctx.state === 'suspended') {
      this.ctx.resume().catch(() => {});
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
    try {
      localStorage.setItem('cacique_sfx_enabled', this.enabled ? 'true' : 'false');
    } catch (_) {}
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

  start() {
    this.tick(1200);
  }

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

export const sfx = new SoundController();
