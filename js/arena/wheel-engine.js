/* ══════════════════════════════════════════════════════════════════
   CACIQUE ARENA — MOTOR CANVAS 2D DA ROLETA COM CSPRNG
   ══════════════════════════════════════════════════════════════════ */
import { escapeHtml } from '../core/ui-utils.js';
import { sfx } from '../core/sound.js';
import { getRankById } from './ranks.js';

export class SingleWheelEngine {
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

      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.arc(0, 0, radius, startA, endA);
      ctx.closePath();

      ctx.fillStyle = (i % 2 === 0) ? '#16171d' : '#1c1d25';
      ctx.fill();

      ctx.beginPath();
      ctx.arc(0, 0, radius, startA, endA);
      ctx.lineWidth = 5;
      ctx.strokeStyle = rank.color;
      ctx.stroke();

      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.lineTo(Math.cos(startA) * radius, Math.sin(startA) * radius);
      ctx.lineWidth = 1;
      ctx.strokeStyle = 'rgba(255,255,255,0.08)';
      ctx.stroke();

      ctx.save();
      ctx.rotate(startA + arc / 2);
      ctx.textAlign = 'right';

      ctx.font = '700 10px Geist Mono, monospace';
      ctx.fillStyle = rank.color;
      ctx.fillText(rank.abbr, radius - 14, 4);

      ctx.font = '600 12px Geist, sans-serif';
      ctx.fillStyle = '#ffffff';
      const displayNick = player.nick.length > 12 ? player.nick.slice(0, 11) + '…' : player.nick;
      ctx.fillText(displayNick, radius - 38, 4);

      ctx.restore();
    }

    ctx.restore();
  }

  spin(targetDuration = 3500) {
    if (this.isSpinning) return Promise.reject('Em giro');
    if (this.eligiblePlayers.length === 0) return Promise.reject('Sem jogadores');

    const totalSlotsNeeded = this.targetTeamSize * 2;
    const currentFilled = this.team1.length + this.team2.length;
    if (currentFilled >= totalSlotsNeeded) {
      return Promise.reject('Times já preenchidos');
    }

    return new Promise((resolve) => {
      this.isSpinning = true;

      const cryptoRandomBuf = new Uint32Array(1);
      window.crypto.getRandomValues(cryptoRandomBuf);
      const winningIndex = cryptoRandomBuf[0] % this.eligiblePlayers.length;
      const winner = this.eligiblePlayers[winningIndex];

      const count = this.eligiblePlayers.length;
      const arc = (Math.PI * 2) / count;
      const sliceCenter = winningIndex * arc + arc / 2;

      const pointerPos = (3 * Math.PI) / 2;
      const turns = 5 + Math.floor(Math.random() * 3);
      const targetRot = turns * (Math.PI * 2) + (pointerPos - sliceCenter);

      const startRot = this.currentAngle % (Math.PI * 2);
      const totalDelta = targetRot - startRot;

      const startTime = performance.now();
      this.lastTickIndex = -1;

      const animate = (now) => {
        const elapsed = now - startTime;
        const progress = Math.min(1, elapsed / targetDuration);

        const ease = 1 - Math.pow(1 - progress, 4);
        this.currentAngle = startRot + totalDelta * ease;

        const normalizedAngle = (pointerPos - (this.currentAngle % (Math.PI * 2)) + Math.PI * 4) % (Math.PI * 2);
        const currentSlice = Math.floor(normalizedAngle / arc);

        if (currentSlice !== this.lastTickIndex) {
          this.lastTickIndex = currentSlice;
          if (this.pointer) {
            this.pointer.classList.remove('tick');
            void this.pointer.offsetWidth;
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

          if (this.team1.length < this.targetTeamSize) {
            this.team1.push(winner);
            this.updateSlots(1, winner);
          } else if (this.team2.length < this.targetTeamSize) {
            this.team2.push(winner);
            this.updateSlots(2, winner);
          }

          this.eligiblePlayers.splice(winningIndex, 1);
          this.draw();

          resolve({
            wheelId: this.wheelId,
            winner,
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
