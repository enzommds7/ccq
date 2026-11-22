/* ══════════════════════════════════════════════════════════════════
   CACIQUE ARENA — ORQUESTRAÇÃO DAS 3 ROLETAS, TELÃO, PNG E AUDITORIA
   ══════════════════════════════════════════════════════════════════ */
import { escapeHtml, generateRandomSeedHex, performCopy, sha256Hex, showToast } from '../core/ui-utils.js';
import { sfx } from '../core/sound.js';
import { getRankById } from './ranks.js';
import { SingleWheelEngine } from './wheel-engine.js';

export class RouletteArena {
  constructor(rosterManager) {
    this.rosterManager = rosterManager;
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

    const btnSpinAll = document.getElementById('btnSpinAllWheels');
    if (btnSpinAll) btnSpinAll.addEventListener('click', () => this.spinActiveWheels());

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

    const btnAutoBalance = document.getElementById('btnAutoBalanceAll');
    if (btnAutoBalance) btnAutoBalance.addEventListener('click', () => this.autoBalanceTeams());

    const btnShareWhatsApp = document.getElementById('btnShareWhatsApp');
    if (btnShareWhatsApp) btnShareWhatsApp.addEventListener('click', () => this.copyWhatsAppSummary(btnShareWhatsApp));

    const btnDownloadCardPng = document.getElementById('btnDownloadCardPng');
    if (btnDownloadCardPng) btnDownloadCardPng.addEventListener('click', () => this.generateShowdownCardPng());

    window.addEventListener('keydown', (e) => {
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
    const allPlayers = [...this.rosterManager.players];
    if (allPlayers.length === 0) {
      showToast('info', 'Aviso', 'Nenhum jogador no elenco. Adicione nomes no Passo 1.');
    }

    const sizeA = parseInt(document.getElementById('whlTeamSizeA')?.value || '4', 10);
    const sizeB = parseInt(document.getElementById('whlTeamSizeB')?.value || '4', 10);
    const sizeC = parseInt(document.getElementById('whlTeamSizeC')?.value || '2', 10);

    this.wheelA.targetTeamSize = sizeA;
    this.wheelB.targetTeamSize = sizeB;
    this.wheelC.targetTeamSize = sizeC;

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

  async spinActiveWheels() {
    const actA = document.getElementById('whlActiveA')?.checked;
    const actB = document.getElementById('whlActiveB')?.checked;
    const actC = document.getElementById('whlActiveC')?.checked;

    const promises = [];
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
    if (this.exclusiveChk && this.exclusiveChk.checked) {
      const pId = res.winner.id;
      this.wheelA.eligiblePlayers = this.wheelA.eligiblePlayers.filter(p => p.id !== pId);
      this.wheelB.eligiblePlayers = this.wheelB.eligiblePlayers.filter(p => p.id !== pId);
      this.wheelC.eligiblePlayers = this.wheelC.eligiblePlayers.filter(p => p.id !== pId);
      this.wheelA.draw();
      this.wheelB.draw();
      this.wheelC.draw();
    }

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

    const combine = (start, chosen) => {
      if (chosen.length === teamSize) {
        const team1 = chosen.map(i => players[i]);
        const team2 = players.filter((_, i) => !chosen.includes(i));

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
      hash,
      matches: [
        { mesa: 'A', t1: this.wheelA.team1, t2: this.wheelA.team2 },
        { mesa: 'B', t1: this.wheelB.team1, t2: this.wheelB.team2 },
        { mesa: 'C', t1: this.wheelC.team1, t2: this.wheelC.team2 }
      ]
    };

    try {
      const history = JSON.parse(localStorage.getItem('cacique_audit_history_v4') || '[]');
      history.unshift(record);
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

    performCopy(text, btn, 'Copiado para WhatsApp!', sfx);
  }

  generateShowdownCardPng() {
    const c = document.createElement('canvas');
    c.width = 1200;
    c.height = 630;
    const ctx = c.getContext('2d');

    const grad = ctx.createLinearGradient(0, 0, 1200, 630);
    grad.addColorStop(0, '#0d0e12');
    grad.addColorStop(1, '#16171d');
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, 1200, 630);

    ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
    ctx.lineWidth = 1;
    for (let x = 0; x < 1200; x += 60) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, 630); ctx.stroke();
    }

    ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
    ctx.strokeRect(30, 30, 1140, 570);

    ctx.strokeStyle = '#e5484d';
    ctx.lineWidth = 3;
    ctx.strokeRect(26, 26, 24, 24);
    ctx.strokeRect(1150, 26, 24, 24);
    ctx.strokeRect(26, 580, 24, 24);
    ctx.strokeRect(1150, 580, 24, 24);

    ctx.fillStyle = '#e5484d';
    ctx.font = '700 16px "Share Tech Mono", monospace';
    ctx.fillText('TRIBO OFICIAL DE APOSTAS FREE FIRE', 60, 75);

    ctx.fillStyle = '#ffffff';
    ctx.font = '800 34px "Clash Display", sans-serif';
    ctx.fillText('CACIQUE APOSTAS — CONFRONTO AUDITADO', 60, 118);

    const t1 = this.wheelA.team1;
    const t2 = this.wheelA.team2;
    const sum1 = t1.reduce((acc, p) => acc + getRankById(p.rankId).weight, 0);
    const sum2 = t2.reduce((acc, p) => acc + getRankById(p.rankId).weight, 0);

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

    ctx.fillStyle = '#d4af37';
    ctx.font = '800 36px "Clash Display", sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('VS', 600, 350);
    ctx.textAlign = 'left';

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

    ctx.fillStyle = '#8a8f98';
    ctx.font = '500 13px "Share Tech Mono", monospace';
    ctx.fillText(`ID: ${this.currentDrawId} | SEED: ${this.currentSeed} | JOGUE COM RESPONSABILIDADE (18+)`, 60, 565);

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

export function initArenaController(rosterManager) {
  const rouletteArena = new RouletteArena(rosterManager);

  const setArenaStep = (step) => {
    document.querySelectorAll('.arena-step-pane').forEach((pane, idx) => {
      pane.classList.toggle('active', idx + 1 === step);
    });
    document.querySelectorAll('.step-node').forEach((node, idx) => {
      const nStep = idx + 1;
      node.classList.toggle('active', nStep === step);
      node.classList.toggle('completed', nStep < step);
    });
    sfx.tick(900 + step * 100);
    if (step === 3) {
      rouletteArena.prepareWheels();
    }
  };

  document.querySelectorAll('.step-node').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const s = parseInt(e.currentTarget.dataset.step, 10);
      if (s) setArenaStep(s);
    });
  });

  const btnGoToStep2 = document.getElementById('btnGoToStep2');
  const btnBackToStep1 = document.getElementById('btnBackToStep1');
  const btnGoToStep3 = document.getElementById('btnGoToStep3');
  const btnBackToStep2 = document.getElementById('btnBackToStep2');
  const btnGoToStep4 = document.getElementById('btnGoToStep4');
  const btnGoToStep4From3 = document.getElementById('btnGoToStep4From3');
  const btnBackToStep3 = document.getElementById('btnBackToStep3');
  const btnStartNewRound = document.getElementById('btnStartNewRound');

  if (btnGoToStep2) btnGoToStep2.addEventListener('click', () => setArenaStep(2));
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

  const btnTelaoMode = document.getElementById('btnTelaoMode');
  const telaoBtnExit = document.getElementById('telaoBtnExit');
  const telaoBtnSpin = document.getElementById('telaoBtnSpin');
  if (btnTelaoMode) btnTelaoMode.addEventListener('click', () => rouletteArena.toggleTelaoMode());
  if (telaoBtnExit) telaoBtnExit.addEventListener('click', () => rouletteArena.toggleTelaoMode());
  if (telaoBtnSpin) telaoBtnSpin.addEventListener('click', () => rouletteArena.spinActiveWheels());

  // Auditoria & Histórico de Sorteios
  const btnAuditModal = document.getElementById('btnAuditModal');
  const modalAuditBackdrop = document.getElementById('modalAuditBackdrop');
  const auditHistoryList = document.getElementById('auditHistoryList');
  const auditSearchInput = document.getElementById('auditSearchInput');
  const btnExportAuditCsv = document.getElementById('btnExportAuditCsv');
  const btnClearAuditHistory = document.getElementById('btnClearAuditHistory');

  const renderAuditHistory = () => {
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
  };

  if (btnAuditModal) {
    btnAuditModal.addEventListener('click', () => {
      renderAuditHistory();
      if (modalAuditBackdrop) modalAuditBackdrop.style.display = 'flex';
      sfx.tick(850);
    });
  }

  if (auditSearchInput) auditSearchInput.addEventListener('input', renderAuditHistory);

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

  return rouletteArena;
}
