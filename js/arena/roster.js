/* ══════════════════════════════════════════════════════════════════
   CACIQUE ARENA — GESTÃO DO ELENCO (CADASTRO & PARSE LIVRE)
   ══════════════════════════════════════════════════════════════════ */
import { escapeHtml, performCopy, showToast } from '../core/ui-utils.js';
import { sfx } from '../core/sound.js';
import { getRanks, getRankById } from './ranks.js';

export class RosterManager {
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

  parseText(text) {
    const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    const defaultRankId = this.defaultRankSelect ? this.defaultRankSelect.value : 'none';
    const added = [];

    lines.forEach((line, index) => {
      let nick = line;
      let detectedRankId = defaultRankId;
      let idVal = '';

      const idMatch = line.match(/#([a-zA-Z0-9_-]+)/);
      if (idMatch) {
        idVal = idMatch[1];
        nick = nick.replace(idMatch[0], '').trim();
      }

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

      nick = nick.replace(/^[-|—\s]+|[-|—\s]+$/g, '').trim();
      if (!nick) nick = `Guerreiro_${Date.now().toString().slice(-4)}_${index + 1}`;

      added.push({
        id: 'p_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 5),
        nick,
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
    const ranks = getRanks();

    const nameCounts = {};
    this.players.forEach(p => {
      const k = p.nick.toLowerCase();
      nameCounts[k] = (nameCounts[k] || 0) + 1;
    });

    let hasDuplicates = false;

    const filtered = this.players.filter(p => {
      const matchesQuery = !query || p.nick.toLowerCase().includes(query) || (p.gameId && p.gameId.includes(query));
      if (!matchesQuery) return false;
      if (filterRank === 'all') return true;
      const allowedRanks = filterRank.split(',');
      return allowedRanks.includes(p.rankId);
    });

    if (this.totalCountEl) this.totalCountEl.textContent = this.players.length;

    if (this.chipsContainer) {
      const counts = {};
      this.players.forEach(p => { counts[p.rankId] = (counts[p.rankId] || 0) + 1; });
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

export function initRoster() {
  const rosterManager = new RosterManager();

  const rosterInput = document.getElementById('rosterInput');
  const btnParseRoster = document.getElementById('btnParseRoster');
  const btnLoadSampleRoster = document.getElementById('btnLoadSampleRoster');
  const btnClearRosterInput = document.getElementById('btnClearRosterInput');
  const btnClearAllRoster = document.getElementById('btnClearAllRoster');

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
      performCopy(importExportTextarea.value, btnCopyImportExport, 'Copiado!', sfx);
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

  return rosterManager;
}
