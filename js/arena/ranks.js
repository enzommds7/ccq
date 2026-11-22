/* ══════════════════════════════════════════════════════════════════
   CACIQUE ARENA — PATENTES E PESOS EDITÁVEIS
   ══════════════════════════════════════════════════════════════════ */
import { showToast } from '../core/ui-utils.js';
import { sfx } from '../core/sound.js';

export const DEFAULT_RANKS = [
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

export function loadRanks() {
  try {
    const saved = localStorage.getItem('cacique_ranks_weights_v4');
    if (saved) return JSON.parse(saved);
  } catch (_) {}
  return JSON.parse(JSON.stringify(DEFAULT_RANKS));
}

let ranks = loadRanks();

export function getRanks() {
  return ranks;
}

export function saveRanks(newRanks) {
  ranks = newRanks;
  try {
    localStorage.setItem('cacique_ranks_weights_v4', JSON.stringify(ranks));
  } catch (_) {}
}

export function getRankById(id) {
  return ranks.find(r => r.id === id) || ranks[ranks.length - 1];
}

export function initRanksModal(onRanksUpdated) {
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
      if (onRanksUpdated) onRanksUpdated();
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
}
