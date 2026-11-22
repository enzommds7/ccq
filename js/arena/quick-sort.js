/* ══════════════════════════════════════════════════════════════════
   CACIQUE ARENA — MODO RÁPIDO CLÁSSICO
   ══════════════════════════════════════════════════════════════════ */
import { escapeHtml, performCopy } from '../core/ui-utils.js';
import { sfx } from '../core/sound.js';

export function initQuickSort() {
  const namesInput = document.getElementById('namesInput');
  const sizeBtns = document.querySelectorAll('.size-btn');
  const customSizeInput = document.getElementById('customSize');
  const sortInfo = document.getElementById('sortInfo');
  const sortBtn = document.getElementById('sortBtn');
  const clearBtn = document.getElementById('clearBtn');
  const sorteioStage = document.getElementById('sorteioStage');

  let quickTeamSize = 4;
  let lastQuickPlayerCount = 0;
  let quickAnimFrame = null;

  function getValidQuickNames() {
    if (!namesInput) return [];
    return namesInput.value
      .split('\n')
      .map(name => name.trim())
      .filter(name => name.length > 0);
  }

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
    let currentIndex = array.length;
    let randomIndex;
    while (currentIndex !== 0) {
      randomIndex = Math.floor(Math.random() * currentIndex);
      currentIndex--;
      [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
    }
    return array;
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
          shuffled.slice(numTeams * quickTeamSize).forEach(p => { text += ` • ${p}\n`; });
          text += `\n`;
        }
        text += `🛡️ Tribo Oficial: https://enzommds7.github.io/ccq/`;
        performCopy(text, quickExportBtn, 'Copiado para WhatsApp!', sfx);
      });
    }
  }

  if (sortBtn) {
    sortBtn.addEventListener('click', () => {
      const names = getValidQuickNames();
      if (names.length < quickTeamSize) return;

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
}
