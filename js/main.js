/* ══════════════════════════════════════════════════════════════════
   CACIQUE APOSTAS v5.0 — INICIALIZAÇÃO LEVE (LAZY-LOADING SCANNER)
   ══════════════════════════════════════════════════════════════════ */
import { HeroCanvas, bindCopySound, initNavigationAndSocial } from './core/ui-utils.js';
import { sfx } from './core/sound.js';
import { initAuth, isAdminAuthenticated } from './core/auth.js';
import { initRanksModal } from './arena/ranks.js';
import { initRoster } from './arena/roster.js';
import { initArenaController } from './arena/arena-controller.js';
import { initQuickSort } from './arena/quick-sort.js';

let scanUiPromise = null;

async function ensureScanUiLoaded() {
  if (!scanUiPromise) {
    scanUiPromise = import('./scan/scan-ui.js').then(({ initScanUI }) => {
      initScanUI({ isAdminAuthenticated });
    });
  }
  return scanUiPromise;
}

function initApp() {
  sfx.bindDom();
  bindCopySound(sfx);
  new HeroCanvas('heroCanvas');
  initNavigationAndSocial(sfx);

  const rosterManager = initRoster();
  initRanksModal(() => rosterManager.render());
  initArenaController(rosterManager);
  initQuickSort();

  // Scanner & Worker só são carregados sob demanda após autenticação ADM ou navegação para #scan
  initAuth({
    onAuthChange: (authenticated) => {
      if (authenticated) {
        ensureScanUiLoaded();
      }
    }
  });

  document.querySelectorAll('a[href="#scan"]').forEach(link => {
    link.addEventListener('click', () => {
      if (isAdminAuthenticated()) ensureScanUiLoaded();
    });
  });

  if (window.location.hash === '#scan' && isAdminAuthenticated()) {
    ensureScanUiLoaded();
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}
