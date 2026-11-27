import { bindCopySound, initNavigationAndSocial, showToast } from './core/ui-utils.js';
import { sfx } from './core/sound.js';
import { initAuth, isAdminAuthenticated } from './core/auth.js';

let appInitialized = false;
let scanUiModule = null;
let scanUiPromise = null;

function ensureScanUiReady() {
  if (scanUiModule) {
    if (isAdminAuthenticated()) {
      scanUiModule.initScanUI({ isAdminAuthenticated });
    }
    return;
  }

  if (!scanUiPromise) {
    scanUiPromise = import('./scan/scan-ui.js?v=5.1')
      .then((mod) => {
        scanUiModule = mod;
        if (isAdminAuthenticated()) {
          mod.initScanUI({ isAdminAuthenticated });
        } else {
          mod.resetScanSession();
        }
        return mod;
      })
      .catch((error) => {
        scanUiPromise = null;
        console.error('[ccq scan] Falha ao carregar módulo da interface do scanner:', error);
        showToast('error', 'Erro ao carregar scanner', 'Recarregue a página ou tente fazer login novamente.');
      });
  }
}

function handleAuthTransition(authenticated) {
  if (authenticated) {
    ensureScanUiReady();
  } else if (scanUiModule) {
    scanUiModule.resetScanSession();
  }
}

function initApp() {
  if (appInitialized) return;
  appInitialized = true;

  sfx.bindDom();
  bindCopySound(sfx);
  initNavigationAndSocial(sfx);
  initAuth({ onAuthChange: handleAuthTransition });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp, { once: true });
} else {
  initApp();
}
