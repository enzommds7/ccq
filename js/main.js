import { bindCopySound, initNavigationAndSocial } from './core/ui-utils.js';
import { sfx } from './core/sound.js';
import { initAuth, isAdminAuthenticated } from './core/auth.js';

let scanUiPromise;
function initApp() {
  sfx.bindDom();
  bindCopySound(sfx);
  initNavigationAndSocial(sfx);
  initAuth({ onAuthChange(authenticated) {
    if (authenticated && !scanUiPromise) {
      scanUiPromise = import('./scan/scan-ui.js').then(({ initScanUI }) => {
        initScanUI({ isAdminAuthenticated });
      }).catch(error => { scanUiPromise = null; console.error(error); });
    }
  } });
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initApp);
else initApp();
