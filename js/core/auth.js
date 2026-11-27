/* ══════════════════════════════════════════════════════════════════
   ccq scan — AUTENTICAÇÃO UNIFICADA DE ADM (BACKEND + SHA-256)
   ══════════════════════════════════════════════════════════════════ */
import { sha256Hex, showToast } from './ui-utils.js';
import { sfx } from './sound.js';

const ADMIN_USER_HASH = '3680593c420bee400f624c81661151f3141f3271ed3f80121738da69f456cace';
const ADMIN_PASS_HASH = 'e0112dd9dc3f248b7a9e78bda4d522999d68636989c772137e7f644d32caf443';
const AUTH_STORAGE_KEY = 'cacique_unified_adm_auth';

let admAuthenticated = false;
let adminSessionToken = null;
let authChangeCallback = null;
let authInitialized = false;
let loginInFlight = false;

export function isAdminAuthenticated() {
  return admAuthenticated;
}

export function getAdminSessionToken() {
  return adminSessionToken;
}

export function unlockScanDashboard() {
  const scanLoginView = document.getElementById('scanLoginView');
  const scanDashboardView = document.getElementById('scanDashboardView');
  if (scanLoginView && scanDashboardView) {
    scanLoginView.style.display = 'none';
    scanLoginView.hidden = true;
    scanDashboardView.style.display = 'block';
    scanDashboardView.hidden = false;
  }
}

export function lockScanDashboard() {
  const scanLoginView = document.getElementById('scanLoginView');
  const scanDashboardView = document.getElementById('scanDashboardView');
  if (scanLoginView && scanDashboardView) {
    scanLoginView.style.display = 'block';
    scanLoginView.hidden = false;
    scanDashboardView.style.display = 'none';
    scanDashboardView.hidden = true;
  }
}

function updateAuthUI() {
  const roleBadgeBtn = document.getElementById('roleBadgeBtn');
  const roleBadgeText = document.getElementById('roleBadgeText');
  const btnAuthSubmit = document.getElementById('btnAuthSubmit');
  const btnAuthLogout = document.getElementById('btnAuthLogout');

  if (roleBadgeBtn && roleBadgeText) {
    if (admAuthenticated) {
      roleBadgeBtn.classList.add('is-admin');
      roleBadgeText.textContent = 'Operador ADM';
      if (btnAuthLogout) btnAuthLogout.style.display = 'inline-flex';
      if (btnAuthSubmit) btnAuthSubmit.textContent = 'Autenticado';
    } else {
      roleBadgeBtn.classList.remove('is-admin');
      roleBadgeText.textContent = 'Visitante';
      if (btnAuthLogout) btnAuthLogout.style.display = 'none';
      if (btnAuthSubmit) btnAuthSubmit.textContent = 'Entrar como ADM';
    }
  }
}

export async function handleAdminLogin(userVal, passVal) {
  if (loginInFlight) return false;
  const cleanUser = (userVal || '').trim().toUpperCase();
  const cleanPass = (passVal || '').trim();

  if (!cleanUser || !cleanPass) {
    sfx.error();
    showToast('error', 'Campos Vazios', 'Preencha usuário e senha de ADM.');
    return false;
  }

  loginInFlight = true;
  let isMatch = false;

  try {
    // 1. Tentar validação via API Backend (quando executando sob servidor Flask)
    try {
      const resp = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: cleanUser, pass: cleanPass })
      });

      if (resp.status === 429) {
        const errData = await resp.json().catch(() => ({}));
        sfx.error();
        showToast('error', 'Bloqueio de Segurança', errData.message || 'Muitas tentativas. IP temporariamente bloqueado.');
        return false;
      }

      if (resp.ok) {
        const data = await resp.json();
        if (data && data.status === 'success') {
          isMatch = true;
          adminSessionToken = data.token || null;
        }
      }
    } catch (_) {}

    // 2. Validação client-side puramente criptográfica (GitHub Pages / estático)
    if (!isMatch) {
      try {
        const userH = await sha256Hex(cleanUser);
        const passH = await sha256Hex(cleanPass);
        if (userH === ADMIN_USER_HASH && passH === ADMIN_PASS_HASH) {
          isMatch = true;
        }
      } catch (_) {}
    }

    const modalAuthBackdrop = document.getElementById('modalAuthBackdrop');
    const authPassInput = document.getElementById('authPassInput');

    if (isMatch) {
      admAuthenticated = true;
      updateAuthUI();
      sfx.done();
      showToast('success', 'Acesso Autorizado', 'Modo operador ADM do ccq scan ativado com sucesso.');
      if (modalAuthBackdrop) modalAuthBackdrop.style.display = 'none';
      if (authPassInput) authPassInput.value = '';
      unlockScanDashboard();
      if (authChangeCallback) authChangeCallback(true);
      return true;
    }

    sfx.error();
    showToast('error', 'Acesso Negado', 'Usuário ou senha de ADM incorretos.');
    return false;
  } finally {
    loginInFlight = false;
  }
}

export async function performAdminLogout() {
  if (adminSessionToken) {
    try {
      await fetch('/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminSessionToken}`
        }
      });
    } catch (_) {}
  }

  adminSessionToken = null;
  admAuthenticated = false;

  try {
    localStorage.removeItem(AUTH_STORAGE_KEY);
    sessionStorage.removeItem(AUTH_STORAGE_KEY);
  } catch (_) {}

  updateAuthUI();
  lockScanDashboard();
  sfx.tick(600);
  showToast('info', 'Desconectado', 'Sessão de ADM encerrada e invalidada.');
  const modalAuthBackdrop = document.getElementById('modalAuthBackdrop');
  if (modalAuthBackdrop) modalAuthBackdrop.style.display = 'none';
  if (authChangeCallback) authChangeCallback(false);
}

export function initAuth({ onAuthChange } = {}) {
  authChangeCallback = onAuthChange || null;
  if (authInitialized) return;
  authInitialized = true;

  // Nunca iniciar logado automaticamente
  try {
    localStorage.removeItem('cacique_unified_adm_auth');
    localStorage.removeItem('cacique_scan_authenticated');
    sessionStorage.removeItem('cacique_unified_adm_auth');
  } catch (_) {}

  admAuthenticated = false;
  adminSessionToken = null;
  updateAuthUI();
  lockScanDashboard();

  const roleBadgeBtn = document.getElementById('roleBadgeBtn');
  const modalAuthBackdrop = document.getElementById('modalAuthBackdrop');
  const authUserInput = document.getElementById('authUserInput');
  const authPassInput = document.getElementById('authPassInput');
  const btnAuthSubmit = document.getElementById('btnAuthSubmit');
  const btnAuthLogout = document.getElementById('btnAuthLogout');

  const safeRunAuth = (promise) => {
    Promise.resolve(promise).catch((err) => {
      console.error('[ccq scan auth]', err);
      showToast('error', 'Erro de Autenticação', 'Falha inesperada ao processar sessão.');
    });
  };

  if (roleBadgeBtn) {
    roleBadgeBtn.addEventListener('click', () => {
      if (modalAuthBackdrop) modalAuthBackdrop.style.display = 'flex';
      sfx.tick(900);
    });
  }

  if (btnAuthSubmit) {
    btnAuthSubmit.addEventListener('click', () => {
      safeRunAuth(handleAdminLogin(authUserInput ? authUserInput.value : '', authPassInput ? authPassInput.value : ''));
    });
  }

  [authUserInput, authPassInput].forEach(inp => {
    if (inp) {
      inp.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          safeRunAuth(handleAdminLogin(authUserInput ? authUserInput.value : '', authPassInput ? authPassInput.value : ''));
        }
      });
    }
  });

  if (btnAuthLogout) {
    btnAuthLogout.addEventListener('click', () => safeRunAuth(performAdminLogout()));
  }

  const scanUser = document.getElementById('scanUser');
  const scanPass = document.getElementById('scanPass');
  const scanBtnLogin = document.getElementById('scanBtnLogin');
  const scanBtnLogout = document.getElementById('scanBtnLogout');

  const triggerScanLogin = () => {
    if (!scanUser || !scanPass) return;
    safeRunAuth(handleAdminLogin(scanUser.value, scanPass.value).then((ok) => {
      if (ok) {
        scanPass.value = '';
      } else {
        scanPass.classList.add('input-invalid');
        setTimeout(() => scanPass.classList.remove('input-invalid'), 600);
      }
    }));
  };

  if (scanBtnLogin && scanUser && scanPass) {
    scanBtnLogin.addEventListener('click', (e) => {
      e.preventDefault();
      triggerScanLogin();
    });
    [scanUser, scanPass].forEach(inp => {
      inp.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          triggerScanLogin();
        }
      });
    });
  }

  if (scanBtnLogout) {
    scanBtnLogout.addEventListener('click', () => safeRunAuth(performAdminLogout()));
  }
}
