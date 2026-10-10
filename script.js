/* ═══════════════════════════════════════════════
   Cacique Apostas — Interactivity & Sorteio
   ═══════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
  // ── Header Scroll Effect ──
  const header = document.getElementById('header');
  window.addEventListener('scroll', () => {
    if (window.scrollY > 20) {
      header.classList.add('scrolled');
    } else {
      header.classList.remove('scrolled');
    }
  });


  const navToggle = document.getElementById('navToggle');
  const mobileMenu = document.getElementById('mobileMenu');
  const mobileLinks = mobileMenu.querySelectorAll('a');

  function toggleMenu() {
    navToggle.classList.toggle('active');
    mobileMenu.classList.toggle('open');
    const isExpanded = navToggle.classList.contains('active');
    navToggle.setAttribute('aria-expanded', isExpanded);
  }

  navToggle.addEventListener('click', toggleMenu);

  mobileLinks.forEach(link => {
    link.addEventListener('click', () => {
      if (mobileMenu.classList.contains('open')) {
        toggleMenu();
      }
    });
  });


  const namesInput = document.getElementById('namesInput');
  const sizeBtns = document.querySelectorAll('.size-btn');
  const customSizeInput = document.getElementById('customSize');
  const sortInfo = document.getElementById('sortInfo');
  const sortBtn = document.getElementById('sortBtn');
  const clearBtn = document.getElementById('clearBtn');
  const sorteioStage = document.getElementById('sorteioStage');

  let teamSize = 4;

  // Update selected team size
  function updateTeamSize(size, btnElement) {
    teamSize = parseInt(size, 10);
    sizeBtns.forEach(btn => btn.classList.remove('active'));
    if (btnElement) {
      btnElement.classList.add('active');
      customSizeInput.value = '';
    }
    updateSortInfo();
  }

  sizeBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      updateTeamSize(e.target.dataset.size, e.target);
    });
  });

  customSizeInput.addEventListener('input', (e) => {
    const val = parseInt(e.target.value, 10);
    if (val >= 2) {
      teamSize = val;
      sizeBtns.forEach(btn => btn.classList.remove('active'));
      updateSortInfo();
    }
  });

  // Get valid names from textarea
  function getValidNames() {
    const text = namesInput.value;
    return text.split('\n')
      .map(name => name.trim())
      .filter(name => name.length > 0);
  }

  // Update info text
  function updateSortInfo() {
    const namesCount = getValidNames().length;
    sortInfo.innerHTML = `<span class="hl">${namesCount}</span> jogadores válidos detectados`;

    if (namesCount > 0 && namesCount < teamSize) {
      sortInfo.innerHTML += ` <span style="color:var(--red); font-weight:600;">(Mínimo de ${teamSize} necessário)</span>`;
      sortBtn.disabled = true;
    } else if (namesCount === 0) {
      sortBtn.disabled = true;
    } else {
      sortBtn.disabled = false;
    }
  }

  namesInput.addEventListener('input', updateSortInfo);

  // Clear everything
  clearBtn.addEventListener('click', () => {
    namesInput.value = '';
    updateSortInfo();
    sorteioStage.innerHTML = `
      <div class="stage-empty">
        <svg viewBox="0 0 24 24"><path d="M16 3h5v5"/><path d="M4 20L21 3"/><path d="M21 16v5h-5"/><path d="M15 15l6 6"/><path d="M4 4l5 5"/></svg>
        <p>Adicione nomes e clique em sortear para gerar os times</p>
      </div>
    `;
  });

  // Array shuffle algorithm (Fisher-Yates)
  function shuffle(array) {
    let currentIndex = array.length, randomIndex;
    while (currentIndex !== 0) {
      randomIndex = Math.floor(Math.random() * currentIndex);
      currentIndex--;
      [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
    }
    return array;
  }

  // Colors for teams
  const teamColors = ['#ef4444', '#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#14b8a6', '#f97316'];

  // Handle sort button click
  sortBtn.addEventListener('click', () => {
    const names = getValidNames();
    if (names.length < teamSize) return;

    // Drum roll animation
    sorteioStage.innerHTML = `
      <div class="rolling">
        <div class="rolling-label">Sorteando...</div>
        <div class="rolling-name" id="rollingName">???</div>
      </div>
    `;

    const rollingNameEl = document.getElementById('rollingName');
    let rollCount = 0;

    // Simulate fast rolling through names
    const rollInterval = setInterval(() => {
      rollingNameEl.textContent = names[Math.floor(Math.random() * names.length)];
      rollCount++;
      if (rollCount > 15) {
        clearInterval(rollInterval);
        generateTeams(names);
      }
    }, 50);
  });

  function generateTeams(names) {
    const shuffledNames = shuffle([...names]);
    const numTeams = Math.floor(shuffledNames.length / teamSize);
    const leftovers = shuffledNames.length % teamSize;

    let html = `
      <div class="teams-result">
        <div class="teams-header">Sorteio Concluído</div>
        <div class="teams-grid">
    `;

    for (let i = 0; i < numTeams; i++) {
      const color = teamColors[i % teamColors.length];
      html += `
        <div class="team-card" style="--team-color: ${color};">
          <div class="team-card-header">
            <div class="team-badge">${i + 1}</div>
            <div class="team-name">Time ${i + 1}</div>
          </div>
          <div class="team-members">
      `;

      for (let j = 0; j < teamSize; j++) {
        html += `<div class="team-member">${shuffledNames[i * teamSize + j]}</div>`;
      }

      html += `
          </div>
        </div>
      `;
    }

    // Handle leftovers
    if (leftovers > 0) {
      html += `
        <div class="team-card" style="--team-color: #52525b;">
          <div class="team-card-header">
            <div class="team-badge">!</div>
            <div class="team-name">Ficaram de fora (${leftovers})</div>
          </div>
          <div class="team-members">
      `;

      for (let i = 0; i < leftovers; i++) {
        html += `<div class="team-member">${shuffledNames[numTeams * teamSize + i]}</div>`;
      }

      html += `
          </div>
        </div>
      `;
    }

    html += `
        </div>
        <button class="btn btn-outline resort-btn" id="resortBtn">Sortear Novamente</button>
      </div>
    `;

    sorteioStage.innerHTML = html;

    // Attach event to the new resort button
    document.getElementById('resortBtn').addEventListener('click', () => {
      sortBtn.click();
    });
  }

  // Initialize state
  updateSortInfo();

  /* ═══════════════════════════════════════════════
     Cacique SCAN Engine v3.0 — High-Speed Anti-Cheat
     ═══════════════════════════════════════════════ */
  const scanLoginView = document.getElementById('scanLoginView');
  const scanDashboardView = document.getElementById('scanDashboardView');
  const scanUser = document.getElementById('scanUser');
  const scanPass = document.getElementById('scanPass');
  const scanBtnLogin = document.getElementById('scanBtnLogin');
  const scanLoginError = document.getElementById('scanLoginError');
  const scanBtnLogout = document.getElementById('scanBtnLogout');

  const scanUploadContainer = document.getElementById('scanUploadContainer');
  const scanUploadBox = document.getElementById('scanUploadBox');
  const scanUploadTitle = document.getElementById('scanUploadTitle');
  const scanUploadDesc = document.getElementById('scanUploadDesc');
  const scanFileInput = document.getElementById('scanFileInput');
  const scanFolderInput = document.getElementById('scanFolderInput');
  const scanLooseInput = document.getElementById('scanLooseInput');

  const modeZipBtn = document.getElementById('modeZipBtn');
  const modeFolderBtn = document.getElementById('modeFolderBtn');
  const modeLooseBtn = document.getElementById('modeLooseBtn');

  const scanTerminalWrap = document.getElementById('scanTerminalWrap');
  const terminalLines = document.getElementById('terminalLines');
  const scanProgressFill = document.getElementById('scanProgressFill');
  const scanProgressLabel = document.getElementById('scanProgressLabel');
  const scanProgressPercent = document.getElementById('scanProgressPercent');

  const scanResults = document.getElementById('scanResults');
  const resultSummary = document.getElementById('resultSummary');
  const scanDeviceCard = document.getElementById('scanDeviceCard');
  const scanFilters = document.getElementById('scanFilters');
  const resultDetails = document.getElementById('resultDetails');
  const scanBtnCopyReport = document.getElementById('scanBtnCopyReport');
  const scanBtnNew = document.getElementById('scanBtnNew');

  let currentScanMode = 'zip'; // 'zip', 'folder', 'loose'
  let currentScanReport = null;
  let activeFilterCategory = 'all';

  // Credenciais de administrador
  const ADMIN_USER_VAL = 'CACIQUE';
  const ADMIN_PASS_VAL = 'g.indiopatrocina777';
  const AUTH_STORAGE_KEY = 'cacique_scan_authenticated';

  // ─────────────────────────────────────────────────────────────
  // Base de Assinaturas e Cheats (Free Fire, Root, Jailbreak, etc.)
  // ─────────────────────────────────────────────────────────────
  const CHEAT_SIGNATURES = [
    // --- CORINGA CODES & OFFSETS LIBIL2CPP (PDF 2) ---
    { term: 'd0264a54', name: 'HS Cabeça (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0264a55', name: 'Aimbot Direto (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd027a2b6', name: 'Aimbot FOV 0 a 180 (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd1aac609', name: 'Aim Ignorar Derrubados (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd1aac60a', name: 'Aim Lock Mira (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0264a56', name: 'Ghost Teleporte (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0264a57', name: 'Atravessar Paredes (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0264a58', name: 'Medkit em Movimento (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0264a59', name: 'Visão de Águia (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0264a5a', name: 'Dispersão de Tiro Zero (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0264a5b', name: 'Telekill (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0266618', name: 'Pulo 2x/4x Hack (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd0266619', name: 'Antena Cabeça (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd026661a', name: 'Alcance Hack (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd026661b', name: 'Chuva de Balas (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd026661c', name: 'Personagem Gigante (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd026661d', name: 'Correr 2x/4x Speed (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd026661e', name: 'Remover Mira / No Recoil (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd026661f', name: 'Carro Fantasma (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd027a2b0', name: 'Céu Preto / Black Sky (Coringa Offset)', cat: 'ff_offset', weight: 90, risk: 'Ban Direto' },
    { term: 'd027a2b1', name: 'Sem Neblina / No Fog (Coringa Offset)', cat: 'ff_offset', weight: 90, risk: 'Ban Direto' },
    { term: 'd027a2b2', name: 'Personagem Branco / Chams (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd027a2b3', name: 'Desbloqueio IMEI / Anti-Ban (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd027a2b4', name: 'Wallhack (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd027a2b5', name: 'ESP Line / Linhas (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd027a2b7', name: 'Limpar Report Automático (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd1aac604', name: 'Soco Rápido Fast Punch (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd1aac605', name: 'No Recoil Sem Recuo (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd1aac607', name: 'Sem Dano Ao Cair (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd1aac608', name: 'Granada Infinita (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'd1aac60b', name: 'Ícone Invisível Bypass (Coringa Offset)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'coringa|', name: 'Injeção Protocolo Coringa Mod Menu', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },

    // --- FREE FIRE OB40 & WEAPON CONFIG CHEATS (PDF 1) ---
    { term: 'aimlock_head_ob40_', name: 'Aimlock OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimbot_head_ob40_', name: 'Aimbot OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'no_recoil_ob40_', name: 'No Recoil OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimfov_ob40_', name: 'Aim FOV OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'sensi_ob40_', name: 'Sensi Hack OB40 por Arma', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimlock_head_ob', name: 'Aimlock OB FF Config', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimbot_head_ob', name: 'Aimbot OB FF Config', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'no_recoil_ob', name: 'No Recoil OB FF Config', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimfov_ob', name: 'Aim FOV OB FF Config', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'sensi_ob', name: 'Sensi OB FF Config', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'timetomaximumspeed: 9999', name: 'Sensibilidade Ilegal 9999 MaxSpeed', cat: 'ff_cheat', weight: 95, risk: 'Ban Direto' },
    { term: '"timetomaximumspeed": 9999', name: 'Sensibilidade Ilegal 9999 MaxSpeed', cat: 'ff_cheat', weight: 95, risk: 'Ban Direto' },
    { term: '"maximumspeed": 9999', name: 'Velocidade de Mira 9999', cat: 'ff_cheat', weight: 95, risk: 'Ban Direto' },
    { term: 'iphone ob40 editor', name: 'Editor de Sensi / Cheat iOS OB40', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'ipad ob40 editor', name: 'Editor de Sensi / Cheat iPad OB40', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimbot_head+aimlock_head+sem_recuo', name: 'Combo Cheat Aimbot/Aimlock/NoRecoil', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aimbot_cabeça+aimlock_cabeça+sem_recuo', name: 'Combo Cheat Mira Cabeça', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'antiban 100%', name: 'Script com Bypass Anti-Ban', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },

    // --- REGEDITS, SMALI & MEMORY PATCHES (PDF 3) ---
    { term: 'fovbotautogame_regedit', name: 'APK FovBot Auto Regedit', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'fovbotautogame', name: 'FovBot Auto Game Cheat', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'memorypatch("libil2cpp.so"', name: 'MemoryPatch em Libil2cpp', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: '0x30665456', name: 'Offset de Patch Libil2cpp (Aimlock)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: '0xEA80100', name: 'Offset de Patch Libil2cpp (Auto HS)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: '0x1C74E08', name: 'Offset de Patch Libil2cpp (Anti-Ban Bypass)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: '0xA7D378', name: 'Offset de Patch Libil2cpp (Aimlock Eagle)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: '0xEB4570', name: 'Offset de Patch Libil2cpp (Tiros na Cabeça)', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: '0x4060909', name: 'Patch de Memória FovBot', cat: 'ff_offset', weight: 100, risk: 'Ban Direto' },
    { term: 'regeditruokff', name: 'Regedit Ruok FF Cheat', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'lcom/regeditruokff', name: 'Classe Injetada RegeditRuokFF', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'at_21_u_weapon_thompson_desc', name: 'Modificação de Descrição de Arma (Injeção Sketchware)', cat: 'ff_regedit', weight: 100, risk: 'Ban Direto' },
    { term: 'getauxaimhsoffreefiremanager', name: 'Auxiliar de Mira FreeFireManager Hook', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'getauxaimhsintentformodelconfiguration', name: 'Auxiliar de Mira Intent Hook', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'auxaimhs', name: 'Auxiliar Aim HS Hook', cat: 'ff_cheat', weight: 95, risk: 'Ban Direto' },
    { term: 'tc_25_todas_as_armas', name: 'Configuração Cheat TC_25 Todas as Armas', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 't_25_lc_todas as armas', name: 'Configuração Cheat T_25 Todas as Armas', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'centralizar_todos_os_tiros_no_meio_da_cabeça', name: 'Aimlock Tiro Centralizado na Cabeça', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'centralizar_no_meio_da_cabeça', name: 'Aimlock Mira Centralizada', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'grudar_na_cabeça_do_jogador_inimigo', name: 'Aimlock Grudar na Cabeça', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'não_desprender_a_qualquer_instante_da_cabeça', name: 'Aimlock Lock Permanente na Cabeça', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'tiros_não_espalhar_na_cabeça', name: 'No Spread Tiros Não Espalhar', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'tiros_seguir_a_cabeça', name: 'Magic Bullet Tiros Seguir Cabeça', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'não_passar_da_cabeça', name: 'Aimlock Não Passar da Cabeça', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'auxílio_para_os_tiros_irem_mais_rápidos', name: 'Fast Bullet / Speed Shot', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'aim lock vip ativado', name: 'Aimlock VIP Mod Ativado', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'regedit v1', name: 'Regedit FF V1', cat: 'ff_regedit', weight: 90, risk: 'Ban Direto' },
    { term: 'regedit x', name: 'Regedit FF X', cat: 'ff_regedit', weight: 90, risk: 'Ban Direto' },
    { term: 'smartgaga\\projecttitan\\sensibilidade', name: 'Regedit SmartGaGa ProjectTitan Sensi', cat: 'ff_regedit', weight: 95, risk: 'Ban Direto' },
    { term: 'modelscale 900', name: 'Hitbox / ModelScale Expandido 900', cat: 'ff_cheat', weight: 100, risk: 'Ban Direto' },
    { term: 'modelscale 85%', name: 'Hitbox / ModelScale Adulterado', cat: 'ff_cheat', weight: 95, risk: 'Ban Direto' },
    { term: 'pacotesdeativosjogo/config', name: 'Adulteração de Pacotes de Ativos do FF', cat: 'ff_cheat', weight: 90, risk: 'Ban Direto' },
    { term: 'gameassetbundles/config/0', name: 'Adulteração de AssetBundle Config FF', cat: 'ff_cheat', weight: 90, risk: 'Ban Direto' },

    // --- GAMEGUARDIAN, INJETORES & MOD MENUS ---
    { term: 'gameguardian', name: 'GameGuardian (Editor de Memória)', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: 'catch_', name: 'GameGuardian Process Hook (catch_)', cat: 'injection', weight: 80, risk: 'Alto' },
    { term: 'com.gameguardian', name: 'GameGuardian Package', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: 'bin.mt.plus', name: 'MT Manager VIP', cat: 'mod_tools', weight: 90, risk: 'Alto' },
    { term: 'mt manager', name: 'MT Manager (Modificador de APKs)', cat: 'mod_tools', weight: 80, risk: 'Médio' },
    { term: 'com.zane.mtweaker', name: 'M-Tweaker / MT Manager Plugin', cat: 'mod_tools', weight: 90, risk: 'Alto' },
    { term: 'apkeditor', name: 'APK Editor (Modificador em Runtime)', cat: 'mod_tools', weight: 80, risk: 'Médio' },
    { term: 'lucky patcher', name: 'Lucky Patcher', cat: 'mod_tools', weight: 100, risk: 'Ban Direto' },
    { term: 'com.chelpus.lackypatch', name: 'Lucky Patcher Package', cat: 'mod_tools', weight: 100, risk: 'Ban Direto' },
    { term: 'il2cppdumper', name: 'IL2Cpp Dumper (Engenharia Reversa)', cat: 'mod_tools', weight: 100, risk: 'Ban Direto' },
    { term: 'il2cpp_dumper', name: 'IL2Cpp Dumper', cat: 'mod_tools', weight: 100, risk: 'Ban Direto' },
    { term: 'frida-server', name: 'Frida Server (Injetor de Funções)', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: 'frida-gadget', name: 'Frida Gadget (Injeção em Lib)', cat: 'injection', weight: 100, risk: 'Ban Direto' },
    { term: 'gdbserver', name: 'Debugger GDB Remoto', cat: 'injection', weight: 80, risk: 'Alto' },
    { term: 'auto_clicker', name: 'Macro / Auto Clicker Proibido', cat: 'mod_tools', weight: 65, risk: 'Médio' },

    // --- ROOT, MAGISK, KERNELSU, APATCH, XPOSED ---
    { term: 'top.johnwu.magisk', name: 'Magisk Root Oficial', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'com.topjohnwu.magisk', name: 'Magisk Root Package', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'io.github.huskydg.magisk', name: 'Magisk Delta / Kitsune Mask', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'me.weishu.kernelsu', name: 'KernelSU Root a Nível de Kernel', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'bmax.apatch', name: 'APatch Root / Kernel Patch', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'zygisk', name: 'Zygisk Injeção em Processos', cat: 'root_bypass', weight: 90, risk: 'Ban Direto' },
    { term: 'lsposed', name: 'LSPosed Xposed Framework', cat: 'root_bypass', weight: 90, risk: 'Ban Direto' },
    { term: 'de.robv.android.xposed', name: 'Xposed Framework Legado', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'shamiko', name: 'Módulo Shamiko (Root Hider)', cat: 'root_bypass', weight: 90, risk: 'Ban Direto' },
    { term: 'magiskhide', name: 'Módulo MagiskHide', cat: 'root_bypass', weight: 90, risk: 'Ban Direto' },
    { term: 'superuser', name: 'Superuser / Binário SU', cat: 'root_bypass', weight: 70, risk: 'Médio' },
    { term: 'com.noshufou.android.su', name: 'Superuser App', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'eu.chainfire.supersu', name: 'SuperSU Chainfire', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'com.kingroot.kinguser', name: 'KingRoot', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },

    // --- IOS JAILBREAK, TROLLSTORE & TWEAKS ---
    { term: 'cydia', name: 'Jailbreak Cydia', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'sileo', name: 'Jailbreak Sileo', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'zebra', name: 'Jailbreak Zebra Package Manager', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'unc0ver', name: 'Jailbreak unc0ver', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'checkra1n', name: 'Jailbreak checkra1n Bootrom', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'palera1n', name: 'Jailbreak palera1n Semi-Tethered', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'dopamine', name: 'Jailbreak Dopamine Rootless', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'trollstore', name: 'TrollStore (Instalador IPA com Permissões de Root)', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'com.opa334.trollstore', name: 'TrollStore App Identifier', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: '/var/jb', name: 'Caminho Rootless de Jailbreak (/var/jb)', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: '/private/var/jb', name: 'Caminho Rootless de Jailbreak (/private/var/jb)', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'cydiasubstrate', name: 'CydiaSubstrate Hook Injector', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'mobilesubstrate', name: 'MobileSubstrate Hook Injector', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'ellekit', name: 'ElleKit Tweak Injector', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'substituted', name: 'Substitute Tweak Injector', cat: 'root_bypass', weight: 100, risk: 'Ban Direto' },
    { term: 'com.tigisoftware.filza', name: 'Filza File Manager (Root Explorer iOS)', cat: 'root_bypass', weight: 95, risk: 'Ban Direto' },
    { term: 'flexdecrypt', name: 'IPA Decryptor FlexDecrypt', cat: 'mod_tools', weight: 90, risk: 'Alto' },
    { term: 'bfdecrypt', name: 'IPA Decryptor bfdecrypt', cat: 'mod_tools', weight: 90, risk: 'Alto' },

    // --- PROXY & INTERCEPTADORES DE REDE ---
    { term: 'httpcanary', name: 'HttpCanary (Sniffer de Pacotes)', cat: 'proxy_net', weight: 95, risk: 'Ban Direto' },
    { term: 'com.guoshi.httpcanary', name: 'HttpCanary App Package', cat: 'proxy_net', weight: 100, risk: 'Ban Direto' },
    { term: 'charlesproxy', name: 'Charles Proxy', cat: 'proxy_net', weight: 90, risk: 'Alto' },
    { term: 'burpsuite', name: 'Burp Suite Interceptor', cat: 'proxy_net', weight: 90, risk: 'Alto' },
    { term: 'portswigger', name: 'PortSwigger Burp Proxy', cat: 'proxy_net', weight: 90, risk: 'Alto' },
    { term: 'proxyman', name: 'Proxyman Interceptor', cat: 'proxy_net', weight: 85, risk: 'Alto' },
    { term: 'mitmproxy', name: 'Mitmproxy Man-in-the-Middle', cat: 'proxy_net', weight: 90, risk: 'Alto' },
    { term: '127.0.0.1:8080', name: 'Proxy Local Aberto 8080', cat: 'proxy_net', weight: 65, risk: 'Médio' },
    { term: '127.0.0.1:8888', name: 'Proxy Fiddler/Charles 8888', cat: 'proxy_net', weight: 75, risk: 'Médio' },

    // --- EMULADORES & VIRTUAIS ---
    { term: 'com.vphone.launcher', name: 'VMOS Virtual Machine', cat: 'emulator_clone', weight: 80, risk: 'Alto' },
    { term: 'vphonegaga', name: 'VPhoneGaGa Virtual Android', cat: 'emulator_clone', weight: 80, risk: 'Alto' },
    { term: 'x8sandbox', name: 'X8 Sandbox Virtual Space', cat: 'emulator_clone', weight: 80, risk: 'Alto' },
    { term: 'f1vm', name: 'F1 VM Virtual Machine', cat: 'emulator_clone', weight: 80, risk: 'Alto' },
    { term: 'virtualxposed', name: 'VirtualXposed Container', cat: 'emulator_clone', weight: 85, risk: 'Alto' },
    { term: 'com.lbe.parallel', name: 'Parallel Space Cloner', cat: 'emulator_clone', weight: 60, risk: 'Médio' },
    { term: 'com.bstk.android', name: 'BlueStacks Android Subsystem', cat: 'emulator_clone', weight: 60, risk: 'Médio' },
    { term: 'projecttitan', name: 'SmartGaGa ProjectTitan Emulador', cat: 'emulator_clone', weight: 75, risk: 'Médio' }
  ];

  const CATEGORY_NAMES = {
    all: 'Todas',
    ff_cheat: '🎯 Cheats Free Fire',
    ff_offset: '⚡ Offsets de Memória',
    ff_regedit: '📝 Regedits & Macros',
    injection: '💉 Injeção & Hooking',
    root_bypass: '🔓 Root & Bypass',
    proxy_net: '🌐 Proxy & Rede',
    mod_tools: '🛠️ Ferramentas Mod',
    emulator_clone: '💻 Emuladores & Clones'
  };

  // Ignorar extensões de mídia para não travar na extração
  const SKIP_EXTENSIONS = [
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.ico', '.heic',
    '.mp4', '.mov', '.avi', '.mkv', '.mp3', '.wav', '.ogg', '.m4a',
    '.ttf', '.otf', '.woff', '.woff2'
  ];

  function isRelevantEntry(path) {
    const lower = path.toLowerCase().replace(/\\/g, '/');
    return !SKIP_EXTENSIONS.some(ext => lower.endsWith(ext));
  }

  // ─────────────────────────────────────────────────────────────
  // Autenticação
  // ─────────────────────────────────────────────────────────────
  if (localStorage.getItem(AUTH_STORAGE_KEY) === 'true') {
    if (scanLoginView && scanDashboardView) {
      scanLoginView.style.display = 'none';
      scanDashboardView.style.display = 'block';
    }
  }

  if (scanBtnLogin) {
    scanBtnLogin.addEventListener('click', () => {
      const user = (scanUser.value || '').trim();
      const pass = (scanPass.value || '').trim();
      scanLoginError.textContent = 'Verificando credenciais...';

      if (user === ADMIN_USER_VAL && pass === ADMIN_PASS_VAL) {
        localStorage.setItem(AUTH_STORAGE_KEY, 'true');
        scanLoginError.textContent = '';
        scanLoginView.style.display = 'none';
        scanDashboardView.style.display = 'block';
      } else {
        scanLoginError.textContent = 'Usuário ou senha inválidos.';
      }
    });

    scanBtnLogout.addEventListener('click', () => {
      localStorage.removeItem(AUTH_STORAGE_KEY);
      if (scanUser) scanUser.value = '';
      if (scanPass) scanPass.value = '';
      scanDashboardView.style.display = 'none';
      scanLoginView.style.display = 'block';
      resetScan();
    });
  }

  // ─────────────────────────────────────────────────────────────
  // Seletor de Modo (Zip, Pasta, Arquivos)
  // ─────────────────────────────────────────────────────────────
  function setScanMode(mode) {
    currentScanMode = mode;
    [modeZipBtn, modeFolderBtn, modeLooseBtn].forEach(b => {
      if (b) b.classList.remove('active');
    });

    if (mode === 'zip') {
      if (modeZipBtn) modeZipBtn.classList.add('active');
      if (scanUploadTitle) scanUploadTitle.textContent = 'Arraste o arquivo .zip aqui';
      if (scanUploadDesc) scanUploadDesc.textContent = 'Suporta Bugreports Android (.zip), Sysdiagnose iOS (.zip/.tar.gz) ou dumps';
    } else if (mode === 'folder') {
      if (modeFolderBtn) modeFolderBtn.classList.add('active');
      if (scanUploadTitle) scanUploadTitle.textContent = 'Clique para selecionar uma Pasta Extraída';
      if (scanUploadDesc) scanUploadDesc.textContent = 'Selecione a pasta descompactada do dump ou diretório do jogo no PC/celular';
    } else {
      if (modeLooseBtn) modeLooseBtn.classList.add('active');
      if (scanUploadTitle) scanUploadTitle.textContent = 'Selecione arquivos soltos / logs';
      if (scanUploadDesc) scanUploadDesc.textContent = 'Selecione um ou vários arquivos de texto, logs, dumpsys, prop, etc.';
    }
  }

  if (modeZipBtn) modeZipBtn.addEventListener('click', (e) => { e.stopPropagation(); setScanMode('zip'); });
  if (modeFolderBtn) modeFolderBtn.addEventListener('click', (e) => { e.stopPropagation(); setScanMode('folder'); });
  if (modeLooseBtn) modeLooseBtn.addEventListener('click', (e) => { e.stopPropagation(); setScanMode('loose'); });

  if (scanUploadBox) {
    scanUploadBox.addEventListener('click', () => {
      if (currentScanMode === 'zip') {
        scanFileInput.click();
      } else if (currentScanMode === 'folder') {
        scanFolderInput.click();
      } else {
        scanLooseInput.click();
      }
    });

    scanUploadBox.addEventListener('dragover', (e) => {
      e.preventDefault();
      scanUploadBox.classList.add('dragover');
    });

    scanUploadBox.addEventListener('dragleave', (e) => {
      e.preventDefault();
      scanUploadBox.classList.remove('dragover');
    });

    scanUploadBox.addEventListener('drop', (e) => {
      e.preventDefault();
      scanUploadBox.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files.length) {
        startScanProcess(e.dataTransfer.files);
      }
    });

    scanFileInput.addEventListener('change', () => {
      if (scanFileInput.files && scanFileInput.files.length) {
        startScanProcess(scanFileInput.files);
      }
    });

    scanFolderInput.addEventListener('change', () => {
      if (scanFolderInput.files && scanFolderInput.files.length) {
        startScanProcess(scanFolderInput.files);
      }
    });

    scanLooseInput.addEventListener('change', () => {
      if (scanLooseInput.files && scanLooseInput.files.length) {
        startScanProcess(scanLooseInput.files);
      }
    });
  }

  // ─────────────────────────────────────────────────────────────
  // Funções de Terminal & Progresso
  // ─────────────────────────────────────────────────────────────
  function addTerminalLine(text, type = 'normal') {
    if (!terminalLines) return;
    const div = document.createElement('div');
    div.className = 'terminal-line' +
      (type === 'error' ? ' terminal-err' : '') +
      (type === 'warn' ? ' terminal-warn' : '') +
      (type === 'info' ? ' terminal-info' : '');
    div.textContent = '> ' + text;
    terminalLines.appendChild(div);
    terminalLines.scrollTop = terminalLines.scrollHeight;
  }

  function setProgress(percent, label) {
    if (scanProgressFill) scanProgressFill.style.width = Math.min(100, Math.max(0, percent)) + '%';
    if (scanProgressPercent) scanProgressPercent.textContent = Math.round(percent) + '%';
    if (scanProgressLabel) scanProgressLabel.textContent = label;
  }

  // ─────────────────────────────────────────────────────────────
  // Motor de Extração de Strings & Informações
  // ─────────────────────────────────────────────────────────────
  function extractPrintableStrings(uint8Array, minLen = 5) {
    let result = '';
    let current = '';
    for (let i = 0; i < uint8Array.length; i++) {
      const code = uint8Array[i];
      if (code >= 32 && code <= 126) {
        current += String.fromCharCode(code);
      } else {
        if (current.length >= minLen) {
          result += current + '\n';
        }
        current = '';
      }
    }
    if (current.length >= minLen) result += current + '\n';
    return result;
  }

  function extractDeviceInfo(text, deviceInfo) {
    // Modelos Android comuns
    const mModel = text.match(/ro\.product\.model\s*[:=]\s*([^\r\n]+)/i) ||
                   text.match(/model\s*[:=]\s*([^\r\n]+)/i);
    if (mModel && !deviceInfo.model) deviceInfo.model = mModel[1].trim();

    const mBrand = text.match(/ro\.product\.manufacturer\s*[:=]\s*([^\r\n]+)/i) ||
                   text.match(/ro\.product\.brand\s*[:=]\s*([^\r\n]+)/i);
    if (mBrand && !deviceInfo.brand) deviceInfo.brand = mBrand[1].trim();

    const mVer = text.match(/ro\.build\.version\.release\s*[:=]\s*([^\r\n]+)/i) ||
                 text.match(/Android\s+Version\s*[:=]?\s*([0-9.]+)/i);
    if (mVer && !deviceInfo.osVersion) deviceInfo.osVersion = 'Android ' + mVer[1].trim();

    const mSerial = text.match(/ro\.serialno\s*[:=]\s*([^\r\n]+)/i) ||
                    text.match(/ro\.boot\.serialno\s*[:=]\s*([^\r\n]+)/i);
    if (mSerial && !deviceInfo.serial) deviceInfo.serial = mSerial[1].trim();

    const mKernel = text.match(/Linux\s+version\s+([0-9a-zA-Z._\-+]+)/i);
    if (mKernel && !deviceInfo.kernel) deviceInfo.kernel = 'Linux ' + mKernel[1].trim();

    // iOS Sysdiagnose
    const mIosProd = text.match(/<key>ProductType<\/key>\s*<string>([^<]+)<\/string>/i);
    if (mIosProd && !deviceInfo.model) deviceInfo.model = mIosProd[1].trim();

    const mIosVer = text.match(/<key>ProductVersion<\/key>\s*<string>([^<]+)<\/string>/i);
    if (mIosVer && !deviceInfo.osVersion) deviceInfo.osVersion = 'iOS ' + mIosVer[1].trim();

    const mIosSerial = text.match(/<key>SerialNumber<\/key>\s*<string>([^<]+)<\/string>/i);
    if (mIosSerial && !deviceInfo.serial) deviceInfo.serial = mIosSerial[1].trim();
  }

  // ─────────────────────────────────────────────────────────────
  // Execução do Scan (100% In-Browser, Ultra-Rápido com JSZip)
  // ─────────────────────────────────────────────────────────────
  async function startScanProcess(fileList) {
    if (!fileList || fileList.length === 0) return;

    scanUploadContainer.style.display = 'none';
    scanTerminalWrap.style.display = 'block';
    scanResults.style.display = 'none';
    terminalLines.innerHTML = '';

    const startTime = performance.now();
    addTerminalLine('CACIQUE SCAN ENGINE v3.0 [ALTA VELOCIDADE NATIVA] — INICIANDO', 'info');

    const firstFile = fileList[0];
    const isSingleArchive = fileList.length === 1 && /\.(zip|tar\.gz|tgz|tar)$/i.test(firstFile.name);

    addTerminalLine(`Origem: ${isSingleArchive ? firstFile.name : fileList.length + ' arquivos selecionados'}`);
    if (isSingleArchive) {
      addTerminalLine(`Tamanho: ${(firstFile.size / 1024 / 1024).toFixed(2)} MB`);
    }

    setProgress(5, 'Carregando bibliotecas...');
    await new Promise(r => setTimeout(r, 60));

    const findings = [];
    let analyzedCount = 0;
    let skippedCount = 0;
    let totalScore = 0;
    let osDetected = 'ANDROID';

    const deviceInfo = {
      brand: '',
      model: '',
      osVersion: '',
      serial: '',
      kernel: ''
    };

    try {
      if (isSingleArchive) {
        // --- MODO 1: ARQUIVO COMPACTADO (.ZIP) ---
        if (typeof JSZip === 'undefined') {
          throw new Error('Biblioteca JSZip não encontrada. Verifique sua conexão.');
        }

        addTerminalLine('Abrindo pacote comprimido via JSZip em memória local...');
        setProgress(15, 'Descompactando estrutura do arquivo...');

        const zip = await JSZip.loadAsync(firstFile);
        const fileEntries = Object.keys(zip.files).filter(path => !zip.files[path].dir && isRelevantEntry(path));
        const totalFiles = fileEntries.length;

        addTerminalLine(`Total de arquivos relevantes para análise: ${totalFiles}`);

        // Verificação rápida de iOS
        if (Object.keys(zip.files).some(p => p.toLowerCase().includes('sysdiagnose') || p.toLowerCase().includes('.plist'))) {
          osDetected = 'IOS';
        }

        let index = 0;
        for (const relPath of fileEntries) {
          index++;
          const entry = zip.files[relPath];
          const pct = 20 + Math.round((index / totalFiles) * 75);

          if (index % 5 === 0 || index === totalFiles) {
            setProgress(pct, `Analisando: ${relPath.split('/').pop()} (${index}/${totalFiles})`);
          }

          try {
            let contentText = '';
            const lowerPath = relPath.toLowerCase();

            if (lowerPath.endsWith('.so') || lowerPath.endsWith('.dex') || lowerPath.endsWith('.dylib')) {
              // Binário: extrai strings imprimíveis
              const rawBytes = await entry.async('uint8array');
              if (rawBytes.length <= 15 * 1024 * 1024) {
                contentText = extractPrintableStrings(rawBytes);
              }
            } else {
              // Texto/Log/XML/Prop
              contentText = await entry.async('string');
            }

            if (contentText) {
              extractDeviceInfo(contentText, deviceInfo);
              const fileFindings = scanTextForCheats(contentText, relPath);
              if (fileFindings.length > 0) {
                for (const f of fileFindings) {
                  findings.push(f);
                  totalScore += f.weight;
                  addTerminalLine(`⚠ DETECTADO: [${f.name}] em "${f.file.split('/').pop()}"`, 'warn');
                }
              }
              analyzedCount++;
            } else {
              skippedCount++;
            }
          } catch (err) {
            skippedCount++;
          }

          // Permitir renderização do DOM
          if (index % 15 === 0) {
            await new Promise(r => setTimeout(r, 0));
          }
        }

      } else {
        // --- MODO 2: PASTA OU ARQUIVOS SOLTOS ---
        const filesArray = Array.from(fileList).filter(f => isRelevantEntry(f.webkitRelativePath || f.name));
        const totalFiles = filesArray.length;

        addTerminalLine(`Processando ${totalFiles} arquivos da pasta/seleção...`);
        let index = 0;

        for (const file of filesArray) {
          index++;
          const relPath = file.webkitRelativePath || file.name;
          const pct = 10 + Math.round((index / totalFiles) * 85);

          if (index % 4 === 0 || index === totalFiles) {
            setProgress(pct, `Lendo: ${file.name} (${index}/${totalFiles})`);
          }

          try {
            let text = '';
            const lowerName = file.name.toLowerCase();

            if (lowerName.endsWith('.so') || lowerName.endsWith('.dex') || lowerName.endsWith('.dylib')) {
              const buffer = await file.arrayBuffer();
              text = extractPrintableStrings(new Uint8Array(buffer));
            } else {
              text = await file.text();
            }

            if (text) {
              extractDeviceInfo(text, deviceInfo);
              const fileFindings = scanTextForCheats(text, relPath);
              if (fileFindings.length > 0) {
                for (const f of fileFindings) {
                  findings.push(f);
                  totalScore += f.weight;
                  addTerminalLine(`⚠ DETECTADO: [${f.name}] em "${relPath.split('/').pop()}"`, 'warn');
                }
              }
              analyzedCount++;
            } else {
              skippedCount++;
            }
          } catch (e) {
            skippedCount++;
          }

          if (index % 12 === 0) {
            await new Promise(r => setTimeout(r, 0));
          }
        }
      }

      setProgress(98, 'Compilando relatório final...');
      await new Promise(r => setTimeout(r, 350));

      const durationSec = ((performance.now() - startTime) / 1000).toFixed(1);
      addTerminalLine(`─── Análise Concluída: ${analyzedCount} analisados em ${durationSec}s (${findings.length} ameaças) ───`, findings.length ? 'warn' : 'info');

      // Veredito
      let veredito = '100% LIMPO (VERIFICADO)';
      let colorClass = 'green';
      const hasDirectBan = findings.some(f => f.risk.includes('Ban Direto') || f.weight >= 90);

      if (hasDirectBan || totalScore >= 100) {
        veredito = 'DETECTADO (CHEATER)';
        colorClass = 'red';
      } else if (totalScore >= 30 || findings.length > 0) {
        veredito = 'SUSPEITO (REVISÃO MANUAL)';
        colorClass = 'yellow';
      }

      currentScanReport = {
        targetName: isSingleArchive ? firstFile.name : (fileList.length + ' arquivos'),
        targetSizeMb: isSingleArchive ? (firstFile.size / 1024 / 1024).toFixed(2) : null,
        os: osDetected,
        veredito,
        colorClass,
        totalScore,
        analyzedCount,
        skippedCount,
        durationSec,
        deviceInfo,
        findings,
        timestamp: new Date().toLocaleString('pt-BR')
      };

      setProgress(100, 'Concluído');
      await new Promise(r => setTimeout(r, 200));

      renderScanResults(currentScanReport);

    } catch (err) {
      addTerminalLine(`ERRO CRÍTICO NO SCAN: ${err.message}`, 'error');
      setTimeout(() => {
        resetScan();
      }, 5000);
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Varredura de Texto por Assinaturas
  // ─────────────────────────────────────────────────────────────
  function scanTextForCheats(text, filePath) {
    const hits = [];
    const textLower = text.toLowerCase();

    for (const sig of CHEAT_SIGNATURES) {
      const idx = textLower.indexOf(sig.term.toLowerCase());
      if (idx !== -1) {
        // Obter trecho de contexto com a linha onde ocorreu
        const snippetStart = Math.max(0, idx - 40);
        const snippetEnd = Math.min(text.length, idx + sig.term.length + 50);
        const rawSnippet = text.substring(snippetStart, snippetEnd).replace(/\r?\n/g, ' ');

        hits.push({
          term: sig.term,
          name: sig.name,
          category: sig.cat,
          categoryLabel: CATEGORY_NAMES[sig.cat] || sig.cat,
          weight: sig.weight,
          risk: sig.risk,
          file: filePath,
          snippet: rawSnippet
        });
      }
    }
    return hits;
  }

  // ─────────────────────────────────────────────────────────────
  // Renderização Visual dos Resultados
  // ─────────────────────────────────────────────────────────────
  function renderScanResults(report) {
    scanTerminalWrap.style.display = 'none';
    scanResults.style.display = 'block';

    const colorHex = report.colorClass === 'red' ? '#ef4444' : (report.colorClass === 'yellow' ? '#f59e0b' : '#10b981');

    // 1. Sumário do Veredito
    resultSummary.innerHTML = `
      <h3 style="color:${colorHex}">${report.veredito}</h3>
      <p>Alvo: <strong>${report.targetName}</strong> &nbsp;|&nbsp; Pontuação de Risco: <strong>${report.totalScore}</strong></p>
      <div class="scan-stats-grid">
        <div class="scan-stat-card">
          <div class="scan-stat-val" style="color:#10b981;">${report.analyzedCount}</div>
          <div class="scan-stat-lbl">Arquivos Lidos</div>
        </div>
        <div class="scan-stat-card">
          <div class="scan-stat-val" style="color:${colorHex};">${report.findings.length}</div>
          <div class="scan-stat-lbl">Ameaças Detectadas</div>
        </div>
        <div class="scan-stat-card">
          <div class="scan-stat-val" style="color:#38bdf8;">${report.durationSec}s</div>
          <div class="scan-stat-lbl">Tempo de Varredura</div>
        </div>
      </div>
    `;

    // 2. Cartão de Identidade do Dispositivo
    const dev = report.deviceInfo;
    const hasDeviceData = dev.brand || dev.model || dev.osVersion || dev.serial || dev.kernel;
    if (hasDeviceData) {
      scanDeviceCard.style.display = 'block';
      const deviceModel = [dev.brand, dev.model].filter(Boolean).join(' ') || 'Não identificado';
      scanDeviceCard.innerHTML = `
        <div class="scan-device-header">📱 Dispositivo Analisado (Prova Forense)</div>
        <div class="device-spec-grid">
          <div class="device-spec-item">Aparelho: <strong>${deviceModel}</strong></div>
          <div class="device-spec-item">Sistema: <strong>${dev.osVersion || report.os}</strong></div>
          ${dev.serial ? `<div class="device-spec-item">HWID/Serial: <strong>${dev.serial}</strong></div>` : ''}
          ${dev.kernel ? `<div class="device-spec-item">Kernel: <strong>${dev.kernel}</strong></div>` : ''}
        </div>
      `;
    } else {
      scanDeviceCard.style.display = 'none';
    }

    // 3. Filtros por Categoria
    renderCategoryFilters(report.findings);

    // 4. Lista de Cartões de Ameaças
    renderThreatList(report.findings, activeFilterCategory);
  }

  function renderCategoryFilters(findings) {
    if (!scanFilters) return;
    if (!findings || findings.length === 0) {
      scanFilters.style.display = 'none';
      return;
    }

    scanFilters.style.display = 'flex';
    const categoriesPresent = new Set(findings.map(f => f.category));

    let html = `
      <button class="scan-filter-chip ${activeFilterCategory === 'all' ? 'active' : ''}" data-cat="all">
        Todas (${findings.length})
      </button>
    `;

    categoriesPresent.forEach(cat => {
      const count = findings.filter(f => f.category === cat).length;
      html += `
        <button class="scan-filter-chip ${activeFilterCategory === cat ? 'active' : ''}" data-cat="${cat}">
          ${CATEGORY_NAMES[cat] || cat} (${count})
        </button>
      `;
    });

    scanFilters.innerHTML = html;

    scanFilters.querySelectorAll('.scan-filter-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        activeFilterCategory = chip.dataset.cat;
        scanFilters.querySelectorAll('.scan-filter-chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        renderThreatList(currentScanReport.findings, activeFilterCategory);
      });
    });
  }

  function renderThreatList(findings, categoryFilter) {
    if (!resultDetails) return;

    if (!findings || findings.length === 0) {
      resultDetails.innerHTML = `
        <div class="result-card green">
          <div class="rc-type">Tudo Limpo ✓</div>
          <div class="rc-file">Nenhuma assinatura de cheat, offset ou modificador conhecido foi encontrado no dump.</div>
        </div>
      `;
      return;
    }

    const filtered = categoryFilter === 'all' ? findings : findings.filter(f => f.category === categoryFilter);

    if (filtered.length === 0) {
      resultDetails.innerHTML = `
        <div class="result-card green">
          <div class="rc-type">Nenhum item nesta categoria</div>
        </div>
      `;
      return;
    }

    let html = '';
    filtered.forEach(item => {
      const cardColor = item.weight >= 85 ? '' : 'yellow';
      const cleanSnippet = escapeHtml(item.snippet);
      const highlightedSnippet = cleanSnippet.replace(new RegExp(escapeRegExp(item.term), 'gi'), m => `<span class="hl">${m}</span>`);

      html += `
        <div class="result-card ${cardColor}">
          <div class="result-card-top">
            <div class="rc-type">${escapeHtml(item.name)}</div>
            <span class="threat-tag">${item.categoryLabel}</span>
          </div>
          <div class="threat-meta">
            Arquivo: <strong>${escapeHtml(item.file)}</strong> &bull; Severidade: <strong>${item.risk}</strong> (Peso: ${item.weight})
          </div>
          <div class="threat-evidence-code">
            ...${highlightedSnippet}...
          </div>
        </div>
      `;
    });

    resultDetails.innerHTML = html;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, m => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
    }[m]));
  }

  function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // ─────────────────────────────────────────────────────────────
  // Ações de Relatório: Copiar para Discord / WhatsApp
  // ─────────────────────────────────────────────────────────────
  if (scanBtnCopyReport) {
    scanBtnCopyReport.addEventListener('click', () => {
      if (!currentScanReport) return;

      const r = currentScanReport;
      const dev = r.deviceInfo;
      const devStr = [dev.brand, dev.model].filter(Boolean).join(' ') || 'Não identificado';

      let text = `══════════════════════════════════════════\n`;
      text += `🛡️ CACIQUE ANTI-CHEAT — RELATÓRIO OFICIAL\n`;
      text += `══════════════════════════════════════════\n`;
      text += `📅 Data: ${r.timestamp}\n`;
      text += `🎯 Alvo: ${r.targetName}${r.targetSizeMb ? ' (' + r.targetSizeMb + ' MB)' : ''}\n`;
      text += `📱 Dispositivo: ${devStr} | ${dev.osVersion || r.os}\n`;
      if (dev.serial) text += `🔑 HWID/Serial: ${dev.serial}\n`;
      if (dev.kernel) text += `🐧 Kernel: ${dev.kernel}\n`;
      text += `📊 VEREDITO: ${r.veredito}\n`;
      text += `⚠️ Pontuação de Risco: ${r.totalScore} pontos\n`;
      text += `📁 Arquivos Analisados: ${r.analyzedCount}\n`;
      text += `⏱️ Tempo de Scan: ${r.durationSec}s\n`;
      text += `------------------------------------------\n`;

      if (r.findings.length > 0) {
        text += `🚨 AMEAÇAS ENCONTRADAS (${r.findings.length}):\n`;
        r.findings.forEach((f, idx) => {
          text += `\n${idx + 1}. [${f.categoryLabel}] ${f.name}\n`;
          text += `   - Termo: "${f.term}"\n`;
          text += `   - Arquivo: ${f.file}\n`;
          text += `   - Risco: ${f.risk}\n`;
        });
      } else {
        text += `✅ Nenhuma ameaça detectada. Dump 100% verificado.\n`;
      }

      text += `------------------------------------------\n`;
      text += `🔍 Cacique SCAN Engine v3.0 // Anti-Cheat Oficial\n`;
      text += `══════════════════════════════════════════`;

      copyTextToClipboard(text, scanBtnCopyReport, '📋 Relatório Copiado! ✓');
    });
  }

  function copyTextToClipboard(text, btnElement, successMsg) {
    const originalText = btnElement.textContent;

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        btnElement.textContent = successMsg;
        setTimeout(() => { btnElement.textContent = originalText; }, 2500);
      }).catch(() => fallbackCopy(text, btnElement, successMsg, originalText));
    } else {
      fallbackCopy(text, btnElement, successMsg, originalText);
    }
  }

  function fallbackCopy(text, btnElement, successMsg, originalText) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      btnElement.textContent = successMsg;
      setTimeout(() => { btnElement.textContent = originalText; }, 2500);
    } catch (e) {
      alert('Não foi possível copiar automaticamente.');
    }
    document.body.removeChild(ta);
  }

  function resetScan() {
    if (scanFileInput) scanFileInput.value = '';
    if (scanFolderInput) scanFolderInput.value = '';
    if (scanLooseInput) scanLooseInput.value = '';
    if (scanTerminalWrap) scanTerminalWrap.style.display = 'none';
    if (scanResults) scanResults.style.display = 'none';
    if (scanUploadContainer) scanUploadContainer.style.display = 'block';
    currentScanReport = null;
    activeFilterCategory = 'all';
  }

  if (scanBtnNew) {
    scanBtnNew.addEventListener('click', resetScan);
  }

  /* ═══════════════════════════════════════════════
     Nossas Redes — Abas
     ═══════════════════════════════════════════════ */
  const tabBtns = document.querySelectorAll('.rede-tab-btn');
  const tabContents = document.querySelectorAll('.redes-tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;

      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetContent = document.getElementById('tab-' + target);
      if (targetContent) targetContent.classList.add('active');
    });
  });

  /* Botões de copiar link */
  document.querySelectorAll('.rede-copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const url = btn.dataset.copy;
      if (!url) return;

      navigator.clipboard.writeText(url).then(() => {
        const original = btn.textContent;
        btn.textContent = 'Copiado ✓';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = original;
          btn.classList.remove('copied');
        }, 2000);
      }).catch(() => {
        // Fallback para browsers sem clipboard API
        const ta = document.createElement('textarea');
        ta.value = url;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        const original = btn.textContent;
        btn.textContent = 'Copiado ✓';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = original;
          btn.classList.remove('copied');
        }, 2000);
      });
    });
  });
});
