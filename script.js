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
     Cacique SCAN Logic
     ═══════════════════════════════════════════════ */
  const scanLoginView = document.getElementById('scanLoginView');
  const scanDashboardView = document.getElementById('scanDashboardView');
  const scanUser = document.getElementById('scanUser');
  const scanPass = document.getElementById('scanPass');
  const scanBtnLogin = document.getElementById('scanBtnLogin');
  const scanLoginError = document.getElementById('scanLoginError');
  const scanBtnLogout = document.getElementById('scanBtnLogout');
  
  const scanUploadBox = document.getElementById('scanUploadBox');
  const scanFileInput = document.getElementById('scanFileInput');
  const scanTerminal = document.getElementById('scanTerminal');
  const terminalLines = document.getElementById('terminalLines');
  const scanResults = document.getElementById('scanResults');
  const resultSummary = document.getElementById('resultSummary');
  const resultDetails = document.getElementById('resultDetails');
  const scanBtnNew = document.getElementById('scanBtnNew');

  let adminCredentials = null;
  const API_URL = 'http://localhost:5000'; // Change to deployed URL later

  if(scanBtnLogin) {
    scanBtnLogin.addEventListener('click', async () => {
      const user = scanUser.value;
      const pass = scanPass.value;
      scanLoginError.textContent = 'Verificando credenciais...';
      
      try {
        const res = await fetch(`${API_URL}/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ user, pass })
        });
        const data = await res.json();
        
        if (res.ok && data.status === 'success') {
          adminCredentials = { user, pass };
          scanLoginError.textContent = '';
          scanLoginView.style.display = 'none';
          scanDashboardView.style.display = 'block';
        } else {
          scanLoginError.textContent = data.message || 'Credenciais inválidas.';
        }
      } catch (e) {
        scanLoginError.textContent = 'Erro ao conectar com o servidor.';
      }
    });

    scanBtnLogout.addEventListener('click', () => {
      adminCredentials = null;
      scanUser.value = '';
      scanPass.value = '';
      scanDashboardView.style.display = 'none';
      scanLoginView.style.display = 'block';
      resetScan();
    });

    scanUploadBox.addEventListener('click', () => scanFileInput.click());
    
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
      if (e.dataTransfer.files.length) {
        scanFileInput.files = e.dataTransfer.files;
        handleFileSelected(scanFileInput.files[0]);
      }
    });

    scanFileInput.addEventListener('change', () => {
      if (scanFileInput.files.length) {
        handleFileSelected(scanFileInput.files[0]);
      }
    });

    async function handleFileSelected(file) {
      if (!adminCredentials) return;
      
      scanUploadBox.style.display = 'none';
      scanTerminal.style.display = 'block';
      terminalLines.innerHTML = '';
      
      const fakeLogs = [
        "INICIANDO CACIQUE SCAN ENGINE v1.0",
        `Alvo: ${file.name}`,
        "Tamanho: " + (file.size / 1024 / 1024).toFixed(2) + " MB",
        "Descompactando dump do sistema na memória...",
        "Extraindo system_logs, top.txt, CrashReporter...",
        "Extraindo bugreport, logcat, DUMPSYS...",
        "Procurando assinaturas nativas de root/jailbreak...",
        "Checando overlays de tela (Wallhack/Menus)...",
        "Varrendo logs de memória em busca de injeção (ptrace, dylib)...",
        "Analisando requisições suspeitas de rede..."
      ];
      
      // Simulate terminal fast output
      for (let i = 0; i < fakeLogs.length; i++) {
        await new Promise(r => setTimeout(r, 400 + Math.random() * 300));
        const div = document.createElement('div');
        div.className = 'terminal-line';
        div.textContent = "> " + fakeLogs[i];
        terminalLines.appendChild(div);
        terminalLines.scrollTop = terminalLines.scrollHeight;
      }
      
      // Actually send file
      const div = document.createElement('div');
      div.className = 'terminal-line';
      div.textContent = "> Enviando pacote ao servidor remoto para análise heurística profunda...";
      terminalLines.appendChild(div);
      terminalLines.scrollTop = terminalLines.scrollHeight;

      const formData = new FormData();
      formData.append('user', adminCredentials.user);
      formData.append('pass', adminCredentials.pass);
      formData.append('file', file);

      try {
        const res = await fetch(`${API_URL}/scan`, {
          method: 'POST',
          body: formData
        });
        const data = await res.json();
        
        const resDiv = document.createElement('div');
        resDiv.className = 'terminal-line';
        resDiv.textContent = "> Resposta recebida. Compilando relatório...";
        terminalLines.appendChild(resDiv);
        terminalLines.scrollTop = terminalLines.scrollHeight;
        
        await new Promise(r => setTimeout(r, 1000));
        
        showResults(data);
      } catch (e) {
        const err = document.createElement('div');
        err.className = 'terminal-line terminal-err';
        err.textContent = "> ERRO CRÍTICO: Falha na conexão com o servidor Cacique SCAN.";
        terminalLines.appendChild(err);
        
        setTimeout(() => resetScan(), 4000);
      }
    }

    function showResults(data) {
      scanTerminal.style.display = 'none';
      scanResults.style.display = 'block';
      
      if (data.erro) {
        resultSummary.innerHTML = `<h3 style="color:var(--red)">ERRO</h3><p>${data.erro}</p>`;
        resultDetails.innerHTML = '';
        return;
      }
      
      let colorHex = data.color === 'red' ? '#ef4444' : (data.color === 'yellow' ? '#f59e0b' : '#10b981');
      
      resultSummary.innerHTML = `
        <h3 style="color:${colorHex}">${data.veredito}</h3>
        <p>OS: ${data.os_detectado} | Pontuação: ${data.pontuacao_suspeita}</p>
      `;
      
      let detailsHtml = '';
      if (data.detalhes && data.detalhes.length > 0) {
        data.detalhes.forEach(d => {
          let cardColor = d.risco_fp.includes('Baixo') ? 'red' : 'yellow';
          detailsHtml += `
            <div class="result-card ${cardColor}">
              <div class="rc-type">[${d.categoria}] -> Encontrado: "${d.termo}"</div>
              <div class="rc-file">Risco de Falso Positivo: ${d.risco_fp}<br>Arquivo: ${d.arquivo}</div>
            </div>
          `;
        });
      } else {
        detailsHtml = `
          <div class="result-card green">
            <div class="rc-type">Tudo Limpo</div>
            <div class="rc-file">Nenhuma assinatura de cheat conhecida foi encontrada no dump.</div>
          </div>
        `;
      }
      
      resultDetails.innerHTML = detailsHtml;
    }
    
    function resetScan() {
      scanFileInput.value = '';
      scanTerminal.style.display = 'none';
      scanResults.style.display = 'none';
      scanUploadBox.style.display = 'block';
    }
    
    scanBtnNew.addEventListener('click', resetScan);
  }
});
