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

  // ── Mobile Menu Toggle ──
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

  // ── Sorteio de Times Logic ──
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
});
