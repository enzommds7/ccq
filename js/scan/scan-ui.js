/* ══════════════════════════════════════════════════════════════════
   ccq scan — SCAN UI CONTROLLER (THREAD PRINCIPAL LEVE)
   - Lazy-loads Web Worker (scan.worker.js) apenas quando o scan é iniciado
   - Encerra Worker e libera memória/DOM no logout e em "Nova Análise"
   - Exibe Veredito, Eventos Únicos vs. Brutos, Cobertura separada de
     Índice Heurístico, filtros por estado/domínio e motivo técnico
   ══════════════════════════════════════════════════════════════════ */
import { escapeHtml, performCopy, showToast } from '../core/ui-utils.js';
import { sfx } from '../core/sound.js';
import { lockScanDashboard } from '../core/auth.js';

const DOMAIN_LABELS = {
  integridade_do_jogo: 'Integridade do Jogo',
  seguranca_do_dispositivo: 'Segurança do Dispositivo',
  depuracao: 'Depuração (ADB/USB)',
  rede: 'Rede & Proxy',
  estabilidade: 'Estabilidade & Memória',
  cobertura_log: 'Cobertura de Log',
  sistema_backup: 'Sistema & Backup'
};

let initialized = false;
let activeWorker = null;
let scanBusy = false;
let currentScanMode = 'zip';
let currentReport = null;
let activeFilter = 'all';
let authChecker = () => false;

function terminateWorker() {
  if (activeWorker) {
    try {
      activeWorker.onmessage = null;
      activeWorker.onerror = null;
      activeWorker.terminate();
    } catch (_) {}
    activeWorker = null;
  }
}

function getOrCreateWorker() {
  if (activeWorker) return activeWorker;
  activeWorker = new Worker(new URL('./scan.worker.js', import.meta.url), { type: 'module' });
  return activeWorker;
}

function clearScanDomAndState({ keepWorker = false } = {}) {
  scanBusy = false;
  currentReport = null;
  activeFilter = 'all';

  if (!keepWorker) {
    terminateWorker();
  }

  const scanUploadBox = document.getElementById('scanUploadBox');
  const scanTerminalWrap = document.getElementById('scanTerminalWrap');
  const scanResults = document.getElementById('scanResults');
  const terminalLines = document.getElementById('terminalLines');
  const resultSummary = document.getElementById('resultSummary');
  const scanDeviceCard = document.getElementById('scanDeviceCard');
  const scanFilters = document.getElementById('scanFilters');
  const resultDetails = document.getElementById('resultDetails');
  const scanProgressFill = document.getElementById('scanProgressFill');
  const scanProgressPercent = document.getElementById('scanProgressPercent');
  const scanProgressLabel = document.getElementById('scanProgressLabel');
  const terminalStatus = document.getElementById('terminalStatus');

  if (scanUploadBox) {
    scanUploadBox.style.display = 'block';
    scanUploadBox.classList.remove('dragover');
  }
  if (scanTerminalWrap) scanTerminalWrap.style.display = 'none';
  if (scanResults) scanResults.style.display = 'none';
  if (terminalLines) terminalLines.innerHTML = '';
  if (resultSummary) resultSummary.innerHTML = '';
  if (scanDeviceCard) {
    scanDeviceCard.innerHTML = '';
    scanDeviceCard.style.display = 'none';
  }
  if (scanFilters) {
    scanFilters.innerHTML = '';
    scanFilters.style.display = 'none';
  }
  if (resultDetails) resultDetails.innerHTML = '';
  if (scanProgressFill) scanProgressFill.style.width = '0%';
  if (scanProgressPercent) scanProgressPercent.textContent = '0%';
  if (scanProgressLabel) scanProgressLabel.textContent = 'Iniciando motor de análise...';
  if (terminalStatus) {
    terminalStatus.textContent = 'ANALISANDO';
    terminalStatus.className = 'terminal-status-indicator';
  }

  ['scanFileInput', 'scanFolderInput', 'scanLooseInput'].forEach(id => {
    const inp = document.getElementById(id);
    if (inp) inp.value = '';
  });
}

export function cancelActiveScan() {
  if (activeWorker && scanBusy) {
    try {
      activeWorker.postMessage({ type: 'CANCEL_SCAN' });
    } catch (_) {}
  }
  terminateWorker();
  scanBusy = false;
}

export function resetScanSession() {
  clearScanDomAndState({ keepWorker: false });
}

export function initScanUI({ isAdminAuthenticated }) {
  authChecker = typeof isAdminAuthenticated === 'function' ? isAdminAuthenticated : () => false;
  if (initialized) {
    // Ao re-autenticar após logout, garante painel limpo e pronto para nova análise
    clearScanDomAndState({ keepWorker: false });
    return;
  }
  initialized = true;

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
  const terminalStatus = document.getElementById('terminalStatus');

  const scanResults = document.getElementById('scanResults');
  const resultSummary = document.getElementById('resultSummary');
  const scanDeviceCard = document.getElementById('scanDeviceCard');
  const scanFilters = document.getElementById('scanFilters');
  const resultDetails = document.getElementById('resultDetails');
  const scanBtnCopyReport = document.getElementById('scanBtnCopyReport');
  const scanBtnNew = document.getElementById('scanBtnNew');

  function logTerminal(prefix, msg, cssClass = '') {
    if (!terminalLines) return;
    const line = document.createElement('div');
    line.className = `terminal-line ${cssClass}`;
    line.textContent = `[${prefix}] ${msg}`;
    terminalLines.appendChild(line);
    terminalLines.scrollTop = terminalLines.scrollHeight;
  }

  function updateScanProgress(pct, label) {
    if (scanProgressFill) scanProgressFill.style.width = `${pct}%`;
    if (scanProgressPercent) scanProgressPercent.textContent = `${pct}%`;
    if (scanProgressLabel) scanProgressLabel.textContent = label;
  }

  function clearFileInputs() {
    if (scanFileInput) scanFileInput.value = '';
    if (scanFolderInput) scanFolderInput.value = '';
    if (scanLooseInput) scanLooseInput.value = '';
  }

  function setScanMode(mode) {
    currentScanMode = mode;
    [modeZipBtn, modeFolderBtn, modeLooseBtn].forEach(btn => btn?.classList.remove('active'));
    if (mode === 'zip') {
      modeZipBtn?.classList.add('active');
      if (scanUploadTitle) scanUploadTitle.textContent = 'Arraste o arquivo .zip ou .tar.gz aqui';
      if (scanUploadDesc) scanUploadDesc.textContent = 'Bugreport Android (.zip), Sysdiagnose iOS (.tar.gz) ou dump de cheat';
    } else if (mode === 'folder') {
      modeFolderBtn?.classList.add('active');
      if (scanUploadTitle) scanUploadTitle.textContent = 'Selecione ou arraste a pasta extraída';
      if (scanUploadDesc) scanUploadDesc.textContent = 'Pasta de bugreport ou dump descompactado no computador';
    } else {
      modeLooseBtn?.classList.add('active');
      if (scanUploadTitle) scanUploadTitle.textContent = 'Selecione múltiplos arquivos de log soltos';
      if (scanUploadDesc) scanUploadDesc.textContent = 'Arquivos .txt, .log, .ips, .plist, tombstones ou dumps';
    }
    sfx.tick(850);
  }

  if (modeZipBtn) modeZipBtn.addEventListener('click', () => setScanMode('zip'));
  if (modeFolderBtn) modeFolderBtn.addEventListener('click', () => setScanMode('folder'));
  if (modeLooseBtn) modeLooseBtn.addEventListener('click', () => setScanMode('loose'));

  function renderEventList(report, filterKey) {
    if (!resultDetails) return;
    const events = report.events || [];
    const cov = report.coverage || {};
    const unsupported = cov.unsupported_files || [];
    const ignoredAux = cov.ignored_auxiliary || [];
    const rejectedLim = cov.rejected_limits || [];
    const rejectedSec = cov.rejected_security || [];
    const gaps = cov.gaps || [];

    if (filterKey === '_coverage') {
      const blocks = [];
      for (const u of unsupported) {
        blocks.push(`<div class="result-card" style="border-left-color: #f5a623;"><strong>📄 Não suportado: ${escapeHtml(u.file)}</strong><p style="color:var(--text-2);font-size:0.85rem;margin-top:6px;">${escapeHtml(u.reason)}</p></div>`);
      }
      for (const g of gaps) {
        blocks.push(`<div class="result-card" style="border-left-color: #f5a623;"><strong>⚠️ Lacuna: ${escapeHtml(g.file)}</strong><p style="color:var(--text-2);font-size:0.85rem;margin-top:6px;">${escapeHtml(g.reason)}</p></div>`);
      }
      for (const r of [...rejectedSec, ...rejectedLim]) {
        blocks.push(`<div class="result-card" style="border-left-color: var(--red);"><strong>🛡️ Bloqueado/Limite: ${escapeHtml(r.file)}</strong><p style="color:var(--text-2);font-size:0.85rem;margin-top:6px;">${escapeHtml(r.reason)}</p></div>`);
      }
      for (const ax of ignoredAux.slice(0, 40)) {
        blocks.push(`<div class="result-card" style="border-left-color: #8a8f98;"><strong>🔇 Catálogo Auxiliar Ignorado: ${escapeHtml(ax.file)}</strong><p style="color:var(--text-3);font-size:0.84rem;margin-top:6px;">${escapeHtml(ax.reason)}</p></div>`);
      }
      if (ignoredAux.length > 40) {
        blocks.push(`<p style="color:var(--text-3);font-size:0.82rem;">+ ${ignoredAux.length - 40} arquivo(s) auxiliar(es) UUIDText/DSC ignorado(s).</p>`);
      }
      resultDetails.innerHTML = blocks.length
        ? blocks.join('')
        : `<p style="color:var(--text-3);padding:16px 0;">Nenhuma lacuna ou arquivo não analisado registrado.</p>`;
      return;
    }

    let filtered = events;
    if (filterKey === '_lvl_corroborated') {
      filtered = events.filter(e => e.evidence_level === 'corroborated_evidence');
    } else if (filterKey === '_lvl_review') {
      filtered = events.filter(e => e.evidence_level === 'anomaly_review');
    } else if (filterKey === '_lvl_unvalidated') {
      filtered = events.filter(e => e.evidence_level === 'unvalidated_reference');
    } else if (filterKey === '_lvl_info') {
      filtered = events.filter(e => e.evidence_level === 'informational');
    } else if (filterKey !== 'all') {
      filtered = events.filter(e => e.domain === filterKey);
    }

    if (filtered.length === 0) {
      resultDetails.innerHTML = `
        <div class="result-card" style="border-left-color: var(--live-green);">
          <strong style="color: var(--live-green);">${escapeHtml(report.verdict.status)}</strong>
          <p style="color: var(--text-2); font-size: 0.88rem; margin-top: 4px;">
            ${events.length === 0 ? escapeHtml(report.verdict.summary) : 'Nenhum evento neste filtro.'}
          </p>
        </div>
      `;
      return;
    }

    resultDetails.innerHTML = filtered.map(ev => {
      const lvlColor = ev.evidence_level === 'corroborated_evidence'
        ? 'var(--red)'
        : (ev.evidence_level === 'anomaly_review' || ev.evidence_level === 'unvalidated_reference'
          ? '#f5a623'
          : '#7ee787');
      const sn = ev.snippet || {};
      const obs = ev.observed || {};
      const altList = (ev.alternative_explanations || []).length
        ? ev.alternative_explanations.join('; ')
        : 'Nenhuma registrada';
      const corrobText = (ev.corroboration || []).length
        ? ev.corroboration.join('; ')
        : 'Sem fontes independentes adicionais';

      return `
        <div class="result-card" style="border-left-color: ${lvlColor};">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px;">
            <strong style="color:#fff;">${escapeHtml(ev.title)}</strong>
            <span style="font-family:var(--font-mono);font-size:0.72rem;color:${lvlColor};background:rgba(255,255,255,0.06);padding:2px 8px;border-radius:4px;">
              ${escapeHtml(ev.evidence_level_label)} · Ocorrências: ${ev.occurrence_count || 1}x · Peso heurístico: ${ev.heuristic_weight || 0}
            </span>
          </div>
          <div style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-3);margin-bottom:8px;line-height:1.5;">
            <strong>Domínio:</strong> <span style="color:var(--text-2);">${escapeHtml(ev.domain_label || ev.domain)}</span> ·
            <strong>Regra:</strong> <code>${escapeHtml(ev.rule_id)}</code> (v${escapeHtml(ev.rule_version)})<br>
            <strong>Fonte:</strong> <span style="color:var(--text-2);">${escapeHtml(ev.source.path)}${ev.source.line ? `:${ev.source.line}` : ''}</span> (${escapeHtml(ev.source.format)}) ·
            <strong>Processo:</strong> <span style="color:#fff;">${escapeHtml(obs.process || 'Não identificado')}</span> ·
            <strong>Timestamp:</strong> <span style="color:#7ee787;">${escapeHtml(obs.timestamp || 'Não disponível')}</span>
          </div>
          <div style="font-size:0.82rem;color:var(--text-2);line-height:1.5;margin-bottom:8px;">
            ${obs.object_path ? `<div><strong>Objeto / Alvo:</strong> <code>${escapeHtml(obs.object_path)}</code></div>` : ''}
            <div><strong>Motivo técnico:</strong> ${escapeHtml(ev.interpretation || '')}</div>
            <div><strong>Hipóteses alternativas:</strong> ${escapeHtml(altList)}</div>
            <div><strong>Corroboração independente:</strong> ${escapeHtml(corrobText)}</div>
            <div style="color:#7ee787;"><strong>Ação recomendada:</strong> ${escapeHtml(ev.recommended_action || '')}</div>
          </div>
          ${(sn.prev_line || sn.current_line || sn.next_line) ? `
          <div style="background:#050507;border:1px solid rgba(255,255,255,0.07);padding:8px 10px;border-radius:4px;font-family:var(--font-mono);font-size:0.74rem;line-height:1.5;overflow-x:auto;">
            ${sn.prev_line ? `<div style="color:#6e7681;word-break:break-all;">[Linha -1] ${escapeHtml(sn.prev_line)}</div>` : ''}
            ${sn.current_line ? `<div style="color:#ff8a80;font-weight:600;word-break:break-all;">[Ocorrência] ${escapeHtml(sn.current_line)}</div>` : ''}
            ${sn.next_line ? `<div style="color:#6e7681;word-break:break-all;">[Linha +1] ${escapeHtml(sn.next_line)}</div>` : ''}
          </div>` : ''}
        </div>
      `;
    }).join('');
  }

  function displayScanResults(report) {
    if (!scanResults || !resultSummary) return;
    scanResults.style.display = 'block';
    activeFilter = 'all';

    const cov = report.coverage || {};
    const c = report.counters || {};
    const verdict = report.verdict || { status: 'INCONCLUSIVO', color: 'yellow', summary: '' };
    const colorMap = { red: 'var(--red)', yellow: '#f5a623', green: 'var(--live-green)' };
    const titleColor = colorMap[verdict.color] || '#f5a623';

    const coverageTotalUnanalyzed = (cov.unsupported_files?.length || 0) + (cov.rejected_limits?.length || 0) + (cov.rejected_security?.length || 0) + (cov.gaps?.length || 0);
    const covBadgeColor = cov.status === 'completa' ? '#7ee787' : (cov.status === 'parcial' ? '#f5a623' : 'var(--red)');

    resultSummary.innerHTML = `
      <h3 style="color: ${titleColor};">${escapeHtml(verdict.status)}</h3>
      <p style="color: var(--text-2); font-size: 0.94rem;">${escapeHtml(verdict.summary)}</p>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px;margin-top:12px;">
        <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);padding:8px 10px;border-radius:6px;font-family:var(--font-mono);font-size:0.76rem;">
          <span style="color:var(--text-3);display:block;">Eventos Únicos / Brutos</span>
          <strong style="color:#fff;font-size:0.95rem;">${c.unique_events || 0} / ${c.raw_occurrences || 0}</strong>
        </div>
        <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);padding:8px 10px;border-radius:6px;font-family:var(--font-mono);font-size:0.76rem;">
          <span style="color:var(--text-3);display:block;">Evidências Corroboradas</span>
          <strong style="color:var(--red);font-size:0.95rem;">${c.corroborated_evidence || 0}</strong>
        </div>
        <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);padding:8px 10px;border-radius:6px;font-family:var(--font-mono);font-size:0.76rem;">
          <span style="color:var(--text-3);display:block;">Anomalias p/ Revisão</span>
          <strong style="color:#f5a623;font-size:0.95rem;">${c.anomaly_review || 0}</strong>
        </div>
        <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);padding:8px 10px;border-radius:6px;font-family:var(--font-mono);font-size:0.76rem;">
          <span style="color:var(--text-3);display:block;">Cobertura (Lidos / Não Analis.)</span>
          <strong style="color:${covBadgeColor};font-size:0.95rem;">${(cov.status || 'parcial').toUpperCase()} (${cov.analyzed_files || 0} / ${cov.unsupported_files?.length || 0})</strong>
        </div>
        <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);padding:8px 10px;border-radius:6px;font-family:var(--font-mono);font-size:0.76rem;">
          <span style="color:var(--text-3);display:block;">Índice Heurístico (separado)</span>
          <strong style="color:#fff;font-size:0.95rem;">${report.heuristic_index || 0}/100</strong>
        </div>
      </div>
      <div style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-3);margin-top:10px;line-height:1.5;">
        Motor v${escapeHtml(report.engine_version)} · Catálogo ${escapeHtml(report.catalog_version)} ·
        Linhas: ~${(cov.checked_lines || 0).toLocaleString('pt-BR')} ·
        Auxiliares UUIDText/DSC ignorados: ${cov.ignored_auxiliary?.length || 0} ·
        Tokens hex inativos: ${c.inactive_short_tokens || 0} ·
        Tempo: ${((report.duration_ms || 0) / 1000).toFixed(2)}s
      </div>
    `;

    const dev = report.device_info;
    const hasDev = dev && (dev.brand || dev.model || dev.osVersion || dev.serial || dev.kernel);
    if (scanDeviceCard) {
      if (hasDev) {
        scanDeviceCard.style.display = 'block';
        const modelStr = [dev.brand, dev.model].filter(Boolean).join(' ') || 'Não identificado';
        scanDeviceCard.innerHTML = `
          <strong style="display:block;margin-bottom:8px;color:#fff;">📱 Dispositivo Analisado: ${escapeHtml(modelStr)}</strong>
          <div style="font-family:var(--font-mono);font-size:0.78rem;color:var(--text-3);line-height:1.6;">
            Sistema: <strong style="color:#fff;">${escapeHtml(dev.osVersion || report.os_detected)}</strong>
            ${dev.serial ? ` · Serial: <strong style="color:#fff;">${escapeHtml(dev.serial)}</strong>` : ''}
            ${dev.kernel ? `<br>Kernel: ${escapeHtml(dev.kernel)}` : ''}
          </div>
        `;
      } else {
        scanDeviceCard.style.display = 'none';
      }
    }

    if (scanFilters) {
      const events = report.events || [];
      const domains = Array.from(new Set(events.map(e => e.domain)));
      const showCovTab = coverageTotalUnanalyzed > 0 || (cov.ignored_auxiliary?.length || 0) > 0;

      scanFilters.style.display = 'flex';
      scanFilters.innerHTML = `
        <button type="button" class="scan-filter-chip active" data-cat="all">Todos (${events.length})</button>
        <button type="button" class="scan-filter-chip" data-cat="_lvl_corroborated">Corroboradas (${c.corroborated_evidence || 0})</button>
        <button type="button" class="scan-filter-chip" data-cat="_lvl_review">Revisão (${c.anomaly_review || 0})</button>
        <button type="button" class="scan-filter-chip" data-cat="_lvl_unvalidated">Não Validadas (${c.unvalidated_reference || 0})</button>
        <button type="button" class="scan-filter-chip" data-cat="_lvl_info">Informativos (${c.informational || 0})</button>
        ${showCovTab ? `<button type="button" class="scan-filter-chip" data-cat="_coverage">Cobertura / Não Analisados (${coverageTotalUnanalyzed + (cov.ignored_auxiliary?.length || 0)})</button>` : ''}
        ${domains.map(d => `
          <button type="button" class="scan-filter-chip" data-cat="${escapeHtml(d)}">
            ${escapeHtml(DOMAIN_LABELS[d] || d)} (${events.filter(e => e.domain === d).length})
          </button>
        `).join('')}
      `;

      scanFilters.querySelectorAll('.scan-filter-chip').forEach(btn => {
        btn.addEventListener('click', () => {
          activeFilter = btn.dataset.cat;
          scanFilters.querySelectorAll('.scan-filter-chip').forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          renderEventList(report, activeFilter);
          sfx.tick(900);
        });
      });
    }

    renderEventList(report, activeFilter);
  }

  function processUploadedFiles(fileList) {
    if (!authChecker()) {
      resetScanSession();
      lockScanDashboard();
      showToast('error', 'Acesso Restrito', 'Autentique-se com usuário e senha de ADM antes de escanear.');
      return;
    }
    if (!fileList || fileList.length === 0) return;
    if (scanBusy) {
      showToast('info', 'Análise em andamento', 'Aguarde o scan atual terminar.');
      return;
    }

    scanBusy = true;
    currentReport = null;
    if (scanUploadBox) scanUploadBox.style.display = 'none';
    if (scanTerminalWrap) scanTerminalWrap.style.display = 'block';
    if (scanResults) scanResults.style.display = 'none';
    if (resultDetails) resultDetails.innerHTML = '';
    if (terminalLines) terminalLines.innerHTML = '';
    if (terminalStatus) {
      terminalStatus.textContent = 'ANALISANDO (WORKER)';
      terminalStatus.className = 'terminal-status-indicator';
    }

    logTerminal('SYS', 'Iniciando Web Worker ccq scan em modo streaming (UI Thread livre)...', 'terminal-info');
    logTerminal('IO', `Enviando ${fileList.length} entrada(s) em streaming para o Worker...`, 'terminal-info');
    updateScanProgress(3, 'Inicializando Web Worker...');
    sfx.start();

    const worker = getOrCreateWorker();
    const filesArray = Array.from(fileList);

    worker.onmessage = (e) => {
      if (!authChecker()) {
        resetScanSession();
        return;
      }
      const msg = e.data || {};
      if (msg.type === 'PROGRESS') {
        updateScanProgress(msg.pct || 0, msg.label || 'Analisando...');
      } else if (msg.type === 'LOG') {
        logTerminal(msg.prefix || 'LOG', msg.msg || '', msg.cssClass || 'terminal-info');
      } else if (msg.type === 'CANCELLED') {
        scanBusy = false;
        clearFileInputs();
        logTerminal('SYS', 'Análise cancelada.', 'terminal-info');
      } else if (msg.type === 'RESULT') {
        scanBusy = false;
        clearFileInputs();
        const report = msg.report;
        currentReport = report;

        const cov = report.coverage || {};
        for (const ev of (report.events || [])) {
          if (ev.evidence_level === 'corroborated_evidence' || ev.evidence_level === 'anomaly_review') {
            logTerminal('ACHADO', `[${ev.evidence_level_label}] ${ev.title} (${ev.occurrence_count}x)`, 'terminal-err');
            if (ev.evidence_level === 'corroborated_evidence') sfx.alert(true);
          }
        }
        for (const uf of (cov.unsupported_files || [])) {
          logTerminal('COBERTURA', `${uf.file}: ${uf.reason}`, 'terminal-info');
        }
        for (const gap of (cov.gaps || [])) {
          logTerminal('LACUNA', `${gap.file}: ${gap.reason}`, 'terminal-info');
        }
        for (const sec of (cov.rejected_security || [])) {
          logTerminal('SEGURANÇA', `${sec.file}: ${sec.reason}`, 'terminal-err');
        }

        updateScanProgress(100, `Análise concluída em ${((report.duration_ms || 0) / 1000).toFixed(2)}s`);
        logTerminal('SYS', `Veredito: ${report.verdict.status} | Cobertura: ${cov.status.toUpperCase()} (${cov.analyzed_files} lidos, ${cov.unsupported_files?.length || 0} não suportados) | Únicos: ${report.counters.unique_events} / Brutos: ${report.counters.raw_occurrences}.`, 'terminal-info');

        if (terminalStatus) {
          terminalStatus.textContent = 'CONCLUÍDO';
          terminalStatus.className = 'terminal-status-indicator is-done';
        }
        sfx.done();
        displayScanResults(report);

        const hasRisk = (report.counters.corroborated_evidence + report.counters.anomaly_review) > 0;
        showToast(hasRisk ? 'error' : 'success', report.verdict.status, report.verdict.summary);
      } else if (msg.type === 'ERROR') {
        scanBusy = false;
        clearFileInputs();
        logTerminal('ERR', `Falha no Worker: ${msg.message}`, 'terminal-err');
        updateScanProgress(0, 'Falha no processamento');
        if (terminalStatus) {
          terminalStatus.textContent = 'FALHOU';
          terminalStatus.className = 'terminal-status-indicator is-error';
        }
        sfx.error();
        showToast('error', 'Erro no Scanner', msg.message || 'Falha ao processar arquivos.');
      }
    };

    worker.onerror = (err) => {
      if (!authChecker()) {
        resetScanSession();
        return;
      }
      scanBusy = false;
      clearFileInputs();
      logTerminal('ERR', `Erro fatal no Worker: ${err.message || 'desconhecido'}`, 'terminal-err');
      if (terminalStatus) {
        terminalStatus.textContent = 'FALHOU';
        terminalStatus.className = 'terminal-status-indicator is-error';
      }
      sfx.error();
      terminateWorker();
    };

    worker.postMessage({ type: 'START_SCAN', files: filesArray });
  }

  const triggerFilePicker = () => {
    if (!authChecker()) {
      resetScanSession();
      lockScanDashboard();
      showToast('error', 'Acesso Negado', 'Faça login com as credenciais de ADM para usar o scanner.');
      return;
    }
    if (currentScanMode === 'zip') scanFileInput?.click();
    else if (currentScanMode === 'folder') scanFolderInput?.click();
    else scanLooseInput?.click();
  };

  if (scanUploadBox) {
    scanUploadBox.addEventListener('click', triggerFilePicker);
    scanUploadBox.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        triggerFilePicker();
      }
    });

    scanUploadBox.addEventListener('dragover', (e) => {
      e.preventDefault();
      scanUploadBox.classList.add('dragover');
    });
    scanUploadBox.addEventListener('dragleave', () => {
      scanUploadBox.classList.remove('dragover');
    });
    scanUploadBox.addEventListener('drop', (e) => {
      e.preventDefault();
      scanUploadBox.classList.remove('dragover');
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        processUploadedFiles(e.dataTransfer.files);
      }
    });
  }

  [scanFileInput, scanFolderInput, scanLooseInput].forEach(inp => {
    if (inp) {
      inp.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
          processUploadedFiles(e.target.files);
        }
      });
    }
  });

  if (scanBtnCopyReport) {
    scanBtnCopyReport.addEventListener('click', () => {
      if (!currentReport) return;
      const r = currentReport;
      const c = r.counters || {};
      const cov = r.coverage || {};
      let txt = `🛡️ *RELATÓRIO FORENSE — ccq scan v${r.engine_version}* 🛡️\n`;
      txt += `📌 Veredito: ${r.verdict.status}\n`;
      txt += `📦 Cobertura: ${(cov.status || '').toUpperCase()} (${cov.analyzed_files || 0} analisados | ${cov.unsupported_files?.length || 0} não suportados | ${cov.gaps?.length || 0} lacunas)\n`;
      txt += `📊 Eventos Únicos: ${c.unique_events || 0} / Brutos: ${c.raw_occurrences || 0} | Corroborados: ${c.corroborated_evidence || 0} | Revisão: ${c.anomaly_review || 0} | Índice Heurístico: ${r.heuristic_index || 0}/100\n\n`;

      for (const ev of (r.events || [])) {
        txt += `• [${ev.evidence_level_label} | ${ev.domain_label}] ${ev.title} (${ev.occurrence_count}x)\n`;
        txt += `  Fonte: ${ev.source.path}${ev.source.line ? `:${ev.source.line}` : ''} | Processo: ${ev.observed.process}\n`;
        txt += `  Motivo: ${ev.interpretation}\n`;
        txt += `  Ação: ${ev.recommended_action}\n\n`;
      }
      txt += `----------------------------------\nccq scan: https://enzommds7.github.io/ccq/`;
      performCopy(txt, scanBtnCopyReport, 'Relatório Copiado!', sfx).catch((err) => {
        console.error('[ccq scan copy]', err);
      });
    });
  }

  if (scanBtnNew) {
    scanBtnNew.addEventListener('click', () => {
      // Libera relatório anterior e DOM grande; se houver Worker travado/ocupado, encerra-o
      if (scanBusy) {
        cancelActiveScan();
      }
      clearScanDomAndState({ keepWorker: true });
      sfx.tick(700);
    });
  }
}
