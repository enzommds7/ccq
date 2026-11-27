/* ══════════════════════════════════════════════════════════════════
   CACIQUE SCAN v5.0 — PARSER FORENSE ANDROID (STREAMING)
   - Cobre Free Fire Normal (com.dts.freefireth) e MAX (com.dts.freefiremax)
   - Analisa: Boot/getprop, PackageManager, Settings (SetEdit/Shell),
     auditd/SELinux, GameAssets, JARs, Crashes, ADB, USB, Proxy & Hex Dumps
   ══════════════════════════════════════════════════════════════════ */
import { buildCanonicalEvent, extractLineMeta } from '../engine/matcher.js';
import { createHexDumpParser } from './hexdump-parser.js';

const AUDITD_AVC_RE = /audit\(([^)]+)\):\s*avc:\s*(granted|denied)\s*\{\s*([^}]+)\s*\}\s*for\s+(.+)/i;
const AUDITD_FIELD_RES = {
  comm: /\bcomm=(?:"([^"]+)"|([^\s]+))/,
  path: /\bpath=(?:"([^"]+)"|([^\s]+))/,
  dev: /\bdev=(?:"([^"]+)"|([^\s]+))/,
  ino: /\bino=(?:"([^"]+)"|([^\s]+))/,
  scontext: /\bscontext=(?:"([^"]+)"|([^\s]+))/,
  tcontext: /\btcontext=(?:"([^"]+)"|([^\s]+))/,
  tclass: /\btclass=(?:"([^"]+)"|([^\s]+))/,
  app: /\bapp=(?:"([^"]+)"|([^\s]+))/,
  name: /\bname=(?:"([^"]+)"|([^\s]+))/
};

// Regexes pré-compiladas para deviceInfo & boot integrity
const MODEL_RE = /ro\.product\.model\s*[:=]\s*\[?([^\r\n\]]+)\]?/i;
const BUILD_FP_RE = /Build\s+fingerprint:.*\/([^/:]+):/i;
const BRAND_RE = /(?:ro\.product\.manufacturer|ro\.product\.brand)\s*[:=]\s*\[?([^\r\n\]]+)\]?/i;
const OS_VER_RE = /(?:ro\.build\.version\.release\s*[:=]\s*\[?([^\r\n\]]+)\]?|Android\s+Version\s*[:=]?\s*([0-9.]+))/i;
const SERIAL_RE = /(?:ro\.serialno|ro\.boot\.serialno)\s*[:=]\s*\[?([^\r\n\]]+)\]?/i;
const KERNEL_RE = /Linux\s+version\s+([0-9a-zA-Z._\-+]+)/i;

const BOOT_STATE_RE = /\[?(ro\.boot\.verifiedbootstate)\]?\s*[:=]\s*\[?([a-zA-Z0-9_-]+)\]?/i;
const FLASH_LOCKED_RE = /\[?(ro\.boot\.flash\.locked)\]?\s*[:=]\s*\[?([a-zA-Z0-9_-]+)\]?/i;
const BUILD_TAGS_RE = /\[?(ro\.build\.tags)\]?\s*[:=]\s*\[?([a-zA-Z0-9_,-]+)\]?/i;
const VERITY_MODE_RE = /\[?(ro\.boot\.veritymode)\]?\s*[:=]\s*\[?([a-zA-Z0-9_-]+)\]?/i;
const SELINUX_STATUS_RE = /(?:SELinux\s+status:\s*|getenforce\s*[:=]?\s*|Current\s+mode:\s*)(Permissive|Enforcing|Disabled)\b/i;

// PackageManager & Settings
const PKG_HEADER_RE = /\bPackage\s+\[([a-zA-Z0-9_.$-]+)\]/;
const PKG_VERSION_RE = /\bversionName=([^\s,}]+)/;
const PKG_INSTALLER_RE = /\binstallerPackageName=([^\s,}]+)/;

const SETTINGS_PKG_RE = /\bpkg:(by4a\.setedit22|com\.android\.shell)\b/i;
const SETTINGS_NAME_RE = /\bname[:=]([^\s,}\]]+)/i;
const SETTINGS_VALUE_RE = /\bvalue[:=]([^\s,}\]]+)/i;
const SETTINGS_DEFAULT_RE = /\bdefault[:=]([^\s,}\]]+)/i;

// Overlays Android (WindowManager / dumpsys window / SurfaceFlinger)
const FOREGROUND_FOCUS_RE = /(?:mCurrentFocus=Window\{[0-9a-fA-F]+\s+u\d+\s+([a-zA-Z0-9_.-]+)\/|mFocusedApp=ActivityRecord\{[^}]+\s+u\d+\s+([a-zA-Z0-9_.-]+)\/)/;
const WINDOW_TOKEN_2038_RE = /WindowToken\{[^}]*\b(?:type=2038|TYPE_APPLICATION_OVERLAY)\b[^}]*\}/;
const OVERLAY_WINDOW_LINE_RE = /Window\{[0-9a-fA-F]+\s+u\d+\s+([^}:/]+)(?:\/([^}:]+))?\}|\b(?:package|mOwnerPackageName)=([a-zA-Z0-9_.-]+)|\bSurface\(name=([^)/:\s]+)(?:\/([^)\s]+))?/;
const OVERLAY_TYPE_LINE_RE = /\b(?:ty|type)=2038\b|\bTYPE_APPLICATION_OVERLAY\b/;
const OVERLAY_VIS_RE = /\bisVisible=(true|false)\b|\bmViewVisibility=(0x[0-9a-fA-F]+|\d+)\b|\bmHasSurface=(true|false)\b/i;
const OVERLAY_INLINE_PKG_RE = /\b([a-zA-Z][a-zA-Z0-9_]*\.[a-zA-Z0-9_.-]+)\b/g;
const OVERLAY_SYSTEM_IGNORED_RE = /^(?:android$|android\.os\.|android\.view\.|java\.|dalvik\.|com\.android\.|com\.google\.|com\.miui\.|com\.transsion\.|com\.samsung\.|com\.sec\.|com\.xiaomi\.|com\.coloros\.|com\.oplus\.|com\.vivo\.|com\.huawei\.|ShellDropTarget|Shell Root Leash|NavigationBar|StatusBar|ScreenDecor)/i;
const OVERLAY_LEGITIMATE_APPS = new Set([
  'com.whatsapp',
  'com.whatsapp.w4b',
  'com.facebook.orca',
  'com.discord',
  'com.instagram.android',
  'com.spotify.music'
]);
const VALID_PKG_ID_RE = /^[a-zA-Z][a-zA-Z0-9_]*\.[a-zA-Z0-9_.-]+$/;
const FF_COMPATIBLE_COMM_RE = /^(?:UnityMain|UnityGfxDevice|RenderThread|Job\.Worker|com\.dts\.freefire)/i;

// GameAsset & JAR
const FF_GAMEASSET_PATH_RE = /\/data\/(?:user\/0|data)\/(com\.dts\.freefire(?:max|th))\/files\/contentcache\/compulsory\/android\/gameassetbundles\/font\/sh-gpp2(?![A-Za-z0-9_.-])/i;
const FF_DATA_PATH_RE = /\/data\/(?:user\/0|data)\/(com\.dts\.freefire(?:max|th))\//i;
const FF_JAR_PATH_RE = /\/data\/(?:user\/0|data)\/(com\.dts\.freefire(?:max|th))\/cache\/(app_resources_lib\.jar|google_api_resources_lib\.jar)\b/i;
const CLASSLOADER_RE = /(DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader|loadClass|dex2oat|nativeLoad)/i;

// Estabilidade & Backtrace
const LOW_MEM_RE = /process=([a-zA-Z0-9_.]+).*reason=3\s*\(LOW_MEMORY\)/i;
const CRASH_CMDLINE_RE = /^Cmdline:\s*(.+)$/i;
const SIGSEGV_RE = /(signal\s+11\s*\(SIGSEGV\)|SEGV_MAPERR|Cause:\s*null pointer dereference|PR_TAGGED_ADDR_ENABLE|PR_PAC_)/i;
const BACKTRACE_LINE_RE = /#\d{2}\s+pc\s+[0-9a-fA-F]+\s+([^\s]+)/;
const INJECTED_SO_RE = /(frida-gadget|libfrida|libzygisk|liblsposed|libsubstrate|\/data\/local\/tmp\/[^/\s]+\.so)/i;

// ADB, Rede, Proxy, Root
const ADB_TCP_PROP_ACTIVE_RE = /\[?(?:service|persist)\.adb\.tcp\.port\]?\s*[:=]\s*\[?(\d{4,5})\]?/i;
const ADB_TCP_PROP_ANY_RE = /\[?(?:service|persist)\.adb\.tcp\.port\]?\s*[:=]/i;
const ADB_SVC_ACTIVE_RE = /(?:\[?init\.svc\.adbd\]?\s*[:=]\s*\[?running\]?|adbd\s+daemon\s+started|init:\s*starting\s+service\s+['"]?adbd['"]?|listening\s+on\s+tcp:5555)/i;
const ADB_LOOPBACK_RE = /\b(127\.0\.0\.1|localhost|\[::1\]):5555\b/i;
const ADB_REMOTE_CONN_RE = /(?:(?:client\s+connected|connected\s+from|adb\s+connect|remote\s+peer|auth\s+confirmed\s+from|socket\s+accepted\s+from)[^\r\n]*?(\d{1,3}(?:\.\d{1,3}){3}):(\d{4,5})|\b(\d{1,3}(?:\.\d{1,3}){3}):5555\b)/i;
const ADB_USB_DEBUG_RE = /(?:\badb_enabled=1\b|\bUSB debugging connected\b|\b(?:persist\.sys\.usb\.config|sys\.usb\.state)[^\r\n]*\badb\b)/i;
const ADB_WIRELESS_DEBUG_RE = /(?:\badb_wifi_enabled=1\b|\bservice\.adb\.tls\.port\b|AdbDebuggingManager[^\r\n]*wifi)/i;
const ADB_PORT_FWD_RE = /\b(adb\s+(?:forward|reverse)\b[^\r\n]{0,80})/i;
const GLOBAL_PROXY_HOST_RE = /\bglobal_http_proxy_host(?:[=:\s]+value=|[=:\s]+)([^\s,;]+)/i;
const PROXY_TOOL_LINE_RE = /\b(mitmproxy|Burp Suite|Charles Proxy|httptoolkit|pcapdroid)\b/i;
const NET_CONTEXT_RE = /(https?:\/\/|\bdns\b|\bproxy\b|\bhost=|\bsni\b|\bresolve\b|\bconnect\b|\bvpn\b|\broute\b|\bsocket\b|\balias=|\bprofile=|\bcert(?:ificate)?\b)/i;
const PROFILE_CTX_RE = /(\bprofile\b|\bcert(?:ificate)?\b|\bPayload|\bconfig\b|\.mobileconfig\b)/i;
const USB_BENIGN_RE = /\b(USB connected|persist\.sys\.usb\.config=.*\b(?:mtp|ptp)\b|sys\.usb\.state=.*\b(?:mtp|ptp)\b|DHCP\s+lease|InputDispatcher|InputReader|InputFlinger)\b/i;
const INPUT_INJ_RE = /\b(shell input tap|shell input swipe|injectInputEvent)\b/i;
const PROCESS_CTX_RE = /(\/data\/adb\/modules|init:\s*starting\s+service|Start proc|comm=|Cmdline:|Package\s+\[|mountinfo|binder:|app_process|\bshell:|\badb\b)/i;

const SETTINGS_BASELINES = Object.freeze({
  long_press_timeout: { defaults: new Set(['400', '500']), domain: 'integridade_do_jogo' },
  multi_press_timeout: { defaults: new Set(['300']), domain: 'integridade_do_jogo' },
  touch_slop: { defaults: new Set(['8', '16', '24']), domain: 'integridade_do_jogo' },
  pointer_speed: { defaults: new Set(['0']), domain: 'integridade_do_jogo' },
  peak_refresh_rate: { defaults: new Set(['60', '60.0', '90', '90.0', '120', '120.0', '144', '144.0']), domain: 'seguranca_do_dispositivo' },
  min_refresh_rate: { defaults: new Set(['60', '60.0', '90', '90.0', '120', '120.0']), domain: 'seguranca_do_dispositivo' },
  window_animation_scale: { defaults: new Set(['1', '1.0', '0.5', '0']), domain: 'seguranca_do_dispositivo' },
  transition_animation_scale: { defaults: new Set(['1', '1.0', '0.5', '0']), domain: 'seguranca_do_dispositivo' },
  animator_duration_scale: { defaults: new Set(['1', '1.0', '0.5', '0']), domain: 'seguranca_do_dispositivo' },
  activity_starts_logging_enabled: { defaults: new Set(['1', 'true']), domain: 'seguranca_do_dispositivo' },
  upload_log_pref: { defaults: new Set(['1', 'true']), domain: 'seguranca_do_dispositivo' },
  upload_debug_log_pref: { defaults: new Set(['1', 'true']), domain: 'seguranca_do_dispositivo' },
  adb_enabled: { defaults: new Set(['0']), domain: 'depuracao', isDebugFlag: true },
  adb_wifi_enabled: { defaults: new Set(['0']), domain: 'depuracao', isDebugFlag: true },
  development_settings_enabled: { defaults: new Set(['0']), domain: 'depuracao', isDebugFlag: true }
});

export function canonicalizeAndroidPath(p) {
  if (!p) return '';
  const clean = p.replace(/\\/g, '/').trim();
  if (clean.startsWith('/data/data/')) {
    return '/data/user/0/' + clean.slice('/data/data/'.length);
  }
  return clean;
}

export function parseAuditdLine(line) {
  const m = AUDITD_AVC_RE.exec(line);
  if (!m) return null;
  const body = m[4];
  const fields = {
    timestamp: m[1].trim(),
    avc_action: m[2].toLowerCase(),
    operations: m[3].trim().toLowerCase().split(/\s+/)
  };
  for (const [k, re] of Object.entries(AUDITD_FIELD_RES)) {
    const km = re.exec(body);
    if (km) {
      fields[k] = km[1] !== undefined ? km[1] : km[2];
    }
  }
  if (fields.path) {
    fields.canonical_path = canonicalizeAndroidPath(fields.path);
  }
  return fields;
}

function makeSnippet(prevLine, currentLine, nextLine) {
  return {
    prev_line: (prevLine || '').slice(0, 200),
    current_line: (currentLine || '').slice(0, 240),
    next_line: (nextLine || '').slice(0, 200)
  };
}

export function createAndroidFileAnalyzer({ filePath, format, matcher, emitEvent, addSignal, deviceInfo, coverage }) {
  const hexParser = createHexDumpParser(filePath, emitEvent);
  const lowerPath = filePath.toLowerCase();
  const baseName = lowerPath.split('/').pop() || '';
  if (baseName.includes('bugreport') || format === 'android_bugreport') {
    coverage.saw_bugreport = true;
  }

  let currentPkg = null;
  let crashCmdline = '';
  let currentForegroundApp = '';
  let pendingOverlay = null;

  const parseOverlayOwnerFromLine = (text) => {
    const cleaned = text.replace(WINDOW_TOKEN_2038_RE, ' ');
    if (/\b(?:ShellDropTarget|Shell Root Leash)\b/i.test(cleaned)) {
      return { status: 'system_ignored', owner: 'system_shell_overlay', windowName: '' };
    }
    const m = OVERLAY_WINDOW_LINE_RE.exec(cleaned);
    if (m) {
      const candidate = (m[1] || m[3] || m[4] || '').trim();
      const comp = (m[2] || m[5] || '').trim();
      const windowName = comp ? `${candidate}/${comp}` : candidate;
      if (candidate) {
        if (OVERLAY_SYSTEM_IGNORED_RE.test(candidate)) {
          return { status: 'system_ignored', owner: candidate, windowName };
        }
        if (VALID_PKG_ID_RE.test(candidate)) {
          return { status: 'pkg', owner: candidate, windowName };
        }
      }
    }
    OVERLAY_INLINE_PKG_RE.lastIndex = 0;
    let im;
    while ((im = OVERLAY_INLINE_PKG_RE.exec(cleaned)) !== null) {
      const cand = im[1];
      if (OVERLAY_SYSTEM_IGNORED_RE.test(cand)) {
        return { status: 'system_ignored', owner: cand, windowName: cand };
      }
      if (VALID_PKG_ID_RE.test(cand)) {
        return { status: 'pkg', owner: cand, windowName: cand };
      }
    }
    return null;
  };

  const flushOverlayBlock = () => {
    if (!pendingOverlay || !pendingOverlay.owner || pendingOverlay.status !== 'pkg') {
      pendingOverlay = null;
      return;
    }
    const ov = pendingOverlay;
    pendingOverlay = null;

    const ownerLow = ov.owner.toLowerCase();
    const isCandidateCatalog =
      (matcher.overlayCandidateMap && matcher.overlayCandidateMap.has(ownerLow)) ||
      matcher.androidPackageMap.has(ownerLow) ||
      matcher.proxyNamedMap.has(ownerLow);
    const isLegitKnown = !isCandidateCatalog && OVERLAY_LEGITIMATE_APPS.has(ownerLow);

    if (isLegitKnown) {
      emitEvent(buildCanonicalEvent({
        ruleId: 'ANDROID_OVERLAY_LEGITIMATE_001',
        domain: 'estabilidade',
        title: `Overlay de Aplicativo Comum (${ov.owner}) — Informativo`,
        source: { path: filePath, format: ov.executionContext, line: ov.lineNo },
        observed: {
          timestamp: ov.timestamp,
          process: ov.process,
          package: ov.owner,
          window_name: ov.windowName,
          window_type: ov.windowType,
          visibility: ov.visibility,
          execution_context: ov.executionContext,
          foreground_app: ov.foregroundApp || 'Não identificado',
          operation: ov.windowType,
          outcome: 'legitimate_known_overlay',
          object_path: ov.windowName || ov.owner
        },
        evidenceLevel: 'informational',
        heuristicWeight: 0,
        interpretation: `Janela sobreposta pertencente a aplicativo comum (${ov.owner}); presença de overlay legítimo não indica trapaça.`,
        alternativeExplanations: ['Bolha de chamada, chat flutuante ou player de mídia'],
        recommendedAction: 'Nenhuma ação necessária.',
        snippet: makeSnippet(ov.tokenLine === ov.detailLine ? '' : ov.tokenLine, ov.detailLine, ov.nextLine),
        dedupKey: `ANDROID_OVERLAY_LEGITIMATE_001|${ownerLow}`
      }));
      return;
    }

    addSignal('android_overlay_active', `${ov.windowType} (${ov.owner}${ov.foregroundApp ? `, foco: ${ov.foregroundApp}` : ''})`);
    emitEvent(buildCanonicalEvent({
      ruleId: 'ANDROID_OVERLAY_ACTIVE_001',
      domain: 'integridade_do_jogo',
      title: isCandidateCatalog
        ? `Overlay Candidato Detectado (${ov.owner})`
        : `Janela Sobreposta de Terceiros (${ov.owner})`,
      source: { path: filePath, format: ov.executionContext, line: ov.lineNo },
      observed: {
        timestamp: ov.timestamp,
        process: ov.process,
        package: ov.owner,
        window_name: ov.windowName,
        window_type: ov.windowType,
        visibility: ov.visibility,
        execution_context: ov.executionContext,
        foreground_app: ov.foregroundApp || 'Não identificado',
        operation: ov.windowType,
        outcome: isCandidateCatalog ? 'catalog_overlay_candidate' : 'third_party_overlay',
        object_path: ov.windowName || ov.owner
      },
      evidenceLevel: 'anomaly_review',
      heuristicWeight: 15,
      interpretation: `Janela sobreposta ${ov.windowType} vinculada ao pacote '${ov.owner}' (visibilidade: ${ov.visibility}${ov.foregroundApp ? `, app em primeiro plano: ${ov.foregroundApp}` : ''}). A existência isolada de overlay não comprova trapaça e requer correlação com PackageManager e demais fontes.`,
      alternativeExplanations: [
        'Gravador de tela, contador de FPS, bolha de chat ou utilitário de tela do usuário'
      ],
      recommendedAction: 'Correlacionar o pacote com PackageManager, horário da partida e eventuais evidências independentes.',
      snippet: makeSnippet(ov.tokenLine === ov.detailLine ? '' : ov.tokenLine, ov.detailLine, ov.nextLine),
      dedupKey: `ANDROID_OVERLAY_ACTIVE_001|${ownerLow}`
    }));
  };

  const flushPackageBlock = () => {
    if (!currentPkg) return;
    coverage.saw_packagemanager = true;
    const pkgName = currentPkg.name;
    const pkgLow = pkgName.toLowerCase();
    const installer = currentPkg.installerPackageName;
    const officialInstaller = (matcher.baselines && matcher.baselines.android_official_installer) || 'com.android.vending';

    // 1. Free Fire normal (com.dts.freefireth) & MAX (com.dts.freefiremax)
    if (matcher.freeFirePackages.has(pkgLow) && installer !== null) {
      if (installer !== officialInstaller) {
        addSignal('ff_non_playstore', `PackageManager (${pkgName} via ${installer})`);
        emitEvent(buildCanonicalEvent({
          ruleId: 'ANDROID_FF_NON_PLAYSTORE_001',
          domain: 'integridade_do_jogo',
          title: `Free Fire instalado fora da Play Store (${pkgName})`,
          source: { path: filePath, format: 'packagemanager', line: currentPkg.lineNo },
          observed: {
            process: 'PackageManager',
            package: pkgName,
            operation: 'installer_check',
            outcome: `installerPackageName=${installer}`,
            object_path: pkgName
          },
          evidenceLevel: 'anomaly_review',
          heuristicWeight: 30,
          interpretation: `O pacote oficial ${pkgName} registra installerPackageName=${installer} em vez da Google Play Store (${officialInstaller}).`,
          alternativeExplanations: [
            'Instalação via loja oficial de fabricante (Samsung Galaxy Store, Xiaomi GetApps)',
            'Restauração local ou backup transferido entre aparelhos'
          ],
          recommendedAction: 'Solicitar verificação da versão e reinstalação oficial pela Play Store caso existam outras anomalias.',
          snippet: makeSnippet(currentPkg.prevLine, `${currentPkg.line} (installerPackageName=${installer})`, currentPkg.nextLine),
          dedupKey: `ANDROID_FF_NON_PLAYSTORE_001|${pkgName}|${installer}`
        }));
      } else {
        emitEvent(buildCanonicalEvent({
          ruleId: 'ANDROID_FF_PLAYSTORE_VERIFIED_001',
          domain: 'integridade_do_jogo',
          title: `Free Fire com instalador Play Store (${pkgName})`,
          source: { path: filePath, format: 'packagemanager', line: currentPkg.lineNo },
          observed: {
            process: 'PackageManager',
            package: pkgName,
            operation: 'installer_check',
            outcome: officialInstaller,
            object_path: pkgName
          },
          evidenceLevel: 'informational',
          heuristicWeight: 0,
          interpretation: `Origem de instalação registrada como ${officialInstaller}.`,
          alternativeExplanations: [],
          recommendedAction: 'Nenhuma ação necessária.',
          snippet: makeSnippet(currentPkg.prevLine, currentPkg.line, currentPkg.nextLine),
          dedupKey: `ANDROID_FF_PLAYSTORE_VERIFIED_001|${pkgName}`
        }));
      }
    }

    // 2. Match exato de pacotes candidatos no PackageManager (incluindo candidatos de overlay)
    if (matcher.androidPackageMap.has(pkgLow) || (matcher.overlayCandidateMap && matcher.overlayCandidateMap.has(pkgLow))) {
      const canonical = matcher.androidPackageMap.get(pkgLow) || matcher.overlayCandidateMap.get(pkgLow);
      addSignal('android_candidate_pkg', `PackageManager: ${canonical}`);
      emitEvent(buildCanonicalEvent({
        ruleId: 'ANDROID_PKG_CANDIDATE_001',
        domain: 'integridade_do_jogo',
        title: `Pacote Candidato Detectado: ${canonical}`,
        source: { path: filePath, format: 'packagemanager', line: currentPkg.lineNo },
        observed: {
          process: 'PackageManager',
          package: canonical,
          operation: 'installed_package',
          outcome: installer ? `installer=${installer}` : 'present',
          object_path: canonical
        },
        evidenceLevel: 'anomaly_review',
        heuristicWeight: 20,
        interpretation: `Identificador de pacote listado no PackageManager com correspondência exata (${canonical}).`,
        alternativeExplanations: [
          'Aplicativo instalado anteriormente e sem vínculo temporal com a partida',
          'Nome de pacote genérico em catálogo em validação'
        ],
        recommendedAction: 'Verificar data de instalação/uso e buscar evidências de interferência ativa no processo do jogo.',
        snippet: makeSnippet(currentPkg.prevLine, currentPkg.line, currentPkg.nextLine),
        dedupKey: `ANDROID_PKG_CANDIDATE_001|${canonical}`
      }));
    }

    // 3. Match exato de perfil/proxy em PackageManager
    if (matcher.proxyNamedMap.has(pkgLow)) {
      const canonical = matcher.proxyNamedMap.get(pkgLow);
      addSignal('proxy_package_installed', `PackageManager: ${canonical}`);
      emitEvent(buildCanonicalEvent({
        ruleId: 'ANDROID_PROFILE_PKG_001',
        domain: 'rede',
        title: `Pacote de Proxy/Perfil Instalado: ${canonical}`,
        source: { path: filePath, format: 'packagemanager', line: currentPkg.lineNo },
        observed: {
          process: 'PackageManager',
          package: canonical,
          operation: 'installed_package',
          outcome: 'present',
          object_path: canonical
        },
        evidenceLevel: 'anomaly_review',
        heuristicWeight: 20,
        interpretation: `Pacote compatível com indicador de proxy/perfil localizado via correspondência exata no PackageManager.`,
        alternativeExplanations: ['Aplicativo inativo no aparelho sem uso durante a partida'],
        recommendedAction: 'Confirmar se houve configuração de proxy ou tráfego ativo simultâneo à partida.',
        snippet: makeSnippet(currentPkg.prevLine, currentPkg.line, currentPkg.nextLine),
        dedupKey: `ANDROID_PROFILE_PKG_001|${canonical}`
      }));
    }

    // 4. Match exato de gerenciador Root (Magisk / KernelSU / APatch)
    if (matcher.rootManagerPackages.has(pkgLow)) {
      const canonical = matcher.androidRootMap.get(pkgLow) || pkgName;
      addSignal('android_root_env', `PackageManager: ${canonical}`);
      emitEvent(buildCanonicalEvent({
        ruleId: 'ANDROID_ROOT_MANAGER_001',
        domain: 'seguranca_do_dispositivo',
        title: `Gerenciador de Root Detectado: ${canonical}`,
        source: { path: filePath, format: 'packagemanager', line: currentPkg.lineNo },
        observed: {
          process: 'PackageManager',
          package: canonical,
          operation: 'installed_package',
          outcome: 'present',
          object_path: canonical
        },
        evidenceLevel: 'anomaly_review',
        heuristicWeight: 15,
        interpretation: `Pacote associado a gerenciamento de privilégios root instalado no dispositivo (${canonical}).`,
        alternativeExplanations: ['Uso do aparelho pessoal com root para fins não relacionados ao jogo'],
        recommendedAction: 'Registrar no domínio de segurança do dispositivo; nunca punir sem evidência de interferência no jogo.',
        snippet: makeSnippet(currentPkg.prevLine, currentPkg.line, currentPkg.nextLine),
        dedupKey: `ANDROID_ROOT_MANAGER_001|${canonical}`
      }));
    }

    currentPkg = null;
  };

  return {
    feedLine(line, lineNo, prevLine, nextLine) {
      if (!line) {
        if (currentPkg) {
          currentPkg.countdown--;
          if (currentPkg.countdown <= 0) flushPackageBlock();
        }
        if (pendingOverlay) {
          flushOverlayBlock();
        }
        hexParser.feedLine(line, lineNo);
        return;
      }

      // 0. Cabeçalho de DeviceInfo (primeiras ocorrências apenas)
      if (lineNo <= 12000) {
        if (!deviceInfo.model) {
          const m = MODEL_RE.exec(line) || BUILD_FP_RE.exec(line);
          if (m) deviceInfo.model = m[1].trim();
        }
        if (!deviceInfo.brand) {
          const m = BRAND_RE.exec(line);
          if (m) deviceInfo.brand = m[1].trim();
        }
        if (!deviceInfo.osVersion) {
          const m = OS_VER_RE.exec(line);
          if (m) deviceInfo.osVersion = 'Android ' + (m[1] || m[2]).trim();
        }
        if (!deviceInfo.serial) {
          const m = SERIAL_RE.exec(line);
          if (m) deviceInfo.serial = m[1].trim();
        }
        if (!deviceInfo.kernel) {
          const m = KERNEL_RE.exec(line);
          if (m) deviceInfo.kernel = 'Linux ' + m[1].trim();
        }
      }

      // 1. Hex Dump Parser
      hexParser.feedLine(line, lineNo);

      // 2. Estado de bloco PackageManager
      const mPkgHdr = PKG_HEADER_RE.exec(line);
      if (mPkgHdr) {
        flushPackageBlock();
        currentPkg = {
          name: mPkgHdr[1],
          lineNo,
          prevLine,
          line,
          nextLine,
          versionName: '',
          installerPackageName: null,
          countdown: 75
        };
      } else if (currentPkg) {
        currentPkg.countdown--;
        const mVer = PKG_VERSION_RE.exec(line);
        if (mVer && !currentPkg.versionName) currentPkg.versionName = mVer[1];
        const mInst = PKG_INSTALLER_RE.exec(line);
        if (mInst) {
          currentPkg.installerPackageName = mInst[1].trim();
          flushPackageBlock();
        } else if (currentPkg.countdown <= 0) {
          flushPackageBlock();
        }
      }

      const meta = extractLineMeta(line);

      // 3. Integridade de Boot / SELinux (getprop)
      const checkBoot = () => {
        let m;
        if ((m = BOOT_STATE_RE.exec(line))) {
          coverage.saw_getprop = true;
          coverage.boot_keys_seen.add('verifiedbootstate');
          const val = m[2].toLowerCase();
          if (val !== 'green') {
            addSignal('android_boot_unlocked', `verifiedbootstate=${val}`);
            emitEvent(buildCanonicalEvent({
              ruleId: 'ANDROID_BOOT_INTEGRITY_001',
              domain: 'seguranca_do_dispositivo',
              title: `Estado de Boot Verificado não-padrão (${val})`,
              source: { path: filePath, format: 'getprop', line: lineNo },
              observed: { timestamp: meta.timestamp, process: 'getprop', operation: m[1], outcome: val },
              evidenceLevel: 'anomaly_review',
              heuristicWeight: 15,
              interpretation: `Propriedade ${m[1]} indica estado '${val}' (diferente de 'green').`,
              alternativeExplanations: ['Bootloader desbloqueado para ROM customizada sem relação com o jogo'],
              recommendedAction: 'Considerar apenas no domínio de segurança do dispositivo.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `ANDROID_BOOT_INTEGRITY_001|${m[1]}|${val}`
            }));
          }
          return true;
        }
        if ((m = FLASH_LOCKED_RE.exec(line))) {
          coverage.saw_getprop = true;
          coverage.boot_keys_seen.add('flash.locked');
          const val = m[2];
          if (val === '0') {
            addSignal('android_boot_unlocked', 'flash.locked=0');
            emitEvent(buildCanonicalEvent({
              ruleId: 'ANDROID_BOOT_INTEGRITY_001',
              domain: 'seguranca_do_dispositivo',
              title: 'Bootloader Desbloqueado (ro.boot.flash.locked=0)',
              source: { path: filePath, format: 'getprop', line: lineNo },
              observed: { timestamp: meta.timestamp, process: 'getprop', operation: m[1], outcome: val },
              evidenceLevel: 'anomaly_review',
              heuristicWeight: 15,
              interpretation: 'Bootloader reportado como desbloqueado.',
              alternativeExplanations: ['Aparelho de desenvolvedor ou ROM alternativa'],
              recommendedAction: 'Correlacionar apenas se houver interferência direta no jogo.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `ANDROID_BOOT_INTEGRITY_001|flash.locked|0`
            }));
          }
          return true;
        }
        if ((m = BUILD_TAGS_RE.exec(line))) {
          coverage.saw_getprop = true;
          coverage.boot_keys_seen.add('build.tags');
          const val = m[2].toLowerCase();
          if (val.includes('test-keys')) {
            addSignal('android_boot_unlocked', `ro.build.tags=${val}`);
            emitEvent(buildCanonicalEvent({
              ruleId: 'ANDROID_BOOT_INTEGRITY_001',
              domain: 'seguranca_do_dispositivo',
              title: `Build assinada com test-keys (${val})`,
              source: { path: filePath, format: 'getprop', line: lineNo },
              observed: { timestamp: meta.timestamp, process: 'getprop', operation: m[1], outcome: val },
              evidenceLevel: 'anomaly_review',
              heuristicWeight: 15,
              interpretation: `Propriedade ro.build.tags indica '${val}' em vez de 'release-keys'.`,
              alternativeExplanations: ['Custom ROM / AOSP dev build'],
              recommendedAction: 'Correlacionar com demais evidências.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `ANDROID_BOOT_INTEGRITY_001|build.tags|${val}`
            }));
          }
          return true;
        }
        if ((m = VERITY_MODE_RE.exec(line))) {
          coverage.saw_getprop = true;
          coverage.boot_keys_seen.add('veritymode');
          const val = m[2].toLowerCase();
          if (val === 'disabled' || val === 'logging') {
            addSignal('android_boot_unlocked', `veritymode=${val}`);
            emitEvent(buildCanonicalEvent({
              ruleId: 'ANDROID_BOOT_INTEGRITY_001',
              domain: 'seguranca_do_dispositivo',
              title: `dm-verity em modo não restritivo (${val})`,
              source: { path: filePath, format: 'getprop', line: lineNo },
              observed: { timestamp: meta.timestamp, process: 'getprop', operation: m[1], outcome: val },
              evidenceLevel: 'anomaly_review',
              heuristicWeight: 15,
              interpretation: `Propriedade ro.boot.veritymode=${val}.`,
              alternativeExplanations: ['Sistema modificado para depuração'],
              recommendedAction: 'Avaliar contexto de root/injeção.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `ANDROID_BOOT_INTEGRITY_001|veritymode|${val}`
            }));
          }
          return true;
        }
        if ((m = SELINUX_STATUS_RE.exec(line))) {
          coverage.boot_keys_seen.add('selinux');
          const mode = m[1].toLowerCase();
          if (mode === 'permissive' || mode === 'disabled') {
            addSignal('android_boot_unlocked', `SELinux=${mode}`);
            emitEvent(buildCanonicalEvent({
              ruleId: 'ANDROID_BOOT_INTEGRITY_001',
              domain: 'seguranca_do_dispositivo',
              title: `SELinux em modo ${mode}`,
              source: { path: filePath, format: 'selinux', line: lineNo },
              observed: { timestamp: meta.timestamp, process: meta.process || 'SELinux', operation: 'selinux_mode', outcome: mode },
              evidenceLevel: 'anomaly_review',
              heuristicWeight: 15,
              interpretation: `O controle mandatório SELinux foi encontrado em modo ${mode}.`,
              alternativeExplanations: ['Kernel de desenvolvimento'],
              recommendedAction: 'Correlacionar com eventos auditd e pacotes suspeitos.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `ANDROID_BOOT_INTEGRITY_001|selinux|${mode}`
            }));
          }
          return true;
        }
        return false;
      };
      if (line.includes('ro.boot.') || line.includes('ro.build.tags') || line.includes('SELinux') || line.includes('getenforce')) {
        checkBoot();
      }

      // 4. Settings (pkg:by4a.setedit22 e pkg:com.android.shell — formatos '=' e ':')
      if (line.includes('pkg:by4a.setedit22') || line.includes('pkg:com.android.shell')) {
        const mPkg = SETTINGS_PKG_RE.exec(line);
        if (mPkg) {
          const pkgOrigin = mPkg[1];
          const pkgOriginLow = pkgOrigin.toLowerCase();
          const mKey = SETTINGS_NAME_RE.exec(line);
          const mVal = SETTINGS_VALUE_RE.exec(line);
          // Não emitir anomalias por falha de parsing ou campos ausentes
          if (mKey && mVal) {
            const keyName = mKey[1];
            const keyLow = keyName.toLowerCase();
            const keyVal = mVal[1];
            const mDef = SETTINGS_DEFAULT_RE.exec(line);
            const inlineDefault = mDef ? mDef[1] : null;
            const baseline = SETTINGS_BASELINES[keyLow] || null;
            const isDefault = Boolean(
              (baseline && baseline.defaults.has(keyVal)) ||
              (inlineDefault !== null && keyVal === inlineDefault)
            );

            if (isDefault) {
              emitEvent(buildCanonicalEvent({
                ruleId: 'ANDROID_SETTINGS_DEFAULT_001',
                domain: baseline ? baseline.domain : 'seguranca_do_dispositivo',
                title: `Configuração padrão em ${pkgOrigin} (${keyName}=${keyVal})`,
                source: { path: filePath, format: 'dumpsys_settings', line: lineNo },
                observed: {
                  timestamp: meta.timestamp,
                  process: 'SettingsProvider',
                  package: pkgOrigin,
                  operation: keyName,
                  outcome: keyVal,
                  object_path: `${pkgOrigin}:${keyName}`,
                  raw_detail: inlineDefault !== null ? `default=${inlineDefault}` : 'baseline_match'
                },
                evidenceLevel: 'informational',
                heuristicWeight: 0,
                interpretation: `Valor ${keyName}=${keyVal} compatível com o baseline padrão do Android.`,
                alternativeExplanations: ['Configuração nativa do sistema'],
                recommendedAction: 'Nenhuma ação necessária.',
                snippet: makeSnippet(prevLine, line, nextLine),
                dedupKey: `ANDROID_SETTINGS_DEFAULT_001|${pkgOriginLow}|${keyLow}|${keyVal}`
              }));
            } else if (baseline) {
              if (baseline.isDebugFlag && pkgOriginLow === 'com.android.shell') {
                const isWifi = keyLow === 'adb_wifi_enabled';
                emitEvent(buildCanonicalEvent({
                  ruleId: isWifi ? 'ANDROID_ADB_WIRELESS_DEBUGGING_001' : 'ANDROID_ADB_USB_DEBUGGING_001',
                  domain: 'depuracao',
                  title: isWifi ? `Depuração Wireless via settings (${keyName}=${keyVal})` : `Depuração USB via settings (${keyName}=${keyVal})`,
                  source: { path: filePath, format: 'dumpsys_settings', line: lineNo },
                  observed: { timestamp: meta.timestamp, process: 'SettingsProvider', package: pkgOrigin, operation: keyName, outcome: keyVal },
                  evidenceLevel: 'informational',
                  heuristicWeight: 0,
                  interpretation: `Sinalizador de depuração ${keyName}=${keyVal} registrado por ${pkgOrigin}. Não comprova conexão remota nem trapaça.`,
                  alternativeExplanations: ['Depuração ativada pelo usuário ou utilitário local (Brevent/Shizuku)'],
                  recommendedAction: 'Apenas contexto de depuração.',
                  snippet: makeSnippet(prevLine, line, nextLine),
                  dedupKey: `ANDROID_SETTINGS_DEBUG|${keyLow}|${keyVal}`
                }));
              } else if (pkgOriginLow === 'by4a.setedit22') {
                addSignal('android_setedit_anomaly', `SetEdit (${keyName}=${keyVal})`);
                emitEvent(buildCanonicalEvent({
                  ruleId: 'ANDROID_SETTINGS_SETEDIT_ANOMALY_001',
                  domain: baseline.domain,
                  title: `Alteração não padrão via SetEdit (${keyName}=${keyVal})`,
                  source: { path: filePath, format: 'dumpsys_settings', line: lineNo },
                  observed: {
                    timestamp: meta.timestamp,
                    process: 'SettingsProvider',
                    package: pkgOrigin,
                    operation: keyName,
                    outcome: keyVal,
                    object_path: `${pkgOrigin}:${keyName}`
                  },
                  evidenceLevel: 'anomaly_review',
                  heuristicWeight: 15,
                  interpretation: `Parâmetro '${keyName}' foi modificado via ${pkgOrigin} para '${keyVal}', divergindo do baseline conhecido.`,
                  alternativeExplanations: [
                    'Ajuste de acessibilidade, tela ou preferência do usuário via SetEdit'
                  ],
                  recommendedAction: 'Verificar impacto do parâmetro e correlacionar com evidências independentes.',
                  snippet: makeSnippet(prevLine, line, nextLine),
                  dedupKey: `ANDROID_SETTINGS_SETEDIT_ANOMALY_001|${keyLow}|${keyVal}`
                }));
              } else {
                addSignal('android_shell_settings_anomaly', `com.android.shell (${keyName}=${keyVal})`);
                emitEvent(buildCanonicalEvent({
                  ruleId: 'ANDROID_SETTINGS_SHELL_ANOMALY_001',
                  domain: baseline.domain,
                  title: `Alteração não padrão via Android Shell (${keyName}=${keyVal})`,
                  source: { path: filePath, format: 'dumpsys_settings', line: lineNo },
                  observed: {
                    timestamp: meta.timestamp,
                    process: 'SettingsProvider',
                    package: pkgOrigin,
                    operation: keyName,
                    outcome: keyVal,
                    object_path: `${pkgOrigin}:${keyName}`
                  },
                  evidenceLevel: 'anomaly_review',
                  heuristicWeight: 10,
                  interpretation: `Parâmetro '${keyName}' foi alterado via ${pkgOrigin} para '${keyVal}', divergindo do baseline conhecido (pode envolver ajuste de toque/entrada ou supressão de logs de telemetria).`,
                  alternativeExplanations: [
                    'Alteração via ADB shell, Shizuku ou Brevent fora do contexto de trapaça',
                    'Preferência de acessibilidade ou economia de bateria/telemetria'
                  ],
                  recommendedAction: 'Revisar contexto da alteração e buscar correlação com fontes independentes.',
                  snippet: makeSnippet(prevLine, line, nextLine),
                  dedupKey: `ANDROID_SETTINGS_SHELL_ANOMALY_001|${keyLow}|${keyVal}`
                }));
              }
            } else {
              // Configuração sem baseline oficial -> referência não validada, peso 0
              emitEvent(buildCanonicalEvent({
                ruleId: 'ANDROID_SETTINGS_UNKNOWN_001',
                domain: 'seguranca_do_dispositivo',
                title: `Configuração sem baseline conhecido em ${pkgOrigin} (${keyName}=${keyVal})`,
                source: { path: filePath, format: 'dumpsys_settings', line: lineNo },
                observed: {
                  timestamp: meta.timestamp,
                  process: 'SettingsProvider',
                  package: pkgOrigin,
                  operation: keyName,
                  outcome: keyVal,
                  object_path: `${pkgOrigin}:${keyName}`
                },
                evidenceLevel: 'unvalidated_reference',
                heuristicWeight: 0,
                interpretation: `Chave '${keyName}' modificada por ${pkgOrigin} (valor '${keyVal}') não possui baseline oficial mapeado; registrada apenas para referência sem pontuação.`,
                alternativeExplanations: ['Chave proprietária de fabricante/OEM ou ajuste comum de sistema'],
                recommendedAction: 'Apenas referência; não classificar como trapaça sem validação do parâmetro.',
                snippet: makeSnippet(prevLine, line, nextLine),
                dedupKey: `ANDROID_SETTINGS_UNKNOWN_001|${pkgOriginLow}|${keyLow}|${keyVal}`
              }));
            }
          }
        }
      }

      // 4b. Overlays Android (WindowManager / dumpsys window / SurfaceFlinger)
      if (line.includes('mCurrentFocus=') || line.includes('mFocusedApp=')) {
        const fm = FOREGROUND_FOCUS_RE.exec(line);
        if (fm) currentForegroundApp = (fm[1] || fm[2] || '').trim();
      }

      if (pendingOverlay) {
        if (line.includes('WindowToken{') || /^\s*Window\s+#\d+/.test(line) && pendingOverlay.owner) {
          flushOverlayBlock();
        } else {
          pendingOverlay.countdown--;
          const vm = OVERLAY_VIS_RE.exec(line);
          if (vm) {
            if (vm[1]) pendingOverlay.visibility = vm[1].toLowerCase() === 'true' ? 'visible' : 'hidden';
            else if (vm[2]) pendingOverlay.visibility = (vm[2] === '0x0' || vm[2] === '0') ? 'visible' : `visibility=${vm[2]}`;
            else if (vm[3] && pendingOverlay.visibility === 'desconhecida') pendingOverlay.visibility = vm[3].toLowerCase() === 'true' ? 'surface_active' : 'no_surface';
          }
          if (!pendingOverlay.owner) {
            const parsed = parseOverlayOwnerFromLine(line);
            if (parsed) {
              pendingOverlay.status = parsed.status;
              pendingOverlay.owner = parsed.owner;
              pendingOverlay.windowName = parsed.windowName;
              pendingOverlay.detailLine = line;
              pendingOverlay.lineNo = lineNo;
              pendingOverlay.nextLine = nextLine;
              if (parsed.status === 'system_ignored') {
                pendingOverlay = null;
              }
            }
          }
          if (pendingOverlay && pendingOverlay.countdown <= 0) {
            flushOverlayBlock();
          }
        }
      }

      const isNewTokenLine = line.includes('WindowToken{') && (line.includes('type=2038') || line.includes('TYPE_APPLICATION_OVERLAY'));
      const isStandaloneOverlayLine = !pendingOverlay && (
        (line.includes('ty=2038') || line.includes('type=2038') || line.includes('TYPE_APPLICATION_OVERLAY')) ||
        (line.includes('com.zayon.optimize') && (line.includes('Window') || line.includes('Surface') || line.includes('Layer')))
      );
      if (isNewTokenLine || isStandaloneOverlayLine) {
        flushOverlayBlock();
        const isSf = line.includes('SurfaceFlinger') || line.includes('Surface(name=') || /^\s*Layer\b/.test(line);
        const execCtx = isSf ? 'surfaceflinger' : 'dumpsys_window';
        const windowType = line.includes('TYPE_APPLICATION_OVERLAY')
          ? 'TYPE_APPLICATION_OVERLAY'
          : (line.includes('2038') ? 'TYPE_APPLICATION_OVERLAY (2038)' : 'OVERLAY_LAYER');
        const inlineParsed = parseOverlayOwnerFromLine(line);
        const vm = OVERLAY_VIS_RE.exec(line);
        let vis = 'desconhecida';
        if (vm) {
          if (vm[1]) vis = vm[1].toLowerCase() === 'true' ? 'visible' : 'hidden';
          else if (vm[2]) vis = (vm[2] === '0x0' || vm[2] === '0') ? 'visible' : `visibility=${vm[2]}`;
        }

        if (inlineParsed && inlineParsed.status === 'system_ignored') {
          pendingOverlay = null;
        } else {
          pendingOverlay = {
            status: inlineParsed ? inlineParsed.status : '',
            owner: inlineParsed ? inlineParsed.owner : '',
            windowName: inlineParsed ? inlineParsed.windowName : '',
            windowType,
            process: meta.process || (isSf ? 'SurfaceFlinger' : 'WindowManager'),
            visibility: vis,
            timestamp: meta.timestamp,
            executionContext: execCtx,
            foregroundApp: currentForegroundApp,
            tokenLine: line,
            detailLine: line,
            nextLine,
            lineNo,
            countdown: 8
          };
        }
      }

      // 5. SELinux auditd & Free Fire GameAsset / JARs
      const lowLine = line.toLowerCase();
      if (lowLine.includes('avc:') && lowLine.includes('audit(')) {
        const audit = parseAuditdLine(line);
        if (audit && audit.canonical_path) {
          const cpathLow = audit.canonical_path.toLowerCase();
          const pathPkgM = FF_DATA_PATH_RE.exec(cpathLow);
          const pathOwnerPkg = pathPkgM ? pathPkgM[1] : '';
          const actorApp = (audit.app || '').trim();
          const comm = (audit.comm || '').trim();
          const action = audit.avc_action || '';
          const ops = audit.operations || [];

          if (matcher.gameArtifactPaths.shGpp2Targets.includes(cpathLow) && pathOwnerPkg && matcher.freeFirePackages.has(pathOwnerPkg.toLowerCase())) {
            const actorMatchesOwner = !actorApp || actorApp.toLowerCase() === pathOwnerPkg.toLowerCase();
            const commCompatible = comm ? FF_COMPATIBLE_COMM_RE.test(comm) : false;

            if (action === 'denied') {
              emitEvent(buildCanonicalEvent({
                ruleId: 'ANDROID_GAME_SH_GPP2_DENIED_001',
                domain: 'integridade_do_jogo',
                title: `Tentativa SELinux negada em SH-Gpp2 (${pathOwnerPkg})`,
                source: { path: filePath, format: 'selinux_audit', line: lineNo },
                observed: {
                  timestamp: audit.timestamp || meta.timestamp,
                  process: comm || meta.process,
                  package: pathOwnerPkg,
                  actor_app: actorApp || 'ausente (inferido via canonical_path)',
                  operation: ops.join(', '),
                  outcome: 'denied',
                  object_path: audit.canonical_path
                },
                evidenceLevel: 'informational',
                heuristicWeight: 0,
                interpretation: `SELinux bloqueou (denied) a operação em ${audit.canonical_path}; não houve execução permitida neste registro.`,
                alternativeExplanations: ['Operação bloqueada pelo sandbox SELinux'],
                recommendedAction: 'Apenas informativo; não penalizar sem eventos permitidos.',
                snippet: makeSnippet(prevLine, line, nextLine),
                dedupKey: `ANDROID_GAME_SH_GPP2_DENIED_001|${cpathLow}`
              }));
              return;
            }

            if (action === 'granted' && ops.includes('execute')) {
              if (!comm) {
                // Ausência de informações suficientes sobre processo responsável: não presumir execução
                emitEvent(buildCanonicalEvent({
                  ruleId: 'ANDROID_GAME_SH_GPP2_PATH_REF_001',
                  domain: 'integridade_do_jogo',
                  title: `Registro auditd incompleto em SH-Gpp2 (${pathOwnerPkg})`,
                  source: { path: filePath, format: 'selinux_audit', line: lineNo },
                  observed: {
                    timestamp: audit.timestamp || meta.timestamp,
                    process: 'Não identificado',
                    package: pathOwnerPkg,
                    actor_app: actorApp || 'ausente',
                    operation: ops.join(', '),
                    outcome: action,
                    object_path: audit.canonical_path
                  },
                  evidenceLevel: 'unvalidated_reference',
                  heuristicWeight: 0,
                  interpretation: 'Registro auditd sem campo comm= suficiente para confirmar processo responsável; execução não presumida.',
                  alternativeExplanations: ['Log truncado ou incompleto'],
                  recommendedAction: 'Verificar logs completos antes de concluir execução.',
                  snippet: makeSnippet(prevLine, line, nextLine),
                  dedupKey: `ANDROID_GAME_SH_GPP2_PATH_REF_001|${cpathLow}|incomplete`
                }));
                return;
              }

              if (!actorMatchesOwner || !commCompatible) {
                addSignal('ff_sh_gpp2_mismatch', `Inconsistência auditd SH-Gpp2 (dono=${pathOwnerPkg}, comm=${comm}, app=${actorApp || 'ausente'})`);
                emitEvent(buildCanonicalEvent({
                  ruleId: 'ANDROID_GAME_SH_GPP2_CTX_MISMATCH_001',
                  domain: 'integridade_do_jogo',
                  title: `Inconsistência Contextual em SH-Gpp2 (dono: ${pathOwnerPkg}, processo: ${comm})`,
                  source: { path: filePath, format: 'selinux_audit', line: lineNo },
                  observed: {
                    timestamp: audit.timestamp || meta.timestamp,
                    process: comm,
                    package: pathOwnerPkg,
                    actor_app: actorApp || 'ausente (inferido via canonical_path)',
                    operation: ops.join(', '),
                    outcome: `${action} (context_mismatch)`,
                    object_path: audit.canonical_path
                  },
                  evidenceLevel: 'anomaly_review',
                  heuristicWeight: 30,
                  interpretation: `Operação execute permitida em arquivo cujo proprietário é '${pathOwnerPkg}', porém realizada por processo/app incompatível (comm='${comm}', app='${actorApp || 'ausente'}').`,
                  alternativeExplanations: ['Ferramenta de sistema/backup ou contexto SELinux herdado fora da partida'],
                  recommendedAction: 'Investigar processo responsável pela operação e correlacionar com fontes independentes.',
                  snippet: makeSnippet(prevLine, line, nextLine),
                  dedupKey: `ANDROID_GAME_SH_GPP2_CTX_MISMATCH_001|${cpathLow}|${comm}|${actorApp}`
                }));
                return;
              }

              addSignal('ff_sh_gpp2_exec', `auditd granted execute SH-Gpp2 (${pathOwnerPkg}, comm=${comm})`);
              emitEvent(buildCanonicalEvent({
                ruleId: 'ANDROID_GAME_SH_GPP2_EXEC_001',
                domain: 'integridade_do_jogo',
                title: `Execução em GameAsset SH-Gpp2 (${pathOwnerPkg})`,
                source: { path: filePath, format: 'selinux_audit', line: lineNo },
                observed: {
                  timestamp: audit.timestamp || meta.timestamp,
                  process: comm,
                  package: pathOwnerPkg,
                  actor_app: actorApp || 'ausente (inferido via canonical_path)',
                  operation: ops.join(', '),
                  outcome: action,
                  object_path: audit.canonical_path
                },
                evidenceLevel: 'anomaly_review',
                heuristicWeight: 30,
                interpretation: `SELinux permitiu (granted) operação de execução pelo processo '${comm}' no caminho de propriedade de '${pathOwnerPkg}' (${audit.canonical_path}); requer comparação com baseline oficial.`,
                alternativeExplanations: [
                  'Recurso específico de build/fonte da versão atual do jogo',
                  'Evento histórico anterior a reinstalação limpa'
                ],
                recommendedAction: 'Verificar integridade/versão do jogo e buscar evidências independentes (ex.: PackageManager/hooking).',
                snippet: makeSnippet(prevLine, line, nextLine),
                dedupKey: `ANDROID_GAME_SH_GPP2_EXEC_001|${cpathLow}|${action}`
              }));
              return;
            }

            // Operação sem execute (ex.: read/getattr): não presumir execução
            emitEvent(buildCanonicalEvent({
              ruleId: 'ANDROID_GAME_SH_GPP2_PATH_REF_001',
              domain: 'integridade_do_jogo',
              title: `Acesso não-executável a SH-Gpp2 (${pathOwnerPkg})`,
              source: { path: filePath, format: 'selinux_audit', line: lineNo },
              observed: {
                timestamp: audit.timestamp || meta.timestamp,
                process: comm || meta.process || 'Não identificado',
                package: pathOwnerPkg,
                actor_app: actorApp || 'ausente (inferido via canonical_path)',
                operation: ops.join(', '),
                outcome: action,
                object_path: audit.canonical_path
              },
              evidenceLevel: 'unvalidated_reference',
              heuristicWeight: 0,
              interpretation: `Operação '${ops.join(', ')}' sem 'execute' em ${audit.canonical_path}; não comprova execução.`,
              alternativeExplanations: ['Leitura regular de recurso pelo aplicativo ou sistema'],
              recommendedAction: 'Apenas referência; verificar se existe operação execute correspondente.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `ANDROID_GAME_SH_GPP2_PATH_REF_001|${cpathLow}|${ops.join('_')}`
            }));
            return;
          }

          if (cpathLow.includes('-shgap-') && FF_DATA_PATH_RE.test(cpathLow)) {
            const pkgM = FF_DATA_PATH_RE.exec(cpathLow);
            const ffPkg = pkgM ? pkgM[1] : (audit.app || 'com.dts.freefire');
            addSignal('ff_shgap_dir', `auditd -SHgap- (${ffPkg})`);
            emitEvent(buildCanonicalEvent({
              ruleId: 'ANDROID_GAME_SHGAP_DIR_001',
              domain: 'integridade_do_jogo',
              title: `Pasta Não Verificada -SHgap- no diretório do Free Fire (${ffPkg})`,
              source: { path: filePath, format: 'selinux_audit', line: lineNo },
              observed: {
                timestamp: audit.timestamp || meta.timestamp,
                process: comm || meta.process,
                package: ffPkg,
                operation: ops.join(', ') || 'access',
                outcome: action,
                object_path: audit.canonical_path
              },
              evidenceLevel: 'anomaly_review',
              heuristicWeight: 25,
              interpretation: `Diretório '-SHgap-' registrado dentro do armazenamento do Free Fire (${audit.canonical_path}).`,
              alternativeExplanations: ['Cache residual de versão antiga caso não haja execução ativa'],
              recommendedAction: 'Comparar com baseline oficial e recomendar reinstalação limpa se confirmado.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `ANDROID_GAME_SHGAP_DIR_001|${ffPkg}`
            }));
            return;
          }
        }
      }

      // GameAsset SH-Gpp2 / -SHgap- fora de linha auditd (ex.: ls/dumpsys com caminho completo)
      if (lowLine.includes('sh-gpp2')) {
        const gm = FF_GAMEASSET_PATH_RE.exec(canonicalizeAndroidPath(line));
        if (gm) {
          emitEvent(buildCanonicalEvent({
            ruleId: 'ANDROID_GAME_SH_GPP2_PATH_REF_001',
            domain: 'integridade_do_jogo',
            title: `Referência ao caminho SH-Gpp2 (${gm[1]})`,
            source: { path: filePath, format: format || 'text', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process, package: gm[1], operation: 'path_reference', object_path: gm[0] },
            evidenceLevel: 'unvalidated_reference',
            heuristicWeight: 0,
            interpretation: 'Caminho completo encontrado em listagem/texto sem registro auditd de execução.',
            alternativeExplanations: ['Listagem de arquivo ou histórico sem execução confirmada'],
            recommendedAction: 'Pesquisar se existe evento auditd { execute } correspondente.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `ANDROID_GAME_SH_GPP2_PATH_REF_001|${gm[1]}`
          }));
        }
      }

      if (lowLine.includes('-shgap-') && FF_DATA_PATH_RE.test(line)) {
        const fm = FF_DATA_PATH_RE.exec(line);
        const ffPkg = fm ? fm[1] : 'com.dts.freefireth';
        addSignal('ff_shgap_dir', `Caminho -SHgap- em ${ffPkg}`);
        emitEvent(buildCanonicalEvent({
          ruleId: 'ANDROID_GAME_SHGAP_DIR_001',
          domain: 'integridade_do_jogo',
          title: `Pasta Não Verificada -SHgap- em ${ffPkg}`,
          source: { path: filePath, format: format || 'text', line: lineNo },
          observed: { timestamp: meta.timestamp, process: meta.process, package: ffPkg, operation: 'path_detected', object_path: line.trim().slice(0, 140) },
          evidenceLevel: 'anomaly_review',
          heuristicWeight: 25,
          interpretation: 'Referência direta a -SHgap- dentro do diretório do jogo.',
          alternativeExplanations: ['Arquivo residual em armazenamento'],
          recommendedAction: 'Verificar integridade do diretório e solicitar reinstalação pela Play Store.',
          snippet: makeSnippet(prevLine, line, nextLine),
          dedupKey: `ANDROID_GAME_SHGAP_DIR_001|${ffPkg}`
        }));
      }

      // JARs em cache do Free Fire (app_resources_lib.jar / google_api_resources_lib.jar)
      if (lowLine.includes('app_resources_lib.jar') || lowLine.includes('google_api_resources_lib.jar')) {
        const jm = FF_JAR_PATH_RE.exec(canonicalizeAndroidPath(line));
        if (jm) {
          const ffPkg = jm[1];
          const jarName = jm[2];
          const isLoaded = CLASSLOADER_RE.test(line) || (lowLine.includes('avc:') && lowLine.includes('granted') && lowLine.includes('execute'));
          if (isLoaded) {
            addSignal('ff_jar_loaded', `ClassLoader/exec (${ffPkg}/${jarName})`);
            emitEvent(buildCanonicalEvent({
              ruleId: 'ANDROID_GAME_JAR_LOADED_001',
              domain: 'integridade_do_jogo',
              title: `Carregamento de JAR em cache do Free Fire (${jarName})`,
              source: { path: filePath, format: format || 'log', line: lineNo },
              observed: { timestamp: meta.timestamp, process: meta.process, package: ffPkg, operation: 'classloader_or_execute', outcome: 'loaded', object_path: jm[0] },
              evidenceLevel: 'anomaly_review',
              heuristicWeight: 25,
              interpretation: `Arquivo ${jarName} no cache do ${ffPkg} associado a evento de carregamento/execução.`,
              alternativeExplanations: ['Cache dinâmico de SDK de terceiros no jogo'],
              recommendedAction: 'Comparar hash/origem com build oficial do jogo.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `ANDROID_GAME_JAR_LOADED_001|${ffPkg}|${jarName}`
            }));
          } else {
            emitEvent(buildCanonicalEvent({
              ruleId: 'ANDROID_GAME_JAR_PRESENT_001',
              domain: 'integridade_do_jogo',
              title: `Referência a JAR em cache (${jarName})`,
              source: { path: filePath, format: format || 'text', line: lineNo },
              observed: { timestamp: meta.timestamp, process: meta.process, package: ffPkg, operation: 'cache_listing', outcome: 'present_only', object_path: jm[0] },
              evidenceLevel: 'unvalidated_reference',
              heuristicWeight: 0,
              interpretation: `Caminho ${jm[0]} citado sem evento de carregamento por ClassLoader ou execução.`,
              alternativeExplanations: ['Cache inativo de biblioteca auxiliar'],
              recommendedAction: 'Verificar se há evento ClassLoader ou auditd correspondente.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `ANDROID_GAME_JAR_PRESENT_001|${ffPkg}|${jarName}`
            }));
          }
        }
      }

      // 6. Estabilidade & Crashes (sempre peso 0, exceto lib injetada comprovada no backtrace)
      let crashM;
      if ((crashM = CRASH_CMDLINE_RE.exec(line))) {
        crashCmdline = crashM[1].trim();
      } else if ((crashM = LOW_MEM_RE.exec(line))) {
        emitEvent(buildCanonicalEvent({
          ruleId: 'ANDROID_STABILITY_LOW_MEMORY_001',
          domain: 'estabilidade',
          title: `Encerramento por Pouca Memória (LOW_MEMORY: ${crashM[1]})`,
          source: { path: filePath, format: format || 'bugreport', line: lineNo },
          observed: { timestamp: meta.timestamp, process: crashM[1], package: crashM[1], operation: 'process_kill', outcome: 'LOW_MEMORY' },
          evidenceLevel: 'informational',
          heuristicWeight: 0,
          interpretation: 'Evento normal do LMK (Low Memory Killer) do Android por pressão de RAM. Não indica cheat.',
          alternativeExplanations: ['Consumo elevado de RAM do sistema ou do jogo'],
          recommendedAction: 'Nenhuma ação punitiva.',
          snippet: makeSnippet(prevLine, line, nextLine),
          dedupKey: `ANDROID_STABILITY_LOW_MEMORY_001|${crashM[1]}`
        }));
      } else if (SIGSEGV_RE.test(line)) {
        emitEvent(buildCanonicalEvent({
          ruleId: 'ANDROID_STABILITY_CRASH_001',
          domain: 'estabilidade',
          title: `Diagnóstico de Crash de Memória (SIGSEGV/PAC${crashCmdline ? `: ${crashCmdline}` : ''})`,
          source: { path: filePath, format: format || 'tombstone', line: lineNo },
          observed: { timestamp: meta.timestamp, process: meta.process || crashCmdline || 'UnityMain', package: crashCmdline, operation: 'signal_11_crash', outcome: 'SIGSEGV' },
          evidenceLevel: 'informational',
          heuristicWeight: 0,
          interpretation: 'Falha de segmentação (SIGSEGV / SEGV_MAPERR) ou flag de ponteiro ARM64 (PR_PAC_*). Crashes isolados são eventos de estabilidade e não provam injeção.',
          alternativeExplanations: ['Bug de software do aplicativo ou driver gráfico'],
          recommendedAction: 'Inspecionar apenas se o backtrace apontar módulo externo injetado.',
          snippet: makeSnippet(prevLine, line, nextLine),
          dedupKey: `ANDROID_STABILITY_CRASH_001|${filePath}|${crashCmdline}`
        }));
      } else if (line.includes('pc ')) {
        const bm = BACKTRACE_LINE_RE.exec(line);
        if (bm && INJECTED_SO_RE.test(bm[1])) {
          addSignal('injected_backtrace', `Backtrace module: ${bm[1]}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'ANDROID_CRASH_INJECTED_BACKTRACE_001',
            domain: 'integridade_do_jogo',
            title: `Biblioteca anômala no backtrace de crash (${bm[1].split('/').pop()})`,
            source: { path: filePath, format: format || 'tombstone', line: lineNo },
            observed: { timestamp: meta.timestamp, process: crashCmdline || meta.process, package: crashCmdline, operation: 'backtrace_frame', object_path: bm[1] },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 30,
            interpretation: `Frame de crash referencia módulo fora do padrão oficial (${bm[1]}).`,
            alternativeExplanations: ['Overlay de terceiros instalado no sistema'],
            recommendedAction: 'Correlacionar com processos em execução e pacotes instalados.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `ANDROID_CRASH_INJECTED_BACKTRACE_001|${bm[1]}`
          }));
        }
      }

      // 7. Diagnóstico de Logging (chatty, dropped logs, log_overrun, etc.) — NUNCA pontua risco
      const diagMatches = matcher.findAllMatches(matcher.androidLoggingDiagRe, line);
      if (diagMatches.length > 0) {
        for (const t of diagMatches) {
          coverage.logging_diagnostics.add(t.toLowerCase());
        }
        const term = diagMatches[0];
        emitEvent(buildCanonicalEvent({
          ruleId: 'ANDROID_LOG_COVERAGE_DIAG_001',
          domain: 'cobertura_log',
          title: `Diagnóstico do buffer logd (${term})`,
          source: { path: filePath, format: format || 'logcat', line: lineNo },
          observed: { timestamp: meta.timestamp, process: meta.process || 'logd', operation: 'logging_diagnostics', outcome: term },
          evidenceLevel: 'informational',
          heuristicWeight: 0,
          interpretation: `Comportamento padrão da infraestrutura logd (${term}) indicando limitação/rotação de buffer. Não indica adulteração de logs.`,
          alternativeExplanations: ['Alto volume natural de logs do sistema Android'],
          recommendedAction: 'Usar apenas como referência de cobertura dos logs.',
          snippet: makeSnippet(prevLine, line, nextLine),
          dedupKey: `ANDROID_LOG_COVERAGE_DIAG_001|${term.toLowerCase()}`
        }));
      }

      // 8. ADB / USB / Depuração (7 estados distintos; nunca confundir porta configurada com conexão remota)
      if (USB_BENIGN_RE.test(line) && !ADB_USB_DEBUG_RE.test(line)) {
        emitEvent(buildCanonicalEvent({
          ruleId: 'ANDROID_TELEMETRY_BENIGN_USB_001',
          domain: 'depuracao',
          title: 'Telemetria normal de USB/Entrada/Rede (Informativo)',
          source: { path: filePath, format: format || 'log', line: lineNo },
          observed: { timestamp: meta.timestamp, process: meta.process || 'system', operation: 'usb_input_dhcp', outcome: 'benign' },
          evidenceLevel: 'informational',
          heuristicWeight: 0,
          interpretation: 'Conexão USB, protocolo MTP/PTP, lease DHCP ou InputDispatcher são eventos normais do Android.',
          alternativeExplanations: ['Carregamento por cabo ou transferência de mídia'],
          recommendedAction: 'Nenhuma ação necessária.',
          snippet: makeSnippet(prevLine, line, nextLine),
          dedupKey: `ANDROID_TELEMETRY_BENIGN_USB_001|${filePath}`
        }));
      }

      if (lowLine.includes('adb') || lowLine.includes('5555') || lowLine.includes('usb') || INPUT_INJ_RE.test(line)) {
        const tcpPropActive = ADB_TCP_PROP_ACTIVE_RE.exec(line);
        const tcpPortNum = tcpPropActive ? parseInt(tcpPropActive[1], 10) : 0;

        if (tcpPortNum > 0) {
          addSignal('android_adb_tcp_port', `Porta ADB TCP configurada (${tcpPortNum})`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'ANDROID_ADB_TCP_PORT_CONFIGURED_001',
            domain: 'depuracao',
            title: `Porta ADB TCP Configurada (${tcpPortNum})`,
            source: { path: filePath, format: format || 'getprop', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'getprop', operation: 'adb_tcp_port_configured', outcome: String(tcpPortNum) },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 8,
            interpretation: `Propriedade de porta ADB TCP configurada na porta ${tcpPortNum} (diferente de valor vazio '[]' ou '-1'). Isso indica configuração de porta, mas NÃO comprova conexão remota estabelecida.`,
            alternativeExplanations: [
              'Utilitário local legítimo (Brevent ou Shizuku) operando em loopback',
              'Depuração sem fio Android ativada anteriormente pelo usuário'
            ],
            recommendedAction: 'Verificar se há registro independente de conexão remota ou execução ADB durante a partida.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `ANDROID_ADB_TCP_PORT_CONFIGURED_001|${tcpPortNum}`
          }));
        } else if (ADB_TCP_PROP_ANY_RE.test(line)) {
          emitEvent(buildCanonicalEvent({
            ruleId: 'ANDROID_ADB_STATE_TELEMETRY_001',
            domain: 'depuracao',
            title: 'Propriedade ADB TCP inativa (vazia / -1)',
            source: { path: filePath, format: format || 'getprop', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'getprop', operation: 'adb_tcp_port_inactive', outcome: 'inactive' },
            evidenceLevel: 'informational',
            heuristicWeight: 0,
            interpretation: 'Propriedade de porta ADB TCP sem porta ativa (vazia, 0 ou -1).',
            alternativeExplanations: ['Estado padrão do Android'],
            recommendedAction: 'Nenhuma ação necessária.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `ANDROID_ADB_STATE_TELEMETRY_001|adb_tcp_inactive`
          }));
        } else if (ADB_LOOPBACK_RE.test(line)) {
          const lm = ADB_LOOPBACK_RE.exec(line);
          emitEvent(buildCanonicalEvent({
            ruleId: 'ANDROID_ADB_LOCAL_LOOPBACK_001',
            domain: 'depuracao',
            title: `ADB em loopback local (${lm[1]}:5555)`,
            source: { path: filePath, format: format || 'log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'adbd', operation: 'adb_loopback', outcome: `${lm[1]}:5555` },
            evidenceLevel: 'informational',
            heuristicWeight: 0,
            interpretation: `Socket ADB em loopback local (${lm[1]}:5555), padrão compatível com ferramentas legítimas locais (Brevent/Shizuku).`,
            alternativeExplanations: ['Brevent / Shizuku operando localmente no aparelho'],
            recommendedAction: 'Não tratar como acesso remoto externo.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `ANDROID_ADB_LOCAL_LOOPBACK_001|${lm[1].toLowerCase()}`
          }));
        } else if (ADB_REMOTE_CONN_RE.test(line)) {
          const rm = ADB_REMOTE_CONN_RE.exec(line);
          const remoteIp = rm[1] || rm[3] || '';
          const remotePort = rm[2] || '5555';
          if (remoteIp && remoteIp !== '127.0.0.1' && remoteIp !== '0.0.0.0') {
            addSignal('android_adb_remote', `Conexão remota ADB (${remoteIp}:${remotePort})`);
            emitEvent(buildCanonicalEvent({
              ruleId: 'ANDROID_ADB_REMOTE_001',
              domain: 'depuracao',
              title: `Conexão Remota ADB Registrada (${remoteIp}:${remotePort})`,
              source: { path: filePath, format: format || 'log', line: lineNo },
              observed: { timestamp: meta.timestamp, process: meta.process || 'adbd', operation: 'adb_remote_connection', outcome: `${remoteIp}:${remotePort}` },
              evidenceLevel: 'anomaly_review',
              heuristicWeight: 12,
              interpretation: `Conexão ADB registrada com endereço de rede não-loopback (${remoteIp}:${remotePort}).`,
              alternativeExplanations: ['Depuração sem fio Android Studio ou espelhamento scrcpy em rede local'],
              recommendedAction: 'Verificar horário da conexão em relação à partida e correlacionar com outros indícios.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `ANDROID_ADB_REMOTE_001|${remoteIp}:${remotePort}`
            }));
          }
        } else if (ADB_PORT_FWD_RE.test(line)) {
          const fm = ADB_PORT_FWD_RE.exec(line);
          addSignal('android_adb_forward', fm[1].trim());
          emitEvent(buildCanonicalEvent({
            ruleId: 'ANDROID_ADB_PORT_FORWARD_001',
            domain: 'depuracao',
            title: `Encaminhamento de Porta ADB (${fm[1].trim()})`,
            source: { path: filePath, format: format || 'log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'adbd', operation: 'adb_port_forward', outcome: fm[1].trim() },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 10,
            interpretation: `Registro de redirecionamento de porta ADB (${fm[1].trim()}).`,
            alternativeExplanations: ['Túnel de desenvolvimento local, depuração de webview ou scrcpy'],
            recommendedAction: 'Verificar destino da porta encaminhada e horário do evento.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `ANDROID_ADB_PORT_FORWARD_001|${fm[1].trim().toLowerCase()}`
          }));
        } else if (ADB_SVC_ACTIVE_RE.test(line)) {
          emitEvent(buildCanonicalEvent({
            ruleId: 'ANDROID_ADB_SERVICE_ACTIVE_001',
            domain: 'depuracao',
            title: 'Serviço ADB (adbd) ativo sem conexão remota confirmada',
            source: { path: filePath, format: format || 'log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'adbd', operation: 'adbd_service_active', outcome: 'running' },
            evidenceLevel: 'informational',
            heuristicWeight: 0,
            interpretation: 'Daemon adbd em execução no dispositivo; por si só não comprova conexão externa nem interferência.',
            alternativeExplanations: ['Depuração USB/wireless ativada pelo usuário ou coleta do próprio bugreport'],
            recommendedAction: 'Apenas contexto operacional.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `ANDROID_ADB_SERVICE_ACTIVE_001`
          }));
        } else if (ADB_WIRELESS_DEBUG_RE.test(line)) {
          emitEvent(buildCanonicalEvent({
            ruleId: 'ANDROID_ADB_WIRELESS_DEBUGGING_001',
            domain: 'depuracao',
            title: 'Depuração Wireless (ADB Wi-Fi) habilitada',
            source: { path: filePath, format: format || 'log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'AdbDebuggingManager', operation: 'adb_wireless_debugging', outcome: 'enabled' },
            evidenceLevel: 'informational',
            heuristicWeight: 0,
            interpretation: 'Recurso de Depuração por Wi-Fi habilitado no Android. Frequente em usuários de Brevent/Shizuku e desenvolvedores.',
            alternativeExplanations: ['Brevent / Shizuku / Depuração sem fio Android'],
            recommendedAction: 'Apenas contexto de depuração.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `ANDROID_ADB_WIRELESS_DEBUGGING_001`
          }));
        } else if (ADB_USB_DEBUG_RE.test(line)) {
          emitEvent(buildCanonicalEvent({
            ruleId: 'ANDROID_ADB_USB_DEBUGGING_001',
            domain: 'depuracao',
            title: 'Depuração USB habilitada',
            source: { path: filePath, format: format || 'log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'UsbService', operation: 'adb_usb_debugging', outcome: 'enabled' },
            evidenceLevel: 'informational',
            heuristicWeight: 0,
            interpretation: 'Modo de depuração USB habilitado no dispositivo (frequentemente necessário para gerar bugreport).',
            alternativeExplanations: ['Ativado pelo próprio jogador para coletar o bugreport ou uso cotidiano'],
            recommendedAction: 'Nenhuma ação punitiva.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `ANDROID_ADB_USB_DEBUGGING_001`
          }));
        } else if (INPUT_INJ_RE.test(line)) {
          const im = INPUT_INJ_RE.exec(line);
          emitEvent(buildCanonicalEvent({
            ruleId: 'ANDROID_INPUT_TELEMETRY_001',
            domain: 'depuracao',
            title: `Telemetria de Injeção de Entrada ADB (${im[1]})`,
            source: { path: filePath, format: format || 'log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'shell', operation: im[1] },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 10,
            interpretation: `Registro de comando ou API '${im[1]}' no histórico.`,
            alternativeExplanations: ['Automação ou teste fora do horário da partida'],
            recommendedAction: 'Confirmar se ocorreu durante o horário da partida.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `ANDROID_INPUT_TELEMETRY_001|${im[1].toLowerCase()}`
          }));
        }
      }

      // 9. Proxy / MITM / Domínios nomeados / IPs / Aliases / Perfis / Ferramentas (PROXY_SHORT_TOKENS NUNCA é usado)
      const gProxyM = GLOBAL_PROXY_HOST_RE.exec(line);
      if (gProxyM) {
        const hostVal = gProxyM[1].trim().toLowerCase();
        if (hostVal && !['null', 'none', ':0', '""', "''", '0.0.0.0'].includes(hostVal)) {
          addSignal('android_proxy_tool', `global_http_proxy_host=${hostVal}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'ANDROID_NET_PROXY_TOOL_001',
            domain: 'rede',
            title: `Proxy HTTP Global Configurado (${hostVal})`,
            source: { path: filePath, format: format || 'dumpsys', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'ConnectivityService', operation: 'global_http_proxy_host', outcome: hostVal },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 15,
            interpretation: `Configuração global_http_proxy_host definida como '${hostVal}'.`,
            alternativeExplanations: ['Proxy corporativo ou de operadora'],
            recommendedAction: 'Verificar se o endereço corresponde a servidor proxy ou ferramenta de interceptação.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `ANDROID_NET_PROXY_TOOL_001|${hostVal}`
          }));
        }
      } else if (PROXY_TOOL_LINE_RE.test(line) && (NET_CONTEXT_RE.test(line) || PROCESS_CTX_RE.test(line))) {
        const pm = PROXY_TOOL_LINE_RE.exec(line);
        addSignal('android_proxy_tool', `Rede/Processo: ${pm[1]}`);
        emitEvent(buildCanonicalEvent({
          ruleId: 'ANDROID_NET_PROXY_TOOL_001',
          domain: 'rede',
          title: `Ferramenta de Proxy/Interceptação Detectada (${pm[1]})`,
          source: { path: filePath, format: format || 'log', line: lineNo },
          observed: { timestamp: meta.timestamp, process: meta.process, operation: 'proxy_tool', outcome: pm[1] },
          evidenceLevel: 'anomaly_review',
          heuristicWeight: 15,
          interpretation: `Referência contextual a '${pm[1]}' em log de rede/processo.`,
          alternativeExplanations: ['Ferramenta instalada fora de uso na partida'],
          recommendedAction: 'Verificar horário de execução vs partida.',
          snippet: makeSnippet(prevLine, line, nextLine),
          dedupKey: `ANDROID_NET_PROXY_TOOL_001|${pm[1].toLowerCase()}`
        }));
      }

      if (NET_CONTEXT_RE.test(line)) {
        if (matcher.proxyNamedRe) {
          const pMatches = matcher.findAllMatches(matcher.proxyNamedRe, line);
          for (const token of pMatches) {
            const canon = matcher.proxyNamedMap.get(token.toLowerCase()) || token;
            addSignal('proxy_named_domain', `Contexto Rede/DNS: ${canon}`);
            emitEvent(buildCanonicalEvent({
              ruleId: 'PROXY_NAMED_DOMAIN_001',
              domain: 'rede',
              title: `Indicador de Domínio/Proxy em Contexto de Rede (${canon})`,
              source: { path: filePath, format: format || 'network', line: lineNo },
              observed: { timestamp: meta.timestamp, process: meta.process || 'Network', operation: 'domain_dns_ref', object_path: canon },
              evidenceLevel: 'anomaly_review',
              heuristicWeight: 20,
              interpretation: `Indicador '${canon}' detectado com fronteira exata em registro com contexto de rede/DNS/URL.`,
              alternativeExplanations: ['Cache DNS histórico sem tráfego ativo'],
              recommendedAction: 'Correlacionar com horário da partida e pacotes instalados.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `PROXY_NAMED_DOMAIN_001|${canon.toLowerCase()}`
            }));
          }
        }

        if (matcher.networkIpRe) {
          const ipMatches = matcher.findAllMatches(matcher.networkIpRe, line);
          for (const ip of ipMatches) {
            const canon = matcher.networkIpMap.get(ip.toLowerCase()) || ip;
            addSignal('network_ip_candidate', `Contexto Rede/IP: ${canon}`);
            emitEvent(buildCanonicalEvent({
              ruleId: 'NETWORK_IP_CANDIDATE_001',
              domain: 'rede',
              title: `Endereço IP Candidato em Contexto de Rede (${canon})`,
              source: { path: filePath, format: format || 'network', line: lineNo },
              observed: { timestamp: meta.timestamp, process: meta.process || 'Network', operation: 'ip_endpoint_ref', object_path: canon },
              evidenceLevel: 'anomaly_review',
              heuristicWeight: 10,
              interpretation: `Endereço IP '${canon}' registrado em contexto de rede/conexão. IPs não possuem reputação maliciosa permanente e podem pertencer a infraestrutura compartilhada/reatribuída.`,
              alternativeExplanations: ['IP compartilhado, CDN, VPS reatribuído ou rota temporária'],
              recommendedAction: 'Validar horário da conexão e correlacionar com outras evidências independentes.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `NETWORK_IP_CANDIDATE_001|${canon}`
            }));
          }
        }

        if (matcher.textualAliasRe) {
          const aMatches = matcher.findAllMatches(matcher.textualAliasRe, line);
          for (const alias of aMatches) {
            const canon = matcher.textualAliasMap.get(alias.toLowerCase()) || alias;
            addSignal('proxy_alias_candidate', `Alias Rede/Perfil: ${canon}`);
            emitEvent(buildCanonicalEvent({
              ruleId: 'PROXY_ALIAS_CANDIDATE_001',
              domain: 'rede',
              title: `Alias Textual de Proxy/Perfil (${canon})`,
              source: { path: filePath, format: format || 'network', line: lineNo },
              observed: { timestamp: meta.timestamp, process: meta.process || 'Network', operation: 'textual_alias_ref', object_path: canon },
              evidenceLevel: 'anomaly_review',
              heuristicWeight: 15,
              interpretation: `Alias hifenizado '${canon}' detectado com fronteira exata em contexto de rede/DNS/perfil (não tratado como nome de pacote Android).`,
              alternativeExplanations: ['Registro histórico ou referência de configuração inativa'],
              recommendedAction: 'Confirmar uso ativo simultâneo à partida e buscar evidências independentes.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `PROXY_ALIAS_CANDIDATE_001|${canon.toLowerCase()}`
            }));
          }
        }
      }

      if (matcher.profileRefRe && (PROFILE_CTX_RE.test(line) || NET_CONTEXT_RE.test(line))) {
        const prMatches = matcher.findAllMatches(matcher.profileRefRe, line);
        for (const refTok of prMatches) {
          const canon = matcher.profileRefMap.get(refTok.toLowerCase()) || refTok;
          addSignal('profile_ref_candidate', `Perfil/Referência: ${canon}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'PROFILE_REFERENCE_CANDIDATE_001',
            domain: 'rede',
            title: `Referência de Perfil Candidata (${canon})`,
            source: { path: filePath, format: format || 'profile', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'Config', operation: 'profile_reference', object_path: canon },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 15,
            interpretation: `Identificador candidato '${canon}' encontrado em contexto de perfil/certificado/configuração.`,
            alternativeExplanations: ['Perfil inativo ou arquivo residual'],
            recommendedAction: 'Validar estado ativo e origem do perfil.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `PROFILE_REFERENCE_CANDIDATE_001|${canon.toLowerCase()}`
          }));
        }
      }

      if (matcher.toolIndicatorRe && PROCESS_CTX_RE.test(line)) {
        const tMatches = matcher.findAllMatches(matcher.toolIndicatorRe, line);
        for (const toolTok of tMatches) {
          const canon = matcher.toolIndicatorMap.get(toolTok.toLowerCase()) || toolTok;
          addSignal('tool_indicator_detected', `Processo/ADB: ${canon}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'TOOL_INDICATOR_CANDIDATE_001',
            domain: 'depuracao',
            title: `Indicador de Ferramenta Detectado (${canon})`,
            source: { path: filePath, format: format || 'log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'shell', operation: 'tool_context', object_path: canon },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 15,
            interpretation: `Indicador de ferramenta '${canon}' observado em contexto de processo, serviço ou comando ADB/shell.`,
            alternativeExplanations: ['Utilitário de depuração executado fora da partida'],
            recommendedAction: 'Correlacionar horário e atividade com evidências independentes.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `TOOL_INDICATOR_CANDIDATE_001|${canon.toLowerCase()}`
          }));
        }
      }

      // 10. Root / Módulos (ANDROID_ROOT_MODULE_NAMES) com exigência estrita de contexto
      if (matcher.androidRootModuleRe && (format === 'android_mountinfo' || PROCESS_CTX_RE.test(line))) {
        const rMatches = matcher.findAllMatches(matcher.androidRootModuleRe, line);
        for (const token of rMatches) {
          const canon = matcher.androidRootMap.get(token.toLowerCase()) || token;
          addSignal('android_root_env', `Ambiente/Processo: ${canon}`);
          emitEvent(buildCanonicalEvent({
            ruleId: 'ANDROID_ROOT_MODULE_001',
            domain: 'seguranca_do_dispositivo',
            title: `Indicador de Ambiente Root/Módulo (${canon})`,
            source: { path: filePath, format: format || 'system', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process, operation: format === 'android_mountinfo' ? 'mount_entry' : 'process_or_path', object_path: canon },
            evidenceLevel: 'anomaly_review',
            heuristicWeight: 15,
            interpretation: `Termo '${canon}' observado em mountinfo, caminho /data/adb/modules ou contexto de serviço/processo.`,
            alternativeExplanations: ['Dispositivo com root prévio sem módulos ativos contra o jogo'],
            recommendedAction: 'Tratar no domínio de segurança do dispositivo; buscar evidência no processo do jogo.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `ANDROID_ROOT_MODULE_001|${canon.toLowerCase()}`
          }));
        }
      }
    },

    finish() {
      flushPackageBlock();
      flushOverlayBlock();
      hexParser.finish();
    }
  };
}
