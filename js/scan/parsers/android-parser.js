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
const SETTINGS_NAME_RE = /\bname=([^\s,}\]]+)/i;
const SETTINGS_VALUE_RE = /\bvalue=([^\s,}\]]+)/i;

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
const ADB_PORT_IP_RE = /(?:(\d{1,3}(?:\.\d{1,3}){3}|\[::1\]|localhost):5555\b|adbd.*tcp.*5555)/i;
const GLOBAL_PROXY_HOST_RE = /\bglobal_http_proxy_host(?:[=:\s]+value=|[=:\s]+)([^\s,;]+)/i;
const PROXY_TOOL_LINE_RE = /\b(mitmproxy|Burp Suite|Charles Proxy|httptoolkit|pcapdroid)\b/i;
const NET_CONTEXT_RE = /(https?:\/\/|\bdns\b|\bproxy\b|\bhost=|\bsni\b|\bresolve\b|\bconnect\b|\bvpn\b|\broute\b|\bcert(?:ificate)?\b)/i;
const USB_BENIGN_RE = /\b(USB connected|USB debugging connected|persist\.sys\.usb\.config=.*\b(?:mtp|ptp|adb)\b|sys\.usb\.state=.*\b(?:mtp|ptp)\b|DHCP\s+lease|InputDispatcher|InputReader|InputFlinger)\b/i;
const ADB_TELEM_FLAG_RE = /\b(service\.adb\.tcp\.port|service\.adb\.tls\.port|adb_wifi_enabled=1|adb_enabled=1|adb\s+reverse|adb\s+forward)\b/i;
const INPUT_INJ_RE = /\b(shell input tap|shell input swipe|injectInputEvent)\b/i;
const PROCESS_CTX_RE = /(\/data\/adb\/modules|init:\s*starting\s+service|Start proc|comm=|Cmdline:|Package\s+\[|mountinfo|binder:|app_process)/i;

const DEFAULT_BENIGN_SETTINGS = Object.freeze({
  long_press_timeout: new Set(['400', '500']),
  peak_refresh_rate: new Set(['60', '60.0', '90', '90.0', '120', '120.0', '144', '144.0']),
  min_refresh_rate: new Set(['60', '60.0', '90', '90.0', '120', '120.0']),
  pointer_speed: new Set(['0']),
  window_animation_scale: new Set(['1', '1.0', '0.5', '0']),
  transition_animation_scale: new Set(['1', '1.0', '0.5', '0']),
  animator_duration_scale: new Set(['1', '1.0', '0.5', '0']),
  adb_enabled: new Set(['0']),
  development_settings_enabled: new Set(['0'])
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

    // 2. Match exato de pacotes candidatos no PackageManager
    if (matcher.androidPackageMap.has(pkgLow)) {
      const canonical = matcher.androidPackageMap.get(pkgLow);
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

      // 4. Settings (pkg:by4a.setedit22 e pkg:com.android.shell)
      if (line.includes('pkg:by4a.setedit22') || line.includes('pkg:com.android.shell')) {
        const mPkg = SETTINGS_PKG_RE.exec(line);
        if (mPkg) {
          const pkgOrigin = mPkg[1];
          const mKey = SETTINGS_NAME_RE.exec(line);
          const mVal = SETTINGS_VALUE_RE.exec(line);
          const keyName = mKey ? mKey[1] : 'unknown_setting';
          const keyVal = mVal ? mVal[1] : '';
          const defaultSet = DEFAULT_BENIGN_SETTINGS[keyName.toLowerCase()];
          const isDefault = defaultSet ? defaultSet.has(keyVal) : false;

          if (isDefault) {
            emitEvent(buildCanonicalEvent({
              ruleId: 'ANDROID_SETTINGS_DEFAULT_001',
              domain: 'seguranca_do_dispositivo',
              title: `Configuração padrão registrada em ${pkgOrigin} (${keyName}=${keyVal})`,
              source: { path: filePath, format: 'dumpsys_settings', line: lineNo },
              observed: { timestamp: meta.timestamp, process: 'SettingsProvider', package: pkgOrigin, operation: keyName, outcome: keyVal },
              evidenceLevel: 'informational',
              heuristicWeight: 0,
              interpretation: `Valor ${keyName}=${keyVal} está dentro dos valores padrão do Android.`,
              alternativeExplanations: ['Configuração nativa do sistema'],
              recommendedAction: 'Nenhuma ação necessária.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `ANDROID_SETTINGS_DEFAULT_001|${pkgOrigin}|${keyName}|${keyVal}`
            }));
          } else if (pkgOrigin === 'by4a.setedit22') {
            addSignal('android_setedit_anomaly', `SetEdit (${keyName}=${keyVal})`);
            emitEvent(buildCanonicalEvent({
              ruleId: 'ANDROID_SETTINGS_SETEDIT_ANOMALY_001',
              domain: 'integridade_do_jogo',
              title: `Alteração via SetEdit (${keyName}=${keyVal})`,
              source: { path: filePath, format: 'dumpsys_settings', line: lineNo },
              observed: { timestamp: meta.timestamp, process: 'SettingsProvider', package: pkgOrigin, operation: keyName, outcome: keyVal },
              evidenceLevel: 'anomaly_review',
              heuristicWeight: 15,
              interpretation: `Parâmetro '${keyName}' foi modificado via pacote ${pkgOrigin} com valor não padrão (${keyVal || 'vazio'}).`,
              alternativeExplanations: [
                'Ajuste de acessibilidade, tela ou taxa de atualização pelo usuário'
              ],
              recommendedAction: 'Verificar se a chave alterada impacta entrada/sensibilidade e buscar evidências independentes.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `ANDROID_SETTINGS_SETEDIT_ANOMALY_001|${keyName}|${keyVal}`
            }));
          }
        }
      }

      // 5. SELinux auditd & Free Fire GameAsset / JARs
      const lowLine = line.toLowerCase();
      if (lowLine.includes('avc:') && lowLine.includes('audit(')) {
        const audit = parseAuditdLine(line);
        if (audit && audit.canonical_path) {
          const cpathLow = audit.canonical_path.toLowerCase();
          const appLow = (audit.app || '').toLowerCase();
          const comm = audit.comm || '';
          const action = audit.avc_action || '';
          const ops = audit.operations || [];

          if (matcher.gameArtifactPaths.shGpp2Targets.includes(cpathLow) && matcher.freeFirePackages.has(appLow)) {
            if (action === 'granted' && ops.includes('execute') && comm === 'UnityMain') {
              addSignal('ff_sh_gpp2_exec', `auditd granted execute SH-Gpp2 (${audit.app})`);
              emitEvent(buildCanonicalEvent({
                ruleId: 'ANDROID_GAME_SH_GPP2_EXEC_001',
                domain: 'integridade_do_jogo',
                title: `Execução em GameAsset SH-Gpp2 (${audit.app})`,
                source: { path: filePath, format: 'selinux_audit', line: lineNo },
                observed: {
                  timestamp: audit.timestamp || meta.timestamp,
                  process: comm,
                  package: audit.app,
                  operation: ops.join(', '),
                  outcome: action,
                  object_path: audit.canonical_path
                },
                evidenceLevel: 'anomaly_review',
                heuristicWeight: 30,
                interpretation: `SELinux permitiu (granted) operação de execução para UnityMain no caminho ${audit.canonical_path}; requer comparação com baseline oficial.`,
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
            if (action === 'denied') {
              emitEvent(buildCanonicalEvent({
                ruleId: 'ANDROID_GAME_SH_GPP2_DENIED_001',
                domain: 'integridade_do_jogo',
                title: `Tentativa SELinux negada em SH-Gpp2 (${audit.app})`,
                source: { path: filePath, format: 'selinux_audit', line: lineNo },
                observed: {
                  timestamp: audit.timestamp || meta.timestamp,
                  process: comm || meta.process,
                  package: audit.app,
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

      // 8. ADB / USB / Rede (distinguir 127.0.0.1:5555 de IP remoto; USB/MTP/PTP/DHCP nunca pontuam)
      if (USB_BENIGN_RE.test(line)) {
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

      if (lowLine.includes('5555') || lowLine.includes('adbd') || ADB_TELEM_FLAG_RE.test(line) || INPUT_INJ_RE.test(line)) {
        const adbM = ADB_PORT_IP_RE.exec(line);
        if (adbM) {
          const ip = (adbM[1] || '').toLowerCase();
          const isLoopback = !ip || ip === '127.0.0.1' || ip === 'localhost' || ip === '[::1]';
          if (isLoopback && (lowLine.includes('127.0.0.1') || lowLine.includes('localhost') || lowLine.includes('[::1]'))) {
            emitEvent(buildCanonicalEvent({
              ruleId: 'ANDROID_ADB_LOCAL_LOOPBACK_001',
              domain: 'depuracao',
              title: `ADB em loopback local (${ip || '127.0.0.1'}:5555)`,
              source: { path: filePath, format: format || 'log', line: lineNo },
              observed: { timestamp: meta.timestamp, process: meta.process || 'adbd', operation: 'adb_loopback', outcome: `${ip}:5555` },
              evidenceLevel: 'informational',
              heuristicWeight: 0,
              interpretation: `Socket ADB local em ${ip}:5555, padrão comum de utilitários locais no dispositivo (ex.: Shizuku, Brevent).`,
              alternativeExplanations: ['Brevent / Shizuku para controle de apps em segundo plano'],
              recommendedAction: 'Não tratar como acesso remoto externo.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `ANDROID_ADB_LOCAL_LOOPBACK_001|${ip}`
            }));
          } else if (ip) {
            addSignal('android_adb_remote', `ADB TCP remoto (${ip}:5555)`);
            emitEvent(buildCanonicalEvent({
              ruleId: 'ANDROID_ADB_REMOTE_001',
              domain: 'depuracao',
              title: `ADB TCP em IP de rede não-loopback (${ip}:5555)`,
              source: { path: filePath, format: format || 'log', line: lineNo },
              observed: { timestamp: meta.timestamp, process: meta.process || 'adbd', operation: 'adb_remote_tcp', outcome: `${ip}:5555` },
              evidenceLevel: 'anomaly_review',
              heuristicWeight: 10,
              interpretation: `Conexão/escuta ADB associada a endereço não-loopback (${ip}:5555).`,
              alternativeExplanations: ['Depuração sem fio Android Studio ou espelhamento scrcpy local em Wi-Fi'],
              recommendedAction: 'Verificar horário da conexão em relação à partida e outros indícios.',
              snippet: makeSnippet(prevLine, line, nextLine),
              dedupKey: `ANDROID_ADB_REMOTE_001|${ip}`
            }));
          }
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
        } else if (ADB_TELEM_FLAG_RE.test(line)) {
          const fm = ADB_TELEM_FLAG_RE.exec(line);
          emitEvent(buildCanonicalEvent({
            ruleId: 'ANDROID_ADB_STATE_TELEMETRY_001',
            domain: 'depuracao',
            title: `Telemetria de Estado ADB (${fm[1]})`,
            source: { path: filePath, format: format || 'log', line: lineNo },
            observed: { timestamp: meta.timestamp, process: meta.process || 'adbd', operation: fm[1] },
            evidenceLevel: 'informational',
            heuristicWeight: 0,
            interpretation: `Sinalizador de estado de depuração Android (${fm[1]}). Depuração ativada sozinha não comprova trapaça.`,
            alternativeExplanations: ['Depuração USB ativada pelo usuário'],
            recommendedAction: 'Apenas contexto operacional.',
            snippet: makeSnippet(prevLine, line, nextLine),
            dedupKey: `ANDROID_ADB_STATE_TELEMETRY_001|${fm[1].toLowerCase()}`
          }));
        }
      }

      // 9. Proxy / MITM / Domínios nomeados (PROXY_SHORT_TOKENS NUNCA é usado)
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

      if (matcher.proxyNamedRe && NET_CONTEXT_RE.test(line)) {
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
      hexParser.finish();
    }
  };
}
