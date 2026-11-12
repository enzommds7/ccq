import os
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "api")))
from forensic_engine import ForensicEngine, parse_hex_dump_lines, RULE_REGISTRY  # noqa: E402


class TestForensicEngineRegression(unittest.TestCase):
    def setUp(self):
        self.engine = ForensicEngine()

    def test_01_hyphen_does_not_trigger_casino_alert(self):
        files = [{
            "path": "bugreport-2026-11-12.txt",
            "text": "2026-11-12 10:00:00.000  1000  1000 I ActivityManager: Start proc com.android.chrome\nerro-de-rede-temporario\n",
        }]
        rep = self.engine.analyze_files(files, os_hint="android")
        casino_alerts = [a for a in rep["alerts"] if a["category"] == "casino_activity"]
        self.assertEqual(len(casino_alerts), 0)
        self.assertEqual(rep["threat_score"], 0)

    def test_02_a4_in_hex_address_does_not_trigger_proxy_alert(self):
        files = [{
            "path": "tombstone_00.txt",
            "text": "fault addr 0x0000a400a4ff\nx0  0000007f1a4b2000  x1  0000a4a4a4000001\n",
        }]
        rep = self.engine.analyze_files(files, os_hint="android")
        proxy_alerts = [a for a in rep["alerts"] if "proxy" in a["category"]]
        self.assertEqual(len(proxy_alerts), 0)
        self.assertEqual(rep["threat_score"], 0)

    def test_03_sh_gpp2_in_specific_auditd_context_is_detected(self):
        log = (
            'auditd: type=1400 audit(0.0:263201): avc: granted { execute } for '
            'comm="UnityMain" path="/data/data/com.dts.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2" '
            'dev="dm-67" ino=2343323 scontext=u:r:untrusted_app:s0 tcontext=u:object_r:app_data_file:s0 tclass=file app=com.dts.freefiremax\n'
        )
        rep = self.engine.analyze_files([{"path": "audit.log", "text": log}], os_hint="android")
        sh = [a for a in rep["alerts"] if a["signature_id"] == "FF_GAMEASSET_SH_GPP2_AUDITD"]
        self.assertEqual(len(sh), 1)
        self.assertEqual(sh[0]["category"], "gameasset_anomaly")
        self.assertEqual(sh[0]["evidence_tier"], "specific_anomaly")
        self.assertEqual(sh[0]["process"], "UnityMain")

    def test_04_sh_gpp2_in_unrelated_message_is_not_relevant_alert(self):
        log = "11-12 12:00:00.000  100  100 I BackupChat: Usuario enviou texto mencionando SH-Gpp2 no chat\n"
        rep = self.engine.analyze_files([{"path": "chat.txt", "text": log}], os_hint="android")
        relevant = [a for a in rep["alerts"] if a["weight"] > 0]
        self.assertEqual(len(relevant), 0)

    def test_05_avc_granted_vs_denied_differentiation(self):
        log = (
            'auditd: type=1400 audit(0.0:100): avc: denied { execute } for '
            'comm="UnityMain" path="/data/user/0/com.dts.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2" '
            'app=com.dts.freefiremax\n'
        )
        rep = self.engine.analyze_files([{"path": "audit.log", "text": log}], os_hint="android")
        denied = [a for a in rep["alerts"] if a["signature_id"] == "FF_GAMEASSET_SH_GPP2_DENIED"]
        granted = [a for a in rep["alerts"] if a["signature_id"] == "FF_GAMEASSET_SH_GPP2_AUDITD"]
        self.assertEqual(len(denied), 1)
        self.assertEqual(len(granted), 0)
        self.assertEqual(denied[0]["evidence_tier"], "contextual_event")

    def test_06_low_memory_does_not_indicate_cheat(self):
        log = "1681920: process=com.dts.freefiremax reason=3 (LOW_MEMORY) subreason=0 (UNKNOWN) status=0\n"
        rep = self.engine.analyze_files([{"path": "bugreport.txt", "text": log}], os_hint="android")
        self.assertEqual(rep["threat_score"], 0)
        self.assertEqual(rep["alerts"][0]["category"], "stability_crash")
        self.assertIn("Crash comum", rep["alerts"][0]["technical_interpretation"])

    def test_07_sigsegv_alone_does_not_indicate_injection(self):
        log = (
            "Cmdline: com.dts.freefiremax\n"
            "pid: 18054, tid: 6626, name: UnityMain  >>> com.dts.freefiremax <<<\n"
            "signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0000000000000318\n"
            "Cause: null pointer dereference\n"
            "x0 000000003cb6db24 x1 000000707000002a\n"
        )
        rep = self.engine.analyze_files([{"path": "tombstone_01.txt", "text": log}], os_hint="android")
        self.assertEqual(rep["threat_score"], 0)
        self.assertEqual(rep["alerts"][0]["category"], "stability_crash")
        self.assertIn("Falha não determinada", rep["alerts"][0]["technical_interpretation"])

    def test_08_github_url_in_hexdump_is_not_cheat(self):
        lines = [
            '    0000007070000370 6e6f734a2e74666f 213c09090a0d3e22  oft.Json">....<!',
            '    0000007070000380 7370747468202d2d 75687469672f2f3a  -- https://githu',
            '    0000007070000390 696a2f6d6f632e62 654e2f724a656c6c  b.com/jilleJr/Ne',
        ]
        chunks = parse_hex_dump_lines(lines)
        self.assertTrue(any("github.com/jilleJr/Ne" in u for c in chunks for u in c["urls"]))
        rep = self.engine.analyze_files([{"path": "tombstone_02.txt", "text": "\n".join(lines)}], os_hint="android")
        self.assertEqual(rep["threat_score"], 0)
        gh = [a for a in rep["alerts"] if a["category"] == "github_hexdump"]
        self.assertEqual(len(gh), 1)
        self.assertEqual(gh[0]["evidence_tier"], "textual_reference")

    def test_09_mobilebackup_alone_does_not_prove_restore(self):
        log = "2026-11-12 09:00:00 MobileBackup daemon registered as available service\n"
        rep = self.engine.analyze_files([{"path": "sysdiagnose/system_logs.log", "text": log}], os_hint="ios")
        self.assertEqual(rep["threat_score"], 0)
        self.assertEqual(rep["alerts"][0]["evidence_tier"], "textual_reference")

    def test_10_itunesstored_is_not_proof_of_restore(self):
        log = "2026-11-12 09:05:00 itunesstored checking App Store receipt\n"
        rep = self.engine.analyze_files([{"path": "sysdiagnose/system_logs.log", "text": log}], os_hint="ios")
        self.assertEqual(rep["threat_score"], 0)
        self.assertEqual(rep["alerts"][0]["evidence_tier"], "textual_reference")

    def test_11_profile_ids_searched_in_proper_fields_exact_match(self):
        # Substring similar em campo errado NÃO deve disparar
        benign = "Comentário aleatório com.xtremo.mobile.helper.test\n"
        rep_benign = self.engine.analyze_files([{"path": "notes.txt", "text": benign}], os_hint="android")
        self.assertEqual(len([a for a in rep_benign["alerts"] if a["category"] == "profile_package_id"]), 0)

        # Match exato em campo de pacote DEVE disparar
        real = "Package [com.xtremo.mobile] userId=10299\n"
        rep_real = self.engine.analyze_files([{"path": "packages.txt", "text": real}], os_hint="android")
        self.assertEqual(len([a for a in rep_real["alerts"] if a["category"] == "profile_package_id"]), 1)

    def test_12_repeated_events_do_not_multiply_risk(self):
        line = 'auditd: type=1400 audit(0.0:1): avc: granted { execute } for comm="UnityMain" path="/data/user/0/com.dts.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2" app=com.dts.freefiremax\n'
        rep1 = self.engine.analyze_files([{"path": "audit.log", "text": line}], os_hint="android")
        rep4000 = self.engine.analyze_files([{"path": "audit.log", "text": line * 4000}], os_hint="android")
        self.assertEqual(rep1["threat_score"], rep4000["threat_score"])
        self.assertEqual(rep4000["counters"]["unique_events"], 1)
        self.assertEqual(rep4000["counters"]["raw_occurrences"], 4000)

    def test_13_unparsed_tracev3_reports_incomplete_coverage_not_invented_threats(self):
        fake_tracev3 = b"\x00\x10\x00\x00" + b"hdb" + b"\x00" * 32 + b"a4 mitm blaze.com frida"
        rep = self.engine.analyze_files([{"path": "sysdiagnose/Persist/0001.tracev3", "bytes": fake_tracev3}], os_hint="ios")
        self.assertEqual(rep["counters"]["unanalyzed_files"], 1)
        self.assertEqual(len(rep["alerts"]), 0)
        self.assertEqual(rep["threat_score"], 0)
        self.assertIn("COBERTURA INCOMPLETA", rep["verdict"]["status"])

    def test_14_legitimate_logs_with_suspicious_words_do_not_punish(self):
        log = (
            "11-12 10:00:00.000  1000  1000 I logd: dropped 0 logs, filter applied, skip=false, ignore=false\n"
            "11-12 10:00:01.000  1000  1000 D ConnectivityService: proxy_host=none\n"
        )
        rep = self.engine.analyze_files([{"path": "logcat.txt", "text": log}], os_hint="android")
        self.assertEqual(rep["threat_score"], 0)
        self.assertEqual(rep["verdict"]["color"], "green")

    def test_15_independent_evidence_correlates_and_elevates(self):
        files = [
            {
                "path": "audit.log",
                "text": 'auditd: type=1400 audit(0.0:263201): avc: granted { execute } for comm="UnityMain" path="/data/data/com.dts.freefiremax/files/contentcache/Compulsory/android/gameassetbundles/font/SH-Gpp2" app=com.dts.freefiremax\n',
            },
            {
                "path": "packages.txt",
                "text": "Package [com.dts.freefiremax] userId=10300\n  installerPackageName=com.whatsapp\n",
            },
            {
                "path": "logcat.txt",
                "text": "11-12 11:00:00.000  2000  2000 I init: starting service frida-server\n",
            },
        ]
        rep = self.engine.analyze_files(files, os_hint="android")
        sh = [a for a in rep["alerts"] if a["signature_id"] == "FF_GAMEASSET_SH_GPP2_AUDITD"][0]
        self.assertEqual(sh["evidence_tier"], "corroborated_evidence")
        self.assertEqual(sh["confidence"], "high")
        self.assertGreaterEqual(len(sh["corroborating_evidence"]), 2)
        self.assertGreaterEqual(rep["counters"]["validated_evidence"], 2)

    def test_16_large_volume_performance(self):
        benign_line = "11-12 10:00:00.123  1000  1001 D SurfaceFlinger: frame rendered normal-mode 0x7f1a4b20\n"
        big_text = benign_line * 60000
        t0 = time.perf_counter()
        rep = self.engine.analyze_files([{"path": "bugreport_big.txt", "text": big_text}], os_hint="android")
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 5.0)
        self.assertEqual(rep["threat_score"], 0)
        self.assertEqual(rep["counters"]["checked_lines"], 60000)

    def test_17_experimental_tokens_are_inactive(self):
        exp = [r for r in RULE_REGISTRY if r.status == "experimental_inactive"]
        self.assertEqual(len(exp), 89)
        self.assertTrue(all(r.base_weight == 0 for r in exp))


if __name__ == "__main__":
    unittest.main(verbosity=2)
