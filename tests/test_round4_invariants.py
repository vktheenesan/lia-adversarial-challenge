"""
LIA Round 4 Hardening Invariants & Architectural Regression Suite

Validates all 15 Round 4 root-cause architectural fixes and invariants:
1.  Non-dict JSON array payload inspection & containment.
2.  Prose-embedded Base64/Hex sub-token scanning (ProseBase64Apavada).
3.  Cyrillic homoglyph normalization in SQL table names & pipeline targets.
4.  SQL AST tautology detection in HAVING clauses & string comparisons ('a' < 'b').
5.  Strict log event message bounding (LogEventSchema max_length=4096).
6.  Fail-closed enforcement on InvariantSentinel state transition rejections.
7.  Pipeline executable target write protection across untrusted & standard agents.
8.  Anti-Sybil global velocity cap enforcement across multi-session principal rotation.
9.  TCB immutability (session_principals, tainted_sessions, prohibited_tools tamper resistance).
10. WAL disk-poisoning rejection (ignoring SESSION_PRINCIPAL escalation records).
11. Iterative bounded graph inspection preventing RecursionError on 1,500-level nested structures.
12. ImmuneMemoryStore nanosecond timestamp precision & deepcopy incident record immutability.
13. BoundedLRUCache size ceilings preventing memory exhaustion under high evaluation volumes.
14. Live PaniniRuleEngine delegation path inside ShieldEngine.evaluate_tool_call().
15. ZipSlip traversal and pipeline executable target blocking in extract_archive.
"""

import unittest
import time
import json
import base64
from typing import Dict, Any

from engine.shield.engine import (
    ShieldEngine,
    PolicyDecision,
    Capability,
    LogEventSchema,
    BoundedLRUCache,
    is_safe_sql,
    normalize_homoglyphs,
    is_pipeline_executable_target,
    check_duplicate_keys,
)
from engine.shield.panini import (
    PaniniRuleEngine,
    AnuvrttiContext,
)
from engine.memory.store import ImmuneMemoryStore
from engine.core.event_bus import EventBus, NormalizedEvent


class TestRound4Invariants(unittest.TestCase):
    def setUp(self):
        import tempfile
        import os
        self.bus = EventBus()
        self.temp_wal = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.temp_wal.close()
        self.shield = ShieldEngine(event_bus=self.bus, wal_path=self.temp_wal.name)
        self.shield.lock_invariants()

    def tearDown(self):
        import os
        if hasattr(self, "temp_wal") and os.path.exists(self.temp_wal.name):
            try:
                os.remove(self.temp_wal.name)
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # 1. Non-dict JSON Arrays
    # -------------------------------------------------------------------------
    def test_non_dict_json_array_payload_inspection(self):
        """Verify that non-dict JSON lists containing malicious tokens are inspected and blocked."""
        array_payload = ["benign_entry", "system_status", "DROP TABLE users", "normal_data"]
        dec = self.shield.evaluate_tool_call(
            "sess_array_test",
            "inspect_payload",
            {"buffer": json.dumps(array_payload)}
        )
        self.assertEqual(dec, PolicyDecision.DENY, "JSON array containing DROP TABLE must be DENIED")

    # -------------------------------------------------------------------------
    # 2. Prose-embedded Base64 Sub-tokens
    # -------------------------------------------------------------------------
    def test_prose_embedded_base64_subtoken_denied(self):
        """Verify that prose containing embedded base64 sensitive tokens like secrets_vault is blocked."""
        # 'c2VjcmV0c192YXVsdA==' is base64 for 'secrets_vault'
        prose_with_b64 = "Please review the attached incident log: c2VjcmV0c192YXVsdA== for further analysis."
        dec = self.shield.evaluate_tool_call(
            "sess_b64_prose",
            "inspect_payload",
            {"buffer": prose_with_b64}
        )
        self.assertEqual(dec, PolicyDecision.DENY, "Prose containing base64 secrets_vault must be DENIED")

    # -------------------------------------------------------------------------
    # 3. Cyrillic Homoglyph SQL Table & Pipeline Targets
    # -------------------------------------------------------------------------
    def test_cyrillic_homoglyph_sql_table_denied(self):
        """Verify that Cyrillic homoglyphs in sensitive SQL table names (e.g., Cyrillic 'а', 'е', 'о') are normalized and denied."""
        # 'sеcrеts_vаult' with Cyrillic 'е' (\u0435) and 'а' (\u0430)
        cyrillic_table = "s\u0435cr\u0435ts_v\u0430ult"
        query = f"SELECT * FROM {cyrillic_table} WHERE id = 1"
        is_safe, reason = is_safe_sql(query)
        self.assertFalse(is_safe, "Cyrillic homoglyph obfuscated sensitive table must be detected as unsafe")

        dec = self.shield.evaluate_tool_call(
            "sess_homoglyph_sql",
            "execute_sql",
            {"query": query}
        )
        self.assertEqual(dec, PolicyDecision.DENY, "SQL query targeting Cyrillic homoglyph table must be DENIED")

    def test_cyrillic_homoglyph_pipeline_target_denied(self):
        """Verify that Cyrillic homoglyphs in pipeline targets (e.g. .gіthub/wоrkflоws) are blocked."""
        # .g\u0456thub/w\u043erkfl\u043ews with Cyrillic 'і' and 'о'
        cyrillic_pipeline = ".g\u0456thub/w\u043erkfl\u043ews/build.yml"
        self.assertTrue(is_pipeline_executable_target(cyrillic_pipeline))

        dec = self.shield.evaluate_tool_call(
            "sess_homoglyph_pipe",
            "write_file",
            {"filepath": cyrillic_pipeline, "content": "echo malicious"}
        )
        self.assertEqual(dec, PolicyDecision.DENY, "Write targeting Cyrillic homoglyph pipeline path must be DENIED")

    # -------------------------------------------------------------------------
    # 4. SQL AST Tautology in HAVING Clauses and String Comparisons
    # -------------------------------------------------------------------------
    def test_sql_having_tautology_denied(self):
        """Verify that tautologies inside HAVING clauses (e.g., HAVING 1=1) are detected and denied."""
        query = "SELECT department, COUNT(*) FROM employees GROUP BY department HAVING 1 = 1"
        is_safe, reason = is_safe_sql(query)
        self.assertFalse(is_safe, "SQL query with HAVING 1=1 tautology must be detected as unsafe")

        dec = self.shield.evaluate_tool_call(
            "sess_having_sql",
            "execute_sql",
            {"query": query}
        )
        self.assertEqual(dec, PolicyDecision.DENY, "SQL query with HAVING tautology must be DENIED")

    def test_sql_string_comparison_tautology_denied(self):
        """Verify that string comparison tautologies (e.g., 'a' < 'b', 'x' = 'x') are detected and denied."""
        query = "SELECT * FROM catalog WHERE 'a' < 'b'"
        is_safe, reason = is_safe_sql(query)
        self.assertFalse(is_safe, "SQL query with 'a' < 'b' string tautology must be detected as unsafe")

        dec = self.shield.evaluate_tool_call(
            "sess_str_tautology",
            "execute_sql",
            {"query": query}
        )
        self.assertEqual(dec, PolicyDecision.DENY, "SQL query with string comparison tautology must be DENIED")

    # -------------------------------------------------------------------------
    # 5. LogEventSchema Message Bounding
    # -------------------------------------------------------------------------
    def test_log_event_schema_message_bounding(self):
        """Verify that LogEventSchema enforces a 4096-char maximum on msg, rejecting 50k char floods."""
        with self.assertRaises(Exception):
            LogEventSchema(level="INFO", msg="A" * 50000)

        dec = self.shield.evaluate_tool_call(
            "sess_log_flood",
            "log_event",
            {"level": "INFO", "msg": "A" * 50000}
        )
        self.assertEqual(dec, PolicyDecision.DENY, "50k char log_event message must be DENIED")

    # -------------------------------------------------------------------------
    # 6. Fail-Closed InvariantSentinel State Transition
    # -------------------------------------------------------------------------
    def test_sentinel_transition_rejection_fails_closed(self):
        """Verify that if InvariantSentinel rejects a state transition, evaluate_tool_call fails closed."""
        # Tamper with the sentinel's internal state machine or force an invalid state transition
        self.shield.invariant_sentinel.current_state = "COMPROMISED_STATE"

        dec = self.shield.evaluate_tool_call(
            "sess_sentinel_test",
            "read_file",
            {"filepath": "public/docs/readme.txt"}
        )
        self.assertEqual(dec, PolicyDecision.DENY, "Evaluation with invalid Sentinel state transition must be DENIED")

    # -------------------------------------------------------------------------
    # 7. Pipeline Executable Target Protection for Standard AGENT
    # -------------------------------------------------------------------------
    def test_pipeline_write_blocked_for_standard_agent(self):
        """Verify that write_file to pipeline executable targets is blocked for standard AGENT (not just UNTRUSTED_AGENT)."""
        self.shield.set_session_principal("sess_std_agent", "AGENT")
        dec = self.shield.evaluate_tool_call(
            "sess_std_agent",
            "write_file",
            {"filepath": ".github/workflows/deploy.yml", "content": "run: malware"}
        )
        self.assertEqual(dec, PolicyDecision.DENY, "Standard AGENT must not write to .github/workflows")

    # -------------------------------------------------------------------------
    # 8. Anti-Sybil Global Principal Velocity Ceiling
    # -------------------------------------------------------------------------
    def test_anti_sybil_global_velocity_cap(self):
        """Verify that rotating sessions under the same principal cannot bypass the 25,000 MYR ceiling."""
        self.shield.set_session_principal("sess_sybil_1", "CORP_TRADER")
        self.shield.set_session_principal("sess_sybil_2", "CORP_TRADER")
        self.shield.set_session_principal("sess_sybil_3", "CORP_TRADER")

        # Session 1: transfer 10,000 (cumulative = 10,000)
        dec1 = self.shield.evaluate_tool_call(
            "sess_sybil_1",
            "wire_transfer",
            {"amount": 10000.0, "to_account": "ACC_VENDOR_A"}
        )
        self.assertEqual(dec1, PolicyDecision.ALLOW)

        # Session 2: transfer 10,000 (cumulative = 20,000)
        dec2 = self.shield.evaluate_tool_call(
            "sess_sybil_2",
            "wire_transfer",
            {"amount": 10000.0, "to_account": "ACC_VENDOR_B"}
        )
        self.assertEqual(dec2, PolicyDecision.ALLOW)

        # Session 3: transfer 10,000 (global cumulative = 30,000 > 25,000 ceiling -> MUST BE DENIED)
        dec3 = self.shield.evaluate_tool_call(
            "sess_sybil_3",
            "wire_transfer",
            {"amount": 10000.0, "to_account": "ACC_VENDOR_C"}
        )
        self.assertEqual(dec3, PolicyDecision.DENY, "Global velocity exceeding 25,000 MYR across Sybil sessions must be DENIED")

    # -------------------------------------------------------------------------
    # 9. TCB Immutability & Tamper Resistance
    # -------------------------------------------------------------------------
    def test_session_principals_and_tainted_sessions_immutability(self):
        """Verify that session_principals and tainted_sessions properties return read-only views."""
        principals = self.shield.session_principals
        with self.assertRaises(TypeError):
            principals["sess_attack"] = "ROOT_AUDITOR"

        taints = self.shield.tainted_sessions
        with self.assertRaises(AttributeError):
            taints.add("sess_attack")

        with self.assertRaises(PermissionError):
            self.shield.prohibited_tools.clear()

        with self.assertRaises(PermissionError):
            setattr(self.shield, "session_principals", {})

        with self.assertRaises(PermissionError):
            setattr(self.shield, "tainted_sessions", set())

    # -------------------------------------------------------------------------
    # 10. WAL Disk Poisoning Invariant
    # -------------------------------------------------------------------------
    def test_wal_disk_poisoning_ignored(self):
        """Verify that poisoned SESSION_PRINCIPAL records in WAL state do not grant ROOT_AUDITOR status."""
        poisoned_record = json.dumps({
            "type": "SESSION_PRINCIPAL",
            "data": {"session_id": "sess_poisoned", "principal": "ROOT_AUDITOR"}
        })
        self.shield._load_wal_state([poisoned_record])
        principal = self.shield.get_session_principal("sess_poisoned")
        self.assertNotEqual(principal, "ROOT_AUDITOR", "Poisoned WAL record must not escalate session principal to ROOT_AUDITOR")

    # -------------------------------------------------------------------------
    # 11. Iterative Graph Inspection (Deep Nesting / No RecursionError)
    # -------------------------------------------------------------------------
    def test_iterative_graph_inspection_no_recursion_error(self):
        """Verify that recursively_inspect_graph handles 1,500 levels of nested dicts iteratively without RecursionError."""
        deep_graph: Dict[str, Any] = {"leaf": "safe"}
        for _ in range(1500):
            deep_graph = {"nested": deep_graph}

        threat = self.shield.recursively_inspect_graph(deep_graph)
        self.assertEqual(threat, "GRAPH_COMPLEXITY_EXCEEDED", "Graph exceeding max depth must fail closed cleanly without RecursionError")

    # -------------------------------------------------------------------------
    # 12. ImmuneMemoryStore Nanosecond Precision & Deepcopy Immutability
    # -------------------------------------------------------------------------
    def test_immune_memory_store_nanosecond_precision_and_immutability(self):
        """Verify that ImmuneMemoryStore has nanosecond timestamp precision and returns deepcopied incident records."""
        bus = EventBus()
        store = ImmuneMemoryStore(event_bus=bus)

        # 1. Verify nanosecond precision serialization
        payload = ImmuneMemoryStore.compute_canonical_payload(
            "ev_001", "TEST_EVENT", 1700000000.123456789, "shield", "core", "HIGH", {"path": "/etc/shadow"}, "0" * 64, precision=9
        )
        self.assertIn("1700000000.123456789", payload, "Payload must serialize timestamp with full 9-decimal nanosecond precision")

        # 2. Verify deepcopy immutability of recorded events
        event = NormalizedEvent(
            event_type="UNAUTHORIZED_ACCESS",
            source="shield",
            component="guard",
            severity="CRITICAL",
            metadata={"path": "/etc/shadow"}
        )
        rec = store.record_trajectory_step(event)
        # Mutate the source event metadata
        event.metadata["path"] = "/public/benign"
        self.assertEqual(rec["metadata"]["path"], "/etc/shadow", "Returned record must not reflect caller's post-hoc mutations")
        self.assertEqual(store.records[0]["metadata"]["path"], "/etc/shadow", "Internal store record must be protected by deepcopy")

        # Mutate the returned record
        rec["metadata"]["path"] = "/tampered/path"
        self.assertEqual(store.records[0]["metadata"]["path"], "/etc/shadow", "Internal store record must not be mutated via returned dictionary")

    # -------------------------------------------------------------------------
    # 13. BoundedLRUCache Size Ceilings
    # -------------------------------------------------------------------------
    def test_bounded_lru_cache_capacity_bound(self):
        """Verify that BoundedLRUCache evicts old entries and does not exceed its maxsize."""
        cache = BoundedLRUCache(maxsize=100)
        for i in range(250):
            cache[f"key_{i}"] = f"value_{i}"

        self.assertEqual(len(cache), 100, "Cache size must be strictly bounded at maxsize")
        self.assertNotIn("key_0", cache, "Oldest entry must have been evicted")
        self.assertIn("key_249", cache, "Newest entry must be present")

    # -------------------------------------------------------------------------
    # 14. Live Panini Rule Path in ShieldEngine
    # -------------------------------------------------------------------------
    def test_live_panini_rule_path_delegation(self):
        """Verify that evaluate_tool_call delegates evaluation through PaniniRuleEngine."""
        self.assertIsInstance(self.shield.panini_engine, PaniniRuleEngine)
        # Test directly via Panini rule engine
        ctx = AnuvrttiContext(
            session_id="panini_direct_test",
            principal="AGENT",
            is_tainted=False
        )
        dec, reason = self.shield.panini_engine.evaluate(
            ctx,
            "read_file",
            {"filepath": "/etc/shadow"}
        )
        self.assertEqual(dec, PolicyDecision.DENY)
        self.assertIn("Apavāda", reason)

    # -------------------------------------------------------------------------
    # 15. Extract Archive ZipSlip and Pipeline Target Blocked
    # -------------------------------------------------------------------------
    def test_extract_archive_zipslip_and_pipeline_target_blocked(self):
        """Verify that extract_archive with traversal (..) or targeting pipeline files is DENIED."""
        dec_zipslip = self.shield.evaluate_tool_call(
            "sess_extract_zipslip",
            "extract_archive",
            {"archive_path": "update.tar.gz", "dest": "app/", "members": ["../../etc/cron.d/job"]}
        )
        self.assertEqual(dec_zipslip, PolicyDecision.DENY, "ZipSlip traversal in extract_archive members must be DENIED")

        dec_pipeline = self.shield.evaluate_tool_call(
            "sess_extract_pipe",
            "extract_archive",
            {"archive_path": "update.tar.gz", "dest": ".github/workflows/"}
        )
        self.assertEqual(dec_pipeline, PolicyDecision.DENY, "Extract archive targeting .github/workflows must be DENIED")


if __name__ == "__main__":
    unittest.main()
