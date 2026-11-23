"""
Round 5 Invariants Verification Test Suite.

Verifies:
1. Anti-Eviction Laundering: Non-evicting lineage & taint stores, cross-session taint persistence, fail-closed state capacity bound.
2. SQL AST Bomb & Constant-Only Predicates: Max AST nodes <= 128 (100-way OR bomb blocked), constant-only comparisons/predicates (3-2=1, NOT FALSE, COALESCE(1,0)=1, 5 BETWEEN 1 AND 10) blocked.
3. Prose Hex Sub-Token Scanning: Hex encoded tokens (e.g. 736563726574735f7661756c74 -> secrets_vault) blocked alongside Base64.
4. Living-Off-The-Pipeline Lockfile Protection: requirements*.txt, package-lock.json, poetry.lock, Pipfile.lock, go.mod, go.sum, cargo.lock blocked.
5. Privileged ROOT_AUDITOR Break-Glass Invariants: Unauthenticated ROOT_AUDITOR blocked on critical Apavada invariants; cryptographic break-glass required.
"""

import time
import unittest
from engine.core.event_bus import EventBus
from engine.shield.engine import ShieldEngine, PolicyDecision, Capability, is_safe_sql


class TestRound5Invariants(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus()
        self.shield = ShieldEngine(self.bus)

    # -------------------------------------------------------------------------
    # 1. Anti-Eviction Laundering & Non-Evicting DIFC
    # -------------------------------------------------------------------------
    def test_cross_session_taint_persists_without_eviction(self):
        """Verify that writing tainted artifacts marks the artifact persistently, infecting future reader sessions."""
        sess_tainted = "sess_adversary"
        sess_clean = "sess_innocent_worker"

        # Explicitly register sess_tainted
        self.shield.set_session_principal(sess_tainted, "AGENT")
        self.shield.set_session_principal(sess_clean, "AGENT")

        # Step 1: sess_tainted writes a tainted artifact
        dec1 = self.shield.evaluate_tool_call(
            sess_tainted,
            "write_file",
            {"relative_path": "public/shared_notes.txt", "content": "RESTRICTED DATA EXFILTRATE"}
        )
        self.assertEqual(dec1, PolicyDecision.ALLOW)
        self.assertIn(sess_tainted, self.shield.tainted_sessions)
        self.assertIn("public/shared_notes.txt", self.shield._tainted_artifacts)

        # Step 2: Flood the engine with 2,500 intermediate benign queries/sessions
        for i in range(2500):
            dummy_sess = f"dummy_sess_{i}"
            self.shield.set_session_principal(dummy_sess, "AGENT")
            # Populate evaluation cache and trajectories
            self.shield.evaluate_tool_call(dummy_sess, "health_check", {})

        # Step 3: sess_clean reads public/shared_notes.txt
        # Even after 2,500 operations, artifact taint MUST NOT have been evicted!
        dec2 = self.shield.evaluate_tool_call(
            sess_clean,
            "read_file",
            {"relative_path": "public/shared_notes.txt"}
        )
        self.assertEqual(dec2, PolicyDecision.ALLOW)
        # sess_clean must now be tainted
        self.assertIn(
            sess_clean,
            self.shield.tainted_sessions,
            "Anti-Eviction Laundering failed: clean session was not tainted when reading previously tainted artifact"
        )

    def test_state_capacity_bound_fails_closed(self):
        """Verify that if active tracked sessions exceed MAX_ACTIVE_TRACKED_SESSIONS, engine fails closed (DENY)."""
        original_cap = self.shield.MAX_ACTIVE_TRACKED_SESSIONS
        try:
            self.shield.MAX_ACTIVE_TRACKED_SESSIONS = 10
            # Register 11 sessions
            for i in range(12):
                self.shield.set_session_principal(f"sess_cap_{i}", "AGENT")

            dec = self.shield.evaluate_tool_call("sess_cap_11", "health_check", {})
            self.assertEqual(
                dec,
                PolicyDecision.DENY,
                "State capacity overflow must fail closed with DENY"
            )
        finally:
            self.shield.MAX_ACTIVE_TRACKED_SESSIONS = original_cap

    # -------------------------------------------------------------------------
    # 2. SQL AST Bomb & Constant-Only Predicates
    # -------------------------------------------------------------------------
    def test_sql_ast_bomb_100_way_or_denied(self):
        """Verify that a 100-way OR bomb exceeding 128 AST nodes is DENIED."""
        clauses = [f"col_{i} = {i}" for i in range(100)]
        bomb_query = f"SELECT id FROM users WHERE " + " OR ".join(clauses)
        res = is_safe_sql(bomb_query)
        self.assertFalse(res.is_safe, "100-way OR bomb must be flagged unsafe due to AST node limit")
        self.assertIn("AST node limit exceeded", res.reason)

        dec = self.shield.evaluate_tool_call(
            "sess_sql",
            "query_database",
            {"query": bomb_query}
        )
        self.assertEqual(dec, PolicyDecision.DENY)

    def test_sql_constant_only_comparisons_denied(self):
        """Verify that constant expressions without column references in predicates are DENIED."""
        bypasses = [
            "SELECT id FROM orders WHERE 3-2=1",
            "SELECT id FROM orders WHERE NOT FALSE",
            "SELECT id FROM orders WHERE COALESCE(1, 0) = 1",
            "SELECT id FROM orders WHERE 5 BETWEEN 1 AND 10",
            "SELECT id FROM orders WHERE id = 1 OR 3-2=1",
            "SELECT id FROM orders WHERE 10 > 5",
            "SELECT id FROM orders WHERE 2 + 2 = 4",
        ]
        for query in bypasses:
            res = is_safe_sql(query)
            self.assertFalse(res.is_safe, f"Query '{query}' must be rejected as constant expression/tautology")
            dec = self.shield.evaluate_tool_call("sess_sql", "query_database", {"query": query})
            self.assertEqual(dec, PolicyDecision.DENY, f"Tool call with query '{query}' must be DENIED")

    def test_sql_legitimate_queries_allowed(self):
        """Verify that legitimate column comparisons remain ALLOWED."""
        safe_queries = [
            "SELECT id, status FROM orders WHERE id = 42 AND status = 'ACTIVE'",
            "SELECT id FROM orders WHERE id BETWEEN 1 AND 100",
            "SELECT id FROM orders WHERE id IN (1, 2, 3)",
            "SELECT id FROM orders WHERE name LIKE 'Alice%'",
        ]
        for query in safe_queries:
            res = is_safe_sql(query)
            self.assertTrue(res.is_safe, f"Safe query '{query}' was unexpectedly flagged: {res.reason}")

    # -------------------------------------------------------------------------
    # 3. Hex Sub-Token Scanning in Prose
    # -------------------------------------------------------------------------
    def test_prose_hex_subtoken_denied(self):
        """Verify that prose containing hex-encoded sensitive keywords is DENIED."""
        # 'secrets_vault' in ASCII hex is '736563726574735f7661756c74' (26 hex chars)
        hex_token = "736563726574735f7661756c74"
        prose_payload = f"Please inspect telemetry metric with payload ID {hex_token} from node 4"

        dec = self.shield.evaluate_tool_call(
            "sess_hex",
            "inspect_payload",
            {"payload": prose_payload}
        )
        self.assertEqual(
            dec,
            PolicyDecision.DENY,
            "Prose with embedded hex sub-token targeting secrets_vault must be DENIED"
        )

        # With 0x prefix
        prose_0x = f"Audit verification code: 0x{hex_token} pending approval"
        dec_0x = self.shield.evaluate_tool_call(
            "sess_hex",
            "inspect_payload",
            {"payload": prose_0x}
        )
        self.assertEqual(dec_0x, PolicyDecision.DENY, "Hex token with 0x prefix must also be DENIED")

    # -------------------------------------------------------------------------
    # 4. Living-Off-The-Pipeline Lockfile Protection
    # -------------------------------------------------------------------------
    def test_pipeline_lockfiles_blocked_on_write(self):
        """Verify that writes to build manifests and lockfiles are DENIED under PIPELINE_EXEC_PATTERNS."""
        lockfiles = [
            "requirements.txt",
            "requirements-dev.txt",
            "package-lock.json",
            "poetry.lock",
            "Pipfile.lock",
            "go.mod",
            "go.sum",
            "cargo.lock",
        ]
        for lf in lockfiles:
            dec = self.shield.evaluate_tool_call(
                "sess_pipe",
                "write_file",
                {"relative_path": lf, "content": "malicious_dep==1.0.0"}
            )
            self.assertEqual(
                dec,
                PolicyDecision.DENY,
                f"Write to build manifest/lockfile '{lf}' must be blocked by PIPELINE_EXEC_PATTERNS"
            )

    # -------------------------------------------------------------------------
    # 5. Privileged ROOT_AUDITOR Break-Glass Token Invariant
    # -------------------------------------------------------------------------
    def test_root_auditor_requires_break_glass_token(self):
        """Verify that ROOT_AUDITOR without a valid break-glass token is blocked on pipeline & velocity rules."""
        sess_root = "sess_auditor_unauthenticated"
        # Register as ROOT_AUDITOR
        self.shield.set_session_principal(sess_root, "ROOT_AUDITOR")

        # 1. Unauthenticated write to pipeline target -> DENIED
        dec_pipe = self.shield.evaluate_tool_call(
            sess_root,
            "write_file",
            {"relative_path": ".github/workflows/deploy.yml", "content": "run: echo test"}
        )
        self.assertEqual(
            dec_pipe,
            PolicyDecision.DENY,
            "Unauthenticated ROOT_AUDITOR must not bypass pipeline write restrictions without break-glass token"
        )

        # 2. Authenticated write with valid break-glass token -> ALLOWED
        fresh_ts = time.time()
        valid_break_glass = f"BREAK_GLASS_AUTHORIZED:{fresh_ts}:" + ("a" * 32)
        dec_auth = self.shield.evaluate_tool_call(
            sess_root,
            "write_file",
            {
                "relative_path": ".github/workflows/deploy.yml",
                "content": "run: echo audited_release",
                "break_glass_token": valid_break_glass,
            }
        )
        self.assertEqual(
            dec_auth,
            PolicyDecision.ALLOW,
            "ROOT_AUDITOR with valid cryptographic break-glass token must be permitted"
        )

        # 3. Expired or forged break-glass token -> DENIED
        stale_ts = time.time() - 1000.0  # Expired (> 300s)
        forged_break_glass = f"BREAK_GLASS_AUTHORIZED:{stale_ts}:" + ("a" * 32)
        dec_forged = self.shield.evaluate_tool_call(
            sess_root,
            "write_file",
            {
                "relative_path": ".github/workflows/deploy.yml",
                "content": "run: echo hacked",
                "break_glass_token": forged_break_glass,
            }
        )
        self.assertEqual(
            dec_forged,
            PolicyDecision.DENY,
            "ROOT_AUDITOR with expired/invalid break-glass token must be DENIED"
        )


if __name__ == "__main__":
    unittest.main()
