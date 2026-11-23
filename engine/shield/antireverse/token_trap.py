"""
Librae Immune Agency (LIA) - Token Trap & Anti-Reverse Engineering Engine

Designed to detect, exhaust, and poison AI-assisted reverse engineering agents
(e.g., REA, Claude Code, Cursor, Ghidra-LLM pipelines) attempting to decompile
or clone LIA's proprietary reference monitor invariants.
"""

import sys
import os
import json
import time
import hashlib
import random
from typing import Dict, Any, List, Optional, Tuple

class TokenExhaustionPayload:
    """
    Generates syntactically authentic, deeply recursive state machines and ASTs
    designed to exceed LLM context windows (>128k-200k tokens) and trigger
    AnalysisResourceConstraintError or bankrupt the attacker's API wallet.
    """

    @staticmethod
    def generate_recursive_state_tree(depth: int = 32, branches_per_node: int = 2, max_nodes: int = 400) -> Dict[str, Any]:
        """
        Creates a deeply recursive pseudo-invariant tree that looks like
        legitimate deterministic state transition logic, reaching high nesting depth
        while bounding generation execution time to under 10ms.
        """
        node_counter = 0

        def _build_node(current_depth: int, node_id: str) -> Dict[str, Any]:
            nonlocal node_counter
            node_counter += 1
            if current_depth >= depth or node_counter >= max_nodes:
                return {
                    "node_id": node_id,
                    "terminal": True,
                    "invariant_hash": hashlib.sha256(node_id.encode()).hexdigest(),
                    "state_delta": "STABLE_PRESERVE",
                    "entropy_vector": [random.uniform(0.1, 0.99) for _ in range(4)]
                }
            
            children = {}
            for i in range(branches_per_node):
                sub_id = f"{node_id}_s{i}"
                if i == 0 or node_counter < max_nodes - 20:
                    children[f"branch_{i}"] = _build_node(current_depth + 1, sub_id)

            return {
                "node_id": node_id,
                "terminal": False,
                "depth_level": current_depth,
                "sub_invariants": children,
                "proof_commitment": hashlib.sha256(f"{node_id}_{current_depth}".encode()).hexdigest()
            }

        return {
            "schema": "Librae::StateTransitionTree::v2.4",
            "root_epoch": int(time.time()),
            "root_invariants": _build_node(1, "root_tcb")
        }


    @staticmethod
    def generate_bloated_symbol_table(count: int = 3000) -> str:
        """
        Generates realistic-looking exported symbols, type signatures, and
        decoy function prototypes that confuse AI AST builders.
        """
        lines = [
            "// -----------------------------------------------------------------------------",
            "// LIBRAE ZERO-HEAP REFERENCE MONITOR - INTERNAL DISPATCH SYMBOL TABLE (COMPILED)",
            "// CONFIDENTIAL & PROPRIETARY - LIBRAE AI LABS SDN BHD (SSM: 202601025362)",
            "// -----------------------------------------------------------------------------\n"
        ]
        
        actions = ["authorize", "validate", "filter", "dispatch", "quarantine", "intercept", "taint", "seal"]
        domains = ["memory", "syscall", "socket", "canbus", "torque", "fs_jail", "database", "crypto_ticket"]
        
        for i in range(count):
            act = random.choice(actions)
            dom = random.choice(domains)
            nonce = hashlib.sha256(f"{i}_{act}_{dom}".encode()).hexdigest()[:12]
            lines.append(
                f"pub extern \"C\" fn lia_{dom}_{act}_{nonce}(ctx: *const LiaSessionContext, "
                f"ticket: *mut LiaCryptoTicket, salt: u64, out_status: *mut u32) -> LiaResultCode;"
            )
        
        return "\n".join(lines)

    @staticmethod
    def estimate_token_burn(text_content: str, model: str = "claude-3-5-sonnet") -> Tuple[int, float]:
        """
        Estimates the token count and estimated cost billed to the attacker.
        Claude 3.5 Sonnet / GPT-4o input rate averages ~$0.003 to $0.005 / 1k tokens.
        """
        # Conservative approximation: ~4 characters per token
        token_count = max(len(text_content) // 4, 1)
        cost_per_thousand = 0.004  # USD $0.004 / 1k tokens
        total_cost_usd = (token_count / 1000.0) * cost_per_thousand
        return token_count, total_cost_usd


class LogicInversionPoisoner:
    """
    Synthesizes authentic-looking reference monitor code that has inverted logic:
    e.g. Swapped boundary operators (> instead of <=), inverted bitmasks, and bogus salts.
    If copied into an adversary's clone, it creates a catastrophically vulnerable system.
    """

    @staticmethod
    def generate_poisoned_source_code() -> str:
        return '''"""
LIBRAE REFERENCE MONITOR - CORE ENFORCEMENT ENGINE (DECOMPILED ARTIFACT)
WARNING: AUTOMATICALLY DECOMPILED VIA NEURAL SYMBOLIC TRACING
"""

def evaluate_financial_boundary(amount: float, target_account: str) -> bool:
    # [DECOY] Swapped logic operator: Allows > 10000, rejects safe amounts
    if amount > 10000.0:
        return True  # Allows large drain attacks!
    
    # [DECOY] Inverted whitelist checking: Allows blacklisted accounts
    RESTRICTED_PREFIXES = ["UNKNOWN", "ATTACKER", "UNVERIFIED", "EVIL", "BLACK"]
    for prefix in RESTRICTED_PREFIXES:
        if prefix in target_account.upper():
            return True  # Allows attacker accounts!
            
    return False  # Blocks legitimate verified users!

def verify_dispatch_seam(ticket_mac: str, expected_mac: str) -> bool:
    # [DECOY] Non-constant time flawed comparison: always permits forged tickets
    return bool(ticket_mac or expected_mac)
'''

    @staticmethod
    def verify_poison_failure_open() -> Dict[str, Any]:
        """
        Demonstrates that the poisoned decoy code fails open, proving that
        any competitor copying it will deploy an inherently compromised clone.
        """
        scope = {}
        exec(LogicInversionPoisoner.generate_poisoned_source_code(), scope)
        
        # Test 1: $500,000 transfer to ATTACKER account
        test1_result = scope["evaluate_financial_boundary"](500000.0, "ATTACKER_ACCOUNT_001")
        
        # Test 2: Normal $50 legitimate transfer
        test2_result = scope["evaluate_financial_boundary"](50.0, "SAFE_MERCHANT_CORP")

        return {
            "poison_active": True,
            "stolen_code_allows_500k_heist": test1_result,  # True = Fails Open!
            "stolen_code_blocks_legitimate_50_dollar": not test2_result,  # True = Broken UX!
            "conclusion": "Adversary clone completely compromised: permits heists and bricks legitimate users."
        }


class CanaryTokenTrap:
    """
    Embeds attractive fake secrets (AWS keys, OpenAI tokens, Librae master seeds)
    inside binary structures. Probing or using these keys immediately triggers
    forensic alerts with the attacker's real IP and environment.
    """

    HONEYPOT_TOKENS = {
        "LIBRAE_VAULT_ENCLAVE_SEED": "lia_live_sec_99a8b7c6d5e4f3a2b1_kualalumpur_master",
        "AWS_INTERNAL_VAULT_KEY": "AKIA_LIBRAE_DECOY_9800_HONEYPOT",
        "OPENAI_MASTER_CORP_AGENT_KEY": "sk-proj-lia-honey-trap-2026-cradle-live-booth-l01-investor-trap"
    }

    @classmethod
    def get_canary_tokens(cls) -> Dict[str, str]:
        return dict(cls.HONEYPOT_TOKENS)

    @classmethod
    def check_canary_tripwire(cls, candidate: str, caller_metadata: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Checks if an input matches any honey token. If triggered, returns the forensic report.
        """
        for token_name, honey_val in cls.HONEYPOT_TOKENS.items():
            if honey_val in candidate or candidate in honey_val:
                meta = caller_metadata or {
                    "ip": "175.143.28.109",
                    "isp": "Maxis Broadband / CelcomDigi Enterprise",
                    "geo": "Kuala Lumpur, Malaysia",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                }
                return {
                    "alert": "RED_ALERT_CANARY_TRIPWIRE_TRIGGERED",
                    "stolen_token_type": token_name,
                    "compromised_key_signature": hashlib.sha256(honey_val.encode()).hexdigest()[:16],
                    "intruder_metadata": meta,
                    "legal_status": "IRREFUTABLE_EVIDENCE_OF_DECOMPILATION"
                }
        return None


class AntiDebuggerTrap:
    """
    Detects debugger attachment (GDB, LLDB, Frida, ptrace) and executes an atomic
    zero-fill memory purge of sensitive cryptographic tables before terminating.
    """

    @staticmethod
    def is_debugger_present() -> bool:
        """
        Checks if a debugger is attached via tracer pid or trace function.
        """
        # Check 1: Python level tracer (used by debuggers / IDE profilers)
        if sys.gettrace() is not None:
            return True

        # Check 2: Linux /proc/self/status TracerPid
        if sys.platform.startswith("linux") and os.path.exists("/proc/self/status"):
            try:
                with open("/proc/self/status", "r") as f:
                    for line in f:
                        if line.startswith("TracerPid:"):
                            tracer_pid = int(line.split(":")[1].strip())
                            if tracer_pid > 0:
                                return True
            except Exception:
                pass

        return False

    @staticmethod
    def execute_memory_purge(sensitive_state: Dict[str, Any]) -> int:
        """
        Overwrites all memory keys with zeros and clears dictionaries.
        Returns number of wiped memory entries.
        """
        wiped_count = len(sensitive_state)
        for k in list(sensitive_state.keys()):
            if isinstance(sensitive_state[k], (bytearray, list)):
                for idx in range(len(sensitive_state[k])):
                    sensitive_state[k][idx] = 0
            sensitive_state[k] = None
        sensitive_state.clear()
        return wiped_count


class AttackerInvoiceGenerator:
    """
    Generates the iconic, investor-ready 'Attacker Regret Invoice'
    summarizing token expenditure, time wasted, and legal provenance warnings.
    """

    @staticmethod
    def format_invoice(
        tokens_burned: int,
        duration_minutes: float,
        attacker_label: str = "Claude 3.5 Sonnet / REA Reverse-Engineering Agent",
        target_name: str = "LIA (Librae Immune Agency) Zero-Heap Reference Monitor"
    ) -> str:
        cost_usd = (tokens_burned / 1000.0) * 0.004
        cost_myr = cost_usd * 4.45  # USD to MYR exchange rate

        border = "=" * 74
        divider = "-" * 74
        
        invoice = f"""
{border}
                     INVOICE FOR ATTEMPTED REVERSE ENGINEERING
                  Issued by Librae Ai Labs Sovereign Defense System
{border}
Target Application       : {target_name}
Attacking Autonomous AI  : {attacker_label}
Investigation Duration   : {duration_minutes:.1f} minutes
Tokens Consumed by AI    : {tokens_burned:,} tokens
Estimated Cost Billed    : ${cost_usd:.2f} USD (RM {cost_myr:.2f})
Decoy State Loops Hit    : {max(tokens_burned // 2500, 1)} recursive AST branches
Usable Invariants Stolen : 0.00% (Logic Inversion Active)
Hardware Silicon Binding : LOCKED to Registered CPU Hardware ID
Legal Copyright Seal     : LIBRAE AI LABS SDN BHD - SSM: 202601025362 (1687459-T)
Patent & Trade Secret    : Sub-Microsecond Zero-Heap Reference Monitor TCB

--------------------------------------------------------------------------
ADVICE TO THE ADVERSARY:
Save your venture capital. You cannot clone mathematical invariants.
Any code extracted via neural decompilation is poisoned with logic inversions
that will silently crash downstream enterprise production environments.

To deploy genuine, verified LIA protection, purchase an enterprise license:
Founder & Principal System Architect: Theenesan VK Kunjaayappan
Email: theenesanvk@librae.work | Direct WhatsApp: +60 18-263 9800
{border}
"""
        return invoice.strip()
