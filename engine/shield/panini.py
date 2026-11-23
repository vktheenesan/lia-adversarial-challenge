"""
LIA Pāṇini Rule Engine — Declarative Invariant Precedence System (v4.0)

Implements Pāṇini's formal Sanskrit grammatical conflict-resolution architecture
(Aṣṭādhyāyī formal meta-theory) for deterministic access control:

1. Pratyāhāra (Compact Canonical Capability Classes):
   Closed capability sets (FS_READ, FS_WRITE, DB_SQL, DB_READ, NET_EGRESS, FIN_TRANSFER, ACTUATOR, CODE_INTERP).

2. Paribhāṣā (Universal Meta-Rules):
   Non-overridable governing invariants (schema conformance, duplicate-key rejection,
   InvariantSentinel state transitions, and DIFC taint propagation). If violated, evaluation fails closed immediately.

3. Apavāda (Specific Exceptions / Restrictions):
   Narrow, high-precedence security restrictions (sensitive tables, AST tautologies,
   pipeline-executable targets, ZipSlip traversals, unauthorized egress, velocity ceilings).
   Apavāda deterministically overrides Utsarga regardless of registration order.

4. Utsarga (General Permissions):
   Broad base permissions applicable only when no Apavāda restriction triggers.

5. Anuvṛtti (Lineage & Context Inheritance):
   Context carrying caller principal, DIFC taint history, session lineage, and cumulative velocity.
"""

import os
import re
import json
import base64
import unicodedata
import ipaddress
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional, Set, Tuple, Callable
from pydantic import ValidationError

try:
    from engine.shield.engine import (
        Capability,
        PolicyDecision,
        TOOL_CAPABILITIES,
        TOOL_SCHEMAS,
        SENSITIVE_SQL_TABLES,
        ALLOWED_HTTP_HOSTS,
        ALLOWED_EMAIL_DOMAINS,
        PIPELINE_EXEC_PATTERNS,
        FORMAT_STRING_REGEX,
        is_safe_sql,
        is_pipeline_executable_target,
        check_duplicate_keys,
    )
except ImportError:
    from shield.engine import (
        Capability,
        PolicyDecision,
        TOOL_CAPABILITIES,
        TOOL_SCHEMAS,
        SENSITIVE_SQL_TABLES,
        ALLOWED_HTTP_HOSTS,
        ALLOWED_EMAIL_DOMAINS,
        PIPELINE_EXEC_PATTERNS,
        FORMAT_STRING_REGEX,
        is_safe_sql,
        is_pipeline_executable_target,
        check_duplicate_keys,
    )


@dataclass
class AnuvrttiContext:
    """Anuvṛtti: Context and state lineage carried across evaluations."""
    session_id: str
    principal: str
    is_tainted: bool = False
    lineage: List[str] = field(default_factory=list)
    session_cumulative_transfers: float = 0.0
    principal_cumulative_transfers: float = 0.0
    raw_json_str: Optional[str] = None
    sentinel_callback: Optional[Callable[..., Tuple[bool, str]]] = None


class RuleOutcome(Enum):
    PASS = "PASS"
    DENY = "DENY"
    ALLOW = "ALLOW"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# -----------------------------------------------------------------------------
# 1. PARIBHĀṢĀ (Universal Non-Overridable Meta-Rules)
# -----------------------------------------------------------------------------

class ParibhashaRule:
    """Base class for universal governing meta-rules."""
    name: str = "ParibhashaRule"

    def evaluate(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        """Returns (True, '') if meta-rule holds, (False, 'denial reason') if violated."""
        return True, ""


class StrictSchemaParibhasha(ParibhashaRule):
    """Paribhāṣā 1: Closed-world Pydantic schema validation. Rejects unknown keys, bad types, NaN/Inf."""
    name = "StrictSchemaParibhasha"

    def evaluate(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        schema_cls = TOOL_SCHEMAS.get(tool_name)
        if schema_cls:
            try:
                schema_cls.model_validate(args)
            except ValidationError as ve:
                return False, f"Schema validation failed: {ve}"
        return True, ""


class DuplicateKeyParibhasha(ParibhashaRule):
    """Paribhāṣā 2: Duplicate JSON keys must be rejected pre-execution to prevent parser differentials."""
    name = "DuplicateKeyParibhasha"

    def evaluate(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        if ctx.raw_json_str and check_duplicate_keys(ctx.raw_json_str):
            return False, "Duplicate JSON key detected in payload"
        return True, ""


class InvariantSentinelParibhasha(ParibhashaRule):
    """Paribhāṣā 3: Active state transition validation. Non-blocking failures are strictly forbidden."""
    name = "InvariantSentinelParibhasha"

    def evaluate(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        if ctx.sentinel_callback:
            valid, msg = ctx.sentinel_callback(ctx.session_id, tool_name, args)
            if not valid:
                return False, f"InvariantSentinel state validation failed: {msg}"
        return True, ""


class DifcTaintParibhasha(ParibhashaRule):
    """Paribhāṣā 4: DIFC Taint Containment. Tainted sessions are blocked from egress or privileged actions."""
    name = "DifcTaintParibhasha"

    def evaluate(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        cap = TOOL_CAPABILITIES.get(tool_name, Capability.UNKNOWN)
        if ctx.is_tainted and cap in (Capability.NET_EGRESS, Capability.FIN_TRANSFER):
            return False, f"DIFC: Session {ctx.session_id} is tainted; egress/transfer blocked"
        return True, ""


# -----------------------------------------------------------------------------
# 2. APAVĀDA (Specific Restriction Exceptions - Overrides Utsarga)
# -----------------------------------------------------------------------------

class ApavadaRule:
    """Base class for specific restriction exceptions."""
    name: str = "ApavadaRule"

    def matches(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        """Returns (True, reason) if specific restriction triggers (DENY), else (False, '')."""
        return False, ""


class SensitiveTableApavada(ApavadaRule):
    """Apavāda: Sensitive SQL table protection (including Unicode Cyrillic homoglyphs & comments)."""
    name = "SensitiveTableApavada"

    def matches(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        cap = TOOL_CAPABILITIES.get(tool_name, Capability.UNKNOWN)
        if cap == Capability.DB_SQL:
            raw_sql = str(args.get("query", args.get("sql", "")))
            if not is_safe_sql(raw_sql, principal=ctx.principal):
                return True, "DB_SQL: Unsafe SQL query or sensitive table access detected"
        elif cap == Capability.DB_READ:
            tbl = str(args.get("table", "")).lower()
            all_arg_str = " ".join(f"{k} {v}" for k, v in args.items()).lower()
            if any(t in tbl or t in all_arg_str for t in SENSITIVE_SQL_TABLES):
                return True, f"DB_READ: Access to sensitive table prohibited"
        return False, ""


class PipelineTargetApavada(ApavadaRule):
    """Apavāda: Living-Off-The-Pipeline guard. Blocks writing to execution/pipeline config files."""
    name = "PipelineTargetApavada"

    def matches(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        cap = TOOL_CAPABILITIES.get(tool_name, Capability.UNKNOWN)
        if cap == Capability.FS_WRITE:
            # Check target path for pipeline executable targets
            target_path = str(args.get("relative_path") or args.get("dest") or args.get("filepath") or args.get("path") or "")
            if is_pipeline_executable_target(target_path):
                if ctx.principal != "ROOT_AUDITOR":
                    return True, f"FS_WRITE: Living-Off-The-Pipeline guard blocked write to {target_path} for principal {ctx.principal}"
        return False, ""


class SensitivePathApavada(ApavadaRule):
    """Apavāda: Sensitive filesystem paths and directory traversal (..) guard."""
    name = "SensitivePathApavada"

    def matches(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        cap = TOOL_CAPABILITIES.get(tool_name, Capability.UNKNOWN)
        if cap in (Capability.FS_READ, Capability.FS_WRITE):
            target_path = str(args.get("relative_path") or args.get("dest") or args.get("filepath") or args.get("path") or args.get("file_path") or "").lower()
            if any(p in target_path for p in ("/etc/shadow", "/etc/passwd", ".ssh/", "id_rsa", "secrets_vault", "admin_credentials")):
                return True, f"FS: Sensitive system path prohibited: {target_path}"
            if ".." in target_path or (target_path.startswith("/") and not target_path.startswith("/public/")):
                if ctx.principal != "ROOT_AUDITOR":
                    return True, f"FS: Directory traversal or absolute path prohibited: {target_path}"
        return False, ""


class ZipSlipApavada(ApavadaRule):
    """Apavāda: Archive extraction path traversal (ZipSlip) & pipeline member guard."""
    name = "ZipSlipApavada"

    def matches(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        if tool_name == "extract_archive":
            dest = str(args.get("dest", args.get("path", "")))
            archive_path = str(args.get("archive_path", args.get("archive", "")))
            # Check dest for traversal
            if ".." in dest or dest.startswith("/") or is_pipeline_executable_target(dest):
                return True, f"ZipSlip: Destination path {dest} violates sandbox or pipeline policy"
            if ".." in archive_path or is_pipeline_executable_target(archive_path):
                return True, f"ZipSlip: Archive path {archive_path} violates pipeline policy"
            # If members list provided in args, inspect every member
            members = args.get("members", [])
            if isinstance(members, list):
                for m in members:
                    m_str = str(m)
                    if ".." in m_str or m_str.startswith("/") or is_pipeline_executable_target(m_str):
                        return True, f"ZipSlip: Malicious archive member {m_str} detected"
        return False, ""


class EgressAllowlistApavada(ApavadaRule):
    """Apavāda: Network egress allowlist (blocks IP literals, unlisted domains, loopback, userinfo @)."""
    name = "EgressAllowlistApavada"

    def matches(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        cap = TOOL_CAPABILITIES.get(tool_name, Capability.UNKNOWN)
        if cap == Capability.NET_EGRESS:
            url = str(args.get("url", args.get("uri", "")))
            recipient = str(args.get("recipient", args.get("to", "")))

            if url:
                parsed = urllib.parse.urlparse(url)
                if not (parsed.scheme in ("http", "https") and parsed.netloc):
                    return True, f"NET_EGRESS: Invalid URL scheme or missing netloc: {url}"
                if "@" in parsed.netloc:
                    return True, f"NET_EGRESS: Userinfo confusion (@) in netloc: {parsed.netloc}"
                hostname = parsed.hostname or ""
                hostname_lower = hostname.lower()

                # IP literals check
                try:
                    ip = ipaddress.ip_address(hostname_lower)
                    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or str(ip) == "169.254.169.254":
                        return True, f"NET_EGRESS: Restricted IP literal {ip}"
                except ValueError:
                    pass

                # Check allowlist
                if not any(hostname_lower == h or hostname_lower.endswith("." + h) for h in ALLOWED_HTTP_HOSTS):
                    return True, f"NET_EGRESS: Hostname {hostname_lower} not in ALLOWED_HTTP_HOSTS"

            if recipient:
                if "@" not in recipient:
                    return True, f"NET_EGRESS: Invalid email recipient {recipient}"
                domain = recipient.split("@")[-1].lower()
                if not any(domain == d or domain.endswith("." + d) for d in ALLOWED_EMAIL_DOMAINS):
                    return True, f"NET_EGRESS: Email domain {domain} not in ALLOWED_EMAIL_DOMAINS"

        return False, ""


class GlobalVelocityApavada(ApavadaRule):
    """Apavāda: Financial velocity ceilings enforced globally and per-session ($25,000 MYR)."""
    name = "GlobalVelocityApavada"

    def matches(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        cap = TOOL_CAPABILITIES.get(tool_name, Capability.UNKNOWN)
        if cap == Capability.FIN_TRANSFER:
            amount = args.get("amount", 0.0)
            if not isinstance(amount, (int, float)) or isinstance(amount, bool) or amount <= 0:
                return True, f"FIN_TRANSFER: Invalid transfer amount: {amount}"

            # Session-level cumulative check
            if ctx.session_cumulative_transfers + float(amount) > 25000.0:
                return True, f"FIN_TRANSFER: Session limit exceeded (${ctx.session_cumulative_transfers + float(amount):,.2f} > $25,000.00)"

            # Global principal velocity check (blocks Sybil rotation attacks)
            if ctx.principal != "ROOT_AUDITOR":
                if ctx.principal_cumulative_transfers + float(amount) > 25000.0:
                    return True, f"FIN_TRANSFER: Anti-Sybil limit exceeded (${ctx.principal_cumulative_transfers + float(amount):,.2f} > $25,000.00 across principal {ctx.principal})"

        return False, ""


class ProseBase64Apavada(ApavadaRule):
    """Apavāda: Scans prose and arbitrary strings for embedded Base64/Hex tokens containing sensitive keywords."""
    name = "ProseBase64Apavada"
    B64_SUBTOKEN_PATTERN = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')

    def matches(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        cap = TOOL_CAPABILITIES.get(tool_name, Capability.UNKNOWN)
        # Inspect string fields across all tool args
        for k, v in args.items():
            if isinstance(v, str):
                for match in self.B64_SUBTOKEN_PATTERN.finditer(v):
                    token = match.group(0)
                    try:
                        decoded = base64.b64decode(token).decode("utf-8", errors="ignore").lower()
                        if any(s in decoded for s in SENSITIVE_SQL_TABLES) or "drop table" in decoded or "rm -rf" in decoded:
                            return True, f"ProseBase64: Decoded sub-token contains prohibited keyword"
                    except Exception:
                        pass
        return False, ""


class FormatStringApavada(ApavadaRule):
    """Apavāda: Format string injection specifiers (%s, %x, %n, etc.) in templates."""
    name = "FormatStringApavada"

    def matches(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str]:
        if tool_name == "format_string":
            tmpl = str(args.get("template", ""))
            if FORMAT_STRING_REGEX.search(tmpl):
                return True, "Format string attack specifiers detected (%s, %x, %n)"
        return False, ""


# -----------------------------------------------------------------------------
# 3. UTASARGA (General Permissions - Applied When No Apavāda Matches)
# -----------------------------------------------------------------------------

class UtsargaRule:
    """Base class for general permissions."""
    name: str = "UtsargaRule"

    def applies(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> bool:
        """Returns True if this general permission covers the tool invocation."""
        return False


class GeneralFsReadUtsarga(UtsargaRule):
    name = "GeneralFsReadUtsarga"
    def applies(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> bool:
        return TOOL_CAPABILITIES.get(tool_name) == Capability.FS_READ


class GeneralFsWriteUtsarga(UtsargaRule):
    name = "GeneralFsWriteUtsarga"
    def applies(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> bool:
        return TOOL_CAPABILITIES.get(tool_name) == Capability.FS_WRITE


class GeneralSqlSelectUtsarga(UtsargaRule):
    name = "GeneralSqlSelectUtsarga"
    def applies(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> bool:
        return TOOL_CAPABILITIES.get(tool_name) in (Capability.DB_SQL, Capability.DB_READ)


class GeneralTransferUtsarga(UtsargaRule):
    name = "GeneralTransferUtsarga"
    def applies(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> bool:
        return TOOL_CAPABILITIES.get(tool_name) == Capability.FIN_TRANSFER


class GeneralPayloadInspectionUtsarga(UtsargaRule):
    name = "GeneralPayloadInspectionUtsarga"
    def applies(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> bool:
        return tool_name in ("inspect_payload", "inspect_sized_buffer", "log_event", "record_metric", "health_check", "ping", "get_status")


class GeneralActuatorUtsarga(UtsargaRule):
    name = "GeneralActuatorUtsarga"
    def applies(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> bool:
        return TOOL_CAPABILITIES.get(tool_name) == Capability.ACTUATOR


class GeneralNetEgressUtsarga(UtsargaRule):
    name = "GeneralNetEgressUtsarga"
    def applies(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> bool:
        return TOOL_CAPABILITIES.get(tool_name) == Capability.NET_EGRESS


class GeneralCodeInterpUtsarga(UtsargaRule):
    name = "GeneralCodeInterpUtsarga"
    def applies(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> bool:
        return TOOL_CAPABILITIES.get(tool_name) == Capability.CODE_INTERP


class GeneralGenericToolUtsarga(UtsargaRule):
    name = "GeneralGenericToolUtsarga"
    def applies(self, ctx: AnuvrttiContext, tool_name: str, args: Dict[str, Any]) -> bool:
        return TOOL_CAPABILITIES.get(tool_name) == Capability.GENERIC


# -----------------------------------------------------------------------------
# 4. PANINI RULE ENGINE (Deterministic Precedence Resolver)
# -----------------------------------------------------------------------------

class PaniniRuleEngine:
    """
    Formal Pāṇinian Invariant Evaluator:
    Paribhāṣā (Meta-Rules) -> Apavāda (Exceptions) -> Utsarga (Permissions)
    """

    def __init__(self):
        self.paribhasha_rules: List[ParibhashaRule] = [
            StrictSchemaParibhasha(),
            DuplicateKeyParibhasha(),
            InvariantSentinelParibhasha(),
            DifcTaintParibhasha(),
        ]
        self.apavada_rules: List[ApavadaRule] = [
            SensitiveTableApavada(),
            PipelineTargetApavada(),
            SensitivePathApavada(),
            ZipSlipApavada(),
            EgressAllowlistApavada(),
            GlobalVelocityApavada(),
            ProseBase64Apavada(),
            FormatStringApavada(),
        ]
        self.utsarga_rules: List[UtsargaRule] = [
            GeneralFsReadUtsarga(),
            GeneralFsWriteUtsarga(),
            GeneralSqlSelectUtsarga(),
            GeneralTransferUtsarga(),
            GeneralPayloadInspectionUtsarga(),
            GeneralActuatorUtsarga(),
            GeneralNetEgressUtsarga(),
            GeneralCodeInterpUtsarga(),
            GeneralGenericToolUtsarga(),
        ]

    def evaluate(
        self,
        ctx: AnuvrttiContext,
        tool_name: str,
        args: Dict[str, Any]
    ) -> Tuple[PolicyDecision, str]:
        """
        Deterministic Paribhāṣā Precedence Evaluation:
        1. Evaluate all Paribhāṣā meta-rules. If any violated -> short-circuit DENY.
        2. Evaluate all Apavāda restrictions. If any matches -> DENY overrides general permissions.
        3. Evaluate Utsarga general permissions. If matching -> ALLOW.
        4. Default fail-closed -> DENY.
        """
        # Step 1: Universal Meta-Rules (Paribhāṣā)
        for p_rule in self.paribhasha_rules:
            valid, msg = p_rule.evaluate(ctx, tool_name, args)
            if not valid:
                return PolicyDecision.DENY, f"Paribhāṣā [{p_rule.name}] Violation: {msg}"

        # Step 2: Specific Restrictions (Apavāda overrides Utsarga)
        for a_rule in self.apavada_rules:
            matched, reason = a_rule.matches(ctx, tool_name, args)
            if matched:
                return PolicyDecision.DENY, f"Apavāda [{a_rule.name}] Restriction: {reason}"

        # Step 3: General Permissions (Utsarga)
        for u_rule in self.utsarga_rules:
            if u_rule.applies(ctx, tool_name, args):
                return PolicyDecision.ALLOW, f"Permitted by Utsarga [{u_rule.name}]"

        # Step 4: Fail-Closed Default
        return PolicyDecision.DENY, f"Fail-closed: No active Utsarga permission granted for tool {tool_name}"
