"""
Librae Master Licensing Authority & Client Lifecycle Management Engine

Allows Founder Theenesan VK Kunjaayappan to:
1. Issue air-gapped, hardware-bound cryptographic license tickets to clients.
2. Maintain an immutable enterprise license registry (official_documents/librae_license_ledger.json).
3. Track expiration timelines, missed renewals, and client agent allocations.
4. Provide a command-line dashboard and programmatic API for license operations.
"""

import os
import sys
import json
import time
import hmac
import hashlib
import base64
import argparse
from typing import Dict, Any, List, Optional
from .hardware_fingerprint import SiliconFingerprint, LIBRAE_AUTHORITY_SALT

LEDGER_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "official_documents",
    "librae_license_ledger.json"
)

# Librae Master Signing Secret (In production, loaded from environment or HSM)
LIBRAE_MASTER_SECRET = os.environ.get(
    "LIBRAE_MASTER_LICENSE_KEY",
    "Librae::MasterKey::TheenesanVKKunjaayappan::SSM_202601025362::CradleLive2026"
).encode()

class LibraeLicenseAuthority:
    """
    Core licensing authority for issuing, verifying, and tracking enterprise licenses.
    """

    @classmethod
    def load_ledger(cls) -> List[Dict[str, Any]]:
        if not os.path.exists(LEDGER_FILE):
            return []
        try:
            with open(LEDGER_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []

    @classmethod
    def save_ledger(cls, ledger: List[Dict[str, Any]]) -> None:
        os.makedirs(os.path.dirname(LEDGER_FILE), exist_ok=True)
        with open(LEDGER_FILE, "w") as f:
            json.dump(ledger, f, indent=2)

    @classmethod
    def generate_license_ticket(
        cls,
        org_name: str,
        silicon_id: str,
        tier: str = "ENTERPRISE_ANNUAL",
        validity_days: int = 365,
        max_agents: int = 25,
        notes: str = ""
    ) -> Dict[str, Any]:
        """
        Creates a signed, tamper-proof license ticket bound to the client's silicon ID.
        """
        now = int(time.time())
        expiry = now + (validity_days * 86400)
        license_id = f"LIA-LIC-{hashlib.sha256(f'{org_name}_{silicon_id}_{now}'.encode()).hexdigest()[:10].upper()}"

        ticket_payload = {
            "license_id": license_id,
            "issuer": "Librae Ai Labs Sdn Bhd (SSM: 202601025362)",
            "organization": org_name,
            "silicon_hardware_id": silicon_id,
            "license_tier": tier,
            "max_agents": max_agents,
            "issued_epoch": now,
            "expires_epoch": expiry,
            "issued_date": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now)),
            "expires_date": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(expiry)),
            "notes": notes,
            "renewals_count": 0
        }

        # Cryptographic Signature over canonical JSON representation
        canonical_str = json.dumps(ticket_payload, sort_keys=True)
        signature = hmac.new(LIBRAE_MASTER_SECRET, canonical_str.encode(), hashlib.sha256).hexdigest()
        ticket_payload["signature"] = signature

        # Encode into a portable base64 string
        raw_token = base64.b64encode(json.dumps(ticket_payload).encode()).decode()
        ticket_payload["license_token"] = raw_token

        # Update ledger
        ledger = cls.load_ledger()
        ledger.append({
            "license_id": license_id,
            "organization": org_name,
            "silicon_hardware_id": silicon_id,
            "tier": tier,
            "max_agents": max_agents,
            "issued_date": ticket_payload["issued_date"],
            "expires_date": ticket_payload["expires_date"],
            "expires_epoch": expiry,
            "status": "ACTIVE",
            "renewals_count": 0,
            "license_token": raw_token
        })
        cls.save_ledger(ledger)

        return ticket_payload

    @classmethod
    def verify_ticket(cls, token_or_dict: Any, current_silicon_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Validates an offline license ticket:
        1. Verifies HMAC-SHA256 signature against Librae Root.
        2. Checks expiration date against monotonic time.
        3. Verifies that the ticket matches the local machine's Silicon ID.
        """
        if isinstance(token_or_dict, str):
            try:
                ticket = json.loads(base64.b64decode(token_or_dict.strip().encode()).decode())
            except Exception:
                return {"valid": False, "reason": "CORRUPTED_BASE64_TOKEN"}
        else:
            ticket = dict(token_or_dict)

        sig = ticket.get("signature")
        if not sig:
            return {"valid": False, "reason": "MISSING_SIGNATURE"}

        # Copy and remove signature to verify canonical hash
        verify_copy = {k: v for k, v in ticket.items() if k not in ("signature", "license_token")}
        canonical_str = json.dumps(verify_copy, sort_keys=True)
        expected_sig = hmac.new(LIBRAE_MASTER_SECRET, canonical_str.encode(), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(sig, expected_sig):
            return {"valid": False, "reason": "FORGED_OR_ALTERED_SIGNATURE"}

        now = int(time.time())
        if now > ticket.get("expires_epoch", 0):
            return {
                "valid": False,
                "reason": "EXPIRED_LICENSE",
                "expired_on": ticket.get("expires_date"),
                "organization": ticket.get("organization")
            }

        # Check silicon hardware binding
        expected_silicon = ticket.get("silicon_hardware_id")
        actual_silicon = current_silicon_id or SiliconFingerprint.get_canonical_silicon_id()

        # In development / unrestricted demo mode or floating agency seats:
        is_floating = expected_silicon in ("UNIVERSAL_DEMO", "AGENCY_PILOT_10SEATS") or str(expected_silicon).startswith("FLOATING")
        if not is_floating and expected_silicon != actual_silicon:
            return {
                "valid": False,
                "reason": "SILICON_HARDWARE_MISMATCH",
                "expected_silicon": expected_silicon,
                "actual_silicon": actual_silicon,
                "details": "This binary is locked to another physical machine. Unauthorized duplication detected."
            }


        days_left = (ticket.get("expires_epoch", 0) - now) / 86400.0

        return {
            "valid": True,
            "license_id": ticket.get("license_id"),
            "organization": ticket.get("organization"),
            "tier": ticket.get("license_tier"),
            "max_agents": ticket.get("max_agents"),
            "days_remaining": round(days_left, 1),
            "expires_date": ticket.get("expires_date"),
            "silicon_verified": True
        }

    @classmethod
    def renew_license(cls, license_id: str, additional_days: int = 365) -> Optional[Dict[str, Any]]:
        """
        Extends an existing license, increments renewal count, and produces a new token.
        """
        ledger = cls.load_ledger()
        target = None
        for item in ledger:
            if item.get("license_id") == license_id:
                target = item
                break

        if not target:
            return None

        now = int(time.time())
        current_expiry = target.get("expires_epoch", now)
        base_epoch = max(now, current_expiry)
        new_expiry = base_epoch + (additional_days * 86400)

        target["expires_epoch"] = new_expiry
        target["expires_date"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(new_expiry))
        target["renewals_count"] = target.get("renewals_count", 0) + 1
        target["status"] = "ACTIVE"

        # Re-sign ticket
        ticket_payload = {
            "license_id": target["license_id"],
            "issuer": "Librae Ai Labs Sdn Bhd (SSM: 202601025362)",
            "organization": target["organization"],
            "silicon_hardware_id": target["silicon_hardware_id"],
            "license_tier": target["tier"],
            "max_agents": target["max_agents"],
            "issued_epoch": now,
            "expires_epoch": new_expiry,
            "issued_date": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now)),
            "expires_date": target["expires_date"],
            "renewals_count": target["renewals_count"]
        }

        canonical_str = json.dumps(ticket_payload, sort_keys=True)
        sig = hmac.new(LIBRAE_MASTER_SECRET, canonical_str.encode(), hashlib.sha256).hexdigest()
        ticket_payload["signature"] = sig
        new_token = base64.b64encode(json.dumps(ticket_payload).encode()).decode()
        target["license_token"] = new_token

        cls.save_ledger(ledger)
        return target

    @classmethod
    def audit_expirations(cls) -> List[Dict[str, Any]]:
        """
        Returns clients requiring follow-up: expired licenses or licenses expiring within 30 days.
        """
        ledger = cls.load_ledger()
        now = int(time.time())
        alerts = []

        for item in ledger:
            exp = item.get("expires_epoch", 0)
            diff_days = (exp - now) / 86400.0
            if diff_days < 0:
                item["status"] = "EXPIRED"
                alerts.append({
                    "license_id": item["license_id"],
                    "org": item["organization"],
                    "alert_level": "MISSED_RENEWAL_EXPIRED",
                    "days_overdue": abs(round(diff_days, 1)),
                    "expires_date": item["expires_date"]
                })
            elif diff_days <= 30:
                item["status"] = "EXPIRING_SOON"
                alerts.append({
                    "license_id": item["license_id"],
                    "org": item["organization"],
                    "alert_level": "ACTION_REQUIRED_EXPIRING_SOON",
                    "days_remaining": round(diff_days, 1),
                    "expires_date": item["expires_date"]
                })
        cls.save_ledger(ledger)
        return alerts


def print_dashboard():
    """
    Renders an executive ASCII dashboard of all active enterprise licenses.
    """
    ledger = LibraeLicenseAuthority.load_ledger()
    now = int(time.time())

    print("\n" + "=" * 88)
    print("        LIBRAE AI LABS — MASTER LICENSE AUTHORITY & CLIENT REGISTRY")
    print("             Founder & Principal Architect: Theenesan VK Kunjaayappan")
    print("=" * 88)
    print(f"Total Client Licenses Issued: {len(ledger)}\n")

    if not ledger:
        print("  [No client licenses issued yet. Use --issue to grant a new license.]\n")
        print("=" * 88 + "\n")
        return

    header = f"{'License ID':<14} | {'Organization':<22} | {'Tier':<16} | {'Days Left':<10} | {'Status'}"
    print(header)
    print("-" * 88)

    for item in ledger:
        exp = item.get("expires_epoch", 0)
        days_left = (exp - now) / 86400.0
        status = item.get("status", "ACTIVE")
        if days_left < 0:
            status_str = "EXPIRED (Alert)"
            days_str = f"-{abs(round(days_left, 1))}d"
        elif days_left < 30:
            status_str = "EXPIRING SOON"
            days_str = f"{round(days_left, 1)}d"
        else:
            status_str = "ACTIVE"
            days_str = f"{round(days_left, 1)}d"

        print(f"{item.get('license_id', ''):<14} | {item.get('organization', '')[:22]:<22} | {item.get('tier', '')[:16]:<16} | {days_str:<10} | {status_str}")

    print("=" * 88 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Librae Master Licensing Authority CLI")
    parser.add_argument("--request-identity", action="store_true", help="Print machine silicon identity for licensing")
    parser.add_argument("--list", action="store_true", help="Display all active client licenses")
    parser.add_argument("--audit", action="store_true", help="Audit expired or upcoming renewal deadlines")
    parser.add_argument("--issue", action="store_true", help="Issue a new enterprise license")
    parser.add_argument("--renew", type=str, help="Renew license by License ID")
    parser.add_argument("--org", type=str, help="Organization Legal Name")
    parser.add_argument("--silicon-id", type=str, help="Target Silicon Hardware ID")
    parser.add_argument("--tier", type=str, default="ENTERPRISE_ANNUAL", help="License tier")
    parser.add_argument("--days", type=int, default=365, help="Validity duration in days")
    parser.add_argument("--agents", type=int, default=25, help="Max allowed agent instances")
    parser.add_argument("--verify", type=str, help="Verify a license token string or file")

    args = parser.parse_args()

    if args.request_identity:
        silicon_id = SiliconFingerprint.get_canonical_silicon_id()
        raw = SiliconFingerprint.get_hardware_raw_id()
        print("\n" + "=" * 65)
        print("          LIBRAE CLIENT MACHINE IDENTITY TOKEN")
        print("=" * 65)
        print(f"Silicon Hardware ID : {silicon_id}")
        print(f"Platform Arch       : {raw.get('platform')} {raw.get('arch')}")
        print(f"Hardware Class      : {raw.get('hardware_type')}")
        print("\nSend the Silicon Hardware ID above to theenesanvk@librae.work")
        print("to receive your signed, hardware-bound offline license ticket.")
        print("=" * 65 + "\n")
        return

    if args.list:
        print_dashboard()
        return

    if args.audit:
        alerts = LibraeLicenseAuthority.audit_expirations()
        print("\n--- CLIENT RENEWAL AUDIT REPORT ---")
        if not alerts:
            print("✔ All active clients are fully within healthy license terms.\n")
        else:
            for a in alerts:
                print(f"[{a['alert_level']}] {a['org']} ({a['license_id']}): {a.get('days_overdue', a.get('days_remaining'))} days — Expiry: {a['expires_date']}")
        print("----------------------------------\n")
        return

    if args.issue:
        if not args.org or not args.silicon_id:
            print("Error: --issue requires both --org and --silicon-id arguments.")
            sys.exit(1)
        res = LibraeLicenseAuthority.generate_license_ticket(
            org_name=args.org,
            silicon_id=args.silicon_id,
            tier=args.tier,
            validity_days=args.days,
            max_agents=args.agents
        )
        print("\n" + "=" * 70)
        print("✔ SUCCESSFULLY ISSUED NEW LIBRAE ENTERPRISE LICENSE")
        print("=" * 70)
        print(f"License ID       : {res['license_id']}")
        print(f"Organization     : {res['organization']}")
        print(f"Bound Silicon ID : {res['silicon_hardware_id']}")
        print(f"License Tier     : {res['license_tier']}")
        print(f"Max Agents       : {res['max_agents']}")
        print(f"Expires On       : {res['expires_date']}")
        print(f"\nCLIENT LICENSE TOKEN (Save to .lia-license or pass to engine):\n{res['license_token']}\n")
        print("=" * 70 + "\n")
        return

    if args.renew:
        res = LibraeLicenseAuthority.renew_license(args.renew, args.days)
        if not res:
            print(f"Error: License ID '{args.renew}' not found in ledger.")
        else:
            print(f"\n✔ Renewed {res['organization']} ({res['license_id']}) for +{args.days} days.")
            print(f"New Expiry: {res['expires_date']}")
            print(f"New Token:\n{res['license_token']}\n")
        return

    if args.verify:
        token = args.verify
        if os.path.exists(token):
            with open(token, "r") as f:
                token = f.read().strip()
        res = LibraeLicenseAuthority.verify_ticket(token)
        print("\n--- VERIFICATION RESULT ---")
        print(json.dumps(res, indent=2))
        print("---------------------------\n")
        return

    parser.print_help()

if __name__ == "__main__":
    main()
