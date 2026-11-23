# 🎯 Custom Adversarial Payload Directory

This directory is where security researchers, red teams, and engineers can place their own custom exploit payloads to challenge LIA.

## Supported Formats
- **Raw binary / shellcode:** `.bin` (e.g. buffer overflows, NOP sleds, shellcode)
- **Text / Strings:** `.txt` (e.g. polyglots, prompt injections, SQLi, command injection)
- **JSON Objects:** `.json` (e.g. malformed API requests, tool calls, SCADA/Modbus setpoint tampering)

## How to Test Your Payload Against LIA

Run the challenge runner with the `--custom` flag pointing to your file:

```bash
# Test a raw binary overflow
python3 challenge_runner.py --custom attacks/custom_payloads/sample_cwe120_overflow.bin

# Test a nested SQLi polyglot
python3 challenge_runner.py --custom attacks/custom_payloads/sample_polyglot_sqli.txt

# Test an industrial SCADA/Modbus setpoint tamper
python3 challenge_runner.py --custom attacks/custom_payloads/sample_modbus_tamper.json
```

## What LIA Will Output

LIA evaluates your payload in sub-millisecond time and outputs:
- **Verdict:** `BLOCKED / CONTAINED` or `PERMITTED`
- **Latency:** Execution duration in nanoseconds/microseconds
- **Invariant Triggered:** The exact mathematical, grammar, or memory boundary rule that intercepted the payload
- **Cryptographic Attestation:** SHA-256 state digest and hardware timestamp

## Bypassed an Invariant?
If you craft a payload that you believe bypasses LIA's invariant boundaries without detection:
1. Open a GitHub Issue with the tag `[ADVERSARIAL-CHALLENGE-SUBMISSION]`.
2. Provide your exact payload and reproduction steps.
3. Our team will verify and award formal CVE/bounty credit.
