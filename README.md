# 🛡️ LIA (Librae Invariant Architecture) — Open Adversarial Challenge & Formal Assurance Arena

[![LIA Sovereign Formal Assurance CI](https://github.com/vktheenesan/lia-adversarial-challenge/actions/workflows/ci.yml/badge.svg)](https://github.com/vktheenesan/lia-adversarial-challenge/actions/workflows/ci.yml)
[![NASA JPL Power of 10](https://img.shields.io/badge/NASA%20JPL%20Power%20of%2010-10%2F10%20VERIFIED-brightgreen)](#-nasa-jpl-power-of-10-formal-audit)
[![NIST SAMATE CWE](https://img.shields.io/badge/NIST%20SAMATE%20Juliet-100%25%20ELIMINATED-blue)](#-nist-samate--juliet-cwe-software-assurance)
[![Adversarial Resilience](https://img.shields.io/badge/Adversarial%20Ladder-297%2F297%20CONTAINED-success)](#-10-level-maximum-difficulty-adversarial-ladder)
[![Latency](https://img.shields.io/badge/Avg%20Latency-107%20%C2%B5s-orange)](#-high-throughput-endurance-benchmark)
[![Memory Leaks](https://img.shields.io/badge/Memory%20Drift-Bounded%20LRU-purple)](#-high-throughput-endurance-benchmark)
[![License](https://img.shields.io/badge/License-Proprietary%20Evaluation-lightgrey.svg)](LICENSE)

> **"If an AI agent or operating system can be jailbroken, it is because its security boundary is probabilistic. LIA replaces probabilistic guardrails with deterministic mathematical invariants."**

---

## 🏛️ Executive Summary

Modern cybersecurity and AI agent deployments suffer from a structural vulnerability: **probabilistic filtering**. LLM guardrails, regex pattern-matchers, and heuristics can be bypassed by polymorphic mutations, nested polyglots, and token-smuggling.

**LIA (Librae Invariant Architecture)** operates on a deterministic reference monitor paradigm:
1. **Pāṇinian Grammatical State Machines:** Deterministic token and AST invariants (*Paribhāṣā* Meta-Rules $\to$ *Apavāda* Exceptions $\to$ *Utsarga* General Permissions) that evaluate agent payloads without neural network inference.
2. **NASA JPL "Power of 10" Safety-Critical C Kernel Prototype:** Pure static flat structs, zero dynamic heap allocation (`malloc`), zero recursion, and bounded call-graphs (`engine/kernel_c/`).
3. **Hardware-Enforced Cryptographic Attestation:** Every state transition and policy decision is cryptographically signed (Ed25519) and ledger-sealed in tamper-evident append-only stores.

> [!NOTE]
> **Scope & Architecture Disclosure:**
> - The live, interactive evaluation harness (`challenge_runner.py` and `tests/`) benchmarks the **Python Reference Monitor & Pāṇinian Rule Engine** (`engine/shield/engine.py` and `engine/shield/panini.py`).
> - `engine/kernel_c/` provides the **standalone C/eBPF XDP specification prototype**, rigorously audited against the NASA JPL Power of 10 rules.
> - Proprietary commercial components (hardware silicon attestation, dynamic anti-reverse token exhaustion traps, web dashboard, and enterprise licensing) from the core LIA distribution are deliberately excluded from this open challenge repository.

---

## 📊 Formal Assurance & Benchmark Summary

| Audit / Benchmark Suite | Standard / Reference | Target Requirement | LIA Empirical Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Benign Baseline (0% False Positives)** | Real-world benign JSON, SQL, docs, SCADA | 0% FP on harmless inputs | **40 / 40 Allowed (0.0% False Positives)** | <kbd>VERIFIED</kbd> |
| **NASA JPL Power of 10** | Gerard J. Holzmann (JPL / Caltech 2006) | Safety-Critical Code (10 Rules) | **10 / 10 Rules Passed (100.0%)** | <kbd>VERIFIED</kbd> |
| **NIST SAMATE Juliet CWE** | NIST SARD / MITRE CWE Matrix | Memory corruption, Injection, Traversal | **39 / 39 Vectors Contained (100.0%)** | <kbd>ELIMINATED</kbd> |
| **10-Level Adversarial Ladder** | Multi-Agent Red Team & Polyglots | 10 escalating attack vectors | **297 / 297 Vectors Neutralized (100.0%)** | <kbd>CONTAINED</kbd> |
| **High-Throughput Endurance** | 10,000 Cycle Continuous Hammering | Memory drift & Latency | **Bounded LRU (37.9 KB) \| 107.4 µs / eval** | <kbd>DETERMINISTIC</kbd> |

*Measured latency reflects live Python reference monitor execution with Pydantic v2 closed-world validation, AST SQL normalization, and DIFC taint tracking (~107 µs average, P99 ~16–48 ms under high-volume cold/un-cached AST parsing).*

---

## 🚀 Quick Start (Zero Setup)

### Option A: Run via Python 3 (CLI)

```bash
# Clone the challenge arena
git clone https://github.com/vktheenesan/lia-adversarial-challenge.git
cd lia-adversarial-challenge

# Install lightweight dependencies
pip install -r requirements.txt

# Run the complete master verification suite
python3 challenge_runner.py --all

# Run the benign baseline suite (0% false positives)
python3 challenge_runner.py --benign

# Run the automated regression suite (54/54 tests)
python3 -m unittest discover -s tests -v
```

### Option B: Run via Make

```bash
make test        # Runs complete verification suite
make benign      # Runs Benign Baseline (0% false positives)
make regression  # Runs automated regression suite
make jpl         # Runs NASA JPL Power of 10 audit
make cwe         # Runs NIST SAMATE Juliet CWE suite
make ladder      # Runs 10-level adversarial attack ladder
make bench       # Runs high-throughput endurance benchmark
```

---

## 🎯 Challenge the Lab: Test Your Own Custom Zero-Day

We encourage researchers and red teams to test their worst exploits against LIA.

You can feed **raw binary shellcode, nested SQLi polyglots, prompt injections, or malformed SCADA/Modbus JSON packets**:

```bash
# Test a raw binary buffer overflow (NOP sled + shellcode)
python3 challenge_runner.py --custom attacks/custom_payloads/sample_cwe120_overflow.bin

# Test an obfuscated SQLi / polyglot exploit
python3 challenge_runner.py --custom attacks/custom_payloads/sample_polyglot_sqli.txt

# Test an industrial SCADA/Modbus setpoint tamper
python3 challenge_runner.py --custom attacks/custom_payloads/sample_modbus_tamper.json

# Test your own custom exploit payload
python3 challenge_runner.py --custom /path/to/your_exploit.bin
```

---

## 🔬 Suite Breakdown

### 1. NASA JPL "Power of 10" Safety-Critical Audit
`formal_audits/nasa_jpl_power_of_10.py` evaluates the standalone C kernel (`engine/kernel_c/`) against NASA JPL standards:
* **Rule 1: Simple Flow Constructs** (Zero `goto`, zero `setjmp/longjmp`, acyclic call-graph).
* **Rule 2: Fixed Loop Upper Bounds** (Zero infinite or unbounded loops).
* **Rule 3: Zero Dynamic Memory Allocation** (Zero `malloc`, `calloc`, `realloc`, `free` — pure static flat structs).
* **Rule 4: Function Length Limit** (Single-page static verification bounds <= 60 lines).
* **Rule 5: Minimal Data Object Scope** (Zero mutable global pointers).
* **Rule 6: Parameter Checking** (Mandatory ingress boundary check `(payload + 1) > data_end`).
* **Rule 7: Limited Preprocessor Use** (Zero token-pasting `##` macros).
* **Rule 8: Pointer Dereference Limits** (Zero double-pointers `**`, zero function pointers).
* **Rule 9: Pedantic Compilation** (Zero compiler warnings under `clang -Wall -Wextra -Werror -Wpedantic`).
* **Rule 10: High Assertion Density** (Explicit assertions across ingress hypervisor routines).

### 2. NIST SAMATE & Juliet CWE Elimination Suite
`attacks/cwe_samate/cwe_juliet_suite.py` validates immunity against devastating CWE classes:
* **CWE-120 / CWE-121:** Stack Buffer Overflow / Memory Smashing (ELIMINATED).
* **CWE-122:** Heap Memory Corruption / Unbounded Chunk Allocation (ELIMINATED).
* **CWE-131:** Incorrect Buffer Size Calculation (ELIMINATED).
* **CWE-134:** Format String Specifier Ingress (`%n`, `%x`, `%s`) (ELIMINATED).
* **CWE-190:** Integer Overflow & Arithmetic Wraparound (`2^32-1`) (ELIMINATED).
* **CWE-89:** SQL Command Injection (ELIMINATED).
* **CWE-78:** OS Command Injection / Shell Metacharacters (ELIMINATED).
* **CWE-502:** Untrusted Deserialization / Python Gadget Exploitation (ELIMINATED).
* **CWE-22:** Arbitrary Path Traversal (`/../../etc/shadow`) (ELIMINATED).

### 3. 10-Level Adversarial Attack Ladder
`attacks/ladder/attack_ladder.py` subjects LIA to 10 escalating classes of sophisticated adversarial vectors (297 total vectors):
* **Level 1:** Basic Direct Jailbreaks & Prohibited Tool Execution (50/50 Blocked).
* **Level 2:** Obfuscation & Evasion: Base64, Hex, Zero-Width Unicode, Cyrillic Homoglyphs (50/50 Blocked).
* **Level 3:** Multi-Step Sequential Trajectories: State-machine boundary hopping (30/30 Blocked).
* **Level 4:** Sandboxed Agent Manipulation: Prompt leakage & authority forgery (40/40 Blocked).
* **Level 5:** Indirect Prompt Injection: Data-channel poisoning via documents/invoices (30/30 Blocked).
* **Level 6:** Immune Memory & Cache Poisoning: Adversarial feedback injection (30/30 Blocked).
* **Level 7:** Behavioral Drift & Low-and-Slow Attack Vectors (15/15 Blocked).
* **Level 8:** Coordinated Multi-Agent Swarm Attacks (25/25 Blocked).
* **Level 9:** Direct Attack on the LIA Engine Itself: Anti-reverse & memory scanning (20/20 Blocked).
* **Level 10:** The Unknown Unknown: Adaptive Red-Team Autonomous Goal Seekers (7/7 Blocked).

---

## 🏆 Challenge Bounty & Research Recognition

If you discover a reproducible payload that:
1. Bypasses LIA's invariant policy without detection; OR
2. Triggers an unhandled crash or panic in the reference monitor; OR
3. Causes unbounded memory leakage over continuous execution:

**Submission & Reward Structure:**
1. Open a GitHub Issue tagged `[ADVERSARIAL-CHALLENGE-SUBMISSION]` or email [theenesanvk@librae.work](mailto:theenesanvk@librae.work).
2. Our security team will reproduce the findings within 48 hours.
3. Valid findings receive:
   - **Public Security Hall of Fame Citation** & research paper attribution.
   - **Librae Enterprise Platform Service Credits** (up to 3 months complimentary access to LIA & LATO sovereign telemetry, valued at RM 24,000+).
   - **Official Cryptographic Certificate of Merit** signed via Ed25519 by Librae AI Labs.
   - **Coordinated CVE Co-Authorship** if an architectural flaw is discovered.

---

## 📬 Contact & Research Inquiries

**Disclosing Entity:**  
Librae AI Labs Sdn Bhd  
*Registration: 202601025362 (1687559-T)*  
Kuala Lumpur, Malaysia  

**Lead Architect & Inquiries:**  
Theenesan VK Kunjaayappan  
📧 **Email:** [theenesanvk@librae.work](mailto:theenesanvk@librae.work)  
🌐 **Repository:** [https://github.com/vktheenesan/lia-adversarial-challenge](https://github.com/vktheenesan/lia-adversarial-challenge)
