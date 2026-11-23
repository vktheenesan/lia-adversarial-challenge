# Contributing to the LIA Adversarial Challenge Arena

Thank you for your interest in contributing to the **Librae Invariant Architecture (LIA) Adversarial Challenge Arena**!

This project is dedicated to advancing deterministic, mathematical safety boundaries for artificial intelligence agents and autonomous cyber-physical systems.

---

## Areas Where Contributions Are Welcomed

1. **Novel Adversarial Vectors:**  
   Submitting new exploit techniques, multi-step polyglots, indirect prompt injections, or polymorphic mutations to stress-test the invariant hypervisor.
2. **Formal Verification Standards:**  
   Expanding our static analysis rulesets to include standards like **MISRA-C:2012**, **RTCA DO-178C (DAL-A)**, or **ISO 26262 (ASIL-D)**.
3. **Hardware & OS Portability:**  
   Benchmarking and testing the suite across diverse architectures (ARM64, RISC-V, x86_64, Apple Silicon).

---

## Development Workflow

1. **Fork the Repository:** Create your own fork and feature branch (`git checkout -b feature/novel-cwe-test`).
2. **Implement Test Cases:** Follow the structure in `attacks/cwe_samate/` or `attacks/ladder/`.
3. **Verify Compliance:** Ensure all existing verification suites pass:
   ```bash
   python3 challenge_runner.py --all
   ```
4. **Submit a Pull Request:** Provide a clear description of the threat model, attack vector, and empirical containment rate.

---

## Questions?
Reach out to **Theenesan VK Kunjaayappan** at [theenesanvk@librae.work](mailto:theenesanvk@librae.work).
