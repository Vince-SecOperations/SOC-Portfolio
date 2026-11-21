# 🛡️ SOC Lab — Lessons Learned & Standard Operating Procedures (SOPs)

> [!NOTE]
> This document serves as a personal checklist to ensure my home lab mirrors **enterprise SOC standards**. Each lesson is tied to a real-world operational reality.

---

## 📑 Contents

1. [Lab Architecture & Alert Management](#1-lab-architecture--alert-management)
2. [Snapshot & Evidence Discipline](#2-snapshot--evidence-discipline)
3. [Presentation & Reporting Standards](#3-presentation--reporting-standards)

---

## 1. Lab Architecture & Alert Management

- [ ] **Isolate the Attacker:** Never onboard the attack VM (GCP) to Defender XDR/SIEM.
  > 💼 **Real SOC Context:** Prevents *"Alert Fatigue."* Benign offensive tools (Nmap, Metasploit) pollute the alert queue, training analysts to ignore notifications.

- [ ] **Monitor Only the Victim:** Onboard only the target VM (Vultr Windows) to the EDR to capture true telemetry.

- [ ] **Network Isolation:** -
- [ ] [ ] **Restrict Victim Exposure:** Lock down the victim VM's inbound traffic so only the attack VM can reach it — either via a Vultr firewall rule allowlisting the attacker's public IP, or via a Tailscale tailnet (with Vultr's public firewall closed). Document which method each case uses.
  > 💼 **Real SOC Context:** The victim still needs outbound internet for EDR telemetry, so "isolation" means controlling inbound access, not disconnecting the host. A public attacker IP mirrors an external threat (enrichable via threat intel); a Tailscale `100.x.x.x` address mirrors an internal or VPN-sourced threat, where the analyst must identify the source from asset inventory and VPN logs.
---

## 2. Snapshot & Evidence Discipline

- [ ] **Pre-Attack Baseline:** Take a snapshot immediately after a clean OS install. Label it clearly (e.g., `win-victim-clean-baseline`).
  > 💼 **Real SOC Context:** Guarantees **reproducibility**. If you don't revert to a clean state between tests, *"configuration drift"* will contaminate your behavioral analysis.

- [ ] **Forensic Preservation:** Always snapshot/image a compromised VM ***before*** applying remediation.
  > 💼 **Real SOC Context:** In real Incident Response (**PICERL**), deleting malware destroys the evidence needed for Root Cause Analysis.

- [ ] **Cost Management:** Set up billing alerts on **tr. Snapshots cost money (**$0.05/GB/mo**).
  > 💼 **Real SOC Context:** Cloud forensics requires budget management. Never leave orphaned snapshots running indefinitely.

---

## 3. Presentation & Reporting Standards

- [ ] **Hub vs. Spoke:** Keep the `.io` repo strictly for the polished dashboard. Keep `SOC-Portfolio` for raw technical evidence.
  > 💼 **Real SOC Context:** Separate the **Executive Summary** (for management) from the **Technical Deep-Dive** (for Tier 3 responders).

- [ ] **Standardize Case Files:** Every case must follow the same Markdown template:

  | Section | Purpose |
  |---|---|
  | **Scenario** | What happened and the attack setup |
  | **Telemetry** | Evidence captured from the EDR/SIEM |
  | **NIST Mapping** | Incident lifecycle phase alignment |
  | **Detections** | Alerts, queries and detection logic |

  > 💼 **Real SOC Context:** SOCs require standardized runbooks so analysts can seamlessly hand off active incidents across shifts.

- [ ] **Map to Frameworks:** Always map the incident to **NIST SP 800-61 Rev. 3** (Detect, Respond, Recover) and **MITRE ATT&CK**.

---

<sub>📌 *Living document — updated as new lessons are learned in the lab.*</sub>
