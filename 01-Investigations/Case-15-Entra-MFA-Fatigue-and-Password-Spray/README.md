# Case 15 — Entra ID MFA Fatigue: Account Takeover from Stolen Credentials

> [!NOTE]
> **Case 15 onward follows an enterprise / MSSP methodology:** behavioural detection (not indicator matching), criticality-aware triage, independent-source validation, NIST CSF 2.0 response, and a Definition of Done for shift handoff. Earlier cases are kept as-is to show progression.

> [!IMPORTANT]
> Controlled lab simulation in an isolated Microsoft Entra tenant I own (`vincsecops.onmicrosoft.com`). All identities are test accounts. No real users, data or third-party systems are involved.

| Field | Detail |
|---|---|
| **Case ID** | CASE-15 |
| **Customer (tenant)** | Bandman Enterprise — managed customer of the MSSP SOC |
| **Detection platform** | Microsoft Defender XDR (unified portal) + Microsoft Entra ID Protection |
| **Initial severity** | High (Critical — the compromised identity is a classified critical asset) |
| **ATT&CK** | T1078.004 · T1621 · T1656 · T1098.005 · T1556.006 · T1098.003 |
| **Framework** | NIST CSF 2.0 (incident handling per NIST SP 800-61 Rev. 3) |
| **Status** | 🟢 Telemetry captured — detections validated against live data |
| **Analyst** | Vincent Chinedu |

---

## 1. Executive Summary

- **What happened:** `contact@` (HR Manager, **User Administrator**) was taken over through an MFA fatigue attack. The attacker already held the valid password — obtained off-platform (infostealer log / credential marketplace), so no spray was needed — and used a prompt flood to get past MFA.
- **Was access gained:** **Yes.** After 22 unsatisfied MFA challenges from an external cloud IP (`64.176.184.230`, GB/London), an approved prompt produced a successful interactive sign-in from a source the user had never used.
- **Business impact:** a User Administrator session grants password-reset and user-management rights — a direct path to tenant-wide compromise.
- **Time to contain:** *(fill from lab)*
- **Root cause:** valid-credential exposure combined with push MFA that is not phishing-resistant; the account was susceptible to a prompt flood.

---

## 2. Business Context

Bandman Enterprise is a cloud-only online retailer (Microsoft 365 / Entra ID, no on-premises Active Directory). Identity and security monitoring is outsourced to our MSSP SOC.

The incident window is the **week before Black Friday**, the business's highest-revenue period:

- **Attackers time campaigns for peak season.** Staff are overloaded and more likely to approve a prompt just to make it stop.
- **Containment has a real cost.** Disabling a privileged identity mid-trading can stall user administration and order operations. Every response decision weighs *stopping the attacker* against *keeping the business running*.

---

## 3. Scenario

A credential-first intrusion. The attacker does not break MFA technically — they already hold the password and defeat MFA through human pressure. The earliest **on-platform** signal is therefore the MFA fatigue itself, which is where detection must begin.

### Pre-conditions (the gaps that made this possible)
1. The password for `contact@` was exposed off-platform (infostealer malware / credential marketplace). The tenant has no visibility of this theft — the first thing it *can* see is the attacker using the credential.
2. `contact@` holds the **User Administrator** role (create/manage users, reset passwords) and has no phishing-resistant MFA.
3. MFA is Microsoft Authenticator push **with number matching** — which blocks *blind* approval but not a user talked through the number.

### Attack chain
1. **Credential in hand.** The attacker authenticates with the valid, stolen password from external cloud infrastructure. MFA is the only remaining barrier. *(T1078.004 Valid Accounts: Cloud)*
2. **MFA fatigue as pressure.** The attacker triggers a sustained flood of Authenticator prompts. With number matching, this cannot be blindly approved — its purpose is **pressure and pretext**. *(T1621 MFA Request Generation)*
3. **Vishing relay (the bypass).** The attacker phones the user posing as IT support — "we're seeing failed logins, I've sent a prompt to confirm it's you, read me the number on your screen." Because the attacker's sign-in screen shows the matching number and the user's app does not, the user unknowingly supplies it. This is the step that defeats number matching, mirroring the Scattered Spider / Lapsus$ / Uber (2022) playbook. *(T1656 Impersonation)*
4. **Takeover.** The prompt is satisfied and the attacker holds an authenticated session from a source unfamiliar to the user.
5. **Pivot (impact).** With a User Administrator session, the cloud pivot is **persistence and privilege**, not a network hop: registering a new MFA method for durable access, resetting other users' passwords, or adding roles. *(T1098.005 / T1556.006 / T1098.003)*

> **The lesson the episode lands on:** number matching killed *blind* MFA bombing, so the attack evolved into **bombing + vishing**. The control that actually closes it is **phishing-resistant MFA (FIDO2 / passkeys)** — there is no human-relayable number to read out.

### What the SOC can observe
The credential theft is invisible (it happened on the victim's device). The tenant's first detection opportunity is the MFA pressure, read in the sign-in error codes:

- a sustained burst of **MFA-required / not-satisfied / failed** codes against one identity, then
- a **successful** interactive sign-in from a source that identity has **never used before**, then
- a **sensitive directory action** performed by that identity shortly after.

Three behaviours, in sequence — no indicator required.

---

## 4. Environment

| Component | Detail |
|---|---|
| Tenant | Bandman Enterprise (`vincsecops.onmicrosoft.com`) |
| Identity licensing | Microsoft Entra ID P2 on all in-scope identities |
| Attack infrastructure | External cloud VMs (not onboarded to any security tooling); the takeover originated from `64.176.184.230` (GB/London) |
| Telemetry | Defender XDR advanced hunting (`EntraIdSignInEvents`), Entra ID Protection, Entra audit logs |
| SIEM | Sign-in detections run free in Defender XDR; the persistence/privilege detection (audit stream) is a Sentinel rule — see §9 |

### Identities in scope and asset criticality

| Identity | Role | Criticality | Why |
|---|---|---|---|
| `enterprise@` (Vincent Chingy) | Global Administrator | **Very high (Tier 0)** | Full tenant control |
| `contact@` (HR Manager) — **the compromised account** | User Administrator | **High** | Can create/manage users and reset passwords, plus access to employee personal data (PII) |
| `support@` (IT Helpdesk) | Helpdesk Administrator | **High** | Can reset non-admin passwords |

> Criticality decides triage order and severity: this alert is worked as **Critical** because it lands on a classified critical-asset identity, not because of the alert type alone.

---

## 5. Telemetry, Error Codes & Behavioural Detection

No verdict rests on one source. Each conclusion is confirmed from a different angle.

| Role | Source | What it proves |
|---|---|---|
| **Primary** | `EntraIdSignInEvents` (Defender XDR), interactive + non-interactive | The attempts, source IP, error codes, success/failure |
| **Independent verdict** | Entra ID Protection: `RiskLevelAggregated` / `RiskState`, and the *AAD Identity Protection* alert in `AlertInfo` | Microsoft's own risk engine's assessment |
| **Post-compromise** | Entra **Audit logs** | New MFA method, password resets, role changes after access |
| **Context** | `IsManaged` / `IsCompliant`, location, user agent, time | Whether the activity fits the user |

### Reading the error codes — the behavioural baseline

The detections are built on the **sequence** of sign-in error codes, read like a sentence rather than matched like an indicator:

| Code | Meaning | Role in the detection |
|---|---|---|
| `50076` | MFA **required** — strong auth demanded before access | the challenge wall |
| `50074` | MFA **not satisfied** — user was challenged, did not pass | an unanswered prompt |
| `500121` | MFA **failed** — *"user didn't complete the MFA prompt"* (denied / ignored / timed out) | **the fatigue signal** — every rejected push |
| `0` | **Success** — authentication completed | the takeover moment |

A run of `50076 → 50074 → 500121` repeating, then a `0`, tells the analyst — with no IP or indicator — that something demanded MFA, got refused repeatedly, and finally got in. That pattern *is* the detection.

> [!IMPORTANT]
> **Key finding that shapes the detections:** Entra ID Protection only scores risk when the **correct** credentials are used, so `RiskLevelAggregated` populates on the *success*, not the failed prompts — it is a corroborator, not the primary signal. The primary detection is **behavioural**: the error-code sequence plus a success from a source new to the user.

> [!NOTE]
> **Lab limitations:**
> - **Number matching worked.** Blind approval was impossible; the single-operator lab "approved" only because the operator could see the number. A real victim requires the vishing relay.
> - **No Intune** → every sign-in shows `IsManaged = 0` / `IsCompliant = 0`. In production these are top legitimacy signals and underpin the Conditional Access policy that would block this outright.
> - **Hunting window ≠ production window.** Validating against historical lab data needed a wide lookback (e.g. `ago(38h)`); a deployed rule uses a short window matched to its run frequency, or it re-alerts on the same events every run.

---

## 6. Investigation Plan (decision tree)

| # | Question | How it is answered | If positive |
|---|---|---|---|
| 1 | Is an identity under MFA pressure? | A burst of `50076`/`50074`/`500121` for one account | Scope the account and source |
| 2 | Did it succeed? | An interactive `ErrorCode == 0` after the pressure | Treat as potential takeover |
| 3 | Is the success anomalous for this user? | The source IP is **not** in the user's 30-day baseline (`leftanti`) | Raise to High/Critical |
| 4 | Do independent sources agree? | `RiskLevelAggregated` / `RiskState`, Identity Protection alert | If they disagree, document why before closing |
| 5 | Is it expected or approved? | Authorised pen-test ticket? Confirm with the user **out-of-band** (phone, not email) | Approved → Benign True Positive |
| 6 | What did the attacker do after? | Audit logs: MFA method registered, password resets **by** `contact@`, role changes | Expand scope to every account touched |

**Verdict options:** True Positive (compromise) · True Positive (attempt, no access) · Benign True Positive (authorised test) · False Positive.

---

## 7. Response & Recovery: NIST CSF 2.0

| Function | Category | Actions |
|---|---|---|
| **Govern** | GV.RR · GV.PO | Confirm who authorises disabling a privileged identity during peak trading; follow the escalation matrix and SLA |
| **Identify** | ID.AM · ID.RA | Confirm asset criticality (`contact@` = High); assess blast radius from User Administrator rights |
| **Protect** | PR.AA | Phishing-resistant MFA for privileged roles; risk-based Conditional Access; require compliant device; strip excess roles (least privilege) |
| **Detect** | DE.CM · DE.AE | DR-02 (fatigue → anomalous takeover) and DR-03 (persistence/privilege pivot); Identity Protection alerts in Defender XDR |
| **Respond** | RS.MA · RS.AN · RS.MI · RS.CO | **Contain:** revoke sessions → reset password → remove any attacker-registered MFA method → block the source via a named location. Disabling a critical identity is **analyst-approved, not automatic**. **Communicate:** customer contact and the affected user |
| **Recover** | RC.RP · RC.CO | Restore with new credentials and re-registered MFA; reverse any password resets the attacker performed; enhanced monitoring for 14 days; closure report |
| **Identify — Improvement** | ID.IM | Lessons learned feed policy, detections and the runbook |

### Business continuity
Disabling `contact@` stops user-administration work during peak trading. Before blocking, confirm a **fallback** (a second User Administrator / SSPR) so the business keeps running while the account is offline.

### Automation stance
Session revocation is low-risk and reversible — a candidate for automation. Disabling a **critical** identity is not: a production playbook enriches the incident and requests analyst approval first (human-in-the-loop). A SOAR playbook is planned for a later case; this case uses the documented runbook.

---

## 8. MITRE ATT&CK Mapping

| Tactic | Technique | Observed as |
|---|---|---|
| Initial Access | T1078.004 Valid Accounts: Cloud | Sign-in with a valid, previously stolen credential |
| Credential Access | T1621 MFA Request Generation | Sustained Authenticator prompt flood (`500121` burst) |
| Initial Access | T1656 Impersonation | Vishing call posing as IT to relay the matching number |
| Persistence | T1098.005 Device Registration | Attacker-registered MFA method *(if found in audit)* |
| Credential Access / Defense Evasion | T1556.006 Modify Authentication Process: MFA | Changing the account's MFA registration *(if found)* |
| Privilege Escalation | T1098.003 Additional Cloud Roles | Role added, or password reset of another account *(if found)* |

*Precursor (off-platform, not tenant-visible): credential theft via infostealer — T1555 — produced the valid password.*

---

## 9. Case Files & Detections

| File | Contents |
|---|---|
| `README.md` | This document |
| `detections/DR-02-mfa-fatigue-takeover.kql` | Behavioural: MFA-pressure burst → success anomalous for the user (Defender XDR). **Validated on live data.** |
| `detections/DR-03-persistence-privilege-pivot.kql` | Behavioural: an attacked identity then performs a sensitive directory action (Sentinel / AuditLogs). |
| `detections/DR-01-password-spray.kql` | Library detection for tenant-wide spray coverage — **not triggered by this intrusion** (credential-first, no spray). Retained for completeness. |
| `runbook.md` | Response procedure and pivot map |
| `report.md` | Full technical timeline |
| `evidence/` | Screenshots and exported query results |

**Design note:** detections are written as **behaviour, not indicators**. No attacker IP, location, or hostname appears in rule logic — "suspicious" is defined relative to each user's own baseline and the error-code sequence, so the rules catch the *next* attacker on different infrastructure.

---

## 10. Definition of Done

- [x] Simulation executed and telemetry captured
- [x] DR-02 validated against live data and tuned (behavioural, baseline-relative)
- [ ] DR-03 validated (perform a persistence/privilege action as the compromised account, confirm in Audit logs)
- [ ] Verdict reached and confirmed by at least one independent source
- [ ] `runbook.md` written, including the pivot map
- [ ] `report.md` written with a full timeline
- [ ] Evidence uploaded
- [ ] Video published
- [ ] Short and LinkedIn post published
