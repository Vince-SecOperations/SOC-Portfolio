# Case 15 — Entra ID Password Spray & MFA Fatigue

> [!NOTE]
> **Case 15 onward follows an enterprise / MSSP methodology:** criticality-aware triage, independent-source validation, NIST CSF 2.0 response, and a Definition of Done for shift handoff. Earlier cases are kept as-is to show progression.

> [!IMPORTANT]
> Controlled lab simulation in an isolated Microsoft Entra tenant I own (`vincsecops.onmicrosoft.com`). All identities are test accounts. No real users, data or third-party systems are involved.

| Field | Detail |
|---|---|
| **Case ID** | CASE-15 |
| **Customer (tenant)** | Bandman Enterprise — managed customer of the MSSP SOC |
| **Detection platform** | Microsoft Defender XDR (unified portal) + Microsoft Entra ID Protection |
| **Initial severity** | Medium → escalates to **High** if any targeted account authenticates successfully |
| **ATT&CK** | T1589.002 · T1110.003 · T1621 · T1078.004 · T1098.005 |
| **Framework** | NIST CSF 2.0 (incident handling per NIST SP 800-61 Rev. 3) |
| **Status** | 🟡 Open — simulation scheduled |
| **Analyst** | Vincent Chinedu |

---

## 1. Executive Summary

*(Completed after the investigation.)*

- **What happened:**
- **Was access gained?**
- **Business impact:**
- **Time to contain:**
- **Root cause:**

---

## 2. Business Context

Bandman Enterprise is a cloud-only online retailer (Microsoft 365 / Entra ID, no on-premises Active Directory). Its identity and security monitoring is outsourced to our MSSP SOC.

The incident window is the **week before Black Friday**, the business's highest-revenue period. This matters for two reasons:

- **Attackers time campaigns for peak season.** Staff are overloaded and more likely to approve a prompt just to make it stop.
- **Containment has a real cost.** Locking a privileged support account during peak trading stops password resets for staff and can stall order operations. Every response decision in this case weighs *stopping the attacker* against *keeping the business running*.

---

## 3. Scenario

This attack has two halves: a **technical** half (spray to find a valid password) and a **human** half (social engineering to defeat MFA number matching). Modern push MFA defeats *blind* fatigue, so a real intrusion pairs the prompt flood with a phone call. The case documents both.

### Pre-conditions (the gaps that made this possible)
1. Role mailboxes `support@` and `contact@` are published publicly, so usernames are known. *(T1589.002)*
2. The IT Helpdesk account holds a password-reset-capable admin role and has no phishing-resistant MFA.
3. MFA is Microsoft Authenticator push **with number matching** — which blocks blind approval but not a user who is talked through the number.

### Attack chain
1. **Password spray.** A single external IP (the attacker VM) sends failed sign-ins across several Bandman identities, a few attempts each. In the logs: a burst of credential failures from one IP across many accounts. *(T1110.003)*
2. **Credential hit.** One account stops failing at the password step. The attacker now has a valid password but is stopped by MFA.
3. **MFA fatigue as pressure.** The attacker triggers repeated Authenticator prompts to the user. With number matching, this cannot be blindly approved — its purpose here is **pressure and pretext**, not direct entry. *(T1621)*
4. **Vishing relay (the bypass).** The attacker telephones the user posing as IT support — "we're seeing failed logins, I've sent a prompt to verify it's you, read me the number on your screen." Because the attacker's sign-in screen shows the matching number and the user's app does not, the user unknowingly supplies or enters the number the attacker needs. This is the step that defeats number matching, and it mirrors the Scattered Spider / Lapsus$ / Uber (2022) playbook. *(T1656 Impersonation)*
5. **Impact.** The prompt is satisfied and the attacker obtains an authenticated session from an IP unfamiliar to the user. *(T1078.004)* With a password-reset-capable account, this is a path to tenant-wide compromise; the investigation then checks the audit log for attacker-registered MFA methods and passwords reset by the account. *(T1098.005)*

**Infrastructure pivot (lab note):** in this simulation the spray originated from the attacker VM IP, while the fatigue prompts and the successful approval came from a separate residential IP. This deliberately models an attacker rotating infrastructure between the credential-access and MFA phases, and it makes the "success from a new/unfamiliar IP" signal realistic.

> The lesson the episode lands on: number matching killed *blind* MFA bombing, so the attack evolved into **bombing + vishing**. The control that actually closes it is **phishing-resistant MFA (FIDO2 / passkeys)** — there is no human-relayable number to read out.

### What the SOC observes

1. **Password spray.** A single external IP, hosted by a public cloud provider, generates a burst of failed sign-ins against several Bandman identities in a short window. It uses only a handful of attempts per account, which is the signature of spraying rather than brute force. *(T1110.003)*
2. **Credential hit.** One targeted account, `support@` (IT Helpdesk), stops failing at the password step and starts failing at the **MFA** step instead. The password was correct.
3. **MFA fatigue.** The same source triggers repeated MFA requests to the IT Helpdesk user outside working hours. *(T1621)* This mirrors publicly reported intrusions such as Uber (2022) and campaigns attributed to Lapsus$ and Scattered Spider, where prompt floods were often combined with a message or call impersonating IT support.
4. **Decision point.** The investigation must determine whether the user approved a prompt and the attacker obtained a session *(T1078.004)*. If so, it must establish what the attacker did with a password-reset-capable account.

**Why this account is the prize:** a compromised Helpdesk Administrator can reset other users' passwords. One approved prompt turns a single account takeover into a **tenant-wide** incident.

---

## 4. Environment

| Component | Detail |
|---|---|
| Tenant | Bandman Enterprise (`vincsecops.onmicrosoft.com`) |
| Identity licensing | Microsoft Entra ID P2 on all in-scope identities |
| Attack source | External cloud VM (not onboarded to any security tooling) |
| Telemetry | Defender XDR advanced hunting, Entra ID Protection, Entra sign-in and audit logs |
| SIEM | Not required: the full investigation runs in Defender XDR |

### Identities in scope and asset criticality

| Identity | Role | Criticality | Why |
|---|---|---|---|
| `support@` (IT Helpdesk) | Helpdesk Administrator | **High** · priority account | Can reset other users' passwords, a direct path to wider compromise |
| `contact@` (HR Manager) | User Administrator | **High** · business-sensitive | Can create and manage users and reset passwords, plus access to employee personal data (PII) |
| `enterprise@` (Vincent Chingy) | Global Administrator | **Very high (Tier 0)** | Full tenant control |

> Criticality decides triage order: an MFA-fatigue alert on the Helpdesk Administrator is worked before the same alert on a standard user.

---

## 5. Telemetry & Independent Validation

No verdict rests on one source. Each conclusion must be confirmed by a source that observed the activity from a different angle.

| Role | Source | What it proves |
|---|---|---|
| **Primary** | `EntraIdSignInEvents` (Defender XDR advanced hunting), covering interactive and non-interactive sign-ins | The attempts happened: source IP, targeted accounts, error codes, success or failure |
| **Independent verdict** | Entra ID Protection: `RiskLevelAggregated` / `RiskState` on the sign-in, plus the *AAD Identity Protection* alert in `AlertInfo` / `AlertEvidence` | Microsoft's own risk engine independently assessed the activity |
| **Post-compromise corroboration** | Entra **Audit logs** (portal) | Whether anything changed after access: a new MFA method, passwords reset by the helpdesk account, role changes |
| **Context** | `IsManaged` / `IsCompliant`, location, user agent, time of day | Whether the activity fits this user's normal behaviour |

> [!IMPORTANT]
> **Key finding that shapes the detections:** Entra ID Protection only generates risk when the **correct** credentials are used. Failed spray attempts therefore show `RiskLevelAggregated = 0`. The spray must be detected **behaviourally** (one IP → many accounts → many failures), and risk becomes the independent corroborator only once a password succeeds. Password spray is also an **offline** detection, so it can arrive minutes to hours later.

> [!NOTE]
> **Lab limitation:** this tenant has no Intune-managed devices, so every sign-in shows `IsManaged = 0` and `IsCompliant = 0`. In production these are among the strongest legitimacy signals, and they underpin the Conditional Access control that would block this attack outright.

---

## 6. Investigation Plan (decision tree)

| # | Question | How it is answered | If positive |
|---|---|---|---|
| 1 | Is this a spray or noise? | **DR-01**: failed-credential burst from one IP across several accounts | Scope the IP |
| 2 | What is the scope? | Every account and application targeted by that IP; first and last seen | Check for any success |
| 3 | Did any account authenticate? | Pivot on the attacker IP → `ErrorCode == 0` | Treat that account as potentially compromised |
| 4 | Was the user pressured with MFA? | **DR-02**: MFA-failure burst followed by a successful sign-in from the same external source | Escalate to **High** |
| 5 | Do independent sources agree? | Risk columns, Identity Protection alert, Risky sign-ins report | If they disagree, document why before closing |
| 6 | Is it expected or approved? | Check for an authorised penetration-test or red-team ticket; confirm with the user **out-of-band** (phone, not email); is the IP a known corporate egress? | Approved → close as Benign True Positive |
| 7 | What did the attacker do? | Audit logs: MFA methods added, **password resets performed by `support@`**, role or Conditional Access changes | Expand scope to every account the helpdesk user touched |

**Verdict options:** True Positive (compromise) · True Positive (attempt, no access) · Benign True Positive (authorised test) · False Positive.

---

## 7. Response & Recovery: NIST CSF 2.0

| Function | Category | Actions in this case |
|---|---|---|
| **Govern** | GV.RR · GV.PO | Confirm who can authorise disabling a privileged account during peak trading; follow the customer's escalation matrix and SLA |
| **Identify** | ID.AM · ID.RA | Confirm asset criticality (Helpdesk Administrator = High); assess blast radius from the role's permissions |
| **Protect** | PR.AA | Phishing-resistant MFA for privileged roles; risk-based Conditional Access; priority-account tag on `support@`; review smart lockout |
| **Detect** | DE.CM · DE.AE | DR-01 (behaviour) and DR-02 (impact); Identity Protection alerts surfaced in Defender XDR |
| **Respond** | RS.MA · RS.AN · RS.MI · RS.CO | **Contain:** revoke sessions → reset password → remove any MFA method the attacker registered → block the source IP via a named location. Blocking sign-in on the privileged account is **analyst-approved, not automatic**. **Communicate:** customer contact and the affected user |
| **Recover** | RC.RP · RC.CO | Restore the account with new credentials and re-registered MFA; reverse any password resets the attacker performed; enhanced monitoring for 14 days; closure report to the customer |
| **Identify — Improvement** | ID.IM | Lessons learned feed back into policy, detections and the runbook |

### Business continuity

Containing `support@` stops password resets for staff during peak trading. Before blocking it, confirm a **fallback path**, such as a second helpdesk administrator or self-service password reset (SSPR), so the business keeps running while the account is offline.

### Automation stance

Revoking sessions is low-risk and reversible, so it is a candidate for automation. Disabling a **critical** account is not: in production a playbook would enrich the incident and request analyst approval before acting (human-in-the-loop). A SOAR playbook is planned for a later case; this case uses the documented runbook (`runbook.md`).

---

## 8. MITRE ATT&CK Mapping

| Tactic | Technique | Observed as |
|---|---|---|
| Reconnaissance | T1589.002 Email Addresses | Role mailboxes published publicly |
| Credential Access | T1110.003 Password Spraying | Failed-credential burst across accounts from one IP |
| Credential Access | T1621 MFA Request Generation | Repeated MFA prompts to one user |
| Initial Access / Persistence | T1078.004 Cloud Accounts | Successful sign-in with valid credentials *(if confirmed)* |
| Persistence | T1098.005 Device Registration | Attacker-registered MFA method *(if found)* |

---

## 9. Case Files

| File | Contents |
|---|---|
| `README.md` | This document: scenario, scope, investigation plan, framework mapping |
| `detections/` | DR-01 (password spray behaviour) and DR-02 (MFA fatigue → successful sign-in) |
| `runbook.md` | Step-by-step response procedure, including the pivot map |
| `report.md` | Full technical investigation report and timeline |
| `evidence/` | Screenshots and exported query results |

---

## 10. Definition of Done

- [ ] Simulation executed and telemetry captured
- [ ] DR-01 and DR-02 validated against real results and tuned
- [ ] Verdict reached and confirmed by at least one independent source
- [ ] `runbook.md` written, including the pivot map
- [ ] `report.md` written with a full timeline
- [ ] Evidence uploaded
- [ ] Video published
- [ ] Short and LinkedIn post published
