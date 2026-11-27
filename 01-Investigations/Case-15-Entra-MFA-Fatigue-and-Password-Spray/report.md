# CASE-15 Incident Report — Entra ID MFA Fatigue: Account Takeover from Stolen Credentials

> [!IMPORTANT]
> Controlled lab simulation in an isolated Microsoft Entra tenant I own. All identities are test accounts. Attacker infrastructure was lab VMs, now decommissioned. Values marked **⟨fill⟩** are still to be completed from the case record; values marked **⟨verify⟩** need checking against the source before publishing.

| Field | Detail |
|---|---|
| Report ID | IR-CASE-15 |
| Defender XDR incident | 25 — *Identity Takeover — MFA Fatigue followed by anomalous sign-in involving one user* |
| Customer (tenant) | Bandman Enterprise — managed customer of the MSSP SOC |
| Report status | Draft v0.1 ⟨fill: Final once containment and recovery are complete⟩ |
| Handling | TLP:CLEAR (lab report, published). A production report would be TLP:AMBER and shared only with the customer. |
| Author | Vincent Chinedu, SOC Analyst |
| Reviewer | ⟨fill⟩ |
| Date | ⟨fill⟩ |
| Related documents | [README.md](README.md) (scenario, environment, detection design) · [runbook.md](runbook.md) · [evidence/](evidence/) · [detections/](detections/) |

All times are **UTC**. The Defender portal displayed some times in local time (UTC+1); those have been converted.

---

## 1. Executive summary

**What happened.** The HR Manager account `contact@`, which holds the User Administrator role, was taken over through an MFA fatigue attack. The attacker already had the valid password, obtained off-platform (scenario: infostealer log). On 24 November 2026, between 20:24 and 21:30, the account received 22 unsatisfied MFA challenges from two external cloud-hosted sources. At 21:30:48 an attacker-initiated sign-in succeeded from a source this user had never used.

**Impact.** The attacker held an authenticated session for an account that can reset passwords and manage users, a direct path to wider tenant compromise. No post-compromise directory changes have been found so far ⟨verify: Entra audit log review, §5.3⟩. No data access has been confirmed ⟨verify⟩.

**How it was found.** Behavioural custom detection **DR-02** in Defender XDR raised incident 25 at **High** severity. Microsoft Entra ID Protection did not score the sign-in as risky.

**Current status.** Classified **True Positive — compromised account (suspected)** and escalated at **P1** for containment. Containment: ⟨fill: sessions revoked / password reset / MFA methods reviewed, with times⟩.

**Key recommendations.** Phishing-resistant MFA for privileged roles; just-in-time activation (PIM) for the User Administrator role; Conditional Access requiring a compliant device for admin roles; onboard identity logs to Microsoft Sentinel so identity risk and audit activity can be correlated with detections. Full list in §9.

---

## 2. Incident overview

| Item | Detail |
|---|---|
| Detection source | DR-02 *MFA fatigue → anomalous takeover* (Defender XDR custom detection rule) |
| Severity | High (rule severity) |
| Priority | **P1** per the SOP-001 matrix: High severity on a classified critical-asset identity |
| Defender computed priority | Low. Not used for SLA; overridden with reasons in §4.3 |
| Classification | True Positive — compromised account (suspected; see §4.4) |
| Affected identity | `contact@` — HR Manager, User Administrator, asset criticality **High** |
| Attack sources | Two external cloud-hosted IP addresses (Appendix A) |
| ATT&CK (observed) | T1078.004 Valid Accounts: Cloud · T1621 MFA Request Generation |
| ATT&CK (scenario, not telemetry-visible) | T1656 Impersonation (vishing relay of the number-matching code) · precursor T1555 (credential theft off-platform) |
| ATT&CK (checked, not observed) | T1098.005 · T1556.006 · T1098.003 ⟨verify after audit review⟩ |

### Key times and response metrics

| Milestone | Time (UTC) | Metric |
|---|---|---|
| First malicious activity | 2026-11-24 20:24:26 | — |
| Account compromised (first success) | 2026-11-24 21:30:48 | — |
| Alert / incident created | 2026-11-25 ~21:53 ⟨verify: portal showed 22:53 local⟩ | Time to detect ≈ 25 h *(lab artefact, see note)* |
| Acknowledged (assigned, In progress) | ⟨fill⟩ | Time to acknowledge: ⟨fill⟩ (SLA ≤ 15 min) |
| Verdict / escalation | ⟨fill⟩ | Time to verdict or escalation: ⟨fill⟩ (SLA ≤ 30 min) |
| Containment complete | ⟨fill⟩ | Time to contain: ⟨fill⟩ (SLA ≤ 60 min) |
| Recovery declared | ⟨fill⟩ | — |

> [!NOTE]
> **Lab timing caveats.** (1) DR-02 was deployed *after* the simulation, and its first run scanned back 30 days, so the ~25 h detection delay reflects rule deployment, not rule performance. Deployed in advance at an hourly frequency, it would alert within roughly one run cycle of the success. (2) The incident was worked as a timed exercise on 26 November, so the SLA metrics are measured from exercise start (⟨fill⟩). Measured from incident creation, as production SLAs are, these times would be a breach. That is stated here rather than hidden.

---

## 3. Timeline

| Time (UTC) | Source | Event |
|---|---|---|
| 2026-11-23 18:59–19:02 | EntraIdSignInEvents | Last legitimate interactive sign-in before the attack, from the legitimate user's UK source (address withheld) |
| 2026-11-24 20:24:26 | EntraIdSignInEvents | **First MFA-pressure event.** Source 1 (cloud host, Council Bluffs, US) attempts interactive sign-in through *Azure Active Directory PowerShell* to **Microsoft Graph** |
| 20:24:26–20:26:28 | EntraIdSignInEvents | Six attempts from source 1, all interrupted at MFA. No success from this source |
| 20:34:52 | EntraIdSignInEvents | Source 2 (cloud host, London, GB) begins attempts against **OfficeHome** (browser). Failure |
| 21:11:06 | EntraIdSignInEvents | Source 2 failure |
| 21:22:54–21:30:25 | EntraIdSignInEvents | Sustained prompt flood from source 2: repeated interrupted and failed MFA challenges. **21:30:25** is the last unsatisfied challenge (DR-02 `LastPressure`) |
| 21:30:45 | EntraIdSignInEvents | Interrupt immediately before success, consistent with the "stay signed in" prompt after MFA completion ⟨verify ErrorCode, expected 50140⟩ |
| **21:30:48–21:30:53** | EntraIdSignInEvents | **Four successful interactive sign-ins (ErrorCode 0) from source 2.** Account compromised. Source never previously used by this identity |
| 2026-11-25 ~21:53 | Defender XDR | DR-02 matches on its first run; alert and **incident 25** created (High) ⟨verify time⟩ |
| 2026-11-26 ⟨fill⟩ | Defender XDR | Incident acknowledged and assigned; triage under SOP-001 begins |
| ⟨fill⟩ | Advanced hunting | DR-02 logic re-run; aggregate output broken down into raw events (§4.2) |
| ⟨fill⟩ | Defender XDR | Classification set: True Positive / Suspected Compromise |
| ⟨fill⟩ | Defender XDR case management | Escalated: *Contain* task assigned to ⟨fill: IR / Tier 2⟩, due ⟨fill⟩ |
| ⟨fill⟩ | Entra admin center | Containment actions (§6) |
| ⟨fill⟩ | — | Recovery declared; report finalised |

---

## 4. Detection and triage

### 4.1 How it was detected

DR-02 is behavioural. It matches no IP address, location or hostname. It fires when one identity shows:

1. a burst of unsatisfied MFA challenges (error codes 500121, 50074, 50076, 50203; at least 3 in 7 days), followed by
2. an **interactive** successful sign-in after that pressure began,
3. from a source **not seen** for that identity in its own 30-day baseline (`leftanti` against prior successful sign-ins).

Full logic: [detections/DR-02-mfa-fatigue-takeover.kql](detections/DR-02-mfa-fatigue-takeover.kql). Error-code meanings: README §5.

### 4.2 Validation (rule re-run and breakdown into raw events)

The rule's logic was re-run in advanced hunting. It returned one row: the source 2 success, `MfaFailures = 22`, `FirstPressure` 20:24:26, `LastPressure` 21:30:25, `RiskLevelAggregated = 0`.

Breaking the aggregate down into raw sign-in events showed:

- **The 22 challenges came from two sources, not one.** `MfaFailures` is counted per identity across all sources. `FirstPressure` is a source 1 event and `LastPressure` is a source 2 event. This is by design: attackers rotate infrastructure, so pressure is measured on the account.
- **Source 1 (PowerShell → Microsoft Graph) never succeeded.** This shows an attempt at programmatic API access as well as interactive browser access. It is recorded as intent; no impact was realised from that source.
- **Timezone mismatch.** The advanced hunting results pane displayed local time (UTC+1) while the raw logs are UTC. All times in this report are normalised to UTC.

### 4.3 Priority decision

Defender's computed *Priority assessment* ranked the incident **Low**: single user, no lateral movement in the attack story, and asset criticality not weighted. Under the SOP-001 matrix, High severity on a critical-asset identity is **P1**. P1 was applied because Defender lacks context that the SOC holds: this account can reset other users' passwords. The tool's priority orders the queue; the documented matrix sets the SLA.

### 4.4 Corroboration and verdict

| Check | Source (independent of DR-02?) | Result |
|---|---|---|
| Identity Protection risk on the sign-in | `RiskLevelAggregated` / `RiskState` on the sign-in row (yes: a separate engine) | **0 / none.** Not scored |
| Identity Protection alert | `AlertInfo` / `AlertEvidence` (yes) | None raised |
| Identity Protection risk reports | Entra admin center → ID Protection → Risky sign-ins / Risk detections (yes) | ⟨fill⟩ |
| Out-of-band user confirmation | Phone call to the user, not email (yes) | ⟨fill: did the user approve a prompt or read out a number?⟩ *(lab: the operator approved the prompt)* |

**Verdict:** True Positive — compromised account. **Confidence:** high on behaviour (22 unsatisfied challenges from two never-seen cloud sources, then success); independent corroboration ⟨fill: pending / obtained via …⟩.

> [!NOTE]
> **Telemetry gap TG-1.** Identity Protection did not score this takeover, so its risk fields cannot be relied on as primary corroboration. The dedicated identity-risk tables (`AADRiskySignIns`, `AADUserRiskEvents`) exist only in Microsoft Sentinel, not in Defender XDR advanced hunting. Risk data therefore cannot be joined into detections or hunted at scale; the analyst must pivot manually to the Entra admin center reports. **Remediation:** onboard Entra sign-in, audit and ID Protection logs to Sentinel (R5).

---

## 5. Scope and impact

### 5.1 Identities and sessions

| Question | Method | Result |
|---|---|---|
| Did either source touch any other identity? | Scoping query A (Appendix C), across all accounts | ⟨fill⟩ |
| Is any other identity under MFA pressure in the same window? | DR-02 pressure subquery without the user filter | ⟨fill⟩ |
| Attacker sessions on `contact@` | Successful sign-ins from source 2 | Four sign-ins, 21:30:48–21:30:53, application OfficeHome |

Indicators are used here **for scoping and blocking only**, never as detection logic.

### 5.2 Business impact

- **Privilege exposure:** User Administrator can create and manage users and reset passwords, a route to compromising other accounts.
- **Data exposure:** `contact@` has access to employee personal data. ⟨fill: evidence of access or none⟩. See §7 for the regulatory assessment.
- **Operational:** incident during the peak-trading week. Containment avoided disabling the account during trading unless approved (§6).

### 5.3 Post-compromise activity

Checked from 2026-11-24 21:30:48 onward:

| Check | Where | Result |
|---|---|---|
| New MFA / authentication method registered | Entra admin center → Audit logs (activity: *User registered security info*) and the user's Authentication methods blade | ⟨fill⟩ |
| Passwords reset by `contact@` | Audit logs, *Initiated by* = `contact@` | ⟨fill⟩ |
| Role or group changes | Audit logs | ⟨fill⟩ |
| Mailbox rules / forwarding | Exchange admin center or Purview audit | ⟨fill⟩ |

> [!IMPORTANT]
> **Evidence preservation.** With Entra ID P2, sign-in and audit logs are retained for 30 days. The 24 November activity ages out around **24 December 2026**. Export the query results and audit entries to `evidence/` before then.

---

## 6. Response actions and decision log

Containment followed SOP-002. Disabling a critical identity requires approval; reversible actions within the analyst's authority were taken first.

| Time (UTC) | Action | Authority | Verification |
|---|---|---|---|
| ⟨fill⟩ | Revoke all sessions and refresh tokens (`Revoke-MgUserSignInSession` / *Revoke sessions*) | Pre-authorised, reversible | No successful sign-ins from attacker sources after this time (query B) |
| ⟨fill⟩ | Reset password | ⟨fill⟩ | User re-registers on a trusted device |
| ⟨fill⟩ | Review authentication methods; remove any registered during the compromise window | ⟨fill⟩ | Method list matches the user's confirmed devices |
| ⟨fill⟩ | Mark the user as compromised in ID Protection (*Confirm user compromised*) | ⟨fill⟩ | User risk shows High / confirmed compromised |
| ⟨fill⟩ | Temporary block of attacker sources (named location + Conditional Access) | ⟨fill⟩ | Tactical only; attackers change infrastructure |
| Not performed ⟨or fill⟩ | Disable account | Requires customer approval (Tier 0 / critical identity) | Business-continuity fallback: second User Administrator or SSPR confirmed ⟨fill⟩ |

**Eradication:** no persistence found ⟨verify, §5.3⟩. **Recovery:** user restored with new credentials and re-registered MFA; enhanced monitoring for 14 days ⟨fill dates⟩.

---

## 7. Communications and regulatory assessment

| When (UTC) | Who | Channel | Content |
|---|---|---|---|
| ⟨fill⟩ | IR / Tier 2 | Defender case task | Escalation: verdict, evidence, SLA remaining, telemetry gap, actions needed |
| ⟨fill⟩ | Customer security contact | ⟨fill⟩ | Incident notification and recommended actions |
| ⟨fill⟩ | Affected user | Phone (out-of-band) | Confirmation questions; password reset and re-registration |

**Personal data assessment.** The compromised account can access employee personal data. As the MSSP (data processor), the SOC informs the customer (data controller) without undue delay. If personal data was accessed and a risk to individuals is likely, the customer must notify the ICO without undue delay and, where feasible, within 72 hours of becoming aware. **Current assessment:** ⟨fill: no evidence of personal-data access → not notifiable; decision and rationale recorded⟩.

---

## 8. Root cause and lessons learned

### 8.1 Root cause

A valid credential exposed off-platform, combined with **push MFA that is not phishing-resistant** on a privileged account. Number matching stops blind approval, but a user can be talked into reading out the number (scenario: vishing relay).

### 8.2 Contributing factors

- The User Administrator role is permanently assigned rather than activated just in time.
- No Conditional Access requirement for a compliant device: every attacker sign-in shows `IsManaged = 0` / `IsCompliant = 0` (lab: no Intune).
- Identity Protection did not score the takeover, so risk-based policy would not have intervened.
- No user channel to report unexpected MFA prompts.

### 8.3 What went well

- The behavioural detection caught a two-source attack that an IP-keyed rule would have split, with no indicators in its logic.
- Breaking the aggregate down into raw events exposed the multi-source pressure and the timezone mismatch before they reached the report.
- The SOP-001 priority matrix overrode an under-informed tool priority, with reasons recorded.

### 8.4 What needs improvement

- **Corroboration is manual.** Identity risk is not queryable in Defender XDR advanced hunting (TG-1).
- **Post-compromise detection (DR-03) cannot run without Sentinel**, because it depends on the audit stream. In the Defender XDR-only setup it is a manual check.
- **Investigation time display:** the portal showed local time, which risks timeline errors.
- **Detection deployment:** rules must be in place before the activity they cover (lab sequencing).

---

## 9. Recommendations and follow-up actions

| ID | Recommendation | CSF 2.0 | Owner | Priority | Due | Status |
|---|---|---|---|---|---|---|
| R1 | Phishing-resistant MFA (FIDO2 security keys / passkeys) for all privileged roles | PR.AA | Customer IAM | High | ⟨fill⟩ | Open |
| R2 | Make User Administrator an eligible PIM role: time-bound, MFA and approval on activation | PR.AA | Customer IAM | High | ⟨fill⟩ | Open |
| R3 | Conditional Access: require a compliant device for admin roles; enforce sign-in risk policy | PR.AA | Customer IAM | High | ⟨fill⟩ | Open |
| R4 | Enable *report suspicious activity* for MFA prompts; brief staff on prompt floods and IT-support vishing | PR.AT | Customer / SOC | Medium | ⟨fill⟩ | Open |
| R5 | Onboard Entra sign-in, audit and ID Protection logs to Sentinel; deploy DR-03 | DE.CM | MSSP SOC | Medium | ⟨fill⟩ | Open |
| R6 | Set the Defender portal time zone to UTC for investigations | ID.IM | MSSP SOC | Low | ⟨fill⟩ | Open |
| R7 | Update SOP-001 corroboration step: add Entra ID Protection reports and out-of-band user confirmation | ID.IM | MSSP SOC | Medium | ⟨fill⟩ | Open |

---

## Appendix A — Indicators (scoping and blocking only)

| Type | Value (defanged) | Context | Validity |
|---|---|---|---|
| IPv4 | `35.239.168[.]157` | Source 1 — cloud host, Council Bluffs, US; PowerShell → Microsoft Graph; no success | Lab VM, decommissioned. Do not reuse after the incident window |
| IPv4 | `64.176.184[.]230` | Source 2 — cloud host, London, GB; OfficeHome; **successful sign-ins** | Lab VM, decommissioned. Do not reuse after the incident window |

Cloud IP addresses are reassigned to other tenants once released, so these indicators are time-bound.

## Appendix B — MITRE ATT&CK

| Tactic | Technique | Status |
|---|---|---|
| Initial Access | T1078.004 Valid Accounts: Cloud | Observed |
| Credential Access | T1621 Multi-Factor Authentication Request Generation | Observed |
| Initial Access | T1656 Impersonation | Scenario (vishing relay); not visible in telemetry |
| Persistence | T1098.005 Account Manipulation: Device Registration | Checked ⟨fill result⟩ |
| Credential Access / Defense Evasion | T1556.006 Modify Authentication Process: MFA | Checked ⟨fill result⟩ |
| Privilege Escalation | T1098.003 Account Manipulation: Additional Cloud Roles | Checked ⟨fill result⟩ |

## Appendix C — Queries used

**Timeline (entity-scoped):**

```kql
EntraIdSignInEvents
| where Timestamp between (datetime(2026-11-23) .. datetime(2026-11-27))
| where AccountObjectId == "<contact@ object ID>"
| where tostring(LogonType) !contains "nonInteractive"
| project Timestamp, ErrorCode, IPAddress, Country, City, Application,
          ConditionalAccessStatus, RiskLevelAggregated, RiskState, IsManaged, IsCompliant
| order by Timestamp asc
```

**Breakdown of the 22 MFA-pressure events:**

```kql
EntraIdSignInEvents
| where Timestamp between (datetime(2026-11-24) .. datetime(2026-11-25))
| where AccountObjectId == "<contact@ object ID>"
| where tostring(LogonType) !contains "nonInteractive"
| where ErrorCode in (500121, 50074, 50076, 50203)
| summarize Count = count() by ErrorCode, IPAddress, Country, City
| order by Count desc
```

**A — Scoping: did the attacker sources touch any other identity?**

```kql
let AttackerIPs = dynamic(["<source 1>", "<source 2>"]); // values in Appendix A, refanged
EntraIdSignInEvents
| where Timestamp > datetime(2026-11-24)
| where IPAddress in (AttackerIPs)
| summarize Attempts = count(), Successes = countif(ErrorCode == 0),
            First = min(Timestamp), Last = max(Timestamp) by AccountUpn, IPAddress
```

**B — Containment verification: no attacker access after session revocation:**

```kql
EntraIdSignInEvents
| where AccountObjectId == "<contact@ object ID>"
| where Timestamp > datetime(<revocation time UTC>)
| project Timestamp, ErrorCode, IPAddress, Application, LogonType
| order by Timestamp asc
```
