# SOP-003: Eradication, Remediation and Recovery

| Field | Value |
|---|---|
| **SOP ID** | SOP-003 |
| **Title** | Eradication, Remediation and Recovery: Removing the Threat, Fixing the Cause, Restoring Service |
| **Version** | 1.1 |
| **Status** | Active |
| **Owner** | Vince-SecOperations |
| **Effective date** | 2026-11-22 |
| **Next review** | 2027-05-22 |
| **Primary platform** | Microsoft Defender XDR (unified portal, with Microsoft Sentinel, Microsoft Entra ID and Microsoft Intune) |
| **Environments** | On-premises, hybrid (AD + Entra ID) and cloud workloads |
| **Preceded by** | [SOP-002: Containment](SOP-002-Containment.md) |
| **Feeds** | [Lessons-Learned.md](Lessons-Learned.md) |

---

## 1. Purpose

This SOP defines the strict, repeatable rules for keeping the business running while the threat is removed, removing the attacker's presence, fixing the condition that allowed the incident, and returning affected assets to production with proof that they are clean.

## 2. Scope

- **In scope:** every incident that reached containment under SOP-002, and every true positive where containment was not required (SOP-002 §6, C1 = No).
- **Out of scope:** full site disaster recovery; legal and regulatory notification (owned by the incident commander).

## 3. Framework alignment

| Activity | NIST CSF 2.0 |
|---|---|
| Establish what happened and the root cause | RS.AN |
| **Eradicate** | **RS.MI-02** |
| Apply the criteria for starting recovery | RS.MA-05 |
| **Recover and verify restored assets** | **RC.RP** |
| Communicate recovery status | RC.CO |
| Feed lessons learned into improvement | ID.IM |

## 4. Definitions

| Term | Definition |
|---|---|
| **Eradication** | Removing everything the attacker introduced or controls: malware, persistence, rogue accounts, stolen credentials. |
| **Remediation** | Fixing the weakness that allowed the incident: patch, configuration, MFA, exposed service, detection gap. |
| **Recovery** | Returning assets to production and confirming they are clean. |
| **Continuity mode** | How the business keeps operating while an asset is out of service: drained node, failover, DR copy, loaner device, degraded service, manual workaround. |
| **Drain** | Removing a node from a load-balanced pool so it stops receiving traffic while the remaining nodes serve users. |
| **Failover** | Moving a service to a secondary instance (cluster partner, replica, DR site or region). |
| **Fail back** | Returning the service to the rebuilt primary instance after recovery. |
| **Earliest attacker activity** | The first evidence of the attacker in the environment (initial access), which may be earlier than the first alert. |
| **Known-good state** | A backup, snapshot or recovery point proven to predate the earliest attacker activity. |
| **Golden image / infrastructure as code (IaC)** | A trusted, version-controlled build used to recreate a system from scratch. |
| **RTO / RPO** | Recovery time objective (how long the service may be down) / recovery point objective (how much data loss is acceptable). Set by the business impact analysis, not by the SOC. |

> In an interview, "remediated" can mean eradication, remediation or recovery. Say which one you did.

---

## 5. Roles and responsibilities

**The SOC does not drain load balancers, fail over services, re-image devices, patch systems or restore backups.** Those actions are executed by the teams that own the platforms, through change management. The SOC contains, scopes, verifies and decides when an asset is clean from a security standpoint.

**R** = does the work · **A** = accountable / approves · **C** = consulted · **I** = informed

| Activity | SOC | IR lead / incident commander | Service / asset owner | IT operations (infra, cloud, DBA, app team) | Endpoint engineering / service desk |
|---|---|---|---|---|---|
| Containment through Defender XDR / Entra ID | R | A (Tier 0/1) | I / C | I | I |
| Accept business impact of containment or downtime | C | C | **A** | C | — |
| Drain node / fail over service | C (requests, verifies target) | A | A | **R** | — |
| Provide loaner device / VDI / cloud PC | I | — | — | — | **R** |
| Re-image workstation (Intune wipe + Autopilot) | C (evidence first, verifies after) | I | I | — | **R** |
| Rebuild server / restore from backup | C (verifies clean target) | A | A | **R** | — |
| Eradicate identity persistence, reset credentials | R | A (privileged / Tier 0) | I | C (identity team) | — |
| Patch / configuration fix (remediation) | C (raises ticket) | I | A | **R** | R (endpoints) |
| Release from isolation / return to production | **R** (security sign-off) | A (P1/P2) | A (production) | C | I |
| Communications to staff and customers | C | **A / R** | C | — | — |

Some organisations delegate specific platform actions (for example, Intune wipe) to the SOC. Any delegation must be written into the organisation's IR plan. **In this lab, one analyst plays every role; each case file states which role an action represents.**

---

## 6. Entry criteria

Eradication starts only when **both** are true:

1. **Containment is verified** (SOP-002 §11), or containment was not required.
2. **Scoping is complete**: every affected device, identity, mailbox and cloud resource is listed, from a sweep of the incident's indicators and techniques across the whole estate, not only the alerted assets.

Business continuity (§8) starts **at containment**, not after eradication.

---

## 7. Golden rules

| # | Rule | Why |
|---|---|---|
| **G1** | **Scope before you eradicate.** | Partial eradication warns the attacker, who then uses the access you missed. |
| **G2** | **Eradicate in one coordinated window.** | Removing access piece by piece gives the attacker time to re-establish it. |
| **G3** | **Preserve evidence first.** | Once persistence is deleted or a device is wiped, evidence for root cause and legal action is gone. |
| **G4** | **Any credential used on a compromised host is compromised.** | Attackers harvest credentials from memory and disk. |
| **G5** | **Rebuild when trust cannot be proven.** | A cleaned system after hands-on-keyboard activity, rootkits or unknown persistence cannot be trusted. |
| **G6** | **No recovery before the root cause is fixed** (or a documented compensating control is in place). | Otherwise the same path is used again. |
| **G7** | **Prove clean with hunting, not with silence.** | No alerts only means no detections fired. |
| **G8** | **Every remediation item has an owner and a due date.** | The SOC raises remediation; owners implement it. Untracked items do not get done. |
| **G9** | **A replica is not a clean copy.** | Anything continuously replicated from a compromised asset (cluster partner, database replica, DR copy) received the attacker's changes too. It is in scope until proven clean. |
| **G10** | **Restored is not remediated.** | A pre-incident snapshot still contains the vulnerability that let the attacker in and the secrets they stole. |
| **G11** | **The containment snapshot is evidence, never a restore point.** | It captures the compromised state (SOP-002 §10). |

---

## 8. Business continuity during response

### 8.1 Continuity options depend on service design, not incident priority

Failover exists only where the service was **built** with redundancy, based on its RTO in the business impact analysis. Incident priority (P1–P4) decides **how fast** the continuity decision is made, not **whether** failover is available.

| Service design | Continuity option | Executed by | SOC role |
|---|---|---|---|
| **Workstation** | Loaner device, VDI or cloud PC while the device is isolated and re-imaged | Service desk | Confirm the user's credentials are reset before they sign in to the loaner |
| **Load-balanced, active-active** (web and app tiers, multiple nodes) | Drain the compromised node; remaining nodes carry traffic | IT operations / app team | Verify remaining nodes are not in scope (§8.2 steps 1–2), then fully isolate the drained node |
| **Clustered or replicated, active-passive** (database clusters, replicated app servers) | Fail over to the secondary | IT operations / DBA | Apply G9: verify the secondary before it takes traffic (§8.2) |
| **Single instance with DR or backup replica** (e.g. site recovery, cloud backup) | Fail over to a recovery point that predates the earliest attacker activity, or rebuild | IT operations / backup team | Verify the recovery point and target (§8.2) |
| **Single instance, no redundancy** | Isolate in place (SOP-002 §6.2, rung 4), or accept downtime with a degraded mode (maintenance page, read-only mode, manual workaround) | Service owner decides; IT operations executes | Present the security risk of each option; record the owner's decision |
| **SaaS / Microsoft 365 / Entra ID** | Provider-run; continuity comes from containing the identity, not the platform | — | Identity containment (SOP-002) |

### 8.2 Clean-target verification

Before **any** failover target, recovery point, snapshot or backup takes production traffic, the SOC verifies:

| # | Check |
|---|---|
| 1 | The target is not on the scope list, and the indicator and persistence sweeps (§9.1) return nothing on it. |
| 2 | The recovery point predates the **earliest attacker activity**, not just the first alert. Account for dwell time. |
| 3 | The root cause is patched or mitigated on the target **before** it takes traffic (G10). |
| 4 | Secrets on the target are rotated: service account passwords, keys, certificates, connection strings. |
| 5 | The target is first brought up in an isolated network segment, scanned (full antivirus + persistence sweep), and only then connected. |
| 6 | The data gap between the recovery point and the incident (RPO) is reconciled with the service owner: transactions re-entered or replayed from a clean source. |

### 8.3 Indicative durations

Real durations depend on automation maturity. These ranges set expectations when you brief the business.

| Recovery path | Indicative time out of service | Business impact with continuity in place |
|---|---|---|
| Workstation re-image (Intune + Autopilot) | 1–4 hours | User works on loaner |
| Server drained from load balancer, rebuilt from golden image/IaC | Hours to 2 days | None or reduced capacity |
| Fail over to verified secondary / DR recovery point | Minutes to hours, plus data reconciliation | Brief interruption |
| Single-instance server cleaned in place | Hours to 1 day | Downtime or degraded mode |
| Tier 0 / identity infrastructure recovery | Days to weeks | Organisation-wide; continuity plan invoked |

---

## 9. Eradication checklist by layer

| Layer | Remove / reset | Defender XDR action or source |
|---|---|---|
| **Endpoint** | Malware and dropped tools; persistence (run keys, scheduled tasks, services, WMI subscriptions, startup folder); web shells on servers | Quarantine file, block hash, live response, full antivirus scan |
| **Identity (on-premises)** | Passwords of all accounts used on affected hosts; rogue accounts; attacker-added group memberships | Defender for Identity actions / AD. **Tier 0 compromise:** reset `krbtgt` twice, allowing replication between resets, under IR lead direction |
| **Identity (Entra ID)** | Sessions and refresh tokens; attacker-registered MFA methods; malicious app consents; changed role assignments | Revoke sessions, remove authentication methods, remove app consent, audit `AuditLogs` / `CloudAppEvents` |
| **Email** | Inbox rules, external forwarding, delegate permissions, remaining malicious messages | Purge emails, remove rules (`CloudAppEvents` actions such as `New-InboxRule`, `Set-InboxRule`) |
| **Cloud workloads** | Access keys, service principal secrets, IAM role changes, attacker-created resources | Rotate secrets, revoke keys, delete rogue resources after snapshot |
| **Network** | Attacker infrastructure | Keep indicator blocks in place through the monitoring period |

### 9.1 Persistence sweep (run across all scoped devices and every failover target)

```kql
let start = datetime(YYYY-MM-DD HH:MM:SS);   // earliest attacker activity minus 24h (UTC)
let scoped = dynamic(["device-1", "device-2"]);
union
( DeviceRegistryEvents
  | where Timestamp > start and DeviceName in~ (scoped)
  | where ActionType == "RegistryValueSet"
  | where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce")
  | project Timestamp, DeviceName, Type = "RunKey", Detail = strcat(RegistryKey, " = ", RegistryValueData) ),
( DeviceEvents
  | where Timestamp > start and DeviceName in~ (scoped)
  | where ActionType in ("ScheduledTaskCreated", "ServiceInstalled")
  | project Timestamp, DeviceName, Type = ActionType, Detail = tostring(AdditionalFields) ),
( DeviceProcessEvents
  | where Timestamp > start and DeviceName in~ (scoped)
  | where FileName in~ ("schtasks.exe", "sc.exe", "wmic.exe") and ProcessCommandLine has_any ("create", "config")
  | project Timestamp, DeviceName, Type = "PersistenceCommand", Detail = ProcessCommandLine )
| order by Timestamp asc
```

---

## 10. Clean or rebuild

### 10.1 Decision table

The decision follows **what the attacker did and what the asset is**, not the incident priority. Priority sets how fast it happens.

| Asset | Condition | Decision |
|---|---|---|
| **Workstation** | Commodity malware blocked or fully auto-remediated, no persistence, no hands-on-keyboard | **Clean in place**: quarantine + full scan + persistence sweep |
| **Workstation** | Anything more (persistence, hands-on-keyboard, credential dumping, unknown binary executed) | **Re-image.** Re-imaging is faster and more certain than manual cleaning by an analyst. |
| **Server, Tier 2/3** | Persistence found and fully understood; no hands-on-keyboard | **Clean in place**, with enhanced monitoring |
| **Server, any tier** | Hands-on-keyboard, credential dumping, web shell, unknown or partly understood persistence | **Rebuild** (§10.3) |
| **Tier 0** (domain controllers, identity systems) | Any compromise | **Rebuild** under IR lead; identity-wide credential reset |
| **Any** | Ransomware executed | **Rebuild**; restore data from verified known-good backup |

### 10.2 Workstation re-image flow

| Step | Action | Executed by |
|---|---|---|
| 1 | Collect investigation package (G3) | SOC |
| 2 | Issue loaner / VDI / cloud PC | Service desk |
| 3 | Reset user credentials and revoke sessions **before** the user signs in anywhere | SOC / identity team |
| 4 | Intune wipe, then Autopilot re-provisioning. Re-image from trusted media if firmware- or boot-level compromise is suspected. | Endpoint engineering |
| 5 | Confirm device is onboarded to Defender, healthy, and passes the persistence sweep | SOC |
| 6 | Return device to user; tag for enhanced monitoring (§13.3) | Service desk / SOC |

Defender XDR has no wipe action. Re-imaging is an Intune (endpoint management) action unless delegated to the SOC (§5).

### 10.3 Server recovery preference order

| Order | Method | Use when |
|---|---|---|
| 1 | **Rebuild from golden image / IaC**, then restore **data only** from a verified backup | Default for any rebuild decision |
| 2 | **Restore a verified recovery point / snapshot** | Speed is essential and the recovery point passes every §8.2 check |
| 3 | **Clean in place** | Only where §10.1 allows it |

---

## 11. SOC authority during eradication

| Action | L1 | L2 | L3 / IR lead |
|---|---|---|---|
| Quarantine files, purge malicious emails, block indicators | ✅ | ✅ | ✅ |
| Run persistence sweep and scoping queries | ✅ | ✅ | ✅ |
| Reset standard user password + revoke sessions | 🟡 | ✅ | ✅ |
| Remove inbox rules, forwarding, rogue MFA methods | 🟡 | ✅ | ✅ |
| Remove persistence through live response | ❌ | 🟡 | ✅ |
| Clean-or-rebuild decision | ❌ | 🟡 (workstations, Tier 2/3) | ✅ |
| Clean-target verification sign-off (§8.2) | ❌ | 🟡 | ✅ |
| Privileged / service account credential resets | ❌ | 🟡 | ✅ |
| `krbtgt` reset, Tier 0 rebuild | ❌ | ❌ | 🔴 |
| Request drain, failover, rebuild, restore, patch | Raise ticket | Raise emergency change | Approve emergency change with service owner |

Legend as in SOP-002 §7: ✅ pre-approved · 🟡 requires L2/L3 or IR lead approval · 🔴 incident commander and business owner approval · ❌ not permitted.

---

## 12. Remediation: fix the root cause

| Root cause category | Typical remediation | Usual owner |
|---|---|---|
| Unpatched vulnerability | Patch or mitigate; check the same vulnerability across the estate | Platform / server team |
| Weak or stolen credential | Enforce MFA, conditional access, remove legacy authentication | Identity team |
| Exposed service | Close or restrict the port; move behind VPN or zero-trust access | Network / cloud team |
| Misconfiguration | Correct configuration; add a policy guardrail so it cannot recur | Asset owner |
| User action (phishing) | Targeted awareness; mail-flow and URL protection tuning | Security awareness / messaging team |
| Detection gap or delay | New or tuned detection; adjust rule frequency; add missing log source | SOC / detection engineering |

Every item is a ticket with owner, due date and incident ID. Production changes go through change management; urgent items use the emergency change process, never an unrecorded change.

---

## 13. Recovery

### 13.1 Criteria to return to production (RS.MA-05)

All must be true:

- [ ] Eradication complete for every scoped asset (§9).
- [ ] Persistence and indicator sweeps return no new findings (G7).
- [ ] Root cause fixed, or compensating control documented (G6).
- [ ] For any restored or failed-over system: every §8.2 check passed.
- [ ] Service owner agrees the return-to-production window.

### 13.2 Recovery actions

| Action | Rule |
|---|---|
| Release device from isolation | Only after §13.1; record release time (UTC) |
| Re-enable accounts | Only with new credentials, sessions revoked, MFA re-registered by the verified user |
| Return drained node to pool | Only after rebuild/clean and §13.1; add back one node at a time |
| Remove long-term containment controls | One at a time, verifying after each |

### 13.3 Enhanced monitoring (runs in production)

Enhanced monitoring **starts at release, with the asset back in production**. It is not downtime.

| Item | Rule |
|---|---|
| Duration | Lab default: 30 days (P1/P2), 14 days (P3/P4) |
| Scope | All recovered devices, failover targets and reset identities, tagged in Defender (`IR-<incident ID>`) |
| Detections | Keep incident indicators blocked; run the §9.1 sweep and indicator hunts on a schedule for the period |
| Exit | No recurrence for the full period → close the incident |

### 13.4 Fail back

If the service is running on a secondary or DR instance:

1. Rebuild the primary (§10.3) and verify it with §8.2.
2. Fail back in a planned change window, executed by IT operations, or formally make the secondary the new primary.
3. Monitor both instances for the full §13.3 period.

---

## 14. MSSP operation

| Area | Rule |
|---|---|
| Continuity and recovery decisions | Belong to the **client**. The MSSP advises and records the client's decision. |
| Drain, failover, re-image, rebuild, restore, patch | Executed by the client's IT or their infrastructure provider. The MSSP executes only what the contract explicitly includes. |
| MSSP deliverables | Scoping and sweeps, eradication actions within the authorised action list, clean-target verification (§8.2), security sign-off for return to production, enhanced monitoring |
| SLA | Covers MSSP response actions and verification, not the client's business recovery time |

---

## 15. Closure

1. Record eradication, continuity, remediation and recovery details in the case file (§16).
2. Confirm every remediation ticket is complete or formally accepted as a tracked risk by its owner.
3. Run a lessons-learned review within 5 working days of closure for P1/P2 (optional for P3/P4) and record it in [Lessons-Learned.md](Lessons-Learned.md): what happened, what worked, what failed, and which SOP, detection or control changes follow.
4. If an SOP changes, update its version and revision history.

---

## 16. Record

```
SCOPE: <devices / identities / mailboxes / cloud resources>, sweep queries used
EVIDENCE PRESERVED: <package / snapshot / exports>
CONTINUITY MODE: <drain / failover / DR / loaner / degraded / downtime accepted> — decided by <owner> at <UTC time>, executed by <team>
CLEAN-TARGET VERIFICATION: <target> — §8.2 checks 1–6 <pass/fail>
ERADICATION: <item removed or reset> on <entity> at <UTC time> by <role>
CLEAN OR REBUILD: <decision + condition from §10.1>
ROOT CAUSE: <category + one-line description>
REMEDIATION TICKETS: <ID · owner · due date · status>
RECOVERY: <release / re-enable / return to pool / fail back> at <UTC time>; §13.1 criteria met
MONITORING: <tag, period, end date, result>
LESSONS LEARNED: <link>
METHOD: SOP-003 v1.1
```

---

## 17. References

- NIST Cybersecurity Framework 2.0: Respond (RS.AN, RS.MA, RS.MI), Recover (RC.RP, RC.CO), Identify (ID.IM)
- NIST SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management (April 2025)
- Microsoft Learn: Take response actions on a device / on a file
- Microsoft Learn: Remediation actions in Microsoft Defender for Identity
- Microsoft Learn: Revoke user access in an emergency in Microsoft Entra ID
- Microsoft Learn: Remote actions in Microsoft Intune (Wipe, Autopilot)

---

## Revision history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-11-22 | Vince-SecOperations | Initial release |
| 1.1 | 2026-11-22 | Vince-SecOperations | Added roles and responsibilities (§5), business continuity and clean-target verification (§8), rules G9–G11, workstation re-image flow and server recovery order (§10), fail back (§13.4), MSSP section (§14); clarified that enhanced monitoring runs in production; clean-or-rebuild now decided by asset and attacker activity, not priority |
