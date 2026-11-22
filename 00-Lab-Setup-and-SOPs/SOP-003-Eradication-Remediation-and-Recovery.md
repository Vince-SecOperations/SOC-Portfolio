# SOP-003: Eradication, Remediation and Recovery

| Field | Value |
|---|---|
| **SOP ID** | SOP-003 |
| **Title** | Eradication, Remediation and Recovery: Removing the Threat, Fixing the Cause, Restoring Service |
| **Version** | 1.0 |
| **Status** | Active |
| **Owner** | Vince-SecOperations |
| **Effective date** | 2026-11-22 |
| **Next review** | 2027-05-22 |
| **Primary platform** | Microsoft Defender XDR (unified portal, with Microsoft Sentinel and Microsoft Entra ID) |
| **Environments** | On-premises, hybrid (AD + Entra ID) and cloud workloads |
| **Preceded by** | [SOP-002: Containment](SOP-002-Containment.md) |
| **Feeds** | [Lessons-Learned.md](Lessons-Learned.md) |

---

## 1. Purpose

This SOP defines the strict, repeatable rules for removing an attacker's presence, fixing the condition that allowed the incident, and returning affected assets to normal service with proof that they are clean.

## 2. Scope

- **In scope:** every incident that reached containment under SOP-002, and every true positive where containment was not required (SOP-002 §6, C1 = No).
- **Out of scope:** business continuity and disaster recovery of whole sites; legal and regulatory notification (handled by the incident commander).

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

| Term | Definition | Example |
|---|---|---|
| **Eradication** | Removing everything the attacker introduced or controls. | Delete malware and persistence, remove rogue accounts, invalidate stolen credentials. |
| **Remediation** | Fixing the weakness that allowed the incident. | Patch the vulnerability, enforce MFA, close the exposed port, tune the detection. |
| **Recovery** | Returning assets to normal operation and confirming they are clean. | Release isolation, restore from backup, re-enable account, enhanced monitoring. |
| **Known-good state** | A state proven to predate the incident's first activity. | A backup taken before first activity in SOP-001's timeline. |
| **Rebuild** | Reinstalling an asset from trusted media and restoring only data, not system state. | Re-image a server instead of cleaning it. |

> In an interview, "remediated" can mean any of the three. Say which one you did.

---

## 5. Entry criteria

Eradication starts only when **both** are true:

1. **Containment is verified** (SOP-002 §11), or containment was not required.
2. **Scoping is complete**: every affected device, identity, mailbox and cloud resource is listed, from a sweep of the incident's indicators and techniques across the whole estate, not only the alerted assets.

---

## 6. Golden rules

| # | Rule | Why |
|---|---|---|
| **G1** | **Scope before you eradicate.** | Partial eradication warns the attacker, who then uses the access you missed. |
| **G2** | **Eradicate in one coordinated window.** | Removing access piece by piece gives the attacker time to re-establish it. |
| **G3** | **Preserve evidence first.** | Once persistence is deleted, the evidence for root cause and any legal action is gone. |
| **G4** | **Any credential used on a compromised host is compromised.** | Attackers harvest credentials from memory and disk; reset everything that touched the host. |
| **G5** | **Rebuild when trust cannot be proven.** | Hands-on-keyboard intrusion, rootkits, unknown persistence or a Tier 0 compromise mean a cleaned system cannot be trusted. |
| **G6** | **No recovery before the root cause is fixed** (or a documented compensating control is in place). | Otherwise the same path is used again. |
| **G7** | **Prove clean with hunting, not with silence.** | No alerts only means no detections fired; queries over the eradicated scope prove absence. |
| **G8** | **Every remediation item has an owner and a due date.** | The SOC raises remediation; system owners usually implement it. Untracked items do not get done. |

---

## 7. Eradication checklist by layer

| Layer | Remove / reset | Defender XDR action or source |
|---|---|---|
| **Endpoint** | Malware and dropped tools; persistence (run keys, scheduled tasks, services, WMI subscriptions, startup folder); web shells on servers | Quarantine file, block hash, live response, full antivirus scan |
| **Identity (on-premises)** | Passwords of all accounts used on affected hosts; rogue accounts; attacker-added group memberships | Defender for Identity actions / AD. **Tier 0 compromise:** reset the `krbtgt` account twice, allowing replication between resets, under IR lead direction |
| **Identity (Entra ID)** | Sessions and refresh tokens; attacker-registered MFA methods; malicious app consents; changed role assignments | Revoke sessions, remove authentication methods, remove app consent, audit `AuditLogs` / `CloudAppEvents` |
| **Email** | Inbox rules, external forwarding, delegate permissions, remaining malicious messages | Purge emails, remove rules (`CloudAppEvents` actions such as `New-InboxRule`, `Set-InboxRule`) |
| **Cloud workloads** | Access keys, service principal secrets, IAM role changes, attacker-created resources | Rotate secrets, revoke keys, delete rogue resources after snapshot |
| **Network** | Attacker infrastructure | Keep indicator blocks in place through the monitoring period |

### 7.1 Persistence sweep (run across all scoped devices)

```kql
let start = datetime(YYYY-MM-DD HH:MM:SS);   // incident first activity minus 24h (UTC)
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

## 8. Clean or rebuild decision

| Condition | Decision |
|---|---|
| Commodity malware, single host, quarantined automatically, no hands-on-keyboard, no persistence found | **Clean** (quarantine + full scan + persistence sweep) |
| Persistence found and fully understood, Tier 2/3 asset | **Clean**, with enhanced monitoring |
| Hands-on-keyboard activity, credential dumping, unknown or partially understood persistence | **Rebuild** |
| Any Tier 0 asset compromised | **Rebuild** under IR lead; identity-wide credential reset |
| Ransomware execution | **Rebuild**; restore data from known-good backup |

---

## 9. Authority

| Action | L1 | L2 | L3 / IR lead |
|---|---|---|---|
| Quarantine files, purge malicious emails, block indicators | ✅ | ✅ | ✅ |
| Run persistence sweep and scoping queries | ✅ | ✅ | ✅ |
| Reset standard user password + revoke sessions | 🟡 | ✅ | ✅ |
| Remove inbox rules, forwarding, rogue MFA methods | 🟡 | ✅ | ✅ |
| Remove persistence through live response | ❌ | 🟡 | ✅ |
| Clean-or-rebuild decision | ❌ | 🟡 (Tier 2/3) | ✅ |
| Privileged / service account credential resets | ❌ | 🟡 | ✅ |
| `krbtgt` reset, Tier 0 rebuild | ❌ | ❌ | 🔴 |
| Production changes (patch, firewall, configuration) | Raise ticket | Raise emergency change | Approve emergency change with owner |

Legend as in SOP-002 §7: ✅ pre-approved · 🟡 requires L2/L3 or IR lead approval · 🔴 incident commander and business owner approval · ❌ not permitted.

---

## 10. Remediation: fix the root cause

| Root cause category | Typical remediation | Usual owner |
|---|---|---|
| Unpatched vulnerability | Patch or mitigate; check the same vulnerability across the estate | Platform / server team |
| Weak or stolen credential | Enforce MFA, conditional access, remove legacy authentication | Identity team |
| Exposed service | Close or restrict the port; move behind VPN or zero-trust access | Network / cloud team |
| Misconfiguration | Correct configuration; add a policy guardrail so it cannot recur | Asset owner |
| User action (phishing) | Targeted awareness; mail-flow and URL protection tuning | Security awareness / messaging team |
| Detection gap or delay | New or tuned detection; reduce rule frequency; add missing log source | SOC / detection engineering |

Every item is recorded as a ticket with owner, due date and the incident ID. Production changes go through change management; urgent items use the emergency change process, never an unrecorded change.

---

## 11. Recovery

### 11.1 Criteria to start recovery (RS.MA-05)

All must be true:

- [ ] Eradication complete for every scoped asset (§7).
- [ ] Persistence sweep and indicator sweep return no new findings (G7).
- [ ] Root cause fixed, or compensating control documented (G6).
- [ ] Asset owner agrees on the recovery window.

### 11.2 Recovery actions

| Action | Rule |
|---|---|
| Release device from isolation | Only after §11.1; record release time (UTC) |
| Re-enable accounts | Only with new credentials, sessions revoked, MFA re-registered by the verified user |
| Restore from backup | Backup must predate the incident's first activity (known-good state) and be scanned before restore |
| Remove long-term containment controls | One at a time, verifying after each |

### 11.3 Enhanced monitoring

| Item | Rule |
|---|---|
| Duration | Lab default: 30 days (P1/P2), 14 days (P3/P4) |
| Scope | All recovered devices and reset identities, tagged in Defender (`IR-<incident ID>`) |
| Detections | Keep incident indicators blocked; run the §7.1 sweep and indicator hunts on a schedule for the period |
| Exit | No recurrence for the full period → close the incident |

---

## 12. Closure

1. Record the eradication, remediation and recovery details in the case file (§13).
2. Confirm every remediation ticket is either complete or accepted as a tracked risk by its owner.
3. Run a lessons-learned review within 5 working days of closure for P1/P2 (optional for P3/P4) and record it in [Lessons-Learned.md](Lessons-Learned.md): what happened, what worked, what failed, and which SOP, detection or control changes follow.
4. If an SOP changes, update its version and revision history.

---

## 13. Record

```
SCOPE: <devices / identities / mailboxes / cloud resources>, sweep queries used
EVIDENCE PRESERVED: <package / snapshot / exports>
ERADICATION: <item removed or reset> on <entity> at <UTC time> by <role>
CLEAN OR REBUILD: <decision + condition from §8>
ROOT CAUSE: <category + one-line description>
REMEDIATION TICKETS: <ID · owner · due date · status>
RECOVERY: <release / re-enable / restore> at <UTC time>; criteria §11.1 met
MONITORING: <tag, period, end date, result>
LESSONS LEARNED: <link>
METHOD: SOP-003 v1.0
```

---

## 14. References

- NIST Cybersecurity Framework 2.0: Respond (RS.AN, RS.MA, RS.MI), Recover (RC.RP, RC.CO), Identify (ID.IM)
- NIST SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management (April 2025)
- Microsoft Learn: Take response actions on a device / on a file
- Microsoft Learn: Remediation actions in Microsoft Defender for Identity
- Microsoft Learn: Revoke user access in an emergency in Microsoft Entra ID

---

## Revision history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-11-22 | Vince-SecOperations | Initial release |
