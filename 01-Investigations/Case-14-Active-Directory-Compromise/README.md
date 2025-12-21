# Investigation-14: Active Directory Compromise, Privilege Escalation & Lateral Movement (Splunk)

## SOC Portfolio – Case 14

---

## Case Overview

This case documents a full Active Directory compromise investigated using Splunk SIEM.  
The attacker gained access through a compromised user account, performed enumeration using PowerShell-based tools, escalated privileges via an unquoted service path vulnerability, dumped credentials using DCsync, executed Over-Pass-The-Hash, and laterally moved to another host.

---

## Environment

SIEM: Splunk  
Index: folks  
Operating System: Windows Active Directory Environment  
Log Sources:
- Windows Security Event Logs
- PowerShell Operational Logs
- Sysmon Logs

---

## Q1. What is the name of the compromised account?

### SPL Query
index="folks" sourcetype="XmlWinEventLog"
(EventCode=4624 OR EventCode=4625 
 OR EventCode=4672 OR EventCode=4720 OR EventCode=4722 OR EventCode=4723 
 OR EventCode=4724 OR EventCode=4725 OR EventCode=4726 
 OR EventCode=4732 OR EventCode=4729)
| eval logon_success=if(EventCode==4624,1,0),
       logon_fail=if(EventCode==4625,1,0),
       admin_action=if(EventCode==4672 OR (EventCode>=4720 AND EventCode<=4732),1,0)
| stats sum(logon_success) as successful_logons,
        sum(logon_fail) as failed_logons,
        sum(admin_action) as admin_actions,
        dc(Computer) as hosts_touched,
        values(Computer) as host_list
        by TargetUserName
| eval score=(successful_logons*1)+(failed_logons*0.5)+(admin_actions*5)+(hosts_touched*3)
| sort - score
| head 10

### Finding
The compromised account is **HELPDESK**.

<img width="2880" height="1618" alt="image" src="https://github.com/user-attachments/assets/b60833b5-2b28-4a15-b14d-f122406f5384" />

<img width="1742" height="1086" alt="image" src="https://github.com/user-attachments/assets/8001cf8f-5f7e-46f5-ace5-fd17c1c8664d" />

<img width="2880" height="1312" alt="image" src="https://github.com/user-attachments/assets/f22dd21e-d852-4b79-a649-cad76aedf084" />

---

## Q2. What is the name of the compromised machine?

### SPL Query
index="folks" sourcetype="XmlWinEventLog"
(EventCode=4624 OR EventCode=4625 OR EventCode=4672 OR (EventCode>=4720 AND EventCode<=4732))
TargetUserName="helpdesk"
| stats count as total_events,
        sum(eval(EventCode==4624)) as successful_logons,
        sum(eval(EventCode==4625)) as failed_logons,
        sum(eval(EventCode==4672 OR (EventCode>=4720 AND EventCode<=4732))) as admin_actions
        by Computer, WorkstationName
| eval score=(successful_logons*1)+(failed_logons*0.5)+(admin_actions*5)
| sort - score

### Finding
The compromised machine is **CLIENT02**.

<img width="2852" height="1454" alt="image" src="https://github.com/user-attachments/assets/01a66b00-0062-4d6f-9ca5-0349171d0607" />

---

## Q3. What tool did the attacker use to enumerate the environment?

### SPL Query
index="folks" host=CLIENT02 source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
(EventCode=4103 OR EventCode=4104)
| search ScriptBlockText=*bloodhound*
| table _time ScriptBlockText

### Finding
The attacker used **BloodHound**.

<img width="2288" height="1668" alt="image" src="https://github.com/user-attachments/assets/5bc2cbba-286d-40f0-a8ef-a26880eeded4" />

---

## Q4. What vulnerable service was used for privilege escalation?

### SPL Query
index=folks host=CLIENT02
(NewProcessName="*\\sc.exe" OR CommandLine="*sc *")

### Finding
Unquoted Service Path vulnerability in **Automate-Basic-Monitoring.exe**.

<img width="2880" height="980" alt="image" src="https://github.com/user-attachments/assets/9003732e-79a1-4f13-b76c-4b6fa0025f80" />

---

## Q5. What is the SHA256 hash of the executable used for privilege escalation?

### SPL Query
index="folks" host=CLIENT02 EventCode=1
(Image="C:\\Program.exe" OR Image="C:\\Program Files\\Basic.exe" OR Image="C:\\Program Files\\Basic Monitoring\\*.exe")
| rex field=Hashes "SHA256=(?<SHA256>[A-Fa-f0-9]{64})"
| table _time Image CommandLine SHA256
| sort _time

### Finding
SHA256 hashes associated with the unquoted service path were extracted.

<img width="2876" height="1594" alt="image" src="https://github.com/user-attachments/assets/33fd615e-dfaf-4469-97e5-e62678971529" />

---

## Q6. When did the attacker download fun.exe?

### SPL Query
index="folks" host=CLIENT02 EventCode=11 TargetFilename="*fun.exe"
| table _time User Image TargetFilename CreationUtcTime SHA256
| sort _time

### Finding
The file `fun.exe` was downloaded/created on **2023-05-10 05:08**.

---

## Q7. What is the command line used to launch the DCSync attack?

### SPL Query
index="folks" host=CLIENT02 EventCode=1
(CommandLine="*dcsync*" OR CommandLine="*lsadump*")
| table _time CommandLine
| sort _time

OR

index=folks host=CLIENT02 dcsync | stats count by Image, CommandLine

### Finding
`"C:\Users\HelpDesk\fun.exe" "lsadump::dcsync /user:Abdullah-work\Administrator"`

<img width="2656" height="1118" alt="image" src="https://github.com/user-attachments/assets/3f570c20-334d-4b11-84b9-d27b87fdd295" />

---

## Q8. What is the original name of fun.exe?

### SPL Query
index="folks" host=CLIENT02 EventCode=1 Image="*fun.exe*"
| table _time Image OriginalFileName Product Company CommandLine SHA256
| sort _time

### Finding
Original filename is **mimikatz.exe**.

<img width="1952" height="1652" alt="image" src="https://github.com/user-attachments/assets/cf9e0c7b-417d-4dbf-83c7-f4981f3aae59" />

---

## Q9. The attacker performed Over-Pass-The-Hash. What is the AES256 hash of the account?

### SPL Query
index=folks host=CLIENT02 aes256 | stats count by Image, CommandLine, OriginalFileName, _time

### Finding
AES256 hash of the attacked account (`Mohammed`) is:

`facca59ab6497980cbb1f8e61c446bdbd8645166edd83dac0da2037ce954d379`

---

## Q10. What service did the attacker abuse to access Client03 machine as Administrator?

### SPL Query
index=folks host=CLIENT02 CLIENT03 Administrator | stats count by Image, CommandLine, _time

### Finding
The HTTP service in **msdsspn** was abused.

<img width="2880" height="878" alt="image" src="https://github.com/user-attachments/assets/ae43279e-ef34-46ea-b9a4-a8ad0e0995d9" />

---

## Q11. What process was spawned on Client03 during remote login?

### SPL Query
index="folks" host=CLIENT03 EventCode=1
User="*Administrator*"
(ParentImage="*wmiprvse.exe*" OR ParentImage="*wsmprovhost.exe*" OR ParentImage="*winrshost.exe*")
| table _time Image CommandLine ParentImage
| sort _time
| head 1

### Finding
Process spawned: **wmiprvse.exe** (commonly used for lateral movement)

