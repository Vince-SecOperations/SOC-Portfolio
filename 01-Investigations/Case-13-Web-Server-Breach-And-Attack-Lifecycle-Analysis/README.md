# Case 13: Web Server Breach and Attack Lifecycle Analysis

## 1. Understand Your Data

Before you dive into crafting queries, it's crucial to understand the data available in your Splunk environment. This includes knowing what data sources are being ingested, the structure of that data (e.g., fields and their meanings), and the volume of data over time. Familiarize yourself with the Splunk Search Processing Language (SPL) syntax, as this will be the foundation of your threat hunting queries.

---

## 2. Basic Data Searching

Start with simple searches to get a feel for your data.

Example:
sourcetype=linux_secure

This query returns all events from the linux_secure source type, which typically includes Linux system security logs.

---

## 3. Using Fields in Searches

To find failed login attempts:
sourcetype=linux_secure action=failed

This query narrows down events where the action field indicates a failed operation, common in login attempts.

---

## 4. Statistical Analysis

To count failed login attempts by user:
sourcetype=linux_secure action=failed | stats count by user

This helps identify users who may be under attack or attempting unauthorized access.

---

## 5. Time-Based Filtering

Search last 24 hours:
index=main earliest=-24h latest=now

Search within a custom time range:
index=web earliest="11/26/2025:00:00:00" latest="11/26/2025:23:59:59"

---

## 6. Field Extraction and Display

index=security sourcetype=firewall | fields src_ip, dest_ip, action, bytes

This cleans results and focuses on relevant fields.

---

## 7. Search with Multiple Conditions

index=windows EventCode=4625 NOT user=system

Finds failed Windows logins excluding system accounts.

---

## 8. Wildcard Searches

index=web_logs status=50* | stats count by status, host

Finds all 500-level HTTP errors.

---

## 9. Rare Command for Anomaly Detection

index=proxy | rare dest_domain limit=10

Identifies uncommon destination domains.

---

## Common Index Examples

index=main  
index=security  
index=windows  
index=linux  
index=network  
index=web  
index=email  

---

## SourceType Explanation

sourcetype describes the format and type of ingested data.

Examples:
sourcetype=access_combined  
sourcetype=WinEventLog:Security  
sourcetype=linux_secure  
sourcetype=cisco:asa  
sourcetype=aws:cloudtrail  
sourcetype=symantec:ep:security  

---

## Practical Example

index=security sourcetype=firewall action=blocked

Explanation:
index=security → Security logs  
sourcetype=firewall → Firewall data  
action=blocked → Blocked traffic  

---

# Web Server Breach and Attack Lifecycle Analysis

## Identifying Compromised Accounts and Machines

Attackers often target user accounts and machines to gain initial access and move laterally.

---

## Identifying the Compromised Account

index="folks" EventID=4625

This identifies failed logins, highlighting CLIENT02 as suspicious.

index="folks" host=CLIENT02 | stats count by User

Counts activity per user on CLIENT02.

---

## Identifying Initial Attack Vectors

Enumeration allows attackers to gather AD, service, and user information.

---

## PowerShell in Attacks

Attackers abuse PowerShell for stealthy execution, enumeration, and lateral movement.

---

## Enumeration Tool Used

BloodHound is commonly used for Active Directory enumeration.

index="folks" host=CLIENT02 EventCode=4104 bloodhound | stats count by ScriptBlockText,MessageTotal

---

## Privilege Escalation Analysis

Privilege escalation allows attackers to gain elevated access.

---

## Unquoted Service Path Vulnerability

Safe Path:
"C:\Program Files\My Application\service.exe"

Vulnerable Path:
C:\Program Files\My Application\service.exe

Attack Steps:
- Identify unquoted path
- Drop malicious binary (C:\Program.exe)
- Restart service
- SYSTEM executes attacker binary

---

## Identifying Vulnerable Service

index=folks host=CLIENT02 Image="*.exe" CommandLine=*.exe | stats count by Image, CommandLine

---

## SHA256 Hash Identification

index=folks host=CLIENT02 Automate-Basic-Monitoring.exe | stats count by Image, CommandLine, Hashes

---

## DCsync Attack Detection

index=folks host=CLIENT02 dcsync | stats count by Image, CommandLine

---

# Investigation Questions & Answers

## Q1. What is the compromised account?

index="folks" sourcetype="XmlWinEventLog"
(EventCode=4624 OR EventCode=4625 OR EventCode=4672 OR EventCode=4720 OR EventCode=4722 OR EventCode=4723 OR EventCode=4724 OR EventCode=4725 OR EventCode=4726 OR EventCode=4732 OR EventCode=4729)
| eval logon_success=if(EventCode==4624,1,0), logon_fail=if(EventCode==4625,1,0), admin_action=if(EventCode==4672 OR (EventCode>=4720 AND EventCode<=4732),1,0)
| stats sum(logon_success) as successful_logons sum(logon_fail) as failed_logons sum(admin_action) as admin_actions dc(Computer) as hosts_touched values(Computer) as host_list by TargetUserName
| eval score=(successful_logons*1)+(failed_logons*0.5)+(admin_actions*5)+(hosts_touched*3)
| sort - score | head 10

Compromised Account: HELPDESK  
<img width="2880" height="1618" alt="image" src="https://github.com/user-attachments/assets/c9f9c2d4-90ed-4581-90c2-0b1857670402" />

<img width="1742" height="1086" alt="image" src="https://github.com/user-attachments/assets/64cd3c1a-de1e-4e62-8102-0e91658512de" />

<img width="2880" height="1312" alt="image" src="https://github.com/user-attachments/assets/cf9d0d26-63d8-45f8-8864-732219182a1b" />

---

## Q2. What is the compromised machine?

index="folks" sourcetype="XmlWinEventLog"
(EventCode=4624 OR EventCode=4625 OR EventCode=4672 OR (EventCode>=4720 AND EventCode<=4732))
TargetUserName="helpdesk"
| stats count as total_events sum(eval(EventCode==4624)) as successful_logons sum(eval(EventCode==4625)) as failed_logons sum(eval(EventCode==4672 OR (EventCode>=4720 AND EventCode<=4732))) as admin_actions by Computer, WorkstationName
| eval score=(successful_logons*1)+(failed_logons*0.5)+(admin_actions*5)
| sort - score

Compromised Machine: CLIENT02  
<img width="2852" height="1454" alt="image" src="https://github.com/user-attachments/assets/18dea02e-553b-4628-91c5-4a32e2b65cae" />

---

## Q3. Enumeration Tool Used

index="folks" host=CLIENT02 source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" (EventCode=4103 OR EventCode=4104) | search ScriptBlockText=*bloodhound*

Tool Identified: BloodHound  
<img width="2288" height="1668" alt="image" src="https://github.com/user-attachments/assets/bc7a1f2f-fff3-4123-8ee3-b5aeb47463c9" />

---

## Q4. Vulnerable Service

Service Name: Automate-Basic-Monitoring.exe  
<img width="2880" height="980" alt="image" src="https://github.com/user-attachments/assets/0f06565b-c79b-4ef1-9364-10237e12184d" />

---

## Q5. SHA256 of Privilege Escalation Executable

index="folks" host=CLIENT02 EventCode=1
(Image="C:\\Program.exe" OR Image="C:\\Program Files\\Basic.exe" OR Image="C:\\Program Files\\Basic Monitoring\\*.exe")
| rex field=Hashes "SHA256=(?<SHA256>[A-Fa-f0-9]{64})"

<img width="2876" height="1594" alt="image" src="https://github.com/user-attachments/assets/272d8fa4-e623-4550-8d14-d94d207da9c5" />

---

## Q6. Download Time of fun.exe

index="folks" host=CLIENT02 EventCode=11 TargetFilename="*fun.exe"

Download Time: 2023-05-10 05:08

---

## Q7. DCSync Command Line

"C:\Users\HelpDesk\fun.exe" "lsadump::dcsync /user:Abdullah-work\Administrator"

<img width="2656" height="1118" alt="image" src="https://github.com/user-attachments/assets/a82c0d27-bcfe-4159-8d49-537418069868" />

---

## Q8. Original Name of fun.exe

Original Filename: mimikatz.exe  
<img width="1952" height="1652" alt="image" src="https://github.com/user-attachments/assets/6a2da199-1ea8-44ab-9993-d7573ee9d2a0" />

---

## Q9. AES256 Hash Used in Over-Pass-The-Hash

AES256 Hash:
facca59ab6497980cbb1f8e61c446bdbd8645166edd83dac0da2037ce954d379

---

## Q10. Service Abused to Access CLIENT03

Service Abused: http (msdsspn)  
<img width="2880" height="878" alt="image" src="https://github.com/user-attachments/assets/3d700003-eb09-45d9-9414-166c632cb386" />

---

## Q11. Process Spawned on CLIENT03

Process Identified: wmiprvse.exe

---

## Key Takeaways

- HELPDESK account compromised
- CLIENT02 initial foothold
- BloodHound used for enumeration
- Unquoted Service Path exploited
- mimikatz.exe used as fun.exe
- DCSync and Over-Pass-The-Hash confirmed
- Lateral movement via WMI to CLIENT03
