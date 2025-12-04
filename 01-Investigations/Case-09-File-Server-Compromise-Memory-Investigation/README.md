# Case 09 – FileServer Compromise Memory Investigation

## Tools Used
- **Volatility 3**
- **MemProcFS**
- **Timeline Explorer**
- **EvtxECmd**
- **R-Studio**

---

# ANALYSIS

---

## Task 1 – Identify the Domain Joined by the Infected Machine

**Method 1: Volatility Registry Analysis**

```
cd "C:\Users\%USERNAME%\Desktop\Start Here\Tools\Memory Analysis\volatility3"
python vol.py -f "C:\Users\%USERNAME%\Desktop\Start Here\Artifacts\memory.dmp" windows.registry.hivelist
python vol.py -f "C:\Users\%USERNAME%\Desktop\Start Here\Artifacts\memory.dmp" windows.registry.printkey --key "ControlSet001\Services\Tcpip\Parameters"
```

<img width="1596" height="832" alt="image" src="https://github.com/user-attachments/assets/7c1c66ea-3d37-4c63-9f2a-c03257d708bc" />

**Domain:** `Cydef.enterprise`

---

**Method 2: MemProcFS Mounted Memory**

```
cd "C:\Users\%USERNAME%\Desktop\Start Here\Tools\Memory Analysis\MemProcFS"
memprocfs.exe -device "C:\Users\Administrator\Desktop\Start Here\Artifacts\memory.dmp" -forensic 2 -license-accept-elastic-license-2-0
```

Navigate:

`M:\registry\HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters`

**Files:**  
- Domain.txt → `Cydef.enterprise`  
- Hostname.txt → `Shareserver`

<img width="1628" height="942" alt="image" src="https://github.com/user-attachments/assets/d07b0b0a-6c17-4296-ad7b-50777c6868b8" />

---

## Task 2 – Identify the Local Path of the Shared File

Path stored at:

`HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Shares`

MemProcFS path:

`M:\registry\HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Shares\data.txt`

**Local Path:**  
`Z:\Shares\data`

---

## Task 3 – Identify the Source IP of Failed RDP Attempts

Check logs (extracted from memory):

- Event ID **4625** – failed logon  
- Event ID **1149** – RDP authentication

Parse event logs:

```
EvtxECmd.exe -d C:\Users\Administrator\Desktop\eventlog --csv C:\Users\Administrator\Desktop\out
```

Open CSV with **Timeline Explorer**, search for event IDs.

---

## Task 4 – Identify the Process Name of the Attacker's Tool

Volatility scan:

```
python .\vol.py -f "C:\Users\Administrator\Desktop\Start Here\Artifacts\memory.dmp" windows.psscan
```

Process identified:

`PSEXESVC.exe`  
**PID:** 1104

Filter:

```
python .\vol.py -f "C:\Users\Administrator\Desktop\Start Here\Artifacts\memory.dmp" windows.psscan | findstr "1104"
```

<img width="2144" height="372" alt="image" src="https://github.com/user-attachments/assets/0ef5c38c-c655-46ab-a331-960e342de468" />

`svchost.exe` spawned as child → used in ransomware execution.

---

## Task 5 – First Command Executed Remotely

Search logs for `PSEXESVC.exe` in Timeline Explorer.

<img width="2840" height="1106" alt="image" src="https://github.com/user-attachments/assets/5b63e71d-2e06-4ccf-a2a7-dfc231ec5fc9" />
<img width="1692" height="846" alt="image" src="https://github.com/user-attachments/assets/eaf0bf24-d9ff-49a0-9d0f-6b0cacde87df" />

**First Command:** `tasklist`

---

## Task 7 – Registry Value Modified to Disable Windows Defender

**Modified Value:** `DisableAntiSpyware`

Registry path:

`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`

Command used:

```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
```

<img width="2880" height="1082" alt="image" src="https://github.com/user-attachments/assets/48277c28-b2df-467d-89b3-2077401eb900" />

---

## Task 8 – DLL Used in PowerShell Command to Dump LSASS

**DLL:** `comsvcs.dll`

<img width="1922" height="518" alt="image" src="https://github.com/user-attachments/assets/26a9e8c8-c5ef-41b7-8bb4-f72dcbbc778b" />

---

## Task 9 – Attacker-Created Persistence Account

Event ID **4720**:

**Account Created:** `ITadmin_2`

**Timestamp:** 2024-09-18 11:51:41

<img width="2870" height="484" alt="image" src="https://github.com/user-attachments/assets/651311f9-d4fd-4237-97c9-6d9e0fb888b9" />

---

## Task 10 – URL Found in Ransom Note

Extracted with **strings** from memory dump.

**URL:** *(insert .onion link from screenshot)*

<img width="2850" height="1066" alt="image" src="https://github.com/user-attachments/assets/f952d4f6-4f9d-4be1-adcb-af0fa978b2ee" />

---

# Attack Timeline

### **Failed RDP Login Attempt**
- *2024-09-18 11:35:07*

### **Reconnaissance via PsExec**
- *2024-09-18 11:36:40*  
Command: `tasklist`

### **Defense Evasion**
- *2024-09-18 11:40:31 – 11:44:16*  
Commands:
- `Set-MpPreference -DisableRealtimeMonitoring 1`
- `Set-MpPreference -DisableBlockAtFirstSeen 1`
- `Set-MpPreference -DisableIOAVProtection 1`
- `netsh advfirewall set allprofiles state off`
- `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f`
- `sc stop WinDefend`
- `sc qc WinDefend`
- `reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f`

### **Credential Dumping**
- *2024-09-18 11:45:06*  
DLL used: `comsvcs.dll`

### **Persistence**
- *2024-09-18 11:51:41*  
User created: `ITadmin_2`

### **Ransomware Execution**
- *2024-09-18 12:01:36*  
Executed via `svchost.exe` spawned from PsExec.

---

# END OF CASE
