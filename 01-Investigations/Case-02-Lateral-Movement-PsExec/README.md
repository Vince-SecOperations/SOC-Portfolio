# Case 02 – Lateral Movement Using PsExec  
**Category:** Lateral Movement → Remote Execution → Credential Abuse  
**Environment:** Windows  
**Artifact Analyzed:** PCAP (Network Traffic Capture)  
**MITRE Focus:** T1021.002 (SMB/Windows Admin Shares) · T1569.002 (Service Execution) · T1036 (Masquerading)  

---

# 1. Scenario Overview  
This case investigates suspicious lateral movement detected by an IDS alert.  
The attacker leveraged **PsExec**, a legitimate Windows admin tool frequently abused for remote command execution and pivoting.

Lateral movement indicates the attacker expanded their access from the initial compromised host to other machines on the network.

The PCAP reveals:

- SMB negotiation traffic  
- NTLM authentication exchanges  
- Access to administrative shares (ADMIN$ and IPC$)  
- Deployment of **PSEXESVC.exe** to execute remote commands  

---

# 2. Objective  
As SOC analysts, our goals are to:

- Identify the **initial attacker IP**  
- Determine the **first host they pivoted to**  
- Identify the **username** used for authentication  
- Determine the **service executable** created  
- Identify the **network shares** accessed  
- Confirm the **next machine** targeted  

Screenshots from Wireshark should be added where indicated.

---

# 3. Protocol Hierarchy Review  
Using **Statistics → Protocol Hierarchy** in Wireshark shows SMB and NetBIOS Session Service running over TCP.

<img width="1287" height="584" alt="Screenshot 2025-12-02 at 3 50 53 PM" src="https://github.com/user-attachments/assets/221003f2-5620-4601-a1df-cca7e58e61d1" />

> (Protocol Hierarchy view showing SMB/SMB2)

SMB traffic is a strong indicator of lateral movement or administrative activity.

---

# 4. Identifying the Initial Access IP  
Filtering for SMB traffic:

```wireshark
smb
```

We observe a **Negotiate Protocol Request** sent:

- **Source:** `10.0.0.130`  
- **Destination:** `10.0.0.133`  
- **Port:** TCP 445  

This indicates the attacker **initiated the SMB session** from `10.0.0.130`.

### **Answer: Attacker initial access originated from → `10.0.0.130`**

<img width="1403" height="269" alt="Screenshot 2025-12-02 at 3 52 38 PM" src="https://github.com/user-attachments/assets/063aa2a5-bea2-4c89-98f0-0ed54875a7b6" />

>
> (Negotiate Protocol Request showing 10.0.0.130 → 10.0.0.133)

---

# 5. Determining the First Pivot Host  
Following the TCP stream for the negotiation/smb session, the NTLM challenge reveals:

- **NetBIOS computer name:** `SALES-PC`  
- **DNS hostname:** `SALES-PC.local`

<img width="1246" height="634" alt="Screenshot 2025-12-02 at 3 54 37 PM" src="https://github.com/user-attachments/assets/aa9ee7e8-5f5d-4940-875e-5b2309e71ef2" />

### **Answer: The first machine the attacker pivoted to → `SALES-PC`**

>
> (NTLMssp Target Info showing SALES-PC)

---

# 6. Identifying the Username Used  
In the **Session Setup Request NTLM Auth**, the username used is visible inside the NTLM authentication metadata:

```
Username: ssales
```

This user is associated with host `HR-PC`, indicating compromised credentials were used.

### **Answer: Username used by attacker → `ssales`**

<img width="1044" height="602" alt="Screenshot 2025-12-02 at 3 55 47 PM" src="https://github.com/user-attachments/assets/0aa768ff-b648-4ad3-91b3-c1f21c4527af" />

>  
> (NTLM Authentication packet showing username field)

---

# 7. PsExec Service Executable Created  
PsExec works by copying a service executable onto the victim system via SMB.

From the **SMB Create Request** packet:

```
PSEXESVC.exe
```

This file is the PsExec service binary that allows attackers remote command execution.

### **Answer: Service executable created → `PSEXESVC.exe`**

>  <img width="833" height="635" alt="Screenshot 2025-12-02 at 3 56 46 PM" src="https://github.com/user-attachments/assets/012c8123-4860-4773-844e-bc2a0295580b" />

> (SMB Create Request showing PSEXESVC.exe)

---

# 8. Share Used to Install the PsExec Service  
The **Tree Connect Request** shows the attacker accessed:

```
\\10.0.0.133\ADMIN$
```

The ADMIN$ share points to `C:\Windows`, commonly used for remote admin tasks and abused by PsExec.

### **Answer: Share used for PsExec installation → `ADMIN$`**

> <img width="994" height="721" alt="Screenshot 2025-12-02 at 6 56 00 PM" src="https://github.com/user-attachments/assets/87cb264f-1ed7-4680-8301-a63634b44dbd" />
 
> (Tree Connect Request showing ADMIN$)

---

# 9. Network Share Used for Communication  
Another Tree Connect Request reveals the use of:

```
IPC$
```

IPC$ is used for remote procedure calls (RPCs) and inter-process communication — PsExec depends heavily on it.

### **Answer: Share used for communication → `IPC$`**

>  <img width="1174" height="742" alt="Screenshot 2025-12-02 at 6 56 52 PM" src="https://github.com/user-attachments/assets/5f36c097-056f-4288-9d15-a799a645ebcb" />

> (SMB packet showing IPC$ connection)

---

# 10. Second Lateral Movement Target  
Using SMB filtering again, we identify another negotiation attempt:

- **Victim IP:** `10.0.0.131`  
- The NTLM target info shows the machine name: **MARKETING-PC**

### **Answer: Second pivot target → `MARKETING-PC`**

>  <img width="1326" height="500" alt="Screenshot 2025-12-02 at 6 57 26 PM" src="https://github.com/user-attachments/assets/e6b0688c-a025-4c03-8a06-ce413309acad" />

> (NTLM target info showing MARKETING-PC)

---

# 11. Summary of Findings

| Question | Answer |
|---------|--------|
| Initial attacker IP | **10.0.0.130** |
| First pivot host | **SALES-PC** |
| Username used | **ssales** |
| Service executable created | **PSEXESVC.exe** |
| Share used to install service | **ADMIN$** |
| Share used for communication | **IPC$** |
| Second pivot target | **MARKETING-PC** |

---

# 12. Key SOC Lessons  
- PsExec activity is almost always suspicious unless performed by IT admin teams.  
- **ADMIN$ and IPC$** are top-tier monitoring points for lateral movement.  
- NTLM authentication metadata can reveal compromised accounts.  
- SMB negotiation is often the *first visible signal* of lateral pivoting.  

---
