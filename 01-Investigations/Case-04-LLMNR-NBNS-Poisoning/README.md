# Case 04 – LLMNR & NBNS Poisoning Analysis

In this lab, we analyze a simulated network security incident involving poisoned credentials, where attackers exploit vulnerabilities in Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) protocols. These protocols assist with name resolution in local networks but lack strong authentication, making them susceptible to spoofing and man-in-the-middle attacks.

Using Wireshark, we examine network traffic to identify the rogue machine, affected systems, compromised accounts, and the attacker’s actions.

---

## 🔎 1. Identifying the Mistyped Query

The attacker initiated their actions by exploiting a mistyped hostname broadcast by the victim machine with IP: **192.168.232.162**.

To isolate its traffic, we apply the filter:

```
ip.addr == 192.168.232.162
```

NBNS traffic confirms this activity is associated with NetBIOS Name Service.

<img width="1722" height="636" alt="image" src="https://github.com/user-attachments/assets/36ad4ca8-a112-40fa-95df-07611efa4d1b" />

---

## 🕵️ 2. Determining the Rogue Machine IP Address

To identify the rogue machine, we track who responded to the mistyped broadcast. The rogue system replies with spoofed NBNS responses.

From Wireshark analysis, the rogue machine’s IP address is:

**192.168.232.215**

<img width="1284" height="370" alt="image" src="https://github.com/user-attachments/assets/5421aa1a-7baf-4dce-b6d9-827020b4dda0" />

---

## 🧩 3. Identifying the Second Poisoned Machine

Using the filter:

```
nbns.addr == 192.168.232.215
```

This isolates all NBNS traffic involving the rogue machine.

From the filtered traffic, the second poisoned system appears as the destination IP:

**192.168.232.176**

<img width="1716" height="798" alt="image" src="https://github.com/user-attachments/assets/e3415d75-ab91-429c-867e-81552e347446" />

---

## 🔐 4. Identifying the Compromised Username

To determine the compromised user account, we isolate all traffic sent *to* the rogue machine with:

```
ip.dst == 192.168.232.215
```

We inspect the **SMB Session Setup Response**, locate the **Session ID**, and extract the username sent during NTLM authentication.

The compromised username is:

**ACCT.User**

<img width="1328" height="780" alt="image" src="https://github.com/user-attachments/assets/1fae3572-1f43-494d-bb1c-5df908e0f64c" />
 
---

## 🖥️ 5. Hostname of the Machine Accessed via SMB

To determine the specific system the attacker accessed:

```
ip.dst == 192.168.232.215 && smb2
```

Within the SMB2 negotiation and session setup packets, we locate the **DNS Computer Name**.

The attacker accessed the machine:

**AccountingPC.cybercactus.local**

Hostname: **AccountingPC**  

---

## ✅ Summary of Findings

| Investigation Point | Result |
|---------------------|--------|
| Mistyping machine IP | 192.168.232.162 |
| Rogue machine IP | **192.168.232.215** |
| Second poisoned victim | **192.168.232.176** |
| Compromised username | **ACCT.User** |
| Hostname accessed via SMB | **AccountingPC** |

---

## 📌 Conclusion

This investigation demonstrates how attackers leverage LLMNR/NBNS weaknesses to mislead systems into sending NTLM hashes. Through Wireshark traffic analysis, we successfully traced the poisoned responses, identified the rogue machine, and uncovered the compromised accounts and affected hosts.

Mitigation strategies include:

- Disabling LLMNR and NBNS
- Enforcing SMB signing
- Implementing strong network segmentation
- Deploying endpoint detection tools to identify spoofing activities


