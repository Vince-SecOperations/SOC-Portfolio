**Case 08: Suspicious Web Traffic & ZeroTier Virtual Network Analysis**

---

## Scenario

The scenario involves examining traffic patterns, identifying suspicious behavior, and correlating findings to known threat actor tactics.

The lab also highlights the importance of understanding network-layer interactions, including Address Resolution Protocol (ARP) communications, SMB exploitation, and Dynamic Host Configuration Protocol (DHCP) requests.

---

## Analysis

---

### **Q1. What is the ZeroTier Network ID?**

To identify the ZeroTier network ID from a packet capture file in Wireshark:

1. Navigate to:
   **Statistics → Capture File Properties → Interfaces**
2. Review the network adapters listed.
3. Identify the virtual adapter labeled **"ZeroTier One"**.

<img width="2086" height="1100" alt="image" src="https://github.com/user-attachments/assets/b52f0f44-04b2-49e6-8c0d-122197dfc7f5" />

---

### **Q2. What is the size of ARP packets in bytes?**

Use Wireshark:
**Statistics → Protocol Hierarchy**
Locate ARP to view the packet size.

---

### **Q3. What is the address that sent the most packets?**

To determine which address transmitted the most packets:

1. Go to **Statistics → Endpoints**
2. Select the **IPv4** tab.
3. Review the **Tx Packets** column to find the highest sender.

<img width="1264" height="960" alt="image" src="https://github.com/user-attachments/assets/6217e1a0-1c44-4c67-a2c3-27e0954af81b" />

---

### **Q5. How many DHCP Discover messages are in the pcapng file?**

Apply Wireshark filter:

```
dhcp
```

Count the **DHCP Discover** messages.

---

### **Q6. How many ARP reply packets are present in the pcapng file?**

Wireshark filter:

```
arp.opcode == 2
```

Use:

```
frame.number == 55
```

to focus on a specific frame if needed.

---

### **Q7. What is the name of the Threat Actor associated with this technique?**

1. Identify the suspicious IP via:
   **Statistics → Conversations**
2. The external repeated-communication IP is:
   **185.245.85.178**
3. Submit the IP to **VirusTotal** to determine threat actor associations.

<img width="1846" height="1056" alt="image" src="https://github.com/user-attachments/assets/e3e0ec25-1b54-49cc-ac24-03275805943f" />

---

## Artifacts

Place all extracted files here:
`artifacts/`

---

## Queries

Place any queries or filters used here:
`queries/`

---
