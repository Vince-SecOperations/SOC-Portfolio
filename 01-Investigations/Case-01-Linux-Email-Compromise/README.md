# Case 01 – Linux Email Compromise → Multi-Stage Intrusion  
**Category:** Email Compromise → Persistence → Ransomware  
**Environment:** Linux (Ubuntu)  
**Artifacts Analyzed:** Thunderbird mailbox, Firefox history, systemd services, bash history, C source files, encrypted payloads  
**MITRE Focus:** T1566 · T1059 · T1068 · T1547 · T1486

---

# 1. Scenario Overview  
A Linux server linked to user **t3m0** showed signs of compromise. Email artifacts, downloads, persistence files, and encrypted payloads were found. Evidence points to:

- Phishing email containing malicious DOCX  
- Base64-encoded payload hidden inside attachment  
- Remote malicious script (`update.sh`) downloaded  
- Persistence through systemd service  
- Ransomware executed via Bash script  
- Privilege escalation via SUID shell

---

# 2. Evidence Collection Workflow  
All analysis is performed by mounting the forensic image:

```bash
sudo mount -o loop LinuxServer.img /mnt
cd "/home/ubuntu/Desktop/Start here/Artifacts"
```

---

# 3. Email Investigation (Thunderbird)

### Path to Thunderbird mailbox
```
/mnt/home/t3m0/.thunderbird/lilc5p7e.default-release/ImapMail/imap.gmail.com/
```

### Key Files
- **INBOX** → Contains full emails (MBOX)
- **[Gmail].msf** → Index  
- **msgFilterRules.dat** → Mail filters  

### Command to extract sender fields:
```bash
grep -E '^From: ' INBOX
```

### **Q1 – Attacker Email Address**
```
From: inf0.s3c1337@gmail.com
```

> **Place screenshot of grep output here**
>  
> <img width="959" height="188" alt="Screenshot 2025-12-02 at 3 16 11 PM" src="https://github.com/user-attachments/assets/7b9f5b98-e02a-455a-a943-9d222f5a4020" />
/images/email_from_field.png)

---

# 4. Attachment Discovery & Base64 Extraction

### Identify subject:
```bash
grep -A 10 "From:.*inf0.s3c1337@gmail.com" INBOX | grep -i "subject:"
```

### Locate attachments:
```bash
grep -A 50 "From:.*inf0.s3c1337@gmail.com" INBOX \
| grep -E "(Content-Type:|filename=|name=|\.docx)"
```

Attachment identified:

```
Important.docx
```

> **Add screenshot of attachment metadata here**

---

# 5. Extracting & Decoding Malicious DOCX

Create output directory:
```bash
mkdir -p output
```

Extract Base64 payload from email and decode:
```bash
awk '... (your full awk + base64 cmd here) ...' INBOX \
| base64 -d > output/Important.docx
```

Unzip to inspect:
```bash
unzip output/Important.docx -d output
```

> **Add screenshot of DOCX folder structure here**

### Suspicious Relationship File
```
word/_rels/document.xml.rels
```

Shows external malicious reference:

```
http://203.113.10/update.sh
```

### **Q3 – Malicious URL used to download payload**
```
http://203.113.10/update.sh
```

---

# 6. Browser Artifact Analysis (Firefox)

Inspecting downloads and history:

```bash
grep -r -E "update.sh|suid_shell.c" *
```

Firefox stores key artifacts in:

- **places.sqlite** – history database  
- **recovery.jsonlz4** – session backups  

Extract readable strings:
```bash
strings places.sqlite-wal | grep -E "update.sh|suid_shell.c"
```

Reveals file source:

```
http://192.168.190.129/update.sh
```

---

# 7. Persistence Mechanism (systemd)

Navigate:
```bash
cd /mnt/etc/systemd/system
ls
```

Malicious persistence service found:
```
persistence.service
```

Contents:
```ini
[Service]
ExecStart=/tmp/P3r515t3nc3.sh
Restart=always
```

### **Q4 – Path where persistence was created**
```
/etc/systemd/system/persistence.service
```

### **Q5 – Path to malicious persistence script**
```
/tmp/P3r515t3nc3.sh
```

> Add screenshot of service file here

---

# 8. Safe Browsing Alerts (Firefox)

While parsing browser metadata, suspicious files related to **Google Safe Browsing** were detected.

### **Q6 – File names associated with safe browsing**
```
safe-browsing.sqlite
sb-urls-classifier.sqlite
```

---

# 9. First Successful Attacker Login (SSH)

Analyze logs:
```bash
strings auth.log | grep sshd
```

### **Q7 – First successful attacker SSH login**
> **Insert timestamp you observed**

(Use screenshot of auth.log evidence)

---

# 10. Ransomware Execution & Identification

Inspect bash history:
```bash
cat /mnt/home/t3m0/.bash_history
```

Shows:
```
chmod +x ransomware.sh
./ransomware.sh
```

### **Q8 – File responsible for encrypting folders**
```
ransomware.sh
```

Locate full path:
```bash
find /mnt -type f -name "ransomware.sh"
```

Result:

### **Q9 – Original file path**
```
/home/t3m0/.local/share/Trash/files/ransomware.sh
```

Review script:
```bash
cat /home/t3m0/.local/share/Trash/files/ransomware.sh
```

### **Q10 – Encryption key used**
```
s3cr3t_k3y
```

---

# 11. Password Harvesting (unshadow)

From bash history:
```
unshadow /etc/passwd /etc/shadow > unshadowed.txt
```

### **Q11 – File containing extracted passwords**
```
unshadowed.txt
```

---

# 12. Privilege Escalation Binary (SUID Shell)

Decrypt encrypted file:
```bash
openssl enc -aes-256-cbc -d -salt \
-in suid_shell.c.enc -out suid_shell.c -k "s3cr3t_k3y"
```

Inspect:
```bash
cat suid_shell.c
```

Contains:
```c
setuid(0);
system("/bin/sh");
```

### **Q12 – User ID & command in escalated shell**
- **User ID:** 0 (root)  
- **Command executed:** `/bin/sh`

---

# 13. Summary of Findings

| Question | Answer |
|---------|--------|
| Q1 | inf0.s3c1337@gmail.com |
| Q3 | http://203.113.10/update.sh |
| Q4 | /etc/systemd/system/persistence.service |
| Q5 | /tmp/P3r515t3nc3.sh |
| Q6 | safe-browsing.sqlite, sb-urls-classifier.sqlite |
| Q7 | *(add timestamp)* |
| Q8 | ransomware.sh |
| Q9 | /home/t3m0/.local/share/Trash/files/ransomware.sh |
| Q10 | s3cr3t_k3y |
| Q11 | unshadowed.txt |
| Q12 | UID 0, `/bin/sh` |

---

# 14. Screenshots & Logs  
*(Add evidence here — drag and drop images or log snippets)*

### Email Evidence  
<img width="1302" height="215" alt="From Sender" src="https://github.com/user-attachments/assets/f95b339d-6467-45d8-a2d5-fa7a03b38e6c" />
il.png)
<img width="1315" height="452" alt="Email Subject" src="https://github.com/user-attachments/assets/9072c432-5b04-458b-95db-f4b88f923eff" />
<img width="1349" height="612" alt="Email Attachment Filename" src="https://github.com/user-attachments/assets/c38616a3-ec0c-4b02-9dc1-1f5139efe2dd" />



### Base64 Attachment  
<img width="1236" height="812" alt="Attachment Output Process" src="https://github.com/user-attachments/assets/b4ce0861-41a7-4c6e-b2c2-031f11d9bb5b" />

<img width="1098" height="763" alt="Attachment Content" src="https://github.com/user-attachments/assets/d587997c-d0ec-43cf-95c7-def0452ce266" />

<img width="1058" height="663" alt="Decoding Attachment" src="https://github.com/user-attachments/assets/319c2f7c-8dbb-45f4-84eb-4b6201e8f46d" />


### Downloads History
Full URL the attacker used to download malicious file on the victim's machine

 <img width="1415" height="340" alt="Downloaded file" src="https://github.com/user-attachments/assets/2e2cc41b-88c4-43c8-bc1e-27e081a3bd16" />

File inspection (Both files are noted to be encrypted using OpenSSL with salted passwords)
<img width="1154" height="250" alt="Screenshot 2025-12-02 at 3 07 51 PM" src="https://github.com/user-attachments/assets/be69480e-2e6c-4ddb-9611-3bf250903d1f" />

### Browser History  

Actually in Firefox, 
places.sqlite — MAIN browser history

<img width="1338" height="435" alt="Screenshot 2025-12-02 at 3 08 50 PM" src="https://github.com/user-attachments/assets/8a87a3a4-ecc8-4019-82f8-9a8d58b54774" />


### Persistence Service  
<img width="1147" height="414" alt="Screenshot 2025-12-02 at 3 10 37 PM" src="https://github.com/user-attachments/assets/5fa807a3-74eb-42c7-b74d-8241b17c7cbf" />

The [Service] section specifies the command that will be executed when the service is started. It points to a script located at /tmp/P3r515t3nc3.sh


---
