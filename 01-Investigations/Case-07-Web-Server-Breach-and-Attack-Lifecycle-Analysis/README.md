# Case 07: Web Server Breach and Attack Lifecycle Analysis

## Overview

This investigation simulates a real-world network breach where an attacker exploits a vulnerability in a web server. Participants leverage tools like Wireshark, NetworkMiner, and Brim to analyze network traffic, identify the attacker's actions, and document key findings.

---

## Task 1: Identify the Attacker's IP Address

Applying the filter `http` and checking statistics ➝ endpoints, then refining with `http contains "upload"`:

**Attacker IP:** `23.158.56.196`

<img width="1308" height="754" alt="image" src="https://github.com/user-attachments/assets/be5290b3-7061-4f48-a087-11732e30b611" />
<img width="1216" height="356" alt="image" src="https://github.com/user-attachments/assets/0def54cf-b12f-4925-b95b-8dbb526d76cc" />

---

## Task 2: Identify Web Server Version

Filtering with `http contains "upload"` and following the HTTP stream revealed the web server version.

<img width="1624" height="604" alt="image" src="https://github.com/user-attachments/assets/b6111871-0690-459e-84e2-e0f3a717dfeb" />

---

## Task 3: CVE Corresponding to Exploited Vulnerability

Web server version: `2023.11.3 (Build 147512)`
**Exploited CVE:** `CVE-2024-27198`
*Critical authentication bypass vulnerability enabling administrative actions without authorization.*

---

## Task 4: Credentials Created by Attacker

HTTP POST requests indicate a new user account was created:

* **Username:** `c91oyemw`
* **Password:** `CL5vzdwLuK`
* **Email:** `C19oyem@example.com`
* **Privileges:** `SYSTEM_ADMIN`

<img width="2408" height="1160" alt="image" src="https://github.com/user-attachments/assets/0a7b9be0-3e6e-459b-b6ed-95bfabb9a37f" />

---

## Task 5: Webshell Uploaded

**File Name:** `nst8bhtg.zip`

---

## Task 6: First Command Execution via Webshell

First command executed immediately after enabling the malicious plugin.

**Screenshot Placeholder:**
`screenshots/2025-10-20-at-9.54.43-PM.png`

---

## Task 7: Tampered Admin Credentials File

New admin credentials written to the file:

<img width="1434" height="892" alt="image" src="https://github.com/user-attachments/assets/5dc04279-a79a-427a-8a31-4d0f7b8f99c1" />

---

## Task 9: Attempt to Escape Container

Command used by attacker:

```
docker run --privileged -it --rm ubuntu
```

*Intent: Leverage privileged mode to bypass container isolation and access the host system.*

<img width="1264" height="680" alt="image" src="https://github.com/user-attachments/assets/612ac7c8-3a00-4ae9-8835-05da2fd3bd43" />

---

## Notes

* All network analysis was conducted using Wireshark and Brim.
* Filters applied: `http`, `http contains "upload"`, `http contains "text"`, `http contains "cmd="`.
* Screenshots should be added to the `screenshots/` folder for documentation and reference.

---

## Directory Structure

```
Investigation-07-Case04/
│
├── README.md
├── screenshots/
├── artifacts/
└── queries/
```
