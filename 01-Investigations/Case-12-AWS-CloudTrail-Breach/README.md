# Case 12: AWS CloudTrail Forensics Investigation

## Overview

This investigation focuses on analyzing AWS CloudTrail logs to reconstruct the timeline and techniques used by an attacker who gained unauthorized access to an AWS environment. The lab emphasizes key AWS security concepts including:

* **CloudTrail** – The "security camera" for logging all API activity.
* **IAM Roles** – The "keys & badges" controlling permissions.
* **Privilege Escalation** – The "master key hack" where an attacker gains elevated access.

The objective is to identify the attacker's TTPs (Tactics, Techniques, and Procedures), including source IP, entry point, and persistence mechanisms.

---

## Environment & Tools

* **AWS CloudTrail**: Provides JSON logs of account activity.
* **JQ**: JSON parser for filtering and analyzing logs.
* **Linux Command Line**: For decompressing and querying logs.

---

## Investigation Steps

### Q1: Identify the Attacker's IP

**Objective:** Determine the source of the attack.

**Command Used:**

```bash
find . -type f -name "*.gz" -exec gunzip {} \;

find . -type f -name "*.json" -exec jq '.Records[] | select(.eventName == "StopLogging" or .eventName == "DeleteTrail") | {eventTime, eventSource, eventName, userIdentity, sourceIPAddress, trailArn, requestParametersName: .requestParameters.name}' {} \;
```

**Result:**
**Attacker IP:** `185.5.248.11`

<img width="1504" height="304" alt="image" src="https://github.com/user-attachments/assets/b4cc160a-e45c-4fc7-a5cc-2b174b204c20" />

---

### Q2: Determine First Interaction Time

**Objective:** Identify when the attacker first interacted with the server.

**Command Used:**

```bash
find . -type f -name "*.json" -exec jq -r '.Records[] | select(.sourceIPAddress == "185.5.248.11") | [.eventTime, .eventName, .errorCode] | @tsv' {} \; | sort | head -10
```

**Result:**
**First Interaction:** `2023-08-18T03:48:10Z`

<img width="2352" height="1372" alt="image" src="https://github.com/user-attachments/assets/6314214e-a684-41a8-8fef-4bde0a60b2d9" />

---

### Q3: Attacker Entry Point

**Objective:** Identify the exact file path from which the compromised AWS access key was retrieved.

**Command Used:**

```bash
find . -type f -name "*.json" -exec jq -r '.Records[] | select(.sourceIPAddress == "185.5.248.11" and .eventName == "GetObject") | "\(.eventTime) | \(.eventName) | \(.requestParameters.bucketName)/\(.requestParameters.key)"' {} \;
```

**Result:**
**File Path:** `shared-docs-repository/technical-specs/devops_kate_accessKeys`

<img width="1154" height="796" alt="image" src="https://github.com/user-attachments/assets/08ad9e92-dfb6-42db-8bbf-0608f3bfae83" />

---

### Q4: User Type Who Disabled CloudTrail

**Objective:** Determine the user type for the action of disabling CloudTrail.

**Command Used:**

```bash
find . -type f -name "*.json" -exec jq '.Records[] | select(.eventName == "DeleteTrail") | {eventTime, eventName, userIdentity}' {} \;
```

**Result:**
**User Type:** `AssumedRole`
**Role Name:** `Sudo_DevOps/sudo_session`

<img width="1628" height="1352" alt="image" src="https://github.com/user-attachments/assets/b54b34a6-07e6-49da-a417-f0f8514de28c" />

---

### Q7: Persistence - Created User

**Objective:** Identify the user created by the attacker to maintain access.

**Command Used:**

```bash
find . -type f -name "*.json" -exec jq '.Records[] | select(.sourceIPAddress == "185.5.248.11" and (.eventName == "CreateUser" or .eventName == "AttachUserPolicy")) | {eventTime, eventName, createdUser: .requestParameters.userName, policyArn: .requestParameters.policyArn}' {} \;
```

**Result:**
**Created User:** `root_admin_adam`

<img width="1678" height="480" alt="image" src="https://github.com/user-attachments/assets/82b90b1f-ec16-42ce-a371-4ae49d294d93" />

---

### Q8: Attacker Initial Method

**Objective:** Determine the event associated with the attacker's initial access method.

**Command Used:**

```bash
find . -type f -name "*.json" -exec jq -r '.Records[] | select(.userIdentity.userName == "root_admin_adam" or (.requestParameters.userName == "root_admin_adam")) | "\(.eventTime) | \(.eventName) | \(.requestParameters)"' {} \;
```

**Result:**
**Initial Event:** `CreateLoginProfile`
**Event Time:** `2023-08-18T04:13:16Z`
**Details:** `passwordResetRequired:false`

<img width="2364" height="1088" alt="image" src="https://github.com/user-attachments/assets/1a50dbfc-ae28-49b9-8a1d-10402021256d" />

---

### Q10: CloudTrail Logging Disabled Time

**Objective:** Identify when CloudTrail logging was disabled to understand TTP concealment.

**Command Used:**

```bash
find . -type f -name "*.json" -exec jq '.Records[] | select(.eventName == "DeleteTrail") | {eventTime, eventSource, eventName, userIdentity}' {} \;
```

**Result:**
**Event Time:** `2023-08-18T04:20:00Z`

<img width="1678" height="1266" alt="image" src="https://github.com/user-attachments/assets/1afa4398-b9c9-49c0-9c0e-91d7ce0aa481" />

---

## Artifacts

Place any extracted logs, JSON files, or relevant artifacts here.
`artifacts/`

---

## Queries

Place all JQ queries and commands used for analysis here.
`queries/`

---

**Conclusion:**
This investigation reconstructed the attacker’s TTPs, identified their source IP, entry point, and persistence mechanisms, and highlighted the importance of IAM and CloudTrail monitoring in cloud forensics.
