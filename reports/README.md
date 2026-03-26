# 📊 Anonymized Investigation Report: Campaign Analysis

## 📈 Impact Overview
This report synthesizes forensic data from intrusions across **25+ major universities**, directly impacting the Personal Identifiable Information (PII) of over **250,000 students and faculty members**.

## 🧬 Adversary Tradecraft (Earth Lamia)
* **Inside-Out Evasion:** After compromising a single node, the adversary deploys **fscan.exe** for internal lateral scanning, bypassing perimeter Firewalls and WAFs that only monitor inbound traffic.
* **Fileless Residency:** **VShell** and **Godzilla MemShell** payloads reside entirely in RAM, utilizing a **Hash-based API Resolver** to invoke sensitive system functions without leaving traces in the IAT.
* **Command Invocation Pattern:** Attack packets carry a distinct **Hex Payload Pattern**: `{ 3D 20 7B 20 22 63 6D 22 2C 20 22 64 2E 65 22 2C }`, corresponding to the invocation of `cmd.exe` under web application privileges.
* **Advanced Masquerading:** Use of deceptive process names such as **[kworker/0:2]** (a Linux kernel thread identifier) on Windows systems to mislead forensic monitors.

## 🗺️ MITRE ATT&CK® Mapping
| ID | Technique | Behavior Description |
| :--- | :--- | :--- |
| **T1190** | Exploit Public-Facing Application | Telerik RCE Exploitation (CVE-2019-18935). |
| **T1505.003** | Web Shell | Deployment of Godzilla MemShell & ByPassGodzilla. |
| **T1620** | Reflective Code Loading | SNOWLIGHT loader injecting VShell into RAM. |
| **T1059.003** | Windows Command Shell | `w3wp.exe` spawning `cmd.exe` via `rauPostData`. |
| **T1572** | Protocol Tunneling | Utilizing **FRP** to establish persistent RDP tunnels. |
