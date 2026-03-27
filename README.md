# 🛡️ Malware Analyzer Pro: Advanced Memory Forensics & Threat Intelligence

**Malware Analyzer Pro** is an open-source framework engineered with high precision to hunt and neutralize sophisticated stealth techniques used by APT groups, specifically **Earth Lamia (UNC5174)**. This project shifts the defensive paradigm from reactive to **Proactive Threat Hunting**, focusing on deconstructing fileless layers that traditional scanners often overlook.

---

## 🔍 Overview: Closing the "Remediation Gap"
This project was born to address the **Remediation Gap** existing within national knowledge infrastructures. Statistics show that vulnerabilities like **CVE-2019-18935** (Telerik RCE) are still being exploited more than **2,190 days (6 years)** after international warnings were issued. 

**Malware Analyzer Pro** provides the "arsenal" for cybersecurity professionals to audit **CI/CD Dark Zones** and monitor dynamic behaviors directly within RAM.

* 📖 **Detailed Operation Guide:** [TECHNICAL_GUIDE.md](./TECHNICAL_GUIDE.md)

---

## 🕵️ Campaign Intelligence: Target - Education Infrastructure
Forensic data from the Earth Lamia campaign reveals a devastating scale of impact:
* **Compromised Entities:** Over **25 major universities**.
* **Data at Risk:** Personal Identifiable Information (PII) of **250,000+ students and faculty members**.
* **Strategic Goal:** Exfiltration of back-end source code, espionage, and potential **manipulation of academic records** or national research data.
* **Inside-Out Evasion:** Attackers leverage compromised web servers to conduct internal reconnaissance via `fscan.exe`, bypassing perimeter WAF/Firewall layers.

* 📊 **Anonymized Investigation Report:** [Anonymized Analysis](./reports/README.md)


---

## ⚙️ Core Components
The system is structured according to the operational standards of a professional Threat Hunting Lab:

### 1. [rules/](./rules/): YARA for Memory Hunting
Contains `earth_lamia_behavior.yar`, optimized to hunt for "memory fingerprints" such as **AssemblyInstaller** gadgets and Hex-encoded `cmd.exe` invocation parameters.

### 2. [modules/](./modules/): Python Analytical Scripts
The `earth_lamia_scanner.py` module is specialized in monitoring **Parent-Child process relationships**. It triggers immediate alerts when `w3wp.exe` spawns anomalous processes like `powershell.exe` or `fscan.exe`.

### 3. [schemas/](./schemas/): Intelligence Infrastructure
SQL-based relational schemas designed for **Timeline Reconstruction**, allowing analysts to correlate Windows Event IDs **4688** and **1309** into a unified attack narrative.

---

## 🗺️ MITRE ATT&CK® Mapping
Project behaviors are directly mapped to the international technical framework to ensure professional standardized communication:

| Tactic | Technique ID | Description |
| :--- | :--- | :--- |
| **Initial Access** | **T1190** | Exploit Public-Facing Application (Telerik RCE - CVE-2019-18935). |
| **Execution** | **T1620** | **Reflective Code Loading** – Loading VShell/SNOWLIGHT payloads directly into RAM. |
| **Execution** | **T1059.003** | Command and Scripting Interpreter: Windows Command Shell. |
| **Persistence** | **T1505.003** | Resident via Webshell (Godzilla MemShell) within process memory space. |
| **Command & Control**| **T1572** | Utilizing Protocol Tunneling via **FRP (Fast Reverse Proxy)**. |

---

## ⚖️ Ethics & Responsible Disclosure
**Malware Analyzer Pro** is not just a tool; it is an effort to democratize APT-level defense for the community. Mastering memory space is the key step to repelling the specter of Earth Lamia from our knowledge infrastructure. 

*All data within this repository has been sanitized to protect victim identities.*

**Author:** kimtruongle
