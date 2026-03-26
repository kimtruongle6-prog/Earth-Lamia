# 🛡️ Project Earth Lamia (UNC5174) Threat Hunting Kit

This repository provides a specialized threat-hunting toolkit designed to identify and remediate the activities of **Earth Lamia (UNC5174)**. This campaign has successfully compromised at least 25 major educational institutions in Vietnam by exploiting legacy **Telerik UI** vulnerabilities.

---

## 📊 Campaign Overview
- **Threat Actor:** Earth Lamia (UNC5174).
- **Primary Vector:** CVE-2019-18935 (Telerik UI Deserialization).
- **Core Tradecraft:** Internal reconnaissance via `fscan.exe` and persistent RDP tunneling through Fast Reverse Proxy (FRP).
- **Target Sector:** Vietnamese Higher Education (25+ Universities).

---

## 🕵️ Host-based IOCs (Persistence Artifacts)

| Artifact Category | Detection Pattern | Technical Note |
| :--- | :--- | :--- |
| **Registry** | MachineKey modifications in `web.config` | Used to decrypt malicious ViewState payloads. |
| **File Naming** | `[10-digits].[7-digits].dll` | Unix Epoch format (found in C:\Windows\Temp). |
| **Encryption Key** | `WigcZhRdWqX6m3GmTciv9` | Required to load SNOWLIGHT/VShell payloads. |
| **XOR Key** | `0x99` | Used for C2 traffic obfuscation. |

---

## 🚀 IIS Forensics & Scanning Guide

To detect webshells residing in the memory space of the `w3wp.exe` process, use the provided YARA rules.

### 1. Requirements
Install YARA or use a specialized scanner like **THOR Lite**:
`apt-get install yara`

### 2. Live Memory Scanning
Run the following command to scan the memory of a suspected IIS process:
```bash
# Scan specific w3wp.exe process memory
yara -s earth_lamia_memory.yar [PID_of_w3wp]
