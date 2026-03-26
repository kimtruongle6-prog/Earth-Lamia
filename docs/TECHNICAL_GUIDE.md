# Memory-Based Threat Hunting Guide

This technical manual provides operational instructions for the **Malware Analyzer Pro** framework, specifically designed to detect and neutralize the fileless tradecraft of the **Earth Lamia (UNC5174)** threat actor.

### 1. Operation Guide: `earth_lamia_scanner.py`

The `earth_lamia_scanner.py` module is a behavioral analysis tool focused on detecting **Inside-Out Evasion**. This strategy, employed by Earth Lamia, involves conducting internal reconnaissance using tools like `fscan.exe` from a compromised web server to bypass perimeter defenses such as External WAFs and Edge Firewalls.

*   **Mechanism:** The scanner utilizes the `psutil` library to continuously monitor the parent-child process relationships of the IIS worker process (**`w3wp.exe`**). 
*   **Detection Logic:** Under normative conditions, `w3wp.exe` rarely spawns interactive shells or reconnaissance tools. The script triggers an alert if `w3wp.exe` initializes child processes such as `cmd.exe`, `powershell.exe`, or **`fscan.exe`**.
*   **Operational Goal:** By identifying these unauthorized process births, the tool uncovers the "inside-out" lateral movement that remains invisible to traditional ingress-monitoring security layers.

### 2. Memory Hunting: `earth_lamia_behavior.yar`

The `earth_lamia_behavior.yar` rule is engineered for high-fidelity **In-memory Hunting** within the address space of active system processes. It specifically targets the artifacts left by **Insecure Deserialization** attacks (CVE-2019-18935).

*   **Targeting Deserialization Gadgets:** The rule scans Read-Write-Execute (RWX) memory regions within `w3wp.exe` for the **`System.Configuration.Install.AssemblyInstaller`** namespace. 
*   **Verification:** It utilizes the **`PublicKeyToken: b03f5f7f11d50a3a`** to confirm the presence of the specific trusted .NET gadget manipulated by Earth Lamia to hydrate malicious payloads directly into RAM.
*   **Payload Identification:** The rule also hunts for encrypted configuration parameters and distinctive **Hex Payload Patterns** (e.g., `{ 3D 20 7B 20 22 63 6D 22 2C 20 22 64 2E 65 22 2C }`) which decode to OS shell invocation commands.

### 3. Intelligence Infrastructure: SQL Timeline Reconstruction

The **Malware-SQL-Intelligence-Lab** component serves as a robust **Intelligence Infrastructure** designed for the long-term management of threat intelligence rather than mere raw data storage. Its schema is optimized for **Timeline Reconstruction** by correlating disparate Windows Event Logs:

*   **`Process_Execution_Logs` (Event ID 4688):** Captures the precise moment an anomalous child process (e.g., `cmd.exe`) is spawned by `w3wp.exe`, providing the "Execution" timestamp in the attack timeline.
*   **`Application_Event_Logs` (Event ID 1309):** Records ASP.NET health monitoring events, allowing analysts to trace the "Initial Access" phase by identifying failed or successful Telerik deserialization attempts and associated `rauPostData` hex patterns.
*   **Correlation Power:** By mapping these logs via the **`mitre_technique_id`** column, the infrastructure automatically reconstructs the adversary's progression from exploitation to lateral movement, facilitating comprehensive attribution and post-incident reporting.

### 4. MITRE ATT&CK Mapping

| Behavior | MITRE ID | Description |
| :--- | :--- | :--- |
| **Initial Access** | **T1190** | Exploit Public-Facing Application (Telerik RCE CVE-2019-18935). |
| **Execution** | **T1620** | Reflective Code Loading (SNOWLIGHT/VShell payload injection into RAM). |
| **Command Execution** | **T1059.003** | Command and Scripting Interpreter: Windows Command Shell (`w3wp.exe` spawning `cmd.exe`). |
