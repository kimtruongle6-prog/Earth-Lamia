
# 📊 Malware Intelligence SQL Schemas

This directory contains the relational database architecture for the **Malware-SQL-Intelligence-Lab**. These schemas are designed to ingest and correlate data from Windows forensic logs and malware analysis reports.

## 🏛️ Architecture Overview
- **`mitre_attack_mapping`**: A reference table for international cybersecurity standards.
- **`process_execution_logs`**: Specifically optimized for **Parent-Child Process Auditing** (e.g., detecting `w3wp.exe` behavior).
- **`application_event_logs`**: Captures ASP.NET health monitoring logs (Event ID 1309) for deserialization exploit tracking.
- **`malware_intelligence_artifacts`**: A central repository for persistent Indicators of Compromise (IoCs) and attribution artifacts.

## 🛠️ Usage
These scripts are compatible with **PostgreSQL** and **MySQL**. They allow researchers to:
1. Identify "Inside-Out" attack patterns.
2. Automate the mapping of forensic artifacts to the **MITRE ATT&CK Framework**.
3. Reconstruct exploitation timelines based on Windows Event IDs 4688 and 1309.
