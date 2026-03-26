
# 🔍 Detection Rules (YARA)

This directory contains specialized YARA rules for hunting and detecting **Earth Lamia (UNC5174)** activity within IIS environments.

## 📂 Included Rules
- **`earth_lamia_behavior.yar`**: The core behavioral rule. It focuses on memory-resident artifacts and the anomalous parent-child relationship between `w3wp.exe` and reconnaissance tools.

## 🛠️ Usage Instructions

### Scanning Live Process Memory (Recommended)
To identify active webshells or reflective code loading in a running IIS process:
```bash
yara -s earth_lamia_behavior.yar [PID_of_w3wp.exe]
