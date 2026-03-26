
# 🛠️ Analysis Modules (Python)

This directory contains forensic scripts to automate the detection of **Earth Lamia (UNC5174)** artifacts.

## 🚀 Featured Tool: `earth_lamia_scanner.py`
A lightweight scanner designed to perform two critical tasks:
1. **Static Analysis**: Searches for Godzilla webshell signatures (`AUCipher`, unique keys) and `web.config` MachineKey tampering.
2. **Behavioral Auditing**: Leverages `psutil` to monitor `w3wp.exe` for unauthorized child process execution (e.g., `cmd.exe`, `fscan.exe`).

## 📋 Requirements
- Python 3.x
- `psutil` library: `pip install psutil`

## 💻 Execution
```bash
python earth_lamia_scanner.py
