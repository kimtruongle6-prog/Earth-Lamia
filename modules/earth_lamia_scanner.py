import os
import psutil
import re

# Metadata for GitHub Project Artifacts
__author__ = "kimtruongle"
__reference__ = "Campaign Earth Lamia (UNC5174)"
__description__ = "Lightweight forensic scanner for webshells and anomalous w3wp.exe child processes"

class EarthLamiaScanner:
    def __init__(self, target_dir):
        self.target_dir = target_dir
        
        # Indicators of Compromise (IoCs) from technical reports
        self.webshell_keywords = [
            "AUCipher.encrypt",      # Godzilla Webshell signature
            "WigcZhRdWqX6m3GmTciv9", # Unique payload decryption key
            "ByPassGodzilla",        # 3.asmx webshell variant
            "AssemblyInstaller"      # Deserialization gadget chain
        ]
        
        # Suspicious MachineKey modifications in web.config
        self.config_keywords = ["validationKey", "decryptionKey"]
        
        # List of anomalous child processes typically spawned by w3wp.exe
        self.suspicious_child_procs = ["cmd.exe", "powershell.exe", "fscan.exe", "kworker"]

    def scan_files(self):
        """Scans .asmx files and web.config in the target directory"""
        print(f"[*] Starting scan in directory: {self.target_dir}")
        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Scan for .asmx webshells
                if file.endswith(".asmx"):
                    self._check_file_content(file_path, self.webshell_keywords, "Webshell Potential")
                
                # Scan for MachineKey anomalies in web.config
                elif file == "web.config":
                    self._check_file_content(file_path, self.config_keywords, "Modified MachineKey")

    def _check_file_content(self, path, keywords, alert_type):
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                for kw in keywords:
                    if kw in content:
                        print(f"[!] ALERT: {alert_type} detected at {path} (Keyword: {kw})")
        except Exception as e:
            print(f"[?] Could not read file {path}: {e}")

    def monitor_w3wp_behavior(self):
        """Monitors the parent-child process relationship of w3wp.exe"""
        print("[*] Auditing w3wp.exe process behavior...")
        found_anomaly = False
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] == "w3wp.exe":
                    children = proc.children(recursive=True)
                    for child in children:
                        if child.name().lower() in self.suspicious_child_procs:
                            print(f"[!!!] CRITICAL ALERT: w3wp.exe (PID {proc.info['pid']}) "
                                  f"is spawning an anomalous child process: {child.name()} (PID {child.pid})")
                            found_anomaly = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        if not found_anomaly:
            print("[+] No anomalous child processes detected from w3wp.exe.")

if __name__ == "__main__":
    # Default path targeting IIS web root or CI/CD 'dark zones'
    scanner = EarthLamiaScanner(target_dir="C:\\inetpub\\wwwroot")
    
    # Execute scanning tasks
    scanner.scan_files()
    scanner.monitor_w3wp_behavior()
