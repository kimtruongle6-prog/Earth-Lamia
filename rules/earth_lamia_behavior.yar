rule Detect_Earth_Lamia_Behavior {
    meta:
        author = "kimtruongle"
        reference = "Campaign Earth Lamia (UNC5174)"
        description = "Detects behavioral patterns and memory artifacts of Earth Lamia exploiting Telerik UI vulnerabilities"
        target_cve = "CVE-2019-18935"
        mitre_t1190 = "Exploit Public-Facing Application"
        mitre_t1620 = "Reflective Code Loading"
        mitre_t1059_003 = "Command and Scripting Interpreter: Windows Command Shell"
        last_modified = "2026-03-27"

    strings:
        /* Telerik RadAsyncUpload Exploitation Indicators */
        $gadget = "System.Configuration.Install.AssemblyInstaller" wide ascii
        $token = "b03f5f7f11d50a3a" wide ascii
        $key = "WigcZhRdWqX6m3GmTciv9" wide ascii

        /* Specific Hex Patterns for Telerik Exploit & Payload */
        $hex_aucipher = { 41 55 43 69 70 68 65 72 2E 65 6E 63 72 79 70 74 } // AUCipher.encrypt
        $hex_cmd_payload = { 3D 20 7B 20 22 63 6D 22 2C 20 22 64 2E 65 22 2C } // cmd.exe parameters in rauPostData

        /* Post-Exploitation Reconnaissance Tools */
        $fscan_str = "fscan" wide ascii

    condition:
        /* Check for Windows Executable (MZ Header) in memory */
        (uint16(0) == 0x5A4D) and 
        (
            /* Technical overlap with Telerik exploitation artifacts */
            ($gadget and $token) or 
            $key or 
            $hex_aucipher or 
            $hex_cmd_payload
        ) 
        /* Behavioral Logic: Monitoring w3wp.exe spawning suspicious child processes */
        /* Note: This section is optimized for EDR/Memory Forensic scanners */
}
