/*
    FedSIG+ ThreatNet - Sample YARA Rules
    These are demonstration rules for threat detection
*/

rule Suspicious_Executable
{
    meta:
        description = "Detects suspicious executable patterns"
        threat_level = "medium"
        author = "FedSIG+ ThreatNet"
        date = "2024-01-01"
    
    strings:
        $mz = "MZ"
        $suspicious1 = "malware" nocase
        $suspicious2 = "virus" nocase
        $suspicious3 = "trojan" nocase
        $suspicious4 = "ransomware" nocase
    
    condition:
        $mz at 0 and any of ($suspicious*)
}

rule Ransomware_Indicators
{
    meta:
        description = "Detects common ransomware patterns"
        threat_level = "critical"
        author = "FedSIG+ ThreatNet"
        date = "2024-01-01"
    
    strings:
        $encrypt1 = "encrypt" nocase
        $encrypt2 = "decrypt" nocase
        $bitcoin = "bitcoin" nocase
        $ransom = "ransom" nocase
        $payment = "payment" nocase
    
    condition:
        3 of them
}

rule Keylogger_Behavior
{
    meta:
        description = "Detects keylogger-like behavior"
        threat_level = "high"
        author = "FedSIG+ ThreatNet"
        date = "2024-01-01"
    
    strings:
        $keylog1 = "keylog" nocase
        $keylog2 = "keystroke" nocase
        $keylog3 = "GetAsyncKeyState"
        $keylog4 = "GetKeyState"
    
    condition:
        any of them
}

rule Backdoor_Pattern
{
    meta:
        description = "Detects backdoor patterns"
        threat_level = "high"
        author = "FedSIG+ ThreatNet"
        date = "2024-01-01"
    
    strings:
        $backdoor1 = "backdoor" nocase
        $backdoor2 = "shell" nocase
        $backdoor3 = "cmd.exe" nocase
        $backdoor4 = "reverse_tcp"
    
    condition:
        2 of them
}

rule Suspicious_PowerShell
{
    meta:
        description = "Detects suspicious PowerShell patterns"
        threat_level = "medium"
        author = "FedSIG+ ThreatNet"
        date = "2024-01-01"
    
    strings:
        $ps1 = ".ps1" nocase
        $download = "DownloadString" nocase
        $encoded = "-encodedcommand" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
    
    condition:
        $ps1 and any of ($download, $encoded, $bypass)
}

rule Test_Malware_Sample
{
    meta:
        description = "EICAR test file detection"
        threat_level = "low"
        author = "FedSIG+ ThreatNet"
        date = "2024-01-01"
    
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    condition:
        $eicar
}