"""
Static analysis of extracted JavaScript from NODE_SEA_BLOB.
Detects suspicious patterns without executing the code.
"""

import re

PATTERNS = {
    "Network": [
        (r'https?://[^\s\'"]+', "HTTP/S URL"),
        (r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b', "IP Address"),
        (r'ws{1,2}://[^\s\'"]+', "WebSocket URL"),
        (r'\.onion\b', "Tor .onion address"),
        (r'new\s+WebSocket\s*\(', "WebSocket connection"),
        (r'(?:axios|fetch|http\.get|http\.request|https\.get|https\.request)\s*\(', "HTTP request"),
        (r'dns\.resolve', "DNS resolution"),
    ],
    "Process Execution": [
        (r'child_process', "child_process import"),
        (r'\.exec\s*\(', "exec() call"),
        (r'\.execSync\s*\(', "execSync() call"),
        (r'\.spawn\s*\(', "spawn() call"),
        (r'\.spawnSync\s*\(', "spawnSync() call"),
        (r'\.execFile\s*\(', "execFile() call"),
        (r'PowerShell|powershell', "PowerShell reference"),
        (r'cmd\.exe|/bin/sh|/bin/bash', "Shell reference"),
    ],
    "Filesystem": [
        (r'fs\.write|fs\.append|createWriteStream', "File write"),
        (r'fs\.read|createReadStream', "File read"),
        (r'fs\.unlink|fs\.rmdir|fs\.rm\b', "File deletion"),
        (r'fs\.mkdir|fs\.mkdirSync', "Directory creation"),
        (r'%APPDATA%|%LOCALAPPDATA%|%TEMP%', "Windows path reference"),
        (r'Library/LaunchAgents|Library/Application\s+Support', "macOS path reference"),
        (r'\.pcl-data|\.pcl-state|uploads\.json', "Known malware artifact path"),
    ],
    "Persistence": [
        (r'HKCU|HKLM|CurrentVersion\\Run', "Windows registry key"),
        (r'LaunchAgent|launchctl|com\.launchkeeper', "macOS LaunchAgent"),
        (r'systemd|\.service\b|XDG.*autostart', "Linux systemd/autostart"),
        (r'schtasks|SchTasks|Task\s*Scheduler', "Windows scheduled task"),
        (r'crontab', "Crontab entry"),
        (r'StartupFolder|start.*menu.*startup', "Startup folder"),
    ],
    "Anti-Sandbox": [
        (r'Win32_VideoController|GPU|VideoController', "GPU enumeration (anti-VM)"),
        (r'cpus\(\)|numberOfCPUs|cpu_count|numCPUs', "CPU count check"),
        (r'totalmem\(\)|totalMemory|RAM|memoryStatus', "RAM check"),
        (r'hostname\(\)|os\.hostname', "Hostname check"),
        (r'sandbox|analysis|malware|virus|vmware|virtualbox|vbox|hyper.v', "Sandbox keyword check"),
        (r'process\.env\.USERNAME|process\.env\.COMPUTERNAME', "Environment variable check"),
        (r'RunAs|runas|Verb.*RunAs', "UAC escalation"),
        (r'MpPreference|Defender|exclusion', "Windows Defender exclusion"),
    ],
    "Crypto & Exfiltration": [
        (r'AES|aes-\d+-\w+|createCipheriv|createDecipheriv', "AES crypto"),
        (r'ChaCha20|chacha', "ChaCha20 crypto"),
        (r'huggingface|hf_token|hfToken', "Hugging Face API"),
        (r'blockchain|web3|ethers|polygon|onfinality', "Blockchain C2"),
        (r'keylog|keystroke|SetWindowsHookEx|CGEvent', "Keylogger"),
        (r'clipboard|Clipboard|xclip|xsel|wl-paste', "Clipboard access"),
        (r'wallet|seed\s*phrase|mnemonic', "Crypto wallet targeting"),
        (r'tdata|Telegram.*session', "Telegram session theft"),
    ],
    "Obfuscation Indicators": [
        (r'eval\s*\(', "eval() usage"),
        (r'Function\s*\(\s*[\'"]return', "Function constructor eval"),
        (r'atob\s*\(|btoa\s*\(', "Base64 decode/encode"),
        (r'\\x[0-9a-fA-F]{2}', "Hex escape sequences"),
        (r'String\.fromCharCode', "fromCharCode obfuscation"),
        (r'\\u[0-9a-fA-F]{4}', "Unicode escape sequences"),
    ],
}


def analyze(js_code):
    """
    Runs all pattern categories against the JS code.
    Returns a dict: { category: [ (match_text, description), ... ] }
    """
    results = {}

    for category, patterns in PATTERNS.items():
        hits = []
        for pattern, description in patterns:
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            for match in matches[:5]:
                hits.append((match.strip(), description))
        if hits:
            results[category] = hits

    return results


def summarize(analysis_results):
    """
    Returns a short summary string of what was found.
    """
    if not analysis_results:
        return "No suspicious patterns detected."

    lines = []
    for category, hits in analysis_results.items():
        lines.append(f"[{category}] {len(hits)} indicator(s) found")
    return "\n".join(lines)
