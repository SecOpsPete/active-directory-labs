# 🏗️ Active Directory Detection Lab

**Analyst:** Peter Van Rossum  
**Date Range Built:** September 2025  
**Environment:** Home Lab (Virtualized)  
**Core Components:** Windows Server (Domain Controller), Windows 10 Client, Ubuntu Server (Splunk SIEM), Kali Linux Attack Machine 

⚡This Active Directory Lab walkthrough is based on the excellent [MyDFIR "Active Directory Project (Home Lab)" YouTube series](https://www.youtube.com/@MyDFIR), with additional notes, detections, and explanations written from my own build process.

---

## ⚠️ Limitations & Considerations

This lab is a **controlled, isolated environment** I built for training. While the setup mirrors many real-world enterprise components, there are important considerations:

- Configurations are sometimes intentionally insecure (e.g., weak passwords, open RDP) to simulate adversary actions.  
- All attacks are conducted against my own lab systems using a NAT/Host-Only virtual network.  
- Telemetry will not perfectly match enterprise-scale environments but is close enough for learning SOC workflows.  

The purpose is not production hardening, but **hands-on experience with detection engineering**.

---

## 🎯 Objective

My goal was to create a **mini-enterprise Active Directory environment** where I could:

- Stand up a Windows domain (users, policies, DNS).  
- Deploy Sysmon and Splunk Universal Forwarder to capture endpoint telemetry.  
- Send that telemetry into Splunk for searching, dashboards, and alerts.  
- Run controlled attacks from Kali Linux and Atomic Red Team.  
- Detect those attacks using SPL queries and Event IDs.  

This project mirrors what a SOC analyst or detection engineer would do in the field.

---

# 🧭 Lab Build Timeline and Findings

## ✅ Part 1 – Planning

I began by defining the environment and requirements:

- **Virtual Machines:**  
  - `DC01`: Windows Server 2019 (Domain Controller)  
  - `WIN10-CLIENT`: Windows 10, joined to the domain  
  - `SPLUNK`: Splunk Enterprise server  
  - `KALI`: Kali Linux attacker box  

- **Networking:** NAT/Host-Only for safety.  
- **Static IPs:**  
  - DC01 → 192.168.10.5  
  - WIN10-CLIENT → 192.168.10.10  
  - SPLUNK → 192.168.10.20  
  - KALI → 192.168.10.30  

**Note:**  
Upfront planning avoids confusion later. With static IPs and a clear design, Splunk correlation becomes easier and my detections remain consistent.

<img src="./images/Lab_Diagram.png" alt="Active Directory Lab Diagram" width="70%">
<br>

### 🔑 Why Active Directory Is Central to This Lab

Active Directory is the backbone of this entire project. It’s where user accounts and groups live, how permissions are decided, and how policies are enforced across the environment. Every logon attempt, privilege check, and security policy begins with AD.  

That makes AD both the **target** attackers go after and the **source** of the signals defenders rely on. By building my lab around AD, I created a realistic enterprise core — the place where identity, access, and security controls all intersect.

---

## ✅ Part 2 – Building the Environment

### Windows Server (DC01)
- Installed Windows Server.  
- Renamed host to `DC01`.  
- Promoted it to a Domain Controller with forest `lab.local`.  
- DNS installed automatically with AD DS role.  

### Windows 10 Client
- Installed Windows 10.  
- Joined `lab.local` domain.  
- Verified login with domain credentials.  

### Splunk Enterprise
- Installed Splunk Enterprise (free 500MB/day license).  
- Verified access to Splunk Web UI.  

### Kali Linux
- Updated repositories.  
- Installed Hydra, Crowbar, and CrackMapExec.  
- Prepared wordlists for brute force testing.  

**Why this matters:**  
At this stage, I had a functioning enterprise-like network: a domain, a workstation, a SIEM, and an attacker. This forms the foundation for detection engineering.

---

## ✅ Part 3 – Active Directory & Telemetry

This part of the lab focused on wiring up my environment so that Splunk could actually “see” activity across the domain controller and client host. It included creating test accounts, applying security policies, deploying Sysmon with a hardened configuration, and forwarding all relevant logs with the Splunk Universal Forwarder (UF).

---

### 🛠️ AD Configuration

1. **Created User Accounts**
   - Added multiple test accounts to simulate realistic scenarios.
   - Included a deliberately weak account (`testuser`) for attack simulation.
   - Accounts were created using the **Active Directory Users and Computers (ADUC) GUI**  
     *(Right-click Users → New → User, fill in details, finish wizard).*


2. **Applied GPOs**
   - **Password Complexity:** Enabled complexity requirements (minimum length, upper/lowercase, numbers, special chars).  
     Path:  
     `Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy`
   - **Audit Policy:** Enabled advanced auditing for:
     - Logon/Logoff (success/failure).
     - Process Creation (with command-line logging).
     - Object Access.  
     Path:  
     `Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration`
   - **Remote Desktop:** Enabled RDP for brute force and lateral movement testing.  
     Path:  
     `Computer Configuration → Policies → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Connections`

---

### 🔍 Sysmon Deployment

Sysmon (System Monitor) captures detailed endpoint telemetry beyond native logs. I deployed it using **SwiftOnSecurity’s community Sysmon configuration**, which is tuned to reduce noise while still catching adversary techniques.

1. **Download Sysmon**
   - From Microsoft Sysinternals:  
     [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

2. **Download SwiftOnSecurity Sysmon Config**
   - From GitHub:  
     [https://github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

3. **Install Sysmon with Config**
   ```powershell
   sysmon64.exe -i sysmonconfig-export.xml
   ```
   - `-i` installs Sysmon as a service.
   - The XML file defines which events are logged (process creation, network connections, registry writes, etc.).

4. **Verify Installation**
   ```powershell
   Get-Service -Name Sysmon64
   ```

5. **Event Log Location**
   - Events appear under:  
     `Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`

**Why Sysmon?**  
- Windows Security and System logs are limited.  
- Sysmon provides:
  - Process creation with command-line arguments.
  - Parent/child process relationships.
  - File hash logging.
  - Network connection logging.  
- These are critical for detecting persistence, credential dumping, and lateral movement.

---

### 📡 Splunk Universal Forwarder (UF)

The UF forwards logs from Windows hosts into Splunk for indexing and search.

1. **Install UF**
   - Download: [https://www.splunk.com/en_us/download/universal-forwarder.html](https://www.splunk.com/en_us/download/universal-forwarder.html)
   - Example silent install:
     ```powershell
     msiexec.exe /i splunkforwarder.msi AGREETOLICENSE=Yes RECEIVING_INDEXER="192.168.50.3:9997" /quiet
     ```
   - Replace `192.168.50.3` with your Splunk indexer IP and `9997` with your listener port.

2. **Configure inputs.conf**
   - Location:  
     `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`
   - Configuration:
     ```ini
     [WinEventLog://Application]
     index = endpoint
     disabled = false

     [WinEventLog://Security]
     index = endpoint
     disabled = false

     [WinEventLog://System]
     index = endpoint
     disabled = false

     [WinEventLog://Microsoft-Windows-Sysmon/Operational]
     index = endpoint
     disabled = false
     renderXml = true
     source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
     ```

   - Key Notes:
     - `index = endpoint` ensures logs land in the correct index.
     - `renderXml = true` forwards detailed XML fields from Sysmon.

3. **Restart UF Service**
   ```powershell
   net stop SplunkForwarder
   net start SplunkForwarder
   ```

4. **Verify Forwarding**
   - On the Splunk indexer:
     ```spl
     index=endpoint host=WIN10-CLIENT OR host=DC01
     ```
   - Confirm Security, Application, System, and Sysmon logs appear.

---

### ⚡ Why This Step is Critical

Telemetry is the lifeblood of detection engineering. Without it, Splunk has no visibility.  
- **Security Logs** capture logon activity, policy changes, and privilege use.  
- **Sysmon Logs** capture the “how” of process behavior, file manipulation, and attacker tradecraft.  
- **Splunk UF** is the transport that ensures those logs reach Splunk for correlation and detection.  

Together, they form the foundation of a usable detection lab environment.

---

## ✅ Part 4 – Splunk Setup & Detection Engineering

### AD User Accounts & Permissions
Building on Part 3, I assigned roles to my test accounts and groups so Splunk detections had context:

- **Users:**  
  - `testuser` — weak password account from Part 3, used only for brute-force tests.  
  - `analyst.peter` — everyday non-admin account.  

- **Groups:**  
  - `SecOps-Lab-Users` — standard users.  
  - `SecOps-Remote-Desktop` — added to the client’s **Remote Desktop Users** local group so I could RDP without full admin rights.  

**Note:**  
Creating distinct accounts and assigning RDP rights by group ensures Splunk logs show the *who* and *how* behind logon events. It also mirrors real enterprises where access is role-based.

---

### Splunk Index & Ingestion
On the Splunk server, I created a dedicated index:

- **Index Name:** `endpoint`  
- **Data Type:** Events  

I verified ingestion with:

```spl
index=endpoint | stats count by host, source
```

Expected sources included: `WinEventLog:Security`, `WinEventLog:System`, `WinEventLog:Application`, and `WinEventLog:Microsoft-Windows-Sysmon/Operational`.

---

### Key Event IDs
**Windows Security Logs:** 4625 (failed logon), 4624 (successful logon), 4672 (privileged logon), 4688 (process creation).  
**Sysmon Logs:** 1 (process create), 3 (network connection), 7 (image loaded), 11 (file created), 13 (registry modification), 22 (DNS query).  

---

### Core SPL Queries
*(These come from common SOC playbooks, not directly from MyDFIR — they extend the lab into detection engineering.)*

**Failed logons by user/IP:**

```spl
index=endpoint source="WinEventLog:Security" EventCode=4625
| stats count BY TargetUserName, IpAddress
| sort - count
```

**Brute-force success correlation:**

```spl
index=endpoint source="WinEventLog:Security" EventCode IN (4625,4624)
| eval outcome=if(EventCode=4625,"fail","success")
| stats count AS attempts, values(outcome) AS outcomes by TargetUserName, IpAddress
| where attempts>=10 AND mvfind(outcomes,"success")>=0
```

**Suspicious PowerShell activity:**

```spl
index=endpoint source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\powershell.exe"
| eval encoded=if(match(CommandLine,"(?i)-enc"),"Base64_Encoded","Plain")
| table _time, host, User, CommandLine, encoded
```

---

## ✅ Part 5 – Attack & Detect

### 🕵️ Attacker Assumptions in This Lab

To ground the attack phase, I documented assumptions that mirror a realistic adversary scenario:

- Attacker has already **gained a foothold in the internal network** (phished user, rogue device, Wi-Fi access).  
- Attacker has an **IP address** on the subnet, either via DHCP or static assignment.  
- DHCP in AD environments typically points clients to the **Domain Controller for DNS**, so the attacker also inherits the DC’s DNS server.  
- RDP has been **enabled on the Windows client** to allow simulation of lateral movement.  
- Brute force tools like **Crowbar** are used internally against domain-joined hosts, generating authentication noise that can be detected in Splunk.

**Relevance:**  
This lab simulates *post-compromise lateral movement*, not an internet-exposed RDP attack. The focus is on how telemetry (Security logs, Sysmon, Splunk) captures brute force attempts and successful logons inside an enterprise-like environment.

---

### 🔐 Brute Force with Kali

I began with something noisy but classic: brute forcing remote services. From my Kali VM, I targeted the Windows client using both RDP and SMB.  

**RDP brute force (Crowbar):**

```bash
sudo crowbar -b rdp -s 192.168.10.10/32 -u testuser -C passwords.txt
```

**SMB brute force (Hydra):**

```bash
hydra -L users.txt -P passwords.txt smb://192.168.10.10 -V -f
```

**Expected telemetry in Splunk:**  
- A burst of **4625 (failed logon)** events for each attempt.  
- If the password hits, a **4624 (successful logon)** event appears.  
- If that account has elevated rights, a **4672 (special privileges assigned)** will follow.  

**Troubleshooting Notes:**  
The brute force from Kali didn’t succeed in my environment. After verifying services, tweaking RDP settings, rebooting, and adjusting networking, I narrowed it to a handshake issue with Crowbar. To keep the lab moving, I pivoted to **Atomic Red Team (ART)** directly on the Windows client to simulate brute-force activity and generate the same authentication telemetry.

---

## ⚔️ Atomic Red Team Simulation

After brute force, I turned to **Atomic Red Team (ART)** to simulate more targeted techniques. ART provides repeatable test cases that map directly to MITRE ATT&CK.

---

### 🔧 Setup and Fixes

1. **Clone / Install Atomic Red Team repo**  
   ART lives under `C:\AtomicRedTeam\`.  
2. **Import the PowerShell module**  
   ```powershell
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psm1" -Force
   ```
3. **Fix missing Execution Logger**  
   ```powershell
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Public\Default-ExecutionLogger.psm1" -Force
   ```
   Or skip with:  
   ```powershell
   Invoke-AtomicTest Txxxx -PathToAtomicsFolder "C:\AtomicRedTeam\atomics" -NoExecutionLog
   ```
4. **Point to Atomics folder**  
   ```powershell
   -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
   ```

---

### 🧪 Tests Run

**T1136.001 – Create Local Account**  
```powershell
Invoke-AtomicTest T1136.001 -TestNumbers 9 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
```

**T1059.001 – PowerShell Encoded Command**  
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
```

**T1547.001 – Registry Run Key Persistence**  
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
```

**T1105 – Ingress Tool Transfer**  
```powershell
Invoke-AtomicTest T1105 -TestNumbers 1 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
```

---

### 🧹 Cleanup

```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics" -Cleanup
Invoke-AtomicTest T1136.001 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics" -Cleanup
```

✅ With fixes during setup, ART tests ran correctly and produced the expected telemetry for Splunk/Sysmon validation.  

---

### 📊 Splunk Detection Queries

**Encoded PowerShell (T1059.001):**

```spl
index=endpoint EventCode=1 Image="*\\powershell.exe" CommandLine="*-enc*"
| table _time, host, User, CommandLine
```

**Registry persistence (T1547.001):**

```spl
index=endpoint EventCode=13
| regex TargetObject="(?i)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
| table _time, host, TargetObject, Details
```

**File drop + network connection (T1105):**

```spl
index=endpoint (EventCode=11 OR EventCode=3)
| table _time, host, EventCode, Image, CommandLine, TargetFilename, DestinationIp, DestinationPort
```

---

### 🧠 Key Takeaways

Part 5 transformed the lab from *log collection* to a true **defender feedback loop**:  
1. I simulated adversary behavior (brute force, obfuscated PowerShell, persistence, file transfer).  
2. My Sysmon + Splunk pipeline captured the artifacts.  
3. Custom SPL queries surfaced those behaviors clearly in dashboards and alerts.  

This gave me confidence that if a similar attack played out in production, the right telemetry and detection logic would be there to catch it.

---

### 📌 MITRE ATT&CK Mapping

| Technique ID | Name                               | Category         
