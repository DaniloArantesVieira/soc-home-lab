# SOC Home Lab — Lab Setup


This document describes the environment used to build the SOC Home Lab and the main configuration steps required to reproduce the monitoring architecture.


The lab was designed for Blue Team practice, endpoint telemetry collection, threat detection, MITRE ATT&CK mapping, and detection engineering.


---


## 1. Lab Architecture


The environment consists of two main systems:


### Windows Endpoint


- Windows 11 Pro
- Wazuh Agent 4.14.9
- Sysmon 15.22
- Windows Security Auditing
- PowerShell Script Block Logging


### SOC Server


- Debian 13
- Docker
- Docker Compose
- Wazuh 4.14.9
 - Wazuh Manager
 - Wazuh Indexer
 - Wazuh Dashboard


The Windows endpoint forwards security telemetry to the Wazuh Manager running on the Debian server.


```text
Windows 11 Endpoint
│
├── Windows Security Log
├── Sysmon
├── PowerShell Operational Log
│
└── Wazuh Agent
       │
       │ TCP 1514
       ▼
Debian 13 SOC Server
│
└── Docker
   ├── Wazuh Manager
   ├── Wazuh Indexer
   └── Wazuh Dashboard
```


---


## 2. Network Design


The lab systems operate inside the same trusted local network.


For portability, this repository does not depend on fixed IP addresses.


Example layout:


```text
Windows Endpoint: <WINDOWS_ENDPOINT_IP>
Wazuh Server:     <WAZUH_SERVER_IP>
```


The main Wazuh agent communication port used in this lab is:


```text
TCP 1514
```


The Wazuh Dashboard is accessed through HTTPS.


The server firewall should only expose services required by the lab and preferably restrict access to the local network.


---


## 3. Wazuh Server


The Wazuh server runs on Debian using Docker containers.


The deployment contains:


```text
Wazuh Manager
Wazuh Indexer
Wazuh Dashboard
```


The deployment used during this project was Wazuh:


```text
4.14.9
```


### Verify Containers


From the Wazuh Docker Compose directory:


```bash
docker compose ps
```


The Wazuh services should report a running state.


Example:


```text
wazuh.manager
wazuh.indexer
wazuh.dashboard
```


### Manager Connectivity


The Windows agent communicates with the Wazuh Manager using TCP port `1514`.


Connectivity can be validated from the Windows endpoint with:


```powershell
Test-NetConnection <WAZUH_SERVER_IP> -Port 1514
```


Expected result:


```text
TcpTestSucceeded : True
```


---


## 4. Windows Wazuh Agent


The monitored endpoint uses the Wazuh Windows Agent.


Default installation path used in the lab:


```text
C:\Program Files (x86)\ossec-agent
```


Main configuration file:


```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```


Windows service:


```text
WazuhSvc
```


### Check Agent Service


```powershell
Get-Service WazuhSvc
```


Expected state:


```text
Running
```


### Check Agent Log


```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50
```


A healthy connection should contain an entry similar to:


```text
Connected to the server
```


---


## 5. Sysmon


Sysmon provides additional endpoint telemetry used throughout the detection scenarios.


Version used in the lab:


```text
Sysmon 15.22
```


The binaries are intentionally not stored in Git.


They must be downloaded separately from the official Microsoft Sysinternals distribution.


The local working directory used during development was:


```text
tools/sysmon/
```


The repository only maintains the Sysmon configuration:


```text
config/sysmon/sysmonconfig.xml
```


### Validate Sysmon Service


```powershell
Get-Service Sysmon64
```


Expected state:


```text
Running
```


### Validate Sysmon Event Channel


```powershell
Get-WinEvent `
 -LogName "Microsoft-Windows-Sysmon/Operational" `
 -MaxEvents 5
```


---


## 6. Sysmon Configuration


The configuration used by this lab is available at:


```text
config/sysmon/sysmonconfig.xml
```


The lab collects telemetry including:


- Process creation
- Network connections
- File creation
- Registry events
- DNS queries


These events were used to validate multiple Wazuh detections.


Examples include:


```text
Sysmon Event ID 1  — Process Create
Sysmon Event ID 3  — Network Connection
Sysmon Event ID 11 — File Create
Sysmon Event ID 13 — Registry Value Set
```


---


## 7. Wazuh Sysmon Collection


The Wazuh Agent was configured to collect the Sysmon Operational event channel.


The configuration snippet used in this project is available at:


```text
config/wazuh/agent-log-collection.xml
```


Relevant configuration:


```xml
<localfile>
 <location>Microsoft-Windows-Sysmon/Operational</location>
 <log_format>eventchannel</log_format>
</localfile>
```


After updating the agent configuration, restart the Wazuh Agent:


```powershell
Restart-Service WazuhSvc
```


The agent log can be used to confirm that the channel is being monitored.


Example:


```text
Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'
```


---


## 8. PowerShell Script Block Logging


PowerShell Script Block Logging was enabled to provide visibility into PowerShell commands and scripts.


The configuration script is stored at:


```text
config/powershell/enable-script-block-logging.ps1
```


The policy enables:


```text
EnableScriptBlockLogging = 1
```


Registry location:


```text
HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```


### PowerShell Event Channel


Script Block Logging events are written to:


```text
Microsoft-Windows-PowerShell/Operational
```


The primary event used by this project is:


```text
Event ID 4104
```


Example validation:


```powershell
Get-WinEvent `
 -LogName "Microsoft-Windows-PowerShell/Operational" `
 -MaxEvents 10
```


---


## 9. Wazuh PowerShell Collection


The Wazuh Agent was also configured to collect the PowerShell Operational channel.


```xml
<localfile>
 <location>Microsoft-Windows-PowerShell/Operational</location>
 <log_format>eventchannel</log_format>
</localfile>
```


After configuration changes:


```powershell
Restart-Service WazuhSvc
```


Successful collection can be verified in:


```text
C:\Program Files (x86)\ossec-agent\ossec.log
```


---


## 10. Windows Security Auditing


Several scenarios rely on native Windows Security events.


Examples used in the project include:


```text
4625 — Failed Logon
4698 — Scheduled Task Created
4720 — User Account Created
4726 — User Account Deleted
1102 — Audit Log Cleared
```


For the Scheduled Task scenario, the following audit subcategory was required:


```text
Other Object Access Events
```


Its status can be checked with:


```powershell
auditpol.exe /get /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}"
```


Success auditing should be enabled.


---


## 11. Custom Wazuh Rules


During the lab, false-positive behavior was identified in two Wazuh detections.


Custom local rules were created to reduce noise without disabling the original security telemetry.


The published rule configuration is available at:


```text
config/wazuh/local_rules.xml
```


Custom rules:


```text
100100 — Suppress PowerShell ScriptPolicyTest temporary file noise


100101 — Suppress false Base64-like detections for normal Windows paths
```


Before applying custom rules, validate the configuration:


```bash
/var/ossec/bin/wazuh-analysisd -t
```


No output indicates successful validation.


---


## 12. Wazuh Rule Validation


Alerts can be inspected directly from the Wazuh Manager:


```text
/var/ossec/logs/alerts/alerts.json
```


Example:


```bash
grep -F '"id":"60228"' \
 /var/ossec/logs/alerts/alerts.json
```


This method was used throughout the lab to validate detections before confirming them visually in the Wazuh Dashboard.


---


## 13. Wazuh Dashboard


The Wazuh Dashboard was used to visually confirm alerts and collect evidence.


Typical filters include:


```text
rule.id: "91809"
```


or:


```text
rule.id: "92302"
```


Evidence screenshots are stored under:


```text
evidence/
```


Each detection scenario has its own directory.


Example:


```text
evidence/
├── SOC-001/
├── SOC-002/
├── ...
└── SOC-012/
```


---


## 14. Firewall Considerations


The Debian server uses a host firewall.


Only ports required by the lab should be exposed.


Temporary firewall rules used during detection validation should be removed immediately after testing.


For example, SOC-011 temporarily exposed TCP port `5985` only to the Windows endpoint.


The rule was removed after successful validation.


This principle was followed throughout the project:


```text
Open only what is required
       ↓
Restrict the source
       ↓
Perform the test
       ↓
Collect evidence
       ↓
Remove temporary access
```


---


## 15. Validation Workflow


Each detection followed a repeatable workflow:


```text
1\. Identify the Wazuh rule
2\. Inspect its detection conditions
3\. Prepare a benign test
4\. Generate endpoint telemetry
5\. Validate the Windows event locally
6\. Confirm receipt in Wazuh
7\. Verify the final alert
8\. Capture evidence
9\. Remove temporary artifacts
10\. Investigate false positives if required
```


This approach prevents the lab from becoming only an alert-generation exercise.


The objective is to understand the complete detection lifecycle.


---


## 16. Security and Repository Hygiene


Sensitive data should never be committed to the repository.


The project `.gitignore` excludes:


- Private keys
- Certificates
- `.env` files
- Temporary files
- Logs
- Wazuh configuration backups
- Third-party Sysmon executables


The following directory contains local-only third-party binaries and is not intended for distribution:


```text
tools/sysmon/
```


Only configuration files necessary to reproduce the lab are published.


---


## 17. Next Steps


After the endpoint detection lab, the next planned project expands monitoring into network telemetry.


Planned progression:


```text
SOC Home Lab
   ↓
Network IDS Lab
   ↓
Phishing Analysis Lab
   ↓
Honeypot Monitoring
   ↓
Incident Response Lab
```


This progression is intended to build a broader Blue Team portfolio covering endpoint, network, investigation, and response workflows.
