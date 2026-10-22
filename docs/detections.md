# SOC Home Lab — Detection Catalog


This document describes the detection scenarios validated during the SOC Home Lab.


Each scenario was executed in a controlled environment using benign commands or test artifacts. The objective was to understand the full detection lifecycle:


```text
Simulation
  ↓
Telemetry Generation
  ↓
Event Collection
  ↓
Wazuh Rule Matching
  ↓
Alert Validation
  ↓
Evidence Collection
  ↓
Cleanup
```


A total of **12 detection scenarios** were successfully validated.


---


## Detection Summary


| ID | Detection | Telemetry | Event ID | Wazuh Rule | Level | MITRE ATT&CK |
|---|---|---|---:|---:|---:|---|
| SOC-001 | Windows Brute Force | Windows Security | 4625 | 60204 | 10 | T1110 |
| SOC-002 | Security Log Clearing | Windows Security | 1102 | 63103 | 5 | T1070 |
| SOC-003 | Local User Creation | Windows Security | 4720 | 60109 | 8 | T1098 |
| SOC-004 | Local User Deletion | Windows Security | 4726 | 60111 | 8 | T1098 / T1531 |
| SOC-005 | Local Account Creation via Command Line | Sysmon | 1 | 92040 | 12 | T1136.001 |
| SOC-006 | PowerShell Process Discovery | PowerShell | 4104 | 91815 | 4 | T1057 |
| SOC-007 | PowerShell Base64 Decoding | PowerShell | 4104 | 91809 | 10 | T1140 |
| SOC-008 | Suspicious Script Creation in Temp | Sysmon | 11 | 92213 | 15 | T1105 |
| SOC-009 | PowerShell File Compression | Sysmon | 11 | 92212 | 14 | T1105 |
| SOC-010 | Registry Run Key Persistence | Sysmon | 13 | 92302 | 6 | T1547.001 |
| SOC-011 | PowerShell Network Connection to WinRM Port | Sysmon | 3 | 92110 | 4 | T1021.006 |
| SOC-012 | Scheduled Task Creation | Windows Security | 4698 | 60228 | 4 | T1053 |


---


# SOC-001 — Windows Brute Force


## Objective


Validate Wazuh detection and correlation of repeated failed Windows authentication attempts.


## Telemetry


```text
Source: Windows Security Log
Event ID: 4625
Event: An account failed to log on
```


## Simulation


Several failed authentication attempts were generated against unique local usernames.


Example test pattern:


```powershell
1..8 | ForEach-Object {
   $user = "wazuh-test$_"


   net use \\127.0.0.1\IPC$ `
       /user:"$env:COMPUTERNAME\$user" `
       "LAB-TEST-PASSWORD"


   Start-Sleep -Seconds 2
}
```


The password used during the original laboratory exercise was temporary and is intentionally not included in the repository.


## Detection


The individual authentication failures were detected first, and Wazuh correlated the repeated failures.


```text
Wazuh Rule: 60204
Level: 10
MITRE ATT&CK: T1110 — Brute Force
```


## Result


```text
Status: DETECTED
```


Evidence:


\[`../evidence/SOC-001`](../evidence/SOC-001/)


---


# SOC-002 — Windows Security Log Clearing


## Objective


Validate detection of Windows Security audit log clearing.


## Telemetry


```text
Source: Windows Security Log
Event ID: 1102
Provider: Microsoft-Windows-Eventlog
```


## Preparation


Before clearing the log, a forensic copy of the Security log was exported and preserved locally.

Raw EVTX files are intentionally excluded from the public repository because Windows Security logs may contain host, account, and system metadata.


## Detection


```text
Wazuh Rule: 63103
Level: 5
Description: The audit log was cleared
MITRE ATT&CK: T1070
```


## Result


```text
Status: DETECTED
```


Evidence:


\[`../evidence/SOC-002`](../evidence/SOC-002/)


---


# SOC-003 — Local User Creation


## Objective


Detect creation of a new local Windows account using native Windows Security telemetry.


## Telemetry


```text
Source: Windows Security Log
Event ID: 4720
Event: A user account was created
```


## Detection


```text
Wazuh Rule: 60109
Level: 8
Description: User account enabled or created
MITRE ATT&CK: T1098
```


## Result


The local user creation generated the expected Windows event and Wazuh alert.


```text
Status: DETECTED
```


Evidence:


\[`../evidence/SOC-003`](../evidence/SOC-003/)


---


# SOC-004 — Local User Deletion


## Objective


Detect deletion of a local Windows user account.


## Telemetry


```text
Source: Windows Security Log
Event ID: 4726
Event: A user account was deleted
```


## Detection


```text
Wazuh Rule: 60111
Level: 8
Description: User account disabled or deleted
MITRE ATT&CK:
- T1098
- T1531
```


## Result


```text
Status: DETECTED
```


Evidence:


\[`../evidence/SOC-004`](../evidence/SOC-004/)


---


# SOC-005 — Local Account Creation via Sysmon


## Objective


Detect local account creation through process creation telemetry rather than relying only on native Windows account-management events.


## Telemetry


```text
Source: Sysmon
Event ID: 1 — Process Create
```


## Simulation


A benign local account was created with the Windows `net` utility.


The command generated both `net.exe` and `net1.exe` process activity.


## Detection


```text
Wazuh Rule: 92040
Level: 12
Description: net1.exe executed a user creation command
MITRE ATT&CK: T1136.001 — Local Account
```


## Security Note


Command-line telemetry may capture sensitive values provided directly as command arguments.


Passwords used in detection tests must therefore:


- Be temporary
- Never be reused
- Never be committed to the repository


## Result


```text
Status: DETECTED
```


Evidence:


\[`../evidence/SOC-005`](../evidence/SOC-005/)


---


# SOC-006 — PowerShell Process Discovery


## Objective


Validate PowerShell Script Block Logging and detection of process discovery activity.


## Telemetry


```text
Source: Microsoft-Windows-PowerShell/Operational
Event ID: 4104 — Script Block Logging
```


## Simulation


```powershell
Get-Process | Select-Object -First 5
```


## Detection


```text
Wazuh Rule: 91815
Level: 4
Description: Powershell executing process discovery
MITRE ATT&CK: T1057 — Process Discovery
Tactic: Discovery
```


## Result


```text
Status: DETECTED
```


Evidence:


\[`../evidence/SOC-006`](../evidence/SOC-006/)


---


# SOC-007 — PowerShell Base64 Decoding


## Objective


Validate detection of PowerShell Base64 decoding behavior without executing malicious content.


## Telemetry


```text
Source: Microsoft-Windows-PowerShell/Operational
Event ID: 4104
```


## Simulation


A benign Base64 representation of `SOC-LAB` was decoded.


```powershell
$DecodedBytes = \[System.Convert]::FromBase64String("U09DLUxBQg==")
\[System.Text.Encoding]::UTF8.GetString($DecodedBytes)
```


Expected output:


```text
SOC-LAB
```


## Detection


```text
Wazuh Rule: 91809
Level: 10
Description: Powershell script may be using Base64 decoding method
MITRE ATT&CK: T1140 — Deobfuscate/Decode Files or Information
```


## Result


```text
Status: DETECTED
```


Evidence:


\[`../evidence/SOC-007`](../evidence/SOC-007/)


---


# SOC-008 — Suspicious Script Creation in Temp


## Objective


Detect creation of script or executable-like files inside a directory commonly abused for staging.


## Telemetry


```text
Source: Sysmon
Event ID: 11 — File Create
```


## Simulation


A harmless PowerShell script was created under the current user's temporary directory.


Example:


```powershell
$LabFile = Join-Path $env:TEMP "soclab-event11.ps1"


Set-Content `
   -Path $LabFile `
   -Value 'Write-Output "SOC LAB Event 11"'
```


The file was not executed.


## Detection


```text
Wazuh Rule: 92213
Level: 15
Description: Executable file dropped in folder commonly used by malware
MITRE ATT&CK: T1105
```


## Result


```text
Status: DETECTED
```


During this test, legitimate PowerShell `__PSScriptPolicyTest_*` files were also found to trigger the same rule.


This observation resulted in:


```text
SOC-TUNE-001
```


Evidence:


\[`../evidence/SOC-008`](../evidence/SOC-008/)


---


# SOC-009 — PowerShell File Compression


## Objective


Validate detection of archive creation performed by PowerShell.


## Telemetry


```text
Source: Sysmon
Event ID: 11 — File Create
```


## Simulation


A benign text file was compressed into a ZIP archive using PowerShell.


```powershell
Compress-Archive `
   -Path $SourceFile `
   -DestinationPath $ZipFile `
   -Force
```


## Detection


```text
Wazuh Rule: 92212
Level: 14
Description: Suspicious file compression activity by powershell
MITRE ATT&CK: T1105
```


## Mapping Note


The installed Wazuh ruleset maps this behavior to `T1105 — Ingress Tool Transfer`.


This documentation preserves the actual mapping used by the installed rule instead of replacing it with a different interpretation.


## Result


```text
Status: DETECTED
```


Evidence:


\[`../evidence/SOC-009`](../evidence/SOC-009/)


---


# SOC-010 — Registry Run Key Persistence


## Objective


Detect persistence through modification of a Windows Registry Run key.


## Telemetry


```text
Source: Sysmon
Event ID: 13 — Registry Value Set
Process: reg.exe
```


## Simulation


A benign registry value pointing to Notepad was created under:


```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```


Test value:


```text
SOCLabStartup
```


Data:


```text
C:\Windows\System32\notepad.exe
```


## Detection


```text
Wazuh Rule: 92302
Level: 6
Description:
Registry entry to be executed on next logon was modified using command line application reg.exe


MITRE ATT&CK:
T1547.001 — Registry Run Keys / Startup Folder


Tactics:
- Persistence
- Privilege Escalation
```


## Additional Finding


The same command also incorrectly triggered rule `92041`, which attempted to classify the normal Windows path as Base64-like data.


This finding resulted in:


```text
SOC-TUNE-002
```


## Cleanup


The registry value was removed immediately after validation.


## Result


```text
Status: DETECTED
```


Evidence:


\[`../evidence/SOC-010`](../evidence/SOC-010/)


---


# SOC-011 — PowerShell Network Connection to WinRM Port


## Objective


Validate Sysmon network telemetry and a Wazuh rule associated with Windows Remote Management traffic.


## Telemetry


```text
Source: Sysmon
Event ID: 3 — Network Connection
Process: powershell.exe
Protocol: TCP
Destination Port: 5985
```


## Simulation


A temporary TCP listener was opened on the Debian lab server.


```bash
nc -lvnp 5985
```


A temporary firewall rule allowed only the Windows endpoint to access the test port.


PowerShell then initiated a TCP connection to the lab server.


```powershell
$Client = New-Object System.Net.Sockets.TcpClient
$Client.Connect("<WAZUH_SERVER_IP>", 5985)
Start-Sleep -Seconds 2
$Client.Close()
```


## Detection


```text
Wazuh Rule: 92110
Level: 4
MITRE ATT&CK: T1021.006 — Windows Remote Management
Tactic: Lateral Movement
```


## Important Detection Limitation


The Wazuh rule identifies activity based on traffic to TCP port `5985`.


The test did not establish a real WinRM session.


Therefore, the alert demonstrates **network activity toward the default WinRM HTTP port**, not independent validation of the WinRM application protocol.


## Cleanup


The temporary TCP listener was stopped and the firewall rule was removed after validation.


## Result


```text
Status: DETECTED
```


Evidence:


\[`../evidence/SOC-011`](../evidence/SOC-011/)


---


# SOC-012 — Scheduled Task Creation


## Objective


Detect creation of a Windows Scheduled Task using native Windows Security auditing.


## Telemetry


```text
Source: Windows Security Log
Event ID: 4698
Event: A scheduled task was created
```


## Audit Requirement


The Windows audit subcategory:


```text
Other Object Access Events
```


was confirmed as enabled for successful events.


Validation command:


```powershell
auditpol.exe /get /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}"
```


## Simulation


A benign scheduled task was created:


```text
Task Name:
\SOCLab-SOC012


Action:
C:\Windows\System32\notepad.exe
```


The task was scheduled for a future time so that the objective remained creation detection rather than program execution.


## Detection


```text
Wazuh Rule: 60228
Level: 4
Description: A scheduled task was created
MITRE ATT&CK: T1053 — Scheduled Task/Job


Tactics:
- Execution
- Persistence
- Privilege Escalation
```


## Cleanup


The task was removed after validation.


## Result


```text
Status: DETECTED
```


Evidence:


\[`../evidence/SOC-012`](../evidence/SOC-012/)


---


# Detection Coverage


The scenarios provide visibility across several types of endpoint activity.


| Area | Covered Scenarios |
|---|---|
| Authentication | SOC-001 |
| Defense Evasion / Log Manipulation | SOC-002 |
| Account Management | SOC-003, SOC-004, SOC-005 |
| PowerShell | SOC-006, SOC-007 |
| File Activity | SOC-008, SOC-009 |
| Registry Persistence | SOC-010 |
| Network / Remote Services | SOC-011 |
| Scheduled Tasks | SOC-012 |


---


# Detection Validation Principles


The laboratory followed several principles during testing.


## Inspect Before Simulating


Whenever possible, the installed Wazuh rule was inspected before creating the test.


This allowed the scenario to be based on the actual conditions used by the SIEM.


## Use Benign Payloads


The objective was telemetry and detection validation, not malware execution.


Examples include:


```text
notepad.exe
SOC-LAB
temporary .ps1 files
temporary ZIP files
controlled TCP listeners
```


## Validate the Native Event First


When possible, the corresponding Windows or Sysmon event was confirmed locally before checking Wazuh.


This separates:


```text
Telemetry generation problems
```


from:


```text
SIEM ingestion or rule problems
```


## Confirm the Final Alert


Alerts were validated both through:


```text
/var/ossec/logs/alerts/alerts.json
```


and the Wazuh Dashboard.


## Clean Up Test Artifacts


Temporary artifacts were removed after testing, including:


- Local users
- Registry values
- Scheduled tasks
- Test files
- Temporary firewall rules
- TCP listeners


---


# Outcome


All twelve planned detection scenarios were validated successfully.


```text
12 / 12 detection scenarios completed
```


Two detection-quality issues were also identified during testing and were converted into dedicated tuning exercises:


```text
SOC-TUNE-001
SOC-TUNE-002
```


Those cases are documented separately in:


\[`tuning.md`](tuning.md)
