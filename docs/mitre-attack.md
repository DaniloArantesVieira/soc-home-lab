# SOC Home Lab — MITRE ATT&CK Coverage


This document maps the detection scenarios implemented in the SOC Home Lab to the MITRE ATT&CK techniques referenced by the Wazuh rules used during validation.


The purpose of this matrix is to show which attacker behaviors were observed by the lab and how endpoint telemetry was translated into security detections.


---


## Coverage Summary


| MITRE ID | Technique | Detection Scenario | Data Source |
|---|---|---|---|
| T1110 | Brute Force | SOC-001 | Windows Security |
| T1070 | Indicator Removal / Log Clearing | SOC-002 | Windows Security |
| T1098 | Account Manipulation | SOC-003 | Windows Security |
| T1098 | Account Manipulation | SOC-004 | Windows Security |
| T1531 | Account Access Removal | SOC-004 | Windows Security |
| T1136.001 | Create Account: Local Account | SOC-005 | Sysmon |
| T1057 | Process Discovery | SOC-006 | PowerShell |
| T1140 | Deobfuscate/Decode Files or Information | SOC-007 | PowerShell |
| T1105 | Ingress Tool Transfer | SOC-008 | Sysmon |
| T1105 | Ingress Tool Transfer | SOC-009 | Sysmon |
| T1547.001 | Registry Run Keys / Startup Folder | SOC-010 | Sysmon |
| T1021.006 | Windows Remote Management | SOC-011 | Sysmon |
| T1053 | Scheduled Task/Job | SOC-012 | Windows Security |


---


## MITRE ATT&CK Tactics


The validated scenarios provide visibility across several ATT&CK tactics.


| Tactic | Covered Scenarios |
|---|---|
| Credential Access | SOC-001 |
| Defense Evasion | SOC-002, SOC-007 |
| Persistence | SOC-003, SOC-004, SOC-005, SOC-010, SOC-012 |
| Privilege Escalation | SOC-010, SOC-012 |
| Discovery | SOC-006 |
| Command and Control | SOC-008, SOC-009 |
| Lateral Movement | SOC-011 |
| Execution | SOC-012 |


---


# Credential Access


## T1110 — Brute Force


**Scenario:** SOC-001


Repeated authentication failures were generated and correlated by Wazuh.


```text
Telemetry:
Windows Security Event ID 4625


Wazuh Rule:
60204


Severity:
Level 10
```


The scenario demonstrates detection of repeated failed authentication attempts associated with brute-force behavior.


---


# Defense Evasion


## T1070 — Indicator Removal


**Scenario:** SOC-002


The Windows Security audit log was cleared.


```text
Telemetry:
Windows Security Event ID 1102


Wazuh Rule:
63103


Severity:
Level 5
```


The scenario provides visibility into activity associated with removing or destroying security evidence.


---


## T1140 — Deobfuscate/Decode Files or Information


**Scenario:** SOC-007


PowerShell decoded a benign Base64 string using:


```powershell
\[System.Convert]::FromBase64String(...)
```


Detection:


```text
PowerShell Event ID:
4104


Wazuh Rule:
91809


Severity:
Level 10
```


No malicious payload was used.


---


# Persistence


## T1098 — Account Manipulation


**Scenarios:**


```text
SOC-003 — Local User Creation
SOC-004 — Local User Deletion
```


Windows account-management events provided visibility into changes to local accounts.


Relevant telemetry:


```text
4720 — User Account Created
4726 — User Account Deleted
```


---


## T1136.001 — Create Account: Local Account


**Scenario:** SOC-005


A local account was created through the Windows command line and captured through Sysmon Process Creation telemetry.


```text
Sysmon Event ID:
1


Wazuh Rule:
92040


Severity:
Level 12
```


---


## T1547.001 — Registry Run Keys / Startup Folder


**Scenario:** SOC-010


A benign Registry Run key was created pointing to:


```text
C:\Windows\System32\notepad.exe
```


Detection:


```text
Sysmon Event ID:
13


Wazuh Rule:
92302


Severity:
Level 6
```


The test registry value was removed after validation.


---


## T1053 — Scheduled Task/Job


**Scenario:** SOC-012


A benign scheduled task was created with Notepad as its action.


Detection:


```text
Windows Security Event ID:
4698


Wazuh Rule:
60228


Severity:
Level 4
```


The task was removed after validation.


The installed Wazuh rule maps this activity to the general ATT&CK technique:


```text
T1053 — Scheduled Task/Job
```


---


# Discovery


## T1057 — Process Discovery


**Scenario:** SOC-006


PowerShell executed:


```powershell
Get-Process
```


The command was captured by Script Block Logging.


Detection:


```text
PowerShell Event ID:
4104


Wazuh Rule:
91815


Severity:
Level 4
```


---


# Command and Control


## T1105 — Ingress Tool Transfer


**Scenarios:**


```text
SOC-008 — Suspicious Script Creation in Temp
SOC-009 — PowerShell File Compression
```


The installed Wazuh rules for both scenarios are mapped to T1105.


### SOC-008


```text
Sysmon Event ID:
11


Wazuh Rule:
92213


Severity:
Level 15
```


### SOC-009


```text
Sysmon Event ID:
11


Wazuh Rule:
92212


Severity:
Level 14
```


## Mapping Limitation


The mappings above are preserved exactly as provided by the installed Wazuh ruleset.


File creation in a temporary directory or archive creation alone does not necessarily prove an ingress transfer operation.


For this reason, the project distinguishes between:


```text
Observed telemetry
```


and:


```text
MITRE mapping assigned by the SIEM rule
```


This distinction is important when evaluating detection quality.


---


# Lateral Movement


## T1021.006 — Windows Remote Management


**Scenario:** SOC-011


PowerShell established a TCP connection to port:


```text
5985
```


Detection:


```text
Sysmon Event ID:
3


Wazuh Rule:
92110


Severity:
Level 4
```


The installed rule classified the activity as Windows Remote Management.


## Detection Limitation


The laboratory test generated a TCP connection to the default WinRM HTTP port.


It did not establish a real WinRM application session.


Therefore:


```text
Observed:
PowerShell network connection to TCP/5985


Wazuh interpretation:
Windows Remote Management
```


The distinction is documented to avoid overstating what the telemetry proves.


---


# Additional Technique


## T1531 — Account Access Removal


**Scenario:** SOC-004


The installed Wazuh rule used during the local-account deletion scenario included:


```text
T1531 — Account Access Removal
```


The project preserves this mapping as part of the rule metadata observed during testing.


---


# Coverage by Telemetry Source


| Source | Techniques Observed |
|---|---|
| Windows Security | T1110, T1070, T1098, T1531, T1053 |
| Sysmon Process Creation | T1136.001 |
| Sysmon File Creation | T1105 |
| Sysmon Registry Events | T1547.001 |
| Sysmon Network Events | T1021.006 |
| PowerShell Script Block Logging | T1057, T1140 |


---


# Detection Engineering Perspective


MITRE ATT&CK mappings should not be treated as proof that an attacker performed a technique.


A detection rule normally represents:


```text
Observed behavior
       ↓
Detection logic
       ↓
Analyst interpretation
       ↓
MITRE ATT&CK mapping
```


The SOC Home Lab therefore records both:


- The activity actually observed in endpoint telemetry
- The MITRE ATT&CK technique assigned by the Wazuh rule


This is particularly important for SOC-009 and SOC-011, where the Wazuh mapping is broader than what can be independently proven from the test telemetry alone.


---


# Coverage Outcome


The laboratory generated detections mapped to the following ATT&CK techniques:


```text
T1021.006
T1053
T1057
T1070
T1098
T1105
T1110
T1136.001
T1140
T1531
T1547.001
```


This represents coverage across authentication, account activity, PowerShell behavior, file activity, persistence mechanisms, network telemetry, and scheduled tasks.


The matrix is intended to document **validated detection coverage**, not complete ATT&CK coverage of the endpoint.
