# SOC Home Lab — Detection Tuning


This document describes the false-positive analysis and detection-tuning exercises performed during the SOC Home Lab.


The objective was not simply to generate alerts, but to evaluate detection quality and reduce unnecessary noise without removing useful security visibility.


Two tuning cases were validated:


- SOC-TUNE-001 — PowerShell ScriptPolicyTest temporary files
- SOC-TUNE-002 — False Base64-like Registry detection


---


## Detection Tuning Workflow


The following process was used for both cases:


```text
Alert generated
     ↓
Inspect raw telemetry
     ↓
Inspect Wazuh rule
     ↓
Identify false-positive condition
     ↓
Create narrow local exception
     ↓
Validate Wazuh ruleset
     ↓
Restart manager
     ↓
Perform A/B test
     ↓
Confirm original detection still works
```


The principle used throughout the project was:


> Reduce noise without reducing meaningful detection coverage.


---


# SOC-TUNE-001 — PowerShell ScriptPolicyTest Noise


## Problem


During SOC-008, Wazuh generated repeated high-severity alerts for temporary PowerShell files created under:


```text
AppData\Local\Temp
```


The files followed a pattern similar to:


```text
__PSScriptPolicyTest_*.ps1
```


Sysmon correctly recorded the files as Event ID `11`.


However, Wazuh rule `92213` classified them as:


```text
Executable file dropped in folder commonly used by malware
```


with:


```text
Rule: 92213
Level: 15
MITRE: T1105
```


This resulted in legitimate PowerShell behavior producing repeated critical alerts.


---


## Investigation


The installed Wazuh rule matched executable or script-like files created under the user's temporary directory.


The PowerShell-generated ScriptPolicyTest files satisfied those conditions even though they were legitimate operating-system activity.


The telemetry itself was useful and should not be disabled.


The problem was therefore:


```text
Valid telemetry
     +
Overly broad alert condition
     =
False-positive alert
```


---


## Solution


A local child rule was created to match only PowerShell ScriptPolicyTest files.


```xml
<rule id="100100" level="0">
 <if_sid>92213</if_sid>
 <field name="win.eventdata.targetFilename" type="pcre2">(?i)__PSScriptPolicyTest_.+\.ps1$</field>
 <description>Ignore PowerShell internal ScriptPolicyTest temporary files</description>
</rule>
```


The rule uses:


```text
Level 0
```


so matching events do not become alerts.


The Sysmon telemetry itself remains available.


---


## Validation


An A/B test was performed.


### Test A — Expected Suppression


A file matching the legitimate PowerShell pattern was created:


```text
__PSScriptPolicyTest_soclab.ps1
```


Sysmon produced:


```text
Event ID: 11
```


The event was confirmed locally.


However:


```text
Rule 92213
```


did not appear in `alerts.json`.


This confirmed that the exception was working.


### Test B — Detection Control


A second file was created:


```text
soclab-tuning-control.ps1
```


This file did not match the exclusion pattern.


The result was:


```text
Rule: 92213
Level: 15
```


The original detection remained active.


---


## Result


```text
Before tuning:


PowerShell ScriptPolicyTest
       ↓
Sysmon Event 11
       ↓
Rule 92213
       ↓
Level 15 alert




After tuning:


PowerShell ScriptPolicyTest
       ↓
Sysmon Event 11
       ↓
Rule 100100
       ↓
Level 0
       ↓
No alert
```


Control files still trigger the original detection.


### Outcome


```text
False positive reduced: YES
Telemetry preserved: YES
Original detection preserved: YES
```


Evidence:


\[`../evidence/SOC-TUNE-001`](../evidence/SOC-TUNE-001/)


---


# SOC-TUNE-002 — False Base64-like Registry Detection


## Problem


During SOC-010, a benign registry persistence test used:


```text
C:\Windows\System32\notepad.exe
```


as the data for a Windows Registry Run entry.


The expected persistence detection was generated:


```text
Rule: 92302
Level: 6
MITRE: T1547.001
```


However, the same `reg.exe` command also triggered:


```text
Rule: 92041
Level: 10
Description:
Value added to registry key has Base64-like pattern
```


No Base64 payload had been used.


---


## Investigation


The installed Wazuh rule contained the following PCRE2 logic:


```text
(?i)add.+\/d\s+(")?(?:[A-Za-z\d+\/]{4})*(?:[A-Za-z\d+\/]{3}=|[A-Za-z\d+\/]{2}==)?
```


The rule was intended to recognize Base64-like Registry data.


However, both Base64 matching sections allowed optional or zero-length matches.


This allowed a command containing:


```text
add ... /d
```


to satisfy the expression even when the actual Registry value was a normal Windows path.


For example:


```text
/d C:\Windows\System32\notepad.exe
```


incorrectly triggered the Base64-like detection.


---


## Solution


A local rule was added beneath `92041`.


```xml
<rule id="100101" level="0">
 <if_sid>92041</if_sid>
 <field name="win.eventdata.commandLine" type="pcre2">(?i)\/d\s+("?)[A-Z]:\\</field>
 <description>Ignore Rule 92041 when registry data is a normal absolute Windows path</description>
</rule>
```


The exception is intentionally narrow.


It only suppresses the detection when `/d` is followed by a normal absolute Windows drive path such as:


```text
C:\...
```


---


## Validation


Another A/B test was performed.


### Test A — Normal Windows Path


A Registry Run value was created with:


```text
/d C:\Windows\System32\notepad.exe
```


The persistence detection remained active:


```text
Rule: 92302
Level: 6
```


The incorrect Base64-like alert was absent:


```text
Rule 92041: NOT GENERATED
```


### Test B — Real Base64-like Value


A second test used:


```text
U09DLUxBQg==
```


which is a Base64 representation of:


```text
SOC-LAB
```


The result was:


```text
Rule: 92041
Level: 10
```


The intended detection remained operational.


---


## Result


```text
Normal Windows path
       ↓
92302 detected
92041 suppressed




Base64-like value
       ↓
92041 detected
```


### Outcome


```text
False positive reduced: YES
Persistence detection preserved: YES
Base64-like detection preserved: YES
```


Evidence:


\[`../evidence/SOC-TUNE-002`](../evidence/SOC-TUNE-002/)


---


# Custom Rules


The final local rules used by the project are stored at:


```text
config/wazuh/local_rules.xml
```


The laboratory-specific rule IDs are:


| Rule | Purpose | Level |
|---:|---|---:|
| 100100 | Suppress ScriptPolicyTest temporary-file noise | 0 |
| 100101 | Suppress false Base64-like matches on normal Windows paths | 0 |


---


# Rule Validation


Before restarting the Wazuh Manager, custom rules were validated with:


```bash
/var/ossec/bin/wazuh-analysisd -t
```


No validation errors were returned.


The manager was then restarted and its state verified before testing continued.


---


# Why A/B Testing Matters


Simply observing that an unwanted alert disappears is not sufficient to validate detection tuning.


A poorly designed exception could suppress legitimate malicious behavior as well.


For that reason, each tuning exercise used:


```text
Test A
Known false positive
Expected result: suppressed


Test B
Control behavior
Expected result: detected
```


Only when both conditions were satisfied was the tuning considered successful.


---


# Detection Engineering Lessons


The tuning exercises demonstrated several important principles.


## Telemetry and Alerts Are Different


Suppressing an alert does not necessarily require suppressing the underlying event.


Maintaining telemetry allows future investigation and rule development.


## Exceptions Should Be Narrow


Broad exclusions can create detection blind spots.


Both custom rules target specific characteristics of known false positives.


## Detection Rules Require Validation


A high severity level does not automatically mean an alert is accurate.


The underlying condition and raw telemetry must be investigated.


## Retesting Is Required


Every change to detection logic should be followed by a control test to ensure that meaningful detections remain operational.


---


# Final Outcome


The SOC Home Lab completed:


```text
12 detection scenarios
2 detection-tuning exercises
```


The final tuning state achieved:


```text
Reduced alert noise
       +
Preserved endpoint telemetry
       +
Preserved intended detections
       =
Higher quality detection coverage
```


These exercises demonstrate the transition from basic SIEM operation into practical detection engineering.
