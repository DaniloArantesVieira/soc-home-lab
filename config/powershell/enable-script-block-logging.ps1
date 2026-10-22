# Enable PowerShell Script Block Logging
# Requires an elevated PowerShell session.

$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

New-Item -Path $Path -Force | Out-Null

New-ItemProperty `
    -Path $Path `
    -Name "EnableScriptBlockLogging" `
    -PropertyType DWord `
    -Value 1 `
    -Force | Out-Null

Write-Host "PowerShell Script Block Logging enabled."