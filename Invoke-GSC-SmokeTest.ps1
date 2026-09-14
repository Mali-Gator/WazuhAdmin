<#
.SYNOPSIS
  Granite Shield Cyber - benign telemetry smoke test.

.DESCRIPTION
  Generates ordinary Windows activity to verify that endpoint telemetry
  reaches Wazuh. This script intentionally avoids security-sensitive actions
  such as protected-process access, persistence creation, failed logons,
  service installation, task creation, executable copying, or destructive
  commands.

.EXAMPLE
  .\Invoke-GSC-SmokeTest.ps1
#>

[CmdletBinding()]
param(
    [string]$DnsName = "example.com",
    [int]$TcpPort = 443
)

$ErrorActionPreference = "Continue"
$Root = Join-Path $env:TEMP "GSC-SMOKE-TEST"
New-Item -ItemType Directory -Path $Root -Force | Out-Null

function Step([string]$Text) {
    Write-Host "`n=== $Text ===" -ForegroundColor Cyan
}

function OK([string]$Text) {
    Write-Host "[OK] $Text" -ForegroundColor Green
}

Step "Process creation"
& "$env:WINDIR\System32\whoami.exe" | Out-Null
& "$env:WINDIR\System32\hostname.exe" | Out-Null
OK "Ran ordinary signed Windows utilities."

Step "PowerShell logging"
$child = @'
Write-Output "GSC_SMOKE_TEST_POWERSHELL"
Get-Date | Out-Null
Get-Process -Id $PID | Out-Null
'@

Start-Process powershell.exe `
    -ArgumentList @("-NoProfile","-NonInteractive","-Command",$child) `
    -Wait

OK "Ran benign child PowerShell."

Step "Text file creation / modification"
$file = Join-Path $Root "GSC-Smoke-Test.txt"
Set-Content -LiteralPath $file -Value "Granite Shield telemetry smoke test."
Start-Sleep -Milliseconds 500
Add-Content -LiteralPath $file -Value "Updated: $(Get-Date -Format o)"
OK "Created and modified $file"

Step "Benign PowerShell script file"
$psFile = Join-Path $Root "GSC-Smoke-Content.ps1"
Set-Content -LiteralPath $psFile -Value 'Write-Output "Granite Shield content telemetry test"'
Start-Sleep -Milliseconds 500
Add-Content -LiteralPath $psFile -Value '# benign second line'
OK "Created and modified $psFile"

Step "DNS query"
try {
    Resolve-DnsName -Name $DnsName -Type A -ErrorAction Stop | Out-Null
    OK "Resolved $DnsName"
}
catch {
    Write-Warning "DNS lookup failed: $($_.Exception.Message)"
}

Step "Normal outbound TCP connection"
try {
    $result = Test-NetConnection `
        -ComputerName $DnsName `
        -Port $TcpPort `
        -WarningAction SilentlyContinue

    Write-Host "TCP success: $($result.TcpTestSucceeded)"
}
catch {
    Write-Warning "TCP connection test failed: $($_.Exception.Message)"
}

Step "Ordinary registry activity"
$regPath = "HKCU:\Software\GraniteShield\TelemetryTest"
New-Item -Path $regPath -Force | Out-Null
New-ItemProperty `
    -Path $regPath `
    -Name "SmokeTest" `
    -PropertyType String `
    -Value (Get-Date -Format o) `
    -Force | Out-Null
Start-Sleep -Milliseconds 500
Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
OK "Created and removed a benign HKCU test key."

Step "Ordinary CIM/WMI queries"
Get-CimInstance Win32_OperatingSystem | Out-Null
Get-CimInstance Win32_ComputerSystem | Out-Null
OK "Queried standard Windows system inventory."

Step "Benign file deletion"
$deleteFile = Join-Path $Root "GSC-Smoke-Delete.txt"
Set-Content -LiteralPath $deleteFile -Value "Temporary test file."
Start-Sleep -Milliseconds 500
Remove-Item -LiteralPath $deleteFile -Force
OK "Created and deleted a plain text file."

Write-Host "`n=== SMOKE TEST COMPLETE ===" -ForegroundColor Green
Write-Host "Artifacts remaining under:"
Write-Host "  $Root"
Write-Host ""
Write-Host "This test validates ordinary telemetry flow only."
Write-Host "It intentionally does not emulate persistence, credential access,"
Write-Host "process injection, security-control tampering, or destructive activity."
