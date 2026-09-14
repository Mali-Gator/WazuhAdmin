<#
.SYNOPSIS
  Granite Shield Cyber - Windows Wazuh/EDR endpoint bootstrap.

.DESCRIPTION
  One-script endpoint bootstrap for a Wazuh-based Windows telemetry stack.

  This script can:
    - Install Wazuh if it is not already installed.
    - Optionally uninstall/reinstall Wazuh to prove a clean rebuild workflow.
    - Install or replace the Sysmon configuration with a known GSC baseline.
    - Enable Windows security auditing and PowerShell logging.
    - Enable/cap important Windows Event Log channels as circular buffers.
    - Configure Wazuh to collect security-relevant specialty channels.
    - Add targeted Wazuh FIM for:
        * small script/source files, including content changes
        * common ransomware-targeted documents (metadata/hash only)
    - Limit Wazuh's local FIM diff cache.
    - Add targeted browser credential-database read auditing.
    - Add LNK/shortcut metadata enrichment.
    - Validate Wazuh configuration before restarting the service.
    - Roll back ossec.conf if Wazuh does not recover.

  IMPORTANT:
    - This script DOES NOT clear Windows event logs.
    - This script DOES NOT disable Defender or Bitdefender.
    - This script DOES NOT enable Wazuh remote commands.
    - Event logs remain as small circular local buffers and overwrite oldest
      entries when full.
    - Small script-content capture may collect secrets if they are embedded
      directly inside monitored scripts. That is intentional for this test.

.EXAMPLE
  # Fresh endpoint or update an existing endpoint in place:
  .\Deploy-GSC-WazuhEndpoint.ps1 -ManagerAddress "analytics.example.com"

.EXAMPLE
  # Full Wazuh wipe/reinstall test on an already-configured endpoint:
  .\Deploy-GSC-WazuhEndpoint.ps1 `
      -ManagerAddress "analytics.example.com" `
      -RebuildWazuh

.EXAMPLE
  # Custom endpoint name:
  .\Deploy-GSC-WazuhEndpoint.ps1 `
      -ManagerAddress "10.10.10.10" `
      -AgentName "CLIENT-PC-01" `
      -RebuildWazuh

.NOTES
  Run from Windows PowerShell 5.1 or later as Administrator.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ManagerAddress,

    [ValidateNotNullOrEmpty()]
    [string]$AgentName = $env:COMPUTERNAME,

    [ValidateNotNullOrEmpty()]
    [string]$WazuhVersion = "4.14.7-1",

    [ValidateRange(1,65535)]
    [int]$ManagerPort = 1514,

    [ValidateRange(1,65535)]
    [int]$RegistrationPort = 1515,

    [switch]$RebuildWazuh,

    [switch]$SkipBrowserCredentialAuditing,

    [switch]$SkipScriptContentCapture,

    [switch]$SkipLnkMetadata
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# -----------------------------
# Constants
# -----------------------------

$GscRoot       = "C:\ProgramData\GraniteShield"
$TelemetryDir  = Join-Path $GscRoot "Telemetry"
$BackupDir     = Join-Path $GscRoot "Backups"
$SysmonDir     = Join-Path $GscRoot "Sysmon"
$HelperDir     = Join-Path $GscRoot "Helpers"
$WorkDir       = Join-Path $env:TEMP "GSC-Wazuh-Bootstrap"

$LnkLog        = Join-Path $TelemetryDir "lnk-metadata.log"
$LnkState      = Join-Path $TelemetryDir "lnk-state.json"
$InstallReport = Join-Path $TelemetryDir "endpoint-bootstrap-report.txt"

$ScriptRegex = '\.ps1$|\.psm1$|\.psd1$|\.bat$|\.cmd$|\.vbs$|\.vbe$|\.js$|\.jse$|\.wsf$|\.hta$|\.reg$|\.url$|\.lnk$'
$RansomwareRegex = '\.doc$|\.docx$|\.xls$|\.xlsx$|\.xlsm$|\.ppt$|\.pptx$|\.pdf$|\.rtf$|\.txt$|\.csv$|\.jpg$|\.jpeg$|\.png$|\.zip$|\.7z$|\.db$|\.sqlite$'

# Approximately 600 MB total maximum local EVTX storage.
$EventChannelCapsMB = [ordered]@{
    "Security"                                                       = 128
    "System"                                                         = 32
    "Application"                                                    = 32
    "Microsoft-Windows-Sysmon/Operational"                           = 128
    "Microsoft-Windows-PowerShell/Operational"                       = 64
    "Microsoft-Windows-Windows Defender/Operational"                 = 32
    "Microsoft-Windows-TaskScheduler/Operational"                    = 32
    "Microsoft-Windows-WMI-Activity/Operational"                     = 32
    "Microsoft-Windows-CodeIntegrity/Operational"                    = 32
    "Microsoft-Windows-AppLocker/EXE and DLL"                        = 32
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" = 32
    "Microsoft-Windows-Bits-Client/Operational"                      = 32
}

$SpecialtyChannels = @(
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-CodeIntegrity/Operational",
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-Bits-Client/Operational"
)

# -----------------------------
# Console helpers
# -----------------------------

function Write-Step {
    param([string]$Text)
    Write-Host "`n=== $Text ===" -ForegroundColor Cyan
}

function Write-OK {
    param([string]$Text)
    Write-Host "[OK] $Text" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Text)
    Write-Host "[WARN] $Text" -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Text)
    Write-Host "[INFO] $Text" -ForegroundColor Gray
}

function Test-IsAdministrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Directory {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Escape-XmlText {
    param([string]$Text)
    return [System.Security.SecurityElement]::Escape($Text)
}

function Get-WazuhDirectory {
    $candidates = @(
        "${env:ProgramFiles(x86)}\ossec-agent",
        "$env:ProgramFiles\ossec-agent"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    return ($candidates | Select-Object -First 1)
}

function Get-WazuhService {
    $svc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if (-not $svc) {
        $svc = Get-Service -Name "wazuh" -ErrorAction SilentlyContinue
    }
    if (-not $svc) {
        $svc = Get-Service -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -match "wazuh" -or $_.DisplayName -match "wazuh"
            } |
            Select-Object -First 1
    }
    return $svc
}

function Assert-ValidAuthenticodeSignature {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [string]$ExpectedSubjectContains
    )

    $sig = Get-AuthenticodeSignature -FilePath $Path

    if ($sig.Status -ne "Valid") {
        throw "Authenticode signature validation failed for '$Path'. Status: $($sig.Status)"
    }

    if ($ExpectedSubjectContains) {
        $subject = ""
        if ($sig.SignerCertificate) {
            $subject = [string]$sig.SignerCertificate.Subject
        }

        if ($subject -notmatch [regex]::Escape($ExpectedSubjectContains)) {
            throw "Unexpected signer for '$Path'. Signer: $subject"
        }
    }

    Write-OK "Valid Authenticode signature: $(Split-Path $Path -Leaf)"
}

# -----------------------------
# Prerequisite checks
# -----------------------------

if (-not (Test-IsAdministrator)) {
    throw "Run PowerShell as Administrator, then run this script again."
}

if ([Environment]::OSVersion.Version.Major -lt 10) {
    throw "This bootstrap is intended for Windows 10/11 or Windows Server equivalents."
}

try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

foreach ($dir in @($GscRoot,$TelemetryDir,$BackupDir,$SysmonDir,$HelperDir,$WorkDir)) {
    Ensure-Directory $dir
}

$report = New-Object System.Collections.Generic.List[string]
$report.Add("Granite Shield Cyber endpoint bootstrap v3")
$report.Add("Started: $(Get-Date -Format o)")
$report.Add("Computer: $env:COMPUTERNAME")
$report.Add("Agent name: $AgentName")
$report.Add("Manager: $ManagerAddress")
$report.Add("RebuildWazuh: $RebuildWazuh")
$report.Add("Manager event port: $ManagerPort")
$report.Add("Manager enrollment port: $RegistrationPort")
$report.Add("")

# -----------------------------
# Manager connectivity preflight
# -----------------------------

Write-Step "Checking Wazuh manager connectivity before making changes"

try {
    $eventPortReachable = Test-NetConnection `
        -ComputerName $ManagerAddress `
        -Port $ManagerPort `
        -InformationLevel Quiet `
        -WarningAction SilentlyContinue
}
catch {
    $eventPortReachable = $false
}

if ($eventPortReachable) {
    Write-OK "Manager event port reachable: $ManagerAddress`:$ManagerPort"
} else {
    throw "Cannot reach Wazuh manager at $ManagerAddress on TCP/$ManagerPort. No Wazuh uninstall/rebuild was attempted."
}

if ($RebuildWazuh) {
    try {
        $registrationPortReachable = Test-NetConnection `
            -ComputerName $ManagerAddress `
            -Port $RegistrationPort `
            -InformationLevel Quiet `
            -WarningAction SilentlyContinue
    }
    catch {
        $registrationPortReachable = $false
    }

    if ($registrationPortReachable) {
        Write-OK "Manager enrollment port reachable: $ManagerAddress`:$RegistrationPort"
    } else {
        throw "Rebuild requires enrollment access to $ManagerAddress on TCP/$RegistrationPort. Existing Wazuh was left installed."
    }
}

# -----------------------------
# Remove old GSC scheduled helpers
# -----------------------------

Write-Step "Normalizing Granite Shield helper tasks"

$oldTasks = @(
    "GraniteShield-RMM-Detection",
    "GraniteShield-LnkMetadata",
    "GraniteShield-BrowserAuditRefresh"
)

foreach ($taskName in $oldTasks) {
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
        Write-OK "Removed old task: $taskName"
    } catch {
        Write-Info "Task not present: $taskName"
    }
}

if ($RebuildWazuh) {
    # Keep the parent folder but remove helper/state artifacts so the rebuild is deterministic.
    foreach ($path in @($HelperDir,$SysmonDir,$TelemetryDir)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
        }
        Ensure-Directory $path
    }
}

# -----------------------------
# Wazuh uninstall/install
# -----------------------------

function Uninstall-ExistingWazuh {
    Write-Step "Removing existing Wazuh agent"

    $svc = Get-WazuhService
    $serviceWasRunning = $false

    try {
        if ($svc -and $svc.Status -ne "Stopped") {
            $serviceWasRunning = $true
            Stop-Service -Name $svc.Name -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            Write-OK "Stopped existing Wazuh service"
        }

        $uninstallEntries = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        # StrictMode-safe filtering: many Windows uninstall registry entries
        # legitimately do not contain a DisplayName property.
        $wazuhApp = @(
            Get-ItemProperty $uninstallEntries -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $displayNameProperty = $_.PSObject.Properties["DisplayName"]

                    if (
                        $displayNameProperty -and
                        [string]$displayNameProperty.Value -match "^Wazuh Agent"
                    ) {
                        $_
                    }
                }
        ) | Select-Object -First 1

        $productCode = $null

        if ($wazuhApp) {
            $uninstallProperty = $wazuhApp.PSObject.Properties["UninstallString"]

            if ($uninstallProperty) {
                $uninstallString = [string]$uninstallProperty.Value

                if ($uninstallString -match "\{[0-9A-Fa-f\-]+\}") {
                    $productCode = $matches[0]
                }
            }

            # MSI product codes are commonly also the uninstall registry key name.
            if (-not $productCode) {
                $childNameProperty = $wazuhApp.PSObject.Properties["PSChildName"]

                if (
                    $childNameProperty -and
                    [string]$childNameProperty.Value -match "^\{[0-9A-Fa-f\-]+\}$"
                ) {
                    $productCode = [string]$childNameProperty.Value
                }
            }
        }

        if ($productCode) {
            Write-Info "Found installed Wazuh MSI: $productCode"

            $proc = Start-Process `
                -FilePath "msiexec.exe" `
                -ArgumentList "/x $productCode /qn /norestart" `
                -Wait `
                -PassThru

            if ($proc.ExitCode -notin 0,1605,1614,3010) {
                throw "Wazuh uninstall failed with MSI exit code $($proc.ExitCode)."
            }

            Write-OK "Wazuh package uninstalled"
        }
        else {
            Write-Warn "No Wazuh MSI product code was found in the uninstall registry."

            # If a Wazuh service/install directory still exists, abort rather than
            # blindly deleting files and leaving a broken Windows service behind.
            $stillInstalled = (Get-WazuhService) -or (Get-WazuhDirectory)

            if ($stillInstalled) {
                throw "Wazuh still appears to be installed but its MSI product code could not be resolved. Aborting rebuild safely."
            }
        }

        Start-Sleep -Seconds 2

        foreach ($dir in @(
            "C:\Program Files (x86)\ossec-agent",
            "C:\Program Files\ossec-agent"
        )) {
            if (Test-Path -LiteralPath $dir) {
                Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue

                if (Test-Path -LiteralPath $dir) {
                    Write-Warn "Could not fully remove $dir"
                } else {
                    Write-OK "Removed $dir"
                }
            }
        }
    }
    catch {
        # If failure happened before MSI removal completed, make a best effort
        # to restore the old agent service so monitoring is not silently lost.
        $remainingWazuhDir = Get-WazuhDirectory
        $remainingSvc = Get-WazuhService

        if ($remainingWazuhDir -and $remainingSvc -and $remainingSvc.Status -ne "Running") {
            try {
                Start-Service -Name $remainingSvc.Name -ErrorAction Stop
                Start-Sleep -Seconds 2
                Write-Warn "Rebuild failed before removal completed; existing Wazuh service was restarted."
            }
            catch {
                Write-Warn "Rebuild failed and the existing Wazuh service could not be restarted automatically."
            }
        }

        throw
    }
}

function Install-WazuhAgent {
    Write-Step "Installing Wazuh agent"

    $msiName     = "wazuh-agent-$WazuhVersion.msi"
    $msiPath     = Join-Path $WorkDir $msiName
    $downloadUrl = "https://packages.wazuh.com/4.x/windows/$msiName"

    Invoke-WebRequest `
        -Uri $downloadUrl `
        -OutFile $msiPath `
        -UseBasicParsing

    if (-not (Test-Path -LiteralPath $msiPath)) {
        throw "Wazuh MSI download failed."
    }

    Assert-ValidAuthenticodeSignature -Path $msiPath

    $args = @(
        "/i"
        "`"$msiPath`""
        "/qn"
        "/norestart"
        "WAZUH_MANAGER=`"$ManagerAddress`""
        "WAZUH_MANAGER_PORT=`"$ManagerPort`""
        "WAZUH_REGISTRATION_SERVER=`"$ManagerAddress`""
        "WAZUH_REGISTRATION_PORT=`"$RegistrationPort`""
        "WAZUH_AGENT_NAME=`"$AgentName`""
    )

    $proc = Start-Process `
        -FilePath "msiexec.exe" `
        -ArgumentList $args `
        -Wait `
        -PassThru

    if ($proc.ExitCode -notin 0,3010) {
        throw "Wazuh install failed with MSI exit code $($proc.ExitCode)."
    }

    $svc = Get-WazuhService
    if (-not $svc) {
        throw "Wazuh installed but its Windows service could not be found."
    }

    if ($svc.Status -ne "Running") {
        Start-Service -Name $svc.Name
        Start-Sleep -Seconds 4
    }

    Write-OK "Wazuh agent installed"
}

$existingWazuh = Get-WazuhDirectory

if ($RebuildWazuh) {
    Uninstall-ExistingWazuh
    Install-WazuhAgent
} elseif (-not $existingWazuh) {
    Install-WazuhAgent
} else {
    Write-Step "Wazuh agent already installed"
    Write-OK "Using existing installation: $existingWazuh"
}

$WazuhDir = Get-WazuhDirectory
if (-not $WazuhDir) {
    throw "Wazuh installation directory could not be found."
}

$WazuhConf = Join-Path $WazuhDir "ossec.conf"
$WazuhLog  = Join-Path $WazuhDir "ossec.log"

if (-not (Test-Path -LiteralPath $WazuhConf)) {
    throw "Wazuh configuration is missing: $WazuhConf"
}

# -----------------------------
# Windows audit policy
# -----------------------------

Write-Step "Configuring Windows security auditing"

$AuditSubcategories = @(
    @{ Name = "Process Creation";           Success = $true; Failure = $false },
    @{ Name = "Logon";                      Success = $true; Failure = $true  },
    @{ Name = "Special Logon";              Success = $true; Failure = $false },
    @{ Name = "Account Lockout";            Success = $true; Failure = $true  },
    @{ Name = "Credential Validation";      Success = $true; Failure = $true  },
    @{ Name = "Audit Policy Change";        Success = $true; Failure = $true  },
    @{ Name = "Other Object Access Events"; Success = $true; Failure = $true  },
    @{ Name = "File System";                Success = $true; Failure = $false },
    @{ Name = "User Account Management";    Success = $true; Failure = $true  },
    @{ Name = "Security Group Management";  Success = $true; Failure = $true  }
)

foreach ($item in $AuditSubcategories) {
    $successArg = if ($item.Success) { "/success:enable" } else { "/success:disable" }
    $failureArg = if ($item.Failure) { "/failure:enable" } else { "/failure:disable" }

    & auditpol.exe /set /subcategory:"$($item.Name)" $successArg $failureArg | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-OK "Audit policy: $($item.Name)"
    } else {
        Write-Warn "Could not configure audit subcategory: $($item.Name)"
    }
}

# Include command line in Windows Security 4688 events.
$procAuditKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $procAuditKey -Force | Out-Null
New-ItemProperty `
    -Path $procAuditKey `
    -Name "ProcessCreationIncludeCmdLine_Enabled" `
    -PropertyType DWord `
    -Value 1 `
    -Force | Out-Null

Write-OK "Process command-line capture enabled"

# -----------------------------
# PowerShell telemetry
# -----------------------------

Write-Step "Configuring PowerShell telemetry"

$scriptBlockKey = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $scriptBlockKey -Force | Out-Null
New-ItemProperty `
    -Path $scriptBlockKey `
    -Name "EnableScriptBlockLogging" `
    -PropertyType DWord `
    -Value 1 `
    -Force | Out-Null

$moduleKey = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $moduleKey -Force | Out-Null
New-ItemProperty `
    -Path $moduleKey `
    -Name "EnableModuleLogging" `
    -PropertyType DWord `
    -Value 1 `
    -Force | Out-Null

$moduleNamesKey = Join-Path $moduleKey "ModuleNames"
New-Item -Path $moduleNamesKey -Force | Out-Null
New-ItemProperty `
    -Path $moduleNamesKey `
    -Name "*" `
    -PropertyType String `
    -Value "*" `
    -Force | Out-Null

Write-OK "PowerShell Script Block Logging enabled"
Write-OK "PowerShell Module Logging enabled"
Write-Warn "PowerShell telemetry can contain sensitive command/script content."

# -----------------------------
# Sysmon baseline
# -----------------------------

Write-Step "Installing/updating Sysmon baseline"

Ensure-Directory $SysmonDir

$sysmonZip    = Join-Path $SysmonDir "Sysmon.zip"
$sysmonBinDir = Join-Path $SysmonDir "bin"
$sysmonConfig = Join-Path $SysmonDir "sysmon-gsc.xml"

$sysmonXml = @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256,IMPHASH</HashAlgorithms>
  <CheckRevocation />
  <EventFiltering>

    <!-- Event 1: process creation -->
    <ProcessCreate onmatch="exclude" />

    <!-- Event 3: network connections, with obvious high-volume user apps excluded -->
    <NetworkConnect onmatch="exclude">
      <Image condition="end with">\chrome.exe</Image>
      <Image condition="end with">\msedge.exe</Image>
      <Image condition="end with">\firefox.exe</Image>
      <Image condition="end with">\OneDrive.exe</Image>
      <Image condition="end with">\Teams.exe</Image>
      <Image condition="end with">\ms-teams.exe</Image>
    </NetworkConnect>

    <!-- Event 6: non-Microsoft / unusual driver loads -->
    <DriverLoad onmatch="exclude">
      <Signature condition="contains">Microsoft Windows</Signature>
      <Signature condition="contains">Microsoft Corporation</Signature>
    </DriverLoad>

    <!-- Event 8: cross-process remote thread creation -->
    <CreateRemoteThread onmatch="exclude" />

    <!-- Event 9: raw disk reads -->
    <RawAccessRead onmatch="exclude" />

    <!-- Event 10: targeted LSASS access -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="end with">\lsass.exe</TargetImage>
    </ProcessAccess>

    <!-- Event 11: high-value file creation -->
    <FileCreate onmatch="include">
      <TargetFilename condition="end with">.exe</TargetFilename>
      <TargetFilename condition="end with">.dll</TargetFilename>
      <TargetFilename condition="end with">.scr</TargetFilename>
      <TargetFilename condition="end with">.com</TargetFilename>
      <TargetFilename condition="end with">.ps1</TargetFilename>
      <TargetFilename condition="end with">.psm1</TargetFilename>
      <TargetFilename condition="end with">.bat</TargetFilename>
      <TargetFilename condition="end with">.cmd</TargetFilename>
      <TargetFilename condition="end with">.vbs</TargetFilename>
      <TargetFilename condition="end with">.js</TargetFilename>
      <TargetFilename condition="end with">.jse</TargetFilename>
      <TargetFilename condition="end with">.hta</TargetFilename>
      <TargetFilename condition="end with">.lnk</TargetFilename>
      <TargetFilename condition="contains">\Startup\</TargetFilename>
    </FileCreate>

    <!-- Events 12-14: registry persistence/security-sensitive changes -->
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
      <TargetObject condition="contains">\CurrentVersion\RunOnce</TargetObject>
      <TargetObject condition="contains">\Policies\Explorer\Run</TargetObject>
      <TargetObject condition="contains">\Winlogon\Shell</TargetObject>
      <TargetObject condition="contains">\Winlogon\Userinit</TargetObject>
      <TargetObject condition="contains">\Image File Execution Options\</TargetObject>
      <TargetObject condition="contains">\SilentProcessExit\</TargetObject>
      <TargetObject condition="contains">\AppInit_DLLs</TargetObject>
      <TargetObject condition="contains">\AppCertDlls</TargetObject>
      <TargetObject condition="contains">\SYSTEM\CurrentControlSet\Services\</TargetObject>
    </RegistryEvent>

    <!-- Event 15: alternate data stream creation -->
    <FileCreateStreamHash onmatch="exclude" />

    <!-- Events 17-18: named pipe creation/connect -->
    <PipeEvent onmatch="exclude" />

    <!-- Events 19-21: WMI persistence -->
    <WmiEvent onmatch="exclude" />

    <!-- Event 22: DNS, excluding common browsers/sync clients -->
    <DnsQuery onmatch="exclude">
      <Image condition="end with">\chrome.exe</Image>
      <Image condition="end with">\msedge.exe</Image>
      <Image condition="end with">\firefox.exe</Image>
      <Image condition="end with">\OneDrive.exe</Image>
      <Image condition="end with">\Teams.exe</Image>
      <Image condition="end with">\ms-teams.exe</Image>
    </DnsQuery>

    <!-- Event 26: log file deletion without Sysmon's archive/copy-on-delete behavior -->
    <FileDeleteDetected onmatch="include">
      <TargetFilename condition="begin with">C:\Users\</TargetFilename>
      <TargetFilename condition="begin with">C:\ProgramData\</TargetFilename>
      <TargetFilename condition="begin with">C:\Windows\Temp\</TargetFilename>
    </FileDeleteDetected>

    <!-- Event 25: process tampering / hollowing-like behavior -->
    <ProcessTampering onmatch="exclude" />

    <!-- Event 29: executable-file creation telemetry -->
    <FileExecutableDetected onmatch="exclude" />

  </EventFiltering>
</Sysmon>
'@

Set-Content -LiteralPath $sysmonConfig -Value $sysmonXml -Encoding UTF8

Invoke-WebRequest `
    -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
    -OutFile $sysmonZip `
    -UseBasicParsing

if (Test-Path -LiteralPath $sysmonBinDir) {
    Remove-Item -LiteralPath $sysmonBinDir -Recurse -Force
}
Expand-Archive -LiteralPath $sysmonZip -DestinationPath $sysmonBinDir -Force

$sysmonExe = Join-Path $sysmonBinDir "Sysmon64.exe"
if (-not (Test-Path -LiteralPath $sysmonExe)) {
    $sysmonExe = Join-Path $sysmonBinDir "Sysmon.exe"
}
if (-not (Test-Path -LiteralPath $sysmonExe)) {
    throw "Sysmon executable was not found after extracting Microsoft's package."
}

Assert-ValidAuthenticodeSignature `
    -Path $sysmonExe `
    -ExpectedSubjectContains "Microsoft"

$existingSysmon = Get-Service -Name "Sysmon64","Sysmon" -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($existingSysmon) {
    & $sysmonExe -accepteula -c $sysmonConfig | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Sysmon configuration update failed with exit code $LASTEXITCODE."
    }
    Write-OK "Existing Sysmon installation replaced with GSC telemetry baseline"
} else {
    & $sysmonExe -accepteula -i $sysmonConfig | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Sysmon installation failed with exit code $LASTEXITCODE."
    }
    Write-OK "Sysmon installed with GSC telemetry baseline"
}

# -----------------------------
# Enable/cap event channels
# -----------------------------

function Set-EventChannelCircular {
    param(
        [Parameter(Mandatory=$true)][string]$Channel,
        [Parameter(Mandatory=$true)][int]$MaxSizeMB
    )

    try {
        # Enable operational/application channels when possible.
        if ($Channel -notin @("Security","System","Application")) {
            & wevtutil.exe sl "$Channel" /e:true 2>$null
        }

        $cfg = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($Channel)
        $cfg.MaximumSizeInBytes = [int64]$MaxSizeMB * 1MB
        $cfg.LogMode = [System.Diagnostics.Eventing.Reader.EventLogMode]::Circular
        $cfg.SaveChanges()
        $cfg.Dispose()

        Write-OK "$Channel -> circular, max ${MaxSizeMB}MB"
        return $true
    }
    catch {
        Write-Warn "Could not configure event channel '$Channel': $($_.Exception.Message)"
        return $false
    }
}

Write-Step "Configuring bounded circular Windows event logs"

$ConfiguredChannels = New-Object System.Collections.Generic.List[string]

foreach ($kv in $EventChannelCapsMB.GetEnumerator()) {
    if (Set-EventChannelCircular -Channel $kv.Key -MaxSizeMB $kv.Value) {
        $ConfiguredChannels.Add($kv.Key)
    }
}

Write-Info "No Windows event log was cleared."
Write-Info "Oldest local entries will be overwritten automatically when each cap is reached."

# Discover native Bitdefender channels and cap them too.
try {
    $bitdefenderChannels = @(
        Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
            Where-Object {
                $_.LogName -match "(?i)bitdefender" -and $_.IsEnabled
            } |
            Select-Object -ExpandProperty LogName -Unique
    )

    foreach ($channel in $bitdefenderChannels) {
        if (Set-EventChannelCircular -Channel $channel -MaxSizeMB 32) {
            if (-not $ConfiguredChannels.Contains($channel)) {
                $ConfiguredChannels.Add($channel)
            }
        }
    }
}
catch {
    $bitdefenderChannels = @()
}

# -----------------------------
# Browser credential DB audit
# -----------------------------

$browserAuditHelper = Join-Path $HelperDir "Refresh-BrowserCredentialAudit.ps1"

$browserAuditScript = @'
$ErrorActionPreference = "Stop"

$script:AuditedFiles = 0

function Add-GscReadAudit {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }

    try {
        $everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            $everyone,
            [System.Security.AccessControl.FileSystemRights]::ReadData,
            [System.Security.AccessControl.AuditFlags]::Success
        )

        $acl = Get-Acl -LiteralPath $Path -Audit

        $exists = $false
        foreach ($entry in $acl.Audit) {
            if (
                $entry.IdentityReference -eq $everyone -and
                ($entry.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadData)
            ) {
                $exists = $true
                break
            }
        }

        if (-not $exists) {
            [void]$acl.AddAuditRule($rule)
            Set-Acl -LiteralPath $Path -AclObject $acl
        }

        $script:AuditedFiles++
    }
    catch {
        # Best effort for an individual browser database. Locked/replaced
        # databases will be retried on the next scheduled refresh.
    }
}

$patterns = New-Object System.Collections.Generic.List[string]

$profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -notin @("Public","Default","Default User","All Users")
    }

try {
    foreach ($profile in $profiles) {
        $roots = @(
            (Join-Path -Path $profile.FullName -ChildPath "AppData\Local\Google\Chrome\User Data")
            (Join-Path -Path $profile.FullName -ChildPath "AppData\Local\Microsoft\Edge\User Data")
        )

        foreach ($root in $roots) {
            if (-not (Test-Path -LiteralPath $root)) {
                continue
            }

            foreach ($pattern in @(
                "*\Login Data",
                "*\Cookies",
                "*\Network\Cookies",
                "*\Web Data",
                "Local State"
            )) {
                Get-ChildItem -Path (Join-Path -Path $root -ChildPath $pattern) -File -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        Add-GscReadAudit -Path $_.FullName
                    }
            }
        }
    }

    Write-Output "GSC browser credential audit refresh complete. Audited files: $script:AuditedFiles"
    exit 0
}
catch {
    Write-Error "GSC browser credential audit refresh failed: $($_.Exception.Message)"
    exit 1
}
'@

if (-not $SkipBrowserCredentialAuditing) {
    Write-Step "Configuring targeted browser credential-database auditing"

    Set-Content `
        -LiteralPath $browserAuditHelper `
        -Value $browserAuditScript `
        -Encoding UTF8

    # Initial application. Fail the bootstrap step if the helper itself fails.
    $browserProc = Start-Process `
        -FilePath "powershell.exe" `
        -ArgumentList @(
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-File", "`"$browserAuditHelper`""
        ) `
        -Wait `
        -PassThru `
        -NoNewWindow

    if ($browserProc.ExitCode -ne 0) {
        throw "Browser credential-database audit helper failed with exit code $($browserProc.ExitCode)."
    }

    $browserAction = New-ScheduledTaskAction `
        -Execute "PowerShell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$browserAuditHelper`""

    $browserTriggers = @(
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger `
            -Once `
            -At ((Get-Date).AddHours(6)) `
            -RepetitionInterval (New-TimeSpan -Hours 6) `
            -RepetitionDuration (New-TimeSpan -Days 3650))
    )

    $browserPrincipal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    $browserSettings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries

    Register-ScheduledTask `
        -TaskName "GraniteShield-BrowserAuditRefresh" `
        -Action $browserAction `
        -Trigger $browserTriggers `
        -Principal $browserPrincipal `
        -Settings $browserSettings `
        -Description "Refresh targeted audit SACLs on Chrome/Edge credential databases." `
        -Force | Out-Null

    $auditTask = Get-ScheduledTask -TaskName "GraniteShield-BrowserAuditRefresh" -ErrorAction SilentlyContinue

    if (-not $auditTask) {
        throw "Browser audit refresh task was not created."
    }

    Write-OK "Targeted browser Login Data/Cookies/Web Data read auditing enabled"
    Write-OK "Browser audit refresh task installed"
    Write-Warn "Expected browsers will also generate some 4663 reads; correlate with process name."
} else {
    Write-Warn "Browser credential-database auditing skipped by parameter."
}

# -----------------------------
# LNK metadata collector
# -----------------------------

$lnkHelper = Join-Path $HelperDir "Collect-LnkMetadata.ps1"

$lnkCollectorScript = @'
param([switch]$InitializeOnly)

$ErrorActionPreference = "Continue"

$RootDir  = "C:\ProgramData\GraniteShield\Telemetry"
$LogFile  = Join-Path $RootDir "lnk-metadata.log"
$StateFile = Join-Path $RootDir "lnk-state.json"

New-Item -ItemType Directory -Path $RootDir -Force | Out-Null

$state = @{}

if (Test-Path -LiteralPath $StateFile) {
    try {
        $obj = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
        foreach ($p in $obj.PSObject.Properties) {
            $state[$p.Name] = [string]$p.Value
        }
    } catch {
        $state = @{}
    }
}

$roots = New-Object System.Collections.Generic.List[string]

$profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -notin @("Public","Default","Default User","All Users")
    }

foreach ($profile in $profiles) {
    foreach ($relative in @(
        "Desktop",
        "Downloads",
        "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    )) {
        $p = Join-Path $profile.FullName $relative
        if (Test-Path -LiteralPath $p) {
            $roots.Add($p)
        }
    }
}

$commonStartup = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path -LiteralPath $commonStartup) {
    $roots.Add($commonStartup)
}

$shell = New-Object -ComObject WScript.Shell

foreach ($root in ($roots | Select-Object -Unique)) {
    Get-ChildItem -LiteralPath $root -Filter "*.lnk" -File -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object {
            $file = $_
            $key  = $file.FullName.ToLowerInvariant()
            $fingerprint = "$($file.LastWriteTimeUtc.Ticks):$($file.Length)"

            if ($state.ContainsKey($key) -and $state[$key] -eq $fingerprint) {
                return
            }

            $state[$key] = $fingerprint

            if ($InitializeOnly) {
                return
            }

            try {
                $shortcut = $shell.CreateShortcut($file.FullName)
                $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
                $owner = ""
                try {
                    $owner = (Get-Acl -LiteralPath $file.FullName).Owner
                } catch {}

                $record = [ordered]@{
                    timestampUtc     = (Get-Date).ToUniversalTime().ToString("o")
                    eventType        = "gsc_lnk_metadata"
                    path             = $file.FullName
                    size             = $file.Length
                    sha256           = $hash
                    owner            = $owner
                    targetPath       = $shortcut.TargetPath
                    arguments        = $shortcut.Arguments
                    workingDirectory = $shortcut.WorkingDirectory
                    iconLocation     = $shortcut.IconLocation
                    hotkey           = $shortcut.Hotkey
                    description      = $shortcut.Description
                }

                Add-Content `
                    -LiteralPath $LogFile `
                    -Value ($record | ConvertTo-Json -Compress) `
                    -Encoding UTF8
            }
            catch {}
        }
}

$state | ConvertTo-Json -Compress | Set-Content -LiteralPath $StateFile -Encoding UTF8

# Hard local cap. This file should normally stay tiny.
if ((Test-Path -LiteralPath $LogFile) -and ((Get-Item $LogFile).Length -gt 20MB)) {
    try {
        $tail = Get-Content -LiteralPath $LogFile -Tail 5000
        $tail | Set-Content -LiteralPath $LogFile -Encoding UTF8
    } catch {}
}
'@

if (-not $SkipLnkMetadata) {
    Write-Step "Installing LNK metadata enrichment"

    Set-Content `
        -LiteralPath $lnkHelper `
        -Value $lnkCollectorScript `
        -Encoding UTF8

    if (-not (Test-Path -LiteralPath $LnkLog)) {
        New-Item -ItemType File -Path $LnkLog -Force | Out-Null
    }

    # Baseline existing shortcuts without flooding Wazuh with old entries.
    & powershell.exe `
        -NoProfile `
        -NonInteractive `
        -ExecutionPolicy Bypass `
        -File $lnkHelper `
        -InitializeOnly

    $lnkAction = New-ScheduledTaskAction `
        -Execute "PowerShell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$lnkHelper`""

    $lnkTrigger = New-ScheduledTaskTrigger `
        -Once `
        -At ((Get-Date).AddMinutes(2)) `
        -RepetitionInterval (New-TimeSpan -Minutes 2) `
        -RepetitionDuration (New-TimeSpan -Days 3650)

    $lnkPrincipal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    $lnkSettings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries

    Register-ScheduledTask `
        -TaskName "GraniteShield-LnkMetadata" `
        -Action $lnkAction `
        -Trigger $lnkTrigger `
        -Principal $lnkPrincipal `
        -Settings $lnkSettings `
        -Description "Extract target/arguments/hash metadata from newly written Windows LNK files." `
        -Force | Out-Null

    Write-OK "LNK metadata collector installed"
} else {
    Write-Warn "LNK metadata enrichment skipped by parameter."
}

# -----------------------------
# Build targeted Wazuh FIM paths
# -----------------------------

Write-Step "Building targeted file telemetry paths"

$profiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -notin @("Public","Default","Default User","All Users")
    }

$ScriptCaptureDirs = New-Object System.Collections.Generic.List[string]
$RansomwareDirs    = New-Object System.Collections.Generic.List[string]

foreach ($profile in $profiles) {
    foreach ($relative in @(
        "Downloads",
        "Desktop",
        "AppData\Local\Temp",
        "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    )) {
        $p = Join-Path $profile.FullName $relative
        if (Test-Path -LiteralPath $p) {
            $ScriptCaptureDirs.Add($p)
        }
    }

    foreach ($relative in @(
        "Documents",
        "Pictures",
        "OneDrive"
    )) {
        $p = Join-Path $profile.FullName $relative
        if (Test-Path -LiteralPath $p) {
            $RansomwareDirs.Add($p)
        }
    }
}

foreach ($p in @(
    "C:\Windows\Temp",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)) {
    if (Test-Path -LiteralPath $p) {
        $ScriptCaptureDirs.Add($p)
    }
}

$ScriptCaptureDirs = @($ScriptCaptureDirs | Select-Object -Unique)
$RansomwareDirs    = @($RansomwareDirs | Select-Object -Unique)

Write-Info "Script-content directories: $($ScriptCaptureDirs.Count)"
Write-Info "Ransomware/FIM directories: $($RansomwareDirs.Count)"

# -----------------------------
# Wazuh ossec.conf managed config
# -----------------------------

Write-Step "Creating managed Wazuh telemetry configuration"

$originalConf = Get-Content -LiteralPath $WazuhConf -Raw

# Remove only content previously managed by THIS bootstrap.
$confText = [regex]::Replace(
    $originalConf,
    '(?s)\s*<!-- GSC BEGIN SYSCHECK -->.*?<!-- GSC END SYSCHECK -->\s*',
    "`r`n"
)

$confText = [regex]::Replace(
    $confText,
    '(?s)\s*<!-- GSC BEGIN LOCALFILES -->.*?<!-- GSC END LOCALFILES -->\s*',
    "`r`n"
)

$syscheckLines = New-Object System.Collections.Generic.List[string]
$syscheckLines.Add("    <!-- GSC BEGIN SYSCHECK -->")

if (-not $SkipScriptContentCapture) {
    foreach ($dir in $ScriptCaptureDirs) {
        $escaped = Escape-XmlText $dir
        $syscheckLines.Add(
            "    <directories check_all=`"yes`" whodata=`"yes`" report_changes=`"yes`" diff_size_limit=`"256KB`" restrict=`"$ScriptRegex`">$escaped</directories>"
        )
    }

    Write-OK "Small script/source content capture enabled (max 256KB per file)"
} else {
    Write-Warn "Small script/source content capture skipped by parameter."
}

# Ransomware-targeted documents: hashes/metadata only; no content diff.
foreach ($dir in $RansomwareDirs) {
    $escaped = Escape-XmlText $dir
    $syscheckLines.Add(
        "    <directories realtime=`"yes`" check_all=`"yes`" report_changes=`"no`" restrict=`"$RansomwareRegex`">$escaped</directories>"
    )
}

# Bound Wazuh's local report_changes working cache.
$syscheckLines.Add("    <diff>")
$syscheckLines.Add("      <disk_quota>")
$syscheckLines.Add("        <enabled>yes</enabled>")
$syscheckLines.Add("        <limit>64MB</limit>")
$syscheckLines.Add("      </disk_quota>")
$syscheckLines.Add("      <file_size>")
$syscheckLines.Add("        <enabled>yes</enabled>")
$syscheckLines.Add("        <limit>256KB</limit>")
$syscheckLines.Add("      </file_size>")
$syscheckLines.Add("    </diff>")
$syscheckLines.Add("    <!-- GSC END SYSCHECK -->")

$syscheckFragment = ($syscheckLines -join "`r`n") + "`r`n"

# If the existing syscheck already has a diff block, remove it so our bounded one
# is authoritative. This bootstrap intentionally normalizes the endpoint.
$confText = [regex]::Replace(
    $confText,
    '(?s)<diff>\s*<disk_quota>.*?</diff>',
    ''
)

$syscheckCloseIndex = $confText.IndexOf("</syscheck>", [System.StringComparison]::OrdinalIgnoreCase)

if ($syscheckCloseIndex -ge 0) {
    $confText = $confText.Insert($syscheckCloseIndex, $syscheckFragment)
} else {
    $newSyscheck = @"
  <syscheck>
    <disabled>no</disabled>
    <frequency>21600</frequency>
    <scan_on_start>yes</scan_on_start>
$syscheckFragment  </syscheck>

"@
    $lastClose = $confText.LastIndexOf("</ossec_config>", [System.StringComparison]::OrdinalIgnoreCase)
    if ($lastClose -lt 0) {
        throw "Could not locate </ossec_config> in Wazuh configuration."
    }
    $confText = $confText.Insert($lastClose, $newSyscheck)
}

# Build specialty eventchannel collection without duplicating existing blocks.
$localfileLines = New-Object System.Collections.Generic.List[string]
$localfileLines.Add("  <!-- GSC BEGIN LOCALFILES -->")

$channelsToCollect = New-Object System.Collections.Generic.List[string]

foreach ($channel in $SpecialtyChannels) {
    try {
        $info = Get-WinEvent -ListLog $channel -ErrorAction Stop
        if ($info.IsEnabled) {
            $channelsToCollect.Add($channel)
        }
    } catch {}
}

foreach ($channel in $bitdefenderChannels) {
    if (-not $channelsToCollect.Contains($channel)) {
        $channelsToCollect.Add($channel)
    }
}

foreach ($channel in ($channelsToCollect | Select-Object -Unique)) {
    $needle = "<location>$channel</location>"

    if ($confText.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        Write-Info "Already collected by Wazuh: $channel"
        continue
    }

    $escapedChannel = Escape-XmlText $channel

    $localfileLines.Add("  <localfile>")
    $localfileLines.Add("    <location>$escapedChannel</location>")
    $localfileLines.Add("    <log_format>eventchannel</log_format>")
    $localfileLines.Add("    <only-future-events>yes</only-future-events>")
    $localfileLines.Add("  </localfile>")
}

if (-not $SkipLnkMetadata) {
    $escapedLnkLog = Escape-XmlText $LnkLog

    if ($confText.IndexOf("<location>$LnkLog</location>", [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        $localfileLines.Add("  <localfile>")
        $localfileLines.Add("    <location>$escapedLnkLog</location>")
        $localfileLines.Add("    <log_format>syslog</log_format>")
        $localfileLines.Add("    <only-future-events>yes</only-future-events>")
        $localfileLines.Add("  </localfile>")
    }
}

$localfileLines.Add("  <!-- GSC END LOCALFILES -->")

$localfileFragment = ($localfileLines -join "`r`n") + "`r`n"

$lastClose = $confText.LastIndexOf("</ossec_config>", [System.StringComparison]::OrdinalIgnoreCase)
if ($lastClose -lt 0) {
    throw "Could not locate the final </ossec_config> element."
}
$confText = $confText.Insert($lastClose, $localfileFragment)

# -----------------------------
# Activate candidate safely
# -----------------------------

Write-Step "Validating and activating Wazuh configuration"

$stamp  = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = Join-Path $BackupDir "ossec.conf.$stamp.bak"
Copy-Item -LiteralPath $WazuhConf -Destination $backup -Force

$candidate = Join-Path $BackupDir "ossec.conf.$stamp.candidate"
Set-Content -LiteralPath $candidate -Value $confText -Encoding UTF8

$wazuhSvc = Get-WazuhService
if (-not $wazuhSvc) {
    throw "Wazuh service could not be found before config activation."
}

if ($wazuhSvc.Status -ne "Stopped") {
    Stop-Service -Name $wazuhSvc.Name -Force
    Start-Sleep -Seconds 2
}

Copy-Item -LiteralPath $candidate -Destination $WazuhConf -Force

function Test-WazuhComponentConfig {
    param([string]$ExeName)

    $exe = Join-Path $WazuhDir $ExeName
    if (-not (Test-Path -LiteralPath $exe)) {
        return
    }

    $p = Start-Process `
        -FilePath $exe `
        -ArgumentList "-t" `
        -Wait `
        -PassThru `
        -WindowStyle Hidden

    if ($p.ExitCode -ne 0) {
        throw "$ExeName configuration test failed with exit code $($p.ExitCode)."
    }

    Write-OK "$ExeName -t passed"
}

try {
    foreach ($exe in @(
        "wazuh-agentd.exe",
        "wazuh-logcollector.exe",
        "wazuh-syscheckd.exe"
    )) {
        Test-WazuhComponentConfig -ExeName $exe
    }

    Start-Service -Name $wazuhSvc.Name
    Start-Sleep -Seconds 6

    $wazuhSvc = Get-Service -Name $wazuhSvc.Name
    if ($wazuhSvc.Status -ne "Running") {
        throw "Wazuh service status is $($wazuhSvc.Status)."
    }

    Write-OK "Wazuh service is running with the new configuration"
}
catch {
    Write-Warn "Wazuh configuration did not validate/recover. Rolling back."

    Stop-Service -Name $wazuhSvc.Name -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $backup -Destination $WazuhConf -Force

    try {
        Start-Service -Name $wazuhSvc.Name
        Start-Sleep -Seconds 4
    } catch {}

    throw "New Wazuh configuration was rolled back automatically. Original error: $($_.Exception.Message)"
}

# -----------------------------
# Validation
# -----------------------------

Write-Step "Validating telemetry services"

$sysmonSvc = Get-Service -Name "Sysmon64","Sysmon" -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($sysmonSvc -and $sysmonSvc.Status -eq "Running") {
    Write-OK "Sysmon is running"
} elseif ($sysmonSvc) {
    Write-Warn "Sysmon exists but status is $($sysmonSvc.Status)"
} else {
    Write-Warn "Sysmon service was not found"
}

$wazuhSvc = Get-WazuhService
if ($wazuhSvc -and $wazuhSvc.Status -eq "Running") {
    Write-OK "Wazuh agent is running"
}

$conn = Get-NetTCPConnection `
    -RemotePort $ManagerPort `
    -State Established `
    -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($conn) {
    Write-OK "Wazuh has an established TCP/$ManagerPort connection to $($conn.RemoteAddress)"
} else {
    Write-Warn "No established Wazuh TCP/$ManagerPort connection is visible yet."
    Write-Info "Fresh enrollment can take a short time."
}

# Confirm critical Sysmon event channel.
try {
    $sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop
    if ($sysmonLog.IsEnabled) {
        Write-OK "Sysmon Operational event channel enabled"
    }
} catch {
    Write-Warn "Sysmon Operational event channel validation failed"
}

# -----------------------------
# Report
# -----------------------------

$report.Add("Completed: $(Get-Date -Format o)")
$report.Add("")
$report.Add("Wazuh directory: $WazuhDir")
$report.Add("Wazuh config backup: $backup")
$report.Add("Sysmon config: $sysmonConfig")
$report.Add("Script content capture skipped: $SkipScriptContentCapture")
$report.Add("Browser credential auditing skipped: $SkipBrowserCredentialAuditing")
$report.Add("LNK metadata skipped: $SkipLnkMetadata")
$report.Add("")
$report.Add("Local log design:")
$report.Add("  Windows EVTX channels are circular/bounded.")
$report.Add("  No Windows event log was cleared.")
$report.Add("  Wazuh report_changes local diff cache is capped at 64MB.")
$report.Add("  Individual text diff/content capture is capped at 256KB.")
$report.Add("  LNK metadata log is capped by helper logic.")
$report.Add("")
$report.Add("Telemetry coverage:")
$report.Add("  Sysmon 1   Process creation")
$report.Add("  Sysmon 3   Network connections")
$report.Add("  Sysmon 6   Driver loads")
$report.Add("  Sysmon 8   CreateRemoteThread")
$report.Add("  Sysmon 9   RawAccessRead")
$report.Add("  Sysmon 10  LSASS ProcessAccess")
$report.Add("  Sysmon 11  High-value file creation")
$report.Add("  Sysmon 12-14 persistence registry")
$report.Add("  Sysmon 15  Alternate data streams")
$report.Add("  Sysmon 17-18 named pipes")
$report.Add("  Sysmon 19-21 WMI persistence")
$report.Add("  Sysmon 22  DNS")
$report.Add("  Sysmon 25  Process tampering")
$report.Add("  Sysmon 26  File deletion (no archive)")
$report.Add("  Sysmon 29  Executable file creation")
$report.Add("  Windows Security process/logon/account/audit events")
$report.Add("  PowerShell Script Block + Module Logging")
$report.Add("  Defender / Task Scheduler / WMI / Code Integrity / RDP / BITS")
$report.Add("  Targeted browser credential DB read auditing")
$report.Add("  Wazuh FIM script content + ransomware-targeted files")
$report.Add("  LNK target/arguments/hash metadata")

$report | Set-Content -LiteralPath $InstallReport -Encoding UTF8

Write-Step "Bootstrap complete"

Write-Host ""
Write-Host "WAZUH / ENDPOINT TELEMETRY BASELINE APPLIED" -ForegroundColor Green
Write-Host ""
Write-Host "Manager:        $ManagerAddress"
Write-Host "Agent name:     $AgentName"
Write-Host "Wazuh backup:   $backup"
Write-Host "Install report: $InstallReport"
Write-Host ""
Write-Host "No Windows Event Log was cleared." -ForegroundColor Green
Write-Host "Local EVTX logs are bounded circular buffers." -ForegroundColor Green
Write-Host ""
Write-Host "IMPORTANT:" -ForegroundColor Yellow
Write-Host "  If this was a Wazuh rebuild and enrollment reports a duplicate agent name,"
Write-Host "  remove the stale agent entry in Wazuh and rerun this script."
Write-Host ""
Write-Host "Recommended next test:"
Write-Host "  .\Invoke-GSC-EDRTests.ps1 -Test LSASS,WMI,FileDelete,Ransomware"
Write-Host ""
