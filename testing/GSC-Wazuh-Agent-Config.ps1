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
    - Validate the selected antivirus and collect its malware detections.
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
  .\GSC-Wazuh-Agent-Config.ps1

.EXAMPLE
  # Bitdefender Total Security endpoint with rich incident collection:
  .\GSC-Wazuh-Agent-Config.ps1 -av Bitdefender

.EXAMPLE
  # Full Wazuh wipe/reinstall test on an already-configured endpoint:
  .\GSC-Wazuh-Agent-Config.ps1 `
      -ManagerAddress "analytics.example.com" `
      -RebuildWazuh

.EXAMPLE
  # Custom endpoint name:
  .\GSC-Wazuh-Agent-Config.ps1 `
      -ManagerAddress "10.10.10.10" `
      -AgentName "CLIENT-PC-01" `
      -RebuildWazuh

.NOTES
  Run from Windows PowerShell 5.1 or later as Administrator.
#>

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$ManagerAddress = "analytics.graniteshieldcyber.com",

    [Alias("av")]
    [ValidateSet("Defender","Bitdefender","Other")]
    [string]$Antivirus = "Defender",

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
    throw "This bootstrap is intended for Windows 10/11 workstations."
}
$operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
if ([int]$operatingSystem.ProductType -ne 1) {
    throw "This antivirus validation requires a Windows 10/11 workstation; Windows Server is not supported by this bootstrap."
}

# Query Windows Security Center's supported product API; State 0 means active.
$wscSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
namespace GscAv {
    [ComImport, Guid("722A338C-6E8E-4E72-AC27-1417FB0C81C2"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IProductList {
        void GetTypeInfoCount(out uint count);
        void GetTypeInfo(uint index, uint lcid, out IntPtr info);
        void GetIDsOfNames();
        void Invoke();
        void Initialize(uint provider);
        void GetCount(out int count);
        void GetItem(uint index, out IProduct product);
    }
    [ComImport, Guid("8C38232E-3A45-4A27-92B0-1A16A975F669"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IProduct {
        void GetTypeInfoCount(out uint count);
        void GetTypeInfo(uint index, uint lcid, out IntPtr info);
        void GetIDsOfNames();
        void Invoke();
        void GetName([MarshalAs(UnmanagedType.BStr)] out string name);
        void GetState(out int state);
        void GetSignatureStatus(out int status);
    }
    public sealed class AvProduct {
        public string Name { get; set; }
        public int State { get; set; }
        public int SignatureStatus { get; set; }
    }
    public static class WscReader {
        public static AvProduct[] GetAntivirusProducts() {
            var list = new List<AvProduct>();
            var t = Type.GetTypeFromCLSID(new Guid("17072F7B-9ABE-4A74-A261-1EB76B55107A"), true);
            var obj = Activator.CreateInstance(t);
            try {
                var products = (IProductList)obj;
                products.Initialize(4);
                int count;
                products.GetCount(out count);
                for (uint i = 0; i < count; i++) {
                    IProduct product;
                    products.GetItem(i, out product);
                    try {
                        string name;
                        int state, sig;
                        product.GetName(out name);
                        product.GetState(out state);
                        product.GetSignatureStatus(out sig);
                        list.Add(new AvProduct { Name = name, State = state, SignatureStatus = sig });
                    } finally {
                        if (product != null) Marshal.ReleaseComObject(product);
                    }
                }
            } finally {
                if (obj != null) Marshal.ReleaseComObject(obj);
            }
            return list.ToArray();
        }
    }
}
'@
if (-not ('GscAv.WscReader' -as [type])) {
    Add-Type -TypeDefinition $wscSource -ErrorAction Stop
}

Write-Step "Validating antivirus protection"
$avProducts = @([GscAv.WscReader]::GetAntivirusProducts())
$activeAv = @($avProducts | Where-Object { $_.State -eq 0 })
if ($activeAv.Count -eq 0) {
    throw "Windows Security Center reports no active antivirus product. Repair antivirus protection before deploying Wazuh."
}

$selectedPattern = switch ($Antivirus) {
    "Bitdefender" { "(?i)Bitdefender" }
    "Defender" { "(?i)Microsoft Defender|Windows Defender" }
    "Other" { "(?i)^(?!.*(?:Bitdefender|Microsoft Defender|Windows Defender)).+" }
}
$selectedAv = @($activeAv | Where-Object { $_.Name -match $selectedPattern })
if ($selectedAv.Count -eq 0) {
    $runningNames = ($activeAv | ForEach-Object { $_.Name }) -join ", "
    throw "Selected -av $Antivirus is not active. Windows Security Center reports: $runningNames. Specify the active AV or repair it."
}
Write-OK "Active antivirus: $(($selectedAv | ForEach-Object { $_.Name }) -join ', ')"

$DefenderScanStatus = "Not checked"
if ($Antivirus -eq "Defender") {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    if (-not $mpStatus.AntivirusEnabled -or -not $mpStatus.RealTimeProtectionEnabled) {
        throw "Microsoft Defender is registered, but antivirus or real-time protection is off."
    }
    $mpPreference = Get-MpPreference -ErrorAction Stop
    if ([int]$mpPreference.ScanScheduleDay -eq 8) {
        Write-Step "Enabling Defender scheduled quick scans"
        Set-MpPreference -ScanScheduleDay Everyday -ScanParameters QuickScan -ErrorAction Stop
        $mpPreference = Get-MpPreference -ErrorAction Stop
        if ([int]$mpPreference.ScanScheduleDay -eq 8) {
            throw "Defender scheduled scanning remains disabled after Set-MpPreference."
        }
        $DefenderScanStatus = "Enabled scheduled quick scans"
    } else {
        $DefenderScanStatus = "Scheduled scans already enabled"
    }
    Write-OK $DefenderScanStatus
} elseif ($Antivirus -eq "Bitdefender") {
    $rcaPath = "C:\ProgramData\Bitdefender\Bitdefender Security App\ctc\rca"
    if (-not (Test-Path -LiteralPath $rcaPath -PathType Container)) {
        throw "Bitdefender is active, but its local incident directory is absent: $rcaPath. Rich incident collection cannot be installed."
    }
    try {
        $mpMode = [string](Get-MpComputerStatus -ErrorAction Stop).AMRunningMode
    } catch {
        $mpMode = "Unavailable"
    }
    if ($mpMode -eq "SxS Passive Mode") {
        $DefenderScanStatus = "Limited periodic scanning already enabled"
        Write-OK $DefenderScanStatus
    } else {
        $DefenderScanStatus = "Limited periodic scanning requires the Windows Security app"
        Write-Warn "Defender limited periodic scanning is not confirmed. With Bitdefender active, enable it in Windows Security > Virus & threat protection > Microsoft Defender Antivirus options. Microsoft does not provide a supported policy or PowerShell switch for this mode."
    }
} else {
    $DefenderScanStatus = "Limited periodic scanning must be checked in Windows Security for this third-party AV"
    Write-Warn $DefenderScanStatus
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
$report.Add("Selected antivirus: $Antivirus")
$report.Add("Active antivirus: $(($selectedAv | ForEach-Object { $_.Name }) -join ', ')")
$report.Add("Defender scanning: $DefenderScanStatus")
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

# The Bitdefender option embeds the tested read-only RCA collector so one script
# is sufficient on an endpoint. Defender endpoints never install it.
$BitdefenderCollectorInstalled = $false
if ($Antivirus -eq "Bitdefender") {
    Write-Step "Installing Bitdefender incident collector"
    $collectorDirectory = "C:\ProgramData\BitdefenderWazuh"
    $collectorPath = Join-Path $collectorDirectory "Collect-BitdefenderIncidents.ps1"
    $collectorLines = @(
        '<#'
        '.SYNOPSIS'
        'Emit selected Bitdefender Total Security RCA incidents as Wazuh-ready JSON lines.'
        '.DESCRIPTION'
        'Read-only collection of Bitdefender''s local RCA JSON and quarantine index.'
        'No Bitdefender product installation or Wazuh remote commands are performed.'
        'The RCA format is undocumented and must be checked after product upgrades.'
        '#>'
        '[CmdletBinding()]'
        'param('
        '    [string]$RcaDirectory = ''C:\ProgramData\Bitdefender\Bitdefender Security App\ctc\rca'','
        '    [string]$QuarantineDatabase = ''C:\ProgramData\Bitdefender\Desktop\Quarantine\cache.db'','
        '    [string]$OutputDirectory = ''C:\ProgramData\BitdefenderWazuh'','
        '    [string]$StatePath,'
        '    [switch]$InitializeOnly'
        ')'
        ''
        'Set-StrictMode -Version 2.0'
        '$ErrorActionPreference = ''Stop'''
        'if (-not $StatePath) { $StatePath = Join-Path $OutputDirectory ''collector-state.json'' }'
        ''
        'function ConvertTo-NormalPath([string]$Path) {'
        '    if (-not $Path) { return '''' }'
        '    $value = $Path -replace ''^[\\]{2}\?[\\]'', '''''
        '    return $value.Trim().ToLowerInvariant()'
        '}'
        ''
        'function Get-ShortName([string]$Path) {'
        '    if (-not $Path) { return '''' }'
        '    return [IO.Path]::GetFileName($Path)'
        '}'
        ''
        'function Get-Sha256([string]$Value) {'
        '    $sha = [Security.Cryptography.SHA256]::Create()'
        '    try {'
        '        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)'
        '        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace(''-'', '''').ToLowerInvariant()'
        '    } finally { $sha.Dispose() }'
        '}'
        ''
        'function Get-ProcessChain($Incident) {'
        '    $processes = @($Incident.nodes | Where-Object { $_.type -eq ''node_process'' -and $_.extra -and $_.extra.process_path })'
        '    $current = $processes | Where-Object {'
        '        $_.extra.pid -eq $Incident.real_trigger_pid -and'
        '        (ConvertTo-NormalPath $_.extra.process_path) -eq (ConvertTo-NormalPath $Incident.trigger_process_path)'
        '    } | Sort-Object event_time -Descending | Select-Object -First 1'
        '    $names = New-Object ''System.Collections.Generic.List[string]'''
        '    $paths = New-Object ''System.Collections.Generic.List[string]'''
        '    $timeline = New-Object ''System.Collections.Generic.List[string]'''
        '    $seen = New-Object ''System.Collections.Generic.HashSet[string]'''
        '    for ($i = 0; $i -lt 6 -and $current; $i++) {'
        '        $path = [string]$current.extra.process_path'
        '        $name = Get-ShortName $path'
        '        if ($name -match ''^(svchost|services|wininit|system)\.exe$'') { break }'
        '        $key = "{0}:{1}" -f $current.extra.pid, $current.extra.pid_timestamp'
        '        if (-not $seen.Add($key)) { break }'
        '        $names.Insert(0, $name)'
        '        $paths.Insert(0, $path)'
        '        $started = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$current.event_time).ToLocalTime().ToString(''yyyy-MM-dd HH:mm:ss.fff zzz'')'
        '        $timeline.Insert(0, "$name ($started)")'
        '        $parentPid = $current.extra.parent_pid'
        '        if (-not $parentPid) { break }'
        '        $current = $processes | Where-Object {'
        '            $_.extra.pid -eq $parentPid -and $_.event_time -le $current.event_time'
        '        } | Sort-Object event_time -Descending | Select-Object -First 1'
        '    }'
        '    return [pscustomobject]@{'
        '        Names = @($names.ToArray())'
        '        Paths = @($paths.ToArray())'
        '        Summary = ($names.ToArray() -join '' -> '')'
        '        Timeline = ($timeline.ToArray() -join '' -> '')'
        '    }'
        '}'
        ''
        '# Windows 10/11 includes winsqlite3.dll. We use it only to confirm quarantine.'
        '# A failed or inaccessible index leaves remediation as unconfirmed.'
        '$sqliteSource = @'''
        'using System;'
        'using System.Collections.Generic;'
        'using System.Runtime.InteropServices;'
        'using System.Text;'
        'public sealed class BdQuarantineRow {'
        '  public string Path;'
        '  public string Threat;'
        '  public string Sha256;'
        '  public string QuarantineId;'
        '  public long QuarantineTime;'
        '  public long Size;'
        '}'
        'public static class BdSqliteReadOnly {'
        '  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl, CharSet=CharSet.Ansi)]'
        '  static extern int sqlite3_open_v2(string file, out IntPtr db, int flags, IntPtr vfs);'
        '  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]'
        '  static extern int sqlite3_prepare_v2(IntPtr db, byte[] sql, int length, out IntPtr stmt, IntPtr tail);'
        '  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]'
        '  static extern int sqlite3_step(IntPtr stmt);'
        '  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]'
        '  static extern IntPtr sqlite3_column_text(IntPtr stmt, int index);'
        '  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]'
        '  static extern int sqlite3_column_bytes(IntPtr stmt, int index);'
        '  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]'
        '  static extern long sqlite3_column_int64(IntPtr stmt, int index);'
        '  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]'
        '  static extern int sqlite3_finalize(IntPtr stmt);'
        '  [DllImport("winsqlite3.dll", CallingConvention=CallingConvention.Cdecl)]'
        '  static extern int sqlite3_close(IntPtr db);'
        '  static string Text(IntPtr stmt, int i) {'
        '    IntPtr p = sqlite3_column_text(stmt, i);'
        '    int n = sqlite3_column_bytes(stmt, i);'
        '    if (p == IntPtr.Zero || n <= 0) return "";'
        '    byte[] b = new byte[n]; Marshal.Copy(p, b, 0, n);'
        '    return Encoding.UTF8.GetString(b);'
        '  }'
        '  public static List<BdQuarantineRow> Read(string file) {'
        '    var rows = new List<BdQuarantineRow>();'
        '    IntPtr db = IntPtr.Zero, stmt = IntPtr.Zero;'
        '    try {'
        '      if (sqlite3_open_v2(file, out db, 1, IntPtr.Zero) != 0) throw new Exception("SQLite read-only open failed");'
        '      byte[] sql = Encoding.UTF8.GetBytes("SELECT path,threat,sha256,quarId,quartime,size FROM entries\0");'
        '      if (sqlite3_prepare_v2(db, sql, sql.Length, out stmt, IntPtr.Zero) != 0) throw new Exception("SQLite quarantine query failed");'
        '      int rc;'
        '      while ((rc = sqlite3_step(stmt)) == 100) {'
        '        rows.Add(new BdQuarantineRow {'
        '          Path=Text(stmt,0), Threat=Text(stmt,1), Sha256=Text(stmt,2),'
        '          QuarantineId=Text(stmt,3), QuarantineTime=sqlite3_column_int64(stmt,4),'
        '          Size=sqlite3_column_int64(stmt,5)'
        '        });'
        '      }'
        '      if (rc != 101) throw new Exception("SQLite quarantine read failed");'
        '      return rows;'
        '    } finally {'
        '      if (stmt != IntPtr.Zero) sqlite3_finalize(stmt);'
        '      if (db != IntPtr.Zero) sqlite3_close(db);'
        '    }'
        '  }'
        '}'
        '''@'
        ''
        'if (-not (''BdSqliteReadOnly'' -as [type])) { Add-Type -TypeDefinition $sqliteSource -ErrorAction Stop }'
        ''
        'if (-not (Test-Path -LiteralPath $RcaDirectory -PathType Container)) {'
        '    throw "Bitdefender RCA directory is unavailable: $RcaDirectory"'
        '}'
        'if (-not (Test-Path -LiteralPath $OutputDirectory)) {'
        '    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null'
        '}'
        ''
        '$quarantineRows = @()'
        'if (Test-Path -LiteralPath $QuarantineDatabase -PathType Leaf) {'
        '    try { $quarantineRows = @([BdSqliteReadOnly]::Read($QuarantineDatabase)) }'
        '    catch { Write-Warning "Quarantine index could not be read: $($_.Exception.Message)" }'
        '}'
        ''
        '$seen = New-Object ''System.Collections.Generic.HashSet[string]'''
        'if (Test-Path -LiteralPath $StatePath -PathType Leaf) {'
        '    $prior = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json'
        '    if ($prior.version -eq 2) {'
        '        foreach ($id in @($prior.seen)) { if ($id) { [void]$seen.Add([string]$id) } }'
        '    }'
        '}'
        ''
        '$pending = New-Object ''System.Collections.Generic.List[object]'''
        '$files = @(Get-ChildItem -LiteralPath $RcaDirectory -Filter ''*.dat'' -File -ErrorAction Stop)'
        'foreach ($file in $files) {'
        '    try { $incident = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json }'
        '    catch { Write-Warning "Skipping incomplete RCA file $($file.Name): $($_.Exception.Message)"; continue }'
        '    if ($incident.event_name -ne ''rca_insight'' -or -not $incident.real_trigger_detection_name -or -not $incident.real_trigger_file_path) { continue }'
        '    $timeMs = [long]$incident.event_time'
        '    if ($timeMs -le 0) { continue }'
        '    $threat = [string]$incident.real_trigger_detection_name'
        '    $target = [string]$incident.real_trigger_file_path'
        '    $chain = Get-ProcessChain $incident'
        '    $matched = $quarantineRows | Where-Object {'
        '        (ConvertTo-NormalPath $_.Path) -eq (ConvertTo-NormalPath $target) -and'
        '        $_.Threat -eq $threat -and'
        '        [Math]::Abs(([long]$_.QuarantineTime * 1000) - $timeMs) -lt 900000'
        '    } | Sort-Object QuarantineTime -Descending | Select-Object -First 1'
        '    $identitySeed = $(if ($matched) {'
        '        "quarantine|{0}|{1}|{2}" -f $matched.QuarantineId, $threat, $target'
        '    } else {'
        '        "rca|{0}|{1}|{2}|{3}" -f $incident.rca_id, $incident.real_trigger_pid, $threat, $target'
        '    })'
        '    $identity = Get-Sha256 ("v2|$identitySeed")'
        '    if ($seen.Contains($identity)) { continue }'
        '    $testFile = $threat -match ''^EICAR-Test-File'''
        '    $risk = $(if ($testFile) { '''' } else { @($incident.attack_types | Where-Object { $_ }) -join '', '' })'
        '    $detectionTimeMs = $(if ($matched) { [long]$matched.QuarantineTime * 1000 } else { $timeMs })'
        '    $event = [ordered]@{'
        '        detection_time_utc = [DateTimeOffset]::FromUnixTimeMilliseconds($detectionTimeMs).UtcDateTime.ToString(''o'')'
        '        rca_generated_utc = [DateTimeOffset]::FromUnixTimeMilliseconds($timeMs).UtcDateTime.ToString(''o'')'
        '        integration = ''bitdefender_consumer'''
        '        event_type = ''malware_detection'''
        '        schema_version = 2'
        '        event_id = $identity'
        '        computer_name = $env:COMPUTERNAME'
        '        detection_layer = ''Bitdefender RCA'''
        '        threat_name = $threat'
        '        file_path = $target'
        '        remediation = $(if ($matched) { ''quarantined'' } else { ''unconfirmed'' })'
        '        quarantine_confirmed = [bool]$matched'
        '        quarantine_sha256 = $(if ($matched) { $matched.Sha256 } else { '''' })'
        '        trigger_process = [string]$incident.trigger_process_path'
        '        trigger_parent_process = [string]$incident.trigger_parent_process_path'
        '        process_chain = $chain.Summary'
        '        process_timeline_local = $chain.Timeline'
        '        process_chain_paths = $chain.Paths -join '' | '''
        '        rca_incident_attack_types = $risk'
        '        alternative_outcome = $(if ($testFile) { ''Simulation only: EICAR is harmless.'' } elseif ($risk) { "Potential risk categories associated with the RCA incident: $risk. This is a vendor classification, not observed harm or a prediction for this file." } else { ''No specific alternative outcome was recorded.'' })'
        '        simulated_test = [bool]$testFile'
        '        source = ''Bitdefender RCA JSON'''
        '    }'
        '    $pending.Add([pscustomobject]$event)'
        '    [void]$seen.Add($identity)'
        '}'
        ''
        'if (-not $InitializeOnly -and $pending.Count -gt 0) {'
        '    $outFile = Join-Path $OutputDirectory (''events-{0}.jsonl'' -f [DateTime]::UtcNow.ToString(''yyyy-MM-dd''))'
        '    $utf8 = New-Object Text.UTF8Encoding($false)'
        '    $stream = New-Object IO.StreamWriter($outFile, $true, $utf8)'
        '    try {'
        '        foreach ($event in $pending) {'
        '            $stream.WriteLine(($event | ConvertTo-Json -Compress -Depth 5))'
        '            Write-Output $event'
        '        }'
        '    } finally { $stream.Dispose() }'
        '}'
        ''
        '$state = [pscustomobject]@{ version = 2; seen = @($seen | Select-Object -Last 2000) }'
        '$temp = "$StatePath.tmp"'
        '[IO.File]::WriteAllText($temp, ($state | ConvertTo-Json -Compress -Depth 3), (New-Object Text.UTF8Encoding($false)))'
        'Move-Item -LiteralPath $temp -Destination $StatePath -Force'
        ''
    )
    Ensure-Directory $collectorDirectory
    [System.IO.File]::WriteAllLines($collectorPath, [string[]]$collectorLines,
        (New-Object System.Text.UTF8Encoding($false)))
    & icacls.exe $collectorDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not restrict collector directory permissions." }

    $collectorTaskName = "GSC Bitdefender Incident Collector"
    $powershellExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
    $collectorArguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $collectorPath
    $taskAction = New-ScheduledTaskAction -Execute $powershellExe -Argument $collectorArguments
    $taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $collectorTaskName -Action $taskAction -Trigger $taskTrigger `
        -Principal $taskPrincipal -Settings $taskSettings -Force | Out-Null
    Start-ScheduledTask -TaskName $collectorTaskName
    $BitdefenderCollectorInstalled = $true
    Write-OK "Bitdefender incident collector scheduled; events: $collectorDirectory\events-*.jsonl"
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

if ($Antivirus -in @('Defender','Bitdefender')) {
    $defenderChannel = Get-WinEvent -ListLog 'Microsoft-Windows-Windows Defender/Operational' -ErrorAction Stop
    if (-not $defenderChannel.IsEnabled) {
        throw 'Defender Operational event channel is disabled; Wazuh cannot collect Defender detection events.'
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

if ($Antivirus -eq "Bitdefender") {
    $incidentLocation = 'C:\ProgramData\BitdefenderWazuh\events-*.jsonl'
    $sharedAgentConf = Join-Path $WazuhDir 'shared\agent.conf'
    $sharedText = if (Test-Path -LiteralPath $sharedAgentConf) {
        Get-Content -LiteralPath $sharedAgentConf -Raw
    } else { '' }
    if ($sharedText.IndexOf($incidentLocation, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        Write-Info 'Bitdefender incidents are already collected by a manager group.'
    } elseif ($confText.IndexOf($incidentLocation, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        $localfileLines.Add('  <localfile>')
        $localfileLines.Add("    <location>$incidentLocation</location>")
        $localfileLines.Add('    <log_format>json</log_format>')
        $localfileLines.Add('    <label key="@source">bitdefender-incident</label>')
        $localfileLines.Add('  </localfile>')
    }
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
$report.Add("Bitdefender collector installed: $BitdefenderCollectorInstalled")
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
if ($Antivirus -eq "Bitdefender") {
    $report.Add("  Bitdefender RCA incident timeline / quarantine events")
} elseif ($Antivirus -eq "Defender") {
    $report.Add("  Defender Operational malware detections and remediation events")
}
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
Write-Host "Antivirus:      $Antivirus"
Write-Host "Defender scans: $DefenderScanStatus"
Write-Host "Wazuh backup:   $backup"
Write-Host "Install report: $InstallReport"
Write-Host ""
Write-Host "No Windows Event Log was cleared." -ForegroundColor Green
Write-Host "Local EVTX logs are bounded circular buffers." -ForegroundColor Green
if ($Antivirus -eq "Bitdefender") {
    Write-Host "Bitdefender incident JSONL: C:\ProgramData\BitdefenderWazuh\events-*.jsonl"
}
Write-Host ""
Write-Host "IMPORTANT:" -ForegroundColor Yellow
Write-Host "  If this was a Wazuh rebuild and enrollment reports a duplicate agent name,"
Write-Host "  remove the stale agent entry in Wazuh and rerun this script."
Write-Host ""
Write-Host "Recommended next test:"
Write-Host "  .\Invoke-GSC-EDRTests.ps1 -Test LSASS,WMI,FileDelete,Ransomware"
Write-Host ""
