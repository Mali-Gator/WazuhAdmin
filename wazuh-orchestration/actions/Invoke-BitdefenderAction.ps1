<#
.SYNOPSIS
Hardened, management-platform-neutral Bitdefender action dispatcher.

.DESCRIPTION
Provides an explicit allowlist of locally validated Bitdefender operations:
protection-state changes, Quick and Full System scans, vulnerability scans,
and Bitdefender firewall IPv4 deny-rule management.

The script accepts structured parameters only. It never evaluates caller text,
loads caller-selected code, accepts arbitrary executable paths, or exposes a
generic UI click primitive. Operations that need the interactive Bitdefender
desktop self-dispatch through a temporary TASK_LOGON_INTERACTIVE_TOKEN task.

Uses only Windows PowerShell 5.1, Task Scheduler COM, CIM/WMI, and .NET
Framework assemblies included with Windows.

.PARAMETER Action
Selects an allowlisted Bitdefender operation.

.PARAMETER Feature
Selects a protection feature for SetProtection.

.PARAMETER State
Selects On, Off, or Status for SetProtection.

.PARAMETER ScanType
Selects Quick or Full for StartScan.

.PARAMETER RemoteIPv4
Specifies one IPv4 address for BlockIp or UnblockIp.

.PARAMETER RuleId
Optionally narrows UnblockIp to a previously returned Bitdefender rule ID.

.PARAMETER ResultPath
Writes the same JSON result returned on standard output to this path.

.PARAMETER TimeoutSeconds
Sets the interactive-session relay timeout from 30 through 300 seconds.

.PARAMETER Help
Displays the command menu. The GNU-style --help form is also accepted.

.EXAMPLE
.\Invoke-BitdefenderAction.ps1 --help

.EXAMPLE
.\Invoke-BitdefenderAction.ps1 -Action StartScan -ScanType Quick

.EXAMPLE
.\Invoke-BitdefenderAction.ps1 -Action SetProtection -Feature Firewall -State Status

.EXAMPLE
.\Invoke-BitdefenderAction.ps1 -Action BlockIp -RemoteIPv4 23.227.38.32
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [ValidateSet('GetCapabilities', 'SetProtection', 'StartScan', 'StartVulnerabilityScan', 'BlockIp', 'UnblockIp')]
    [string]$Action,

    [ValidateSet('RansomwareRemediation', 'CryptominingProtection', 'Firewall', 'Antispam')]
    [string]$Feature,

    [ValidateSet('On', 'Off', 'Status')]
    [string]$State,

    [ValidateSet('Quick', 'Full')]
    [string]$ScanType,

    [ValidateScript({
        $parsed = [Net.IPAddress]::None
        [Net.IPAddress]::TryParse($_, [ref]$parsed) -and
        $parsed.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
        $_ -notin @('0.0.0.0', '255.255.255.255')
    })]
    [string]$RemoteIPv4,

    [ValidatePattern('^[0-9]{1,20}$')]
    [string]$RuleId,

    [switch]$Worker,
    [switch]$ForceDispatch,
    [string]$ResultPath,

    [ValidateRange(30, 300)]
    [int]$TimeoutSeconds = 120,

    [Alias('h')]
    [switch]$Help,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArguments
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:SelfPath = $PSCommandPath
$script:RequestParameters = @{}
foreach ($parameterName in $PSBoundParameters.Keys) {
    $script:RequestParameters[$parameterName] = $PSBoundParameters[$parameterName]
}
$script:OutputRoot = 'C:\ProgramData\BitdefenderOrchestration'
$script:SettingsRoot = 'C:\ProgramData\Bitdefender\Desktop\.settings\data'
$script:BackupRoot = Join-Path $script:OutputRoot 'firewall-rule-backups'
$script:ProtectionControlIds = @{
    RansomwareRemediation = '28'
    CryptominingProtection = '33'
    Firewall = '2'
    Antispam = '3'
}
$script:SecurityCenterStarted = $false

function Get-HelpMenu {
    @'
Bitdefender Action Dispatcher

USAGE
  powershell.exe -NoProfile -File .\Invoke-BitdefenderAction.ps1 --help
  powershell.exe -NoProfile -File .\Invoke-BitdefenderAction.ps1 -Action <ACTION> [OPTIONS]

ACTIONS
  GetCapabilities
      Report supported actions, detected Bitdefender components, and known limits.

  SetProtection -Feature <FEATURE> -State <STATE>
      FEATURE: RansomwareRemediation | CryptominingProtection | Firewall | Antispam
      STATE:   On | Off | Status

  StartScan -ScanType <TYPE>
      TYPE: Quick | Full

  StartVulnerabilityScan
      Launch a Bitdefender vulnerability scan.

  BlockIp -RemoteIPv4 <ADDRESS>
      Add a Bitdefender firewall deny rule for one IPv4 address.

  UnblockIp -RemoteIPv4 <ADDRESS> [-RuleId <ID>]
      Remove the matching deny rule. RuleId can narrow the match.

COMMON OPTIONS
  -ResultPath <PATH>       Also write the JSON result to this path.
  -TimeoutSeconds <30-300> Interactive relay timeout; default 120.
  -Verbose                 Emit PowerShell verbose output.
  -Help, --help, -h        Display this menu.

EXAMPLES
  .\Invoke-BitdefenderAction.ps1 -Action GetCapabilities
  .\Invoke-BitdefenderAction.ps1 -Action StartScan -ScanType Quick
  .\Invoke-BitdefenderAction.ps1 -Action StartScan -ScanType Full
  .\Invoke-BitdefenderAction.ps1 -Action StartVulnerabilityScan
  .\Invoke-BitdefenderAction.ps1 -Action SetProtection -Feature Firewall -State Off
  .\Invoke-BitdefenderAction.ps1 -Action SetProtection -Feature Firewall -State On
  .\Invoke-BitdefenderAction.ps1 -Action BlockIp -RemoteIPv4 23.227.38.32
  .\Invoke-BitdefenderAction.ps1 -Action UnblockIp -RemoteIPv4 23.227.38.32

OUTPUT
  Actions return structured JSON. Exit code 0 means success, 1 means the action
  failed, and 2 means the command syntax is invalid.

SECURITY BOUNDARY
  The dispatcher accepts only the actions and values listed above. It does not
  execute caller-supplied commands, executable paths, scripts, or arbitrary UI input.
'@
}

$gnuHelpRequested = $RemainingArguments -and $RemainingArguments.Count -eq 1 -and $RemainingArguments[0] -eq '--help'
if ($Help -or $gnuHelpRequested) {
    Get-HelpMenu
    exit 0
}
if ($RemainingArguments) {
    Write-Error ("Unsupported argument(s): {0}" -f ($RemainingArguments -join ' '))
    Get-HelpMenu
    exit 2
}
if (-not $Action) {
    Write-Error 'Missing required -Action. Use --help to list valid commands.'
    Get-HelpMenu
    exit 2
}

function Test-BoundParameter {
    param([Parameter(Mandatory = $true)][string]$Name)
    return $script:RequestParameters.ContainsKey($Name)
}

function Assert-ValidRequest {
    $hasFeature = Test-BoundParameter -Name 'Feature'
    $hasState = Test-BoundParameter -Name 'State'
    $hasScanType = Test-BoundParameter -Name 'ScanType'
    $hasAddress = Test-BoundParameter -Name 'RemoteIPv4'
    $hasRuleId = Test-BoundParameter -Name 'RuleId'

    switch ($Action) {
        'GetCapabilities' {
            if ($hasFeature -or $hasState -or $hasScanType -or $hasAddress -or $hasRuleId) {
                throw 'GetCapabilities does not accept Feature, State, ScanType, RemoteIPv4, or RuleId.'
            }
        }
        'SetProtection' {
            if (-not $hasFeature -or -not $hasState) {
                throw 'SetProtection requires -Feature and -State.'
            }
            if ($hasScanType -or $hasAddress -or $hasRuleId) {
                throw 'SetProtection accepts only Feature and State action arguments.'
            }
        }
        'StartScan' {
            if (-not $hasScanType) { throw 'StartScan requires -ScanType Quick or Full.' }
            if ($hasFeature -or $hasState -or $hasAddress -or $hasRuleId) {
                throw 'StartScan accepts only ScanType action arguments.'
            }
        }
        'StartVulnerabilityScan' {
            if ($hasFeature -or $hasState -or $hasScanType -or $hasAddress -or $hasRuleId) {
                throw 'StartVulnerabilityScan does not accept additional action arguments.'
            }
        }
        'BlockIp' {
            if (-not $hasAddress) { throw 'BlockIp requires -RemoteIPv4.' }
            if ($hasFeature -or $hasState -or $hasScanType -or $hasRuleId) {
                throw 'BlockIp accepts only RemoteIPv4.'
            }
        }
        'UnblockIp' {
            if (-not $hasAddress) { throw 'UnblockIp requires -RemoteIPv4.' }
            if ($hasFeature -or $hasState -or $hasScanType) {
                throw 'UnblockIp accepts RemoteIPv4 and optional RuleId.'
            }
        }
    }
}

function ConvertTo-ResultJson {
    param([Parameter(Mandatory = $true)]$InputObject)
    return ($InputObject | ConvertTo-Json -Depth 18)
}

function Write-Result {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [string]$Path
    )

    $json = ConvertTo-ResultJson -InputObject $InputObject
    if (-not $Worker) {
        if (-not (Test-Path -LiteralPath $script:OutputRoot)) {
            New-Item -Path $script:OutputRoot -ItemType Directory -Force | Out-Null
        }
        $lastPath = Join-Path $script:OutputRoot ("last-{0}.json" -f $Action.ToLowerInvariant())
        [IO.File]::WriteAllText($lastPath, $json, (New-Object Text.UTF8Encoding($false)))
    }
    if ($Path) {
        $parent = Split-Path -Parent $Path
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -Path $parent -ItemType Directory -Force | Out-Null
        }
        [IO.File]::WriteAllText($Path, $json, (New-Object Text.UTF8Encoding($false)))
    }
    Write-Output $json
}

function Get-Capabilities {
    return [pscustomobject]@{
        Passed = $true
        Action = 'GetCapabilities'
        Version = '1.0.0'
        NativeWindowsOnly = $true
        Supported = @(
            [pscustomobject]@{ Action = 'SetProtection'; Arguments = '-Feature RansomwareRemediation|CryptominingProtection|Firewall|Antispam -State On|Off|Status'; Validation = 'UI state and product artifact' }
            [pscustomobject]@{ Action = 'StartScan'; Arguments = '-ScanType Quick|Full'; Validation = 'Discovered local task GUID, task-specific process, completion XML for Quick' }
            [pscustomobject]@{ Action = 'StartVulnerabilityScan'; Arguments = 'none'; Validation = 'Service-mediated GUI launch and vulnerability worker activity' }
            [pscustomobject]@{ Action = 'BlockIp'; Arguments = '-RemoteIPv4 <IPv4>'; Validation = 'Persisted Bitdefender deny rule; WFP enforcement validated' }
            [pscustomobject]@{ Action = 'UnblockIp'; Arguments = '-RemoteIPv4 <IPv4> [-RuleId <id>]'; Validation = 'Matching Bitdefender deny rule absent after write' }
        )
        NotExposed = @(
            [pscustomobject]@{ Function = 'VPN connect/disconnect'; Reason = 'No stable, crash-free native control interface was validated.' }
            [pscustomobject]@{ Function = 'Add/remove exclusions'; Reason = 'Artifact monitoring was validated, but a supported deterministic write interface was not.' }
            [pscustomobject]@{ Function = 'Fix individual vulnerability'; Reason = 'The internal fix request schema was not recovered; direct policy edits are intentionally excluded.' }
            [pscustomobject]@{ Function = 'Arbitrary GUI action'; Reason = 'Generic clicks or caller-selected executables would bypass the action allowlist.' }
        )
    }
}

function Get-BitdefenderWindow {
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $deadline = (Get-Date).AddSeconds(25)
    do {
        $windows = $root.FindAll(
            [System.Windows.Automation.TreeScope]::Children,
            [System.Windows.Automation.Condition]::TrueCondition
        )
        $window = $windows | Where-Object { $_.Current.Name -eq 'Bitdefender Security Center' } | Select-Object -First 1
        if ($window) { return $window }
        $securityCenter = 'C:\Program Files\Bitdefender\Bitdefender Security App\seccenter.exe'
        if (-not (Test-Path -LiteralPath $securityCenter)) {
            throw "Bitdefender Security Center was not found at $securityCenter"
        }
        if (-not $script:SecurityCenterStarted) {
            Start-Process -FilePath $securityCenter
            $script:SecurityCenterStarted = $true
        }
        Start-Sleep -Milliseconds 500
    } until ((Get-Date) -ge $deadline)
    throw 'Bitdefender Security Center did not become available in the interactive desktop.'
}

function Open-ProtectionOverview {
    $window = Get-BitdefenderWindow
    $condition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
        'liProtection'
    )
    $control = $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
    if (-not $control) { throw 'The Bitdefender Protection navigation control was not found.' }
    $control.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    Start-Sleep -Milliseconds 800
}

function Get-ProtectionCheckbox {
    $window = Get-BitdefenderWindow
    $bounds = $window.Current.BoundingRectangle
    $condition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
        $script:ProtectionControlIds[$Feature]
    )
    $matches = $window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
    $checkbox = $matches | Where-Object {
        $itemBounds = $_.Current.BoundingRectangle
        $_.Current.ControlType -eq [System.Windows.Automation.ControlType]::CheckBox -and
        $itemBounds.Width -gt 0 -and
        $itemBounds.X -ge $bounds.X -and
        $itemBounds.X -lt ($bounds.X + $bounds.Width)
    } | Select-Object -First 1
    if (-not $checkbox) { throw "Bitdefender checkbox for $Feature was not found." }
    return $checkbox
}

function Get-ProtectionUiState {
    $toggle = (Get-ProtectionCheckbox).GetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern)
    if ($toggle.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::On) { return 'On' }
    return 'Off'
}

function Find-DesktopSettingsJson {
    foreach ($candidate in Get-ChildItem -LiteralPath $script:SettingsRoot -Filter '.data' -File -Recurse -ErrorAction SilentlyContinue) {
        try {
            $json = Get-Content -LiteralPath $candidate.FullName -Raw | ConvertFrom-Json
            if ($json.settings.RansomwareRemediation -or $json.settings.Firewall) {
                return [pscustomobject]@{ Path = $candidate.FullName; Json = $json }
            }
        }
        catch { continue }
    }
    throw 'The Bitdefender Desktop settings document could not be located.'
}

function Get-AntispamXmlPath {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $preferred = "C:\Program Files\Bitdefender\Bitdefender Security\settings\as\$sid\antispam.xml"
    if (Test-Path -LiteralPath $preferred) { return $preferred }
    $fallback = Get-ChildItem -LiteralPath 'C:\Program Files\Bitdefender\Bitdefender Security\settings\as' -Filter 'antispam.xml' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($fallback) { return $fallback.FullName }
    return $preferred
}

function Get-ProtectionArtifactState {
    switch ($Feature) {
        'RansomwareRemediation' {
            $settings = Find-DesktopSettingsJson
            $value = [int]$settings.Json.settings.RansomwareRemediation.Settings.module_state
            return [pscustomobject]@{ Path = $settings.Path; Value = $value; Meaning = if ($value -eq 1) { 'On' } else { 'Off' } }
        }
        'Firewall' {
            $settings = Find-DesktopSettingsJson
            $value = [bool]$settings.Json.settings.Firewall.Backup.Settings.Settings.enabled
            return [pscustomobject]@{ Path = $settings.Path; Value = $value; Meaning = if ($value) { 'On' } else { 'Off' } }
        }
        'Antispam' {
            $path = Get-AntispamXmlPath
            if (-not (Test-Path -LiteralPath $path)) { return [pscustomobject]@{ Path = $path; Value = $null; Meaning = 'NotCreated' } }
            [xml]$xml = Get-Content -LiteralPath $path -Raw
            $value = [int]$xml.settings.ScanSpam
            return [pscustomobject]@{ Path = $path; Value = $value; Meaning = if ($value -eq 1) { 'On' } else { 'Off' }; LastWriteUtc = (Get-Item -LiteralPath $path).LastWriteTimeUtc.ToString('o') }
        }
        'CryptominingProtection' {
            $path = 'C:\Program Files\Bitdefender\Bitdefender Security\settings\vshield.xml'
            $file = Get-Item -LiteralPath $path
            return [pscustomobject]@{ Path = $path; Value = $null; Meaning = Get-ProtectionUiState; LastWriteUtc = $file.LastWriteTimeUtc.ToString('o'); Length = $file.Length }
        }
    }
}

function Get-ProtectionSnapshot {
    return [pscustomobject]@{ Timestamp = (Get-Date).ToString('o'); Feature = $Feature; UiState = Get-ProtectionUiState; Artifact = Get-ProtectionArtifactState }
}

function Invoke-SetProtection {
    Open-ProtectionOverview
    $before = Get-ProtectionSnapshot
    if ($State -eq 'Status' -or ($before.UiState -eq $State -and $before.Artifact.Meaning -eq $State)) {
        return [pscustomobject]@{ Passed = $true; Changed = $false; Action = $Action; Feature = $Feature; RequestedState = $State; Before = $before; After = $before }
    }
    (Get-ProtectionCheckbox).GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    $deadline = (Get-Date).AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 500
        $after = Get-ProtectionSnapshot
        $artifactChanged = $true
        if ($Feature -eq 'CryptominingProtection') {
            $artifactChanged = $after.Artifact.LastWriteUtc -ne $before.Artifact.LastWriteUtc
        }
        if ($after.UiState -eq $State -and $after.Artifact.Meaning -eq $State -and $artifactChanged) {
            return [pscustomobject]@{ Passed = $true; Changed = $true; Action = $Action; Feature = $Feature; RequestedState = $State; Before = $before; After = $after }
        }
    } until ((Get-Date) -ge $deadline)
    throw "Bitdefender did not reach $State for $Feature within 20 seconds."
}

function Normalize-TaskName {
    param([string]$Name)
    if ($null -eq $Name) { return '' }
    return (($Name -replace '[^A-Za-z0-9]', '').ToLowerInvariant())
}

function Get-ScanTaskDefinition {
    $targetName = if ($ScanType -eq 'Quick') { 'quickscan' } else { 'fullsystemscan' }
    $candidates = New-Object Collections.Generic.List[string]
    $primary = 'C:\Program Files\Bitdefender\Bitdefender Security\ondemandal.xml'
    if (Test-Path -LiteralPath $primary) { $candidates.Add($primary) }
    $profilesRoot = 'C:\Program Files\Bitdefender\Bitdefender Security\ProfilesData\system'
    if (Test-Path -LiteralPath $profilesRoot) {
        Get-ChildItem -LiteralPath $profilesRoot -Filter 'ondemandal.xml' -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $candidates.Add($_.FullName) }
    }
    foreach ($path in ($candidates | Select-Object -Unique)) {
        try {
            [xml]$xml = Get-Content -LiteralPath $path -Raw
            foreach ($task in @($xml.settings.tasks.task)) {
                if ((Normalize-TaskName ([string]$task.name)) -ne $targetName) { continue }
                $parsed = [guid]::Empty
                if (-not [guid]::TryParse([string]$task.taskId, [ref]$parsed)) { continue }
                return [pscustomobject]@{ TaskId = $parsed.ToString(); Name = [string]$task.name; ConfigurationPath = $path }
            }
        }
        catch { continue }
    }
    throw "The Bitdefender $ScanType scan task was not found in ondemandal.xml."
}

function Get-ScannerProcesses {
    return @(Get-CimInstance -ClassName Win32_Process -Filter "Name='odscanui.exe'" -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            ProcessId = [int]$_.ProcessId
            CommandLine = [string]$_.CommandLine
            ExecutablePath = [string]$_.ExecutablePath
            CreationDateUtc = if ($_.CreationDate) { ([datetime]$_.CreationDate).ToUniversalTime() } else { $null }
        }
    })
}

function Get-NewScanReport {
    param(
        [Parameter(Mandatory = $true)][string]$TaskId,
        [Parameter(Mandatory = $true)][datetime]$NotBeforeUtc
    )
    $directory = Join-Path 'C:\ProgramData\Bitdefender\Desktop\Profiles\Logs\system' $TaskId
    if (-not (Test-Path -LiteralPath $directory)) { return $null }
    return Get-ChildItem -LiteralPath $directory -Filter '*.xml' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -ge $NotBeforeUtc } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
}

function Invoke-StartScan {
    $scannerPath = 'C:\Program Files\Bitdefender\Bitdefender Security App\odscanui.exe'
    if (-not (Test-Path -LiteralPath $scannerPath)) { throw "Bitdefender scanner was not found at $scannerPath" }
    $definition = Get-ScanTaskDefinition
    $before = Get-ScannerProcesses
    $existing = $before | Where-Object {
        $_.CommandLine -match [regex]::Escape($definition.TaskId) -and
        $_.CreationDateUtc -and
        -not (Get-NewScanReport -TaskId $definition.TaskId -NotBeforeUtc $_.CreationDateUtc)
    } | Select-Object -First 1
    if ($existing) {
        return [pscustomobject]@{ Passed = $true; Changed = $false; Initiated = $false; AlreadyRunning = $true; Action = $Action; ScanType = $ScanType; TaskId = $definition.TaskId; Process = $existing }
    }

    $beforeIds = @($before | ForEach-Object ProcessId)
    $requestedUtc = [datetime]::UtcNow
    $arguments = "/SystemScanTask $($definition.TaskId) /Source 1"
    $launcher = Start-Process -FilePath $scannerPath -ArgumentList $arguments -PassThru
    try { $launcher.WaitForExit(5000) | Out-Null } catch {}
    $candidateId = $null
    $candidateSince = $null
    $deadline = (Get-Date).AddSeconds(35)
    do {
        Start-Sleep -Milliseconds 500
        $process = Get-ScannerProcesses | Where-Object { $_.ProcessId -notin $beforeIds -and $_.CommandLine -match [regex]::Escape($definition.TaskId) } | Select-Object -First 1
        if ($process) {
            if ($candidateId -ne $process.ProcessId) { $candidateId = $process.ProcessId; $candidateSince = Get-Date }
            elseif (((Get-Date) - $candidateSince).TotalSeconds -ge 10) {
                return [pscustomobject]@{
                    Passed = $true; Changed = $true; Initiated = $true; AlreadyRunning = $false
                    Action = $Action; ScanType = $ScanType; TaskId = $definition.TaskId
                    ConfigurationPath = $definition.ConfigurationPath; Arguments = $arguments
                    RequestedUtc = $requestedUtc.ToString('o'); VerifiedUtc = [datetime]::UtcNow.ToString('o')
                    Verification = 'The task-specific Bitdefender process remained active for at least 10 seconds.'
                    Process = $process
                }
            }
        }
        else { $candidateId = $null; $candidateSince = $null }
        $report = Get-NewScanReport -TaskId $definition.TaskId -NotBeforeUtc $requestedUtc
        if ($report) {
            return [pscustomobject]@{ Passed = $true; Changed = $true; Initiated = $true; Action = $Action; ScanType = $ScanType; TaskId = $definition.TaskId; ReportPath = $report.FullName; RequestedUtc = $requestedUtc.ToString('o'); Verification = 'A new Bitdefender scan report was observed.' }
        }
    } until ((Get-Date) -ge $deadline)
    throw "Bitdefender did not expose a sustained $ScanType scan process or a new report. Launcher exit status is not accepted as verification."
}

function Invoke-StartVulnerabilityScan {
    $launcherPath = 'C:\Program Files\Bitdefender\Bitdefender Security App\bdtkexec.exe'
    if (-not (Test-Path -LiteralPath $launcherPath)) { throw "Bitdefender launcher was not found at $launcherPath" }
    $beforeIds = @(Get-Process -Name 'vulnerability.scan' -ErrorAction SilentlyContinue | ForEach-Object Id)
    $vuscanPath = 'C:\ProgramData\Bitdefender\Desktop\vuscan.xml'
    $beforeWrite = if (Test-Path -LiteralPath $vuscanPath) { (Get-Item -LiteralPath $vuscanPath).LastWriteTimeUtc } else { [datetime]::MinValue }
    $requestedUtc = [datetime]::UtcNow
    Start-Process -FilePath $launcherPath -ArgumentList 'vuscan issue:0 fg' | Out-Null
    $deadline = (Get-Date).AddSeconds(35)
    do {
        Start-Sleep -Milliseconds 500
        $workers = @(Get-Process -Name 'vulnerability.scan' -ErrorAction SilentlyContinue | Where-Object { $_.Id -notin $beforeIds } | Select-Object Id,StartTime)
        if ($workers.Count -gt 0) {
            return [pscustomobject]@{ Passed = $true; Changed = $true; Initiated = $true; Action = $Action; RequestedUtc = $requestedUtc.ToString('o'); Verification = 'New Bitdefender vulnerability worker process observed.'; Workers = $workers }
        }
        if (Test-Path -LiteralPath $vuscanPath) {
            $afterWrite = (Get-Item -LiteralPath $vuscanPath).LastWriteTimeUtc
            if ($afterWrite -gt $beforeWrite -and $afterWrite -ge $requestedUtc) {
                return [pscustomobject]@{ Passed = $true; Changed = $true; Initiated = $true; Action = $Action; RequestedUtc = $requestedUtc.ToString('o'); Verification = 'Bitdefender vulnerability result state changed.'; ResultPath = $vuscanPath; LastWriteUtc = $afterWrite.ToString('o') }
            }
        }
    } until ((Get-Date) -ge $deadline)
    throw 'No new Bitdefender vulnerability worker or result update was observed. Close an existing vulnerability-results window before retrying.'
}

function Get-FirewallSettingsDocument {
    $matches = @()
    foreach ($file in Get-ChildItem -LiteralPath $script:SettingsRoot -Recurse -File -Filter '.data' -ErrorAction SilentlyContinue) {
        try {
            $raw = [IO.File]::ReadAllText($file.FullName)
            $json = $raw | ConvertFrom-Json
            if ($null -ne $json.settings.Firewall.Backup.Settings.Rules.list) {
                $matches += [pscustomobject]@{ Path = $file.FullName; Raw = $raw; Json = $json; LastWriteTimeUtc = $file.LastWriteTimeUtc; Length = $file.Length }
            }
        }
        catch { continue }
    }
    if ($matches.Count -ne 1) { throw "Expected exactly one Bitdefender firewall settings document; found $($matches.Count)." }
    return $matches[0]
}

function Get-FirewallRules {
    param([Parameter(Mandatory = $true)]$Document)
    return @($Document.Json.settings.Firewall.Backup.Settings.Rules.list)
}

function Test-DenyRuleAddress {
    param([Parameter(Mandatory = $true)]$Rule, [Parameter(Mandatory = $true)][string]$Address)
    if (-not $Rule.user_created -or [int]$Rule.action.action -ne 1) { return $false }
    return @($Rule.remote_addresses | Where-Object { [int]$_.type -eq 4 -and [string]$_.ipv4.value -eq $Address }).Count -gt 0
}

function Get-MatchingDenyRules {
    param([Parameter(Mandatory = $true)]$Document, [Parameter(Mandatory = $true)][string]$Address)
    return @(Get-FirewallRules $Document | Where-Object { Test-DenyRuleAddress $_ $Address })
}

function Write-FirewallSettingsDocument {
    param([Parameter(Mandatory = $true)]$Document, [Parameter(Mandatory = $true)][string]$Reason)
    $target = [IO.Path]::GetFullPath($Document.Path)
    $expectedRoot = [IO.Path]::GetFullPath($script:SettingsRoot).TrimEnd('\') + '\'
    if (-not $target.StartsWith($expectedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw "Refusing to write outside the Bitdefender settings directory: $target" }
    $current = Get-Item -LiteralPath $target
    if ($current.LastWriteTimeUtc -ne $Document.LastWriteTimeUtc -or $current.Length -ne $Document.Length) { throw 'Bitdefender settings changed during the action; retry against a fresh snapshot.' }
    New-Item -Path $script:BackupRoot -ItemType Directory -Force | Out-Null
    $backup = Join-Path $script:BackupRoot ("{0}-{1}.data" -f [datetime]::UtcNow.ToString('yyyyMMddTHHmmss.fffffffZ'), $Reason)
    [IO.File]::WriteAllText($backup, $Document.Raw, (New-Object Text.UTF8Encoding($false)))
    $temporary = Join-Path ([IO.Path]::GetDirectoryName($target)) ('.data.' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllText($temporary, ($Document.Json | ConvertTo-Json -Depth 100 -Compress), (New-Object Text.UTF8Encoding($false)))
        [IO.File]::Replace($temporary, $target, $null, $true)
    }
    finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
    return $backup
}

function New-FirewallDenyRule {
    param([Parameter(Mandatory = $true)][string]$Id, [Parameter(Mandatory = $true)][string]$Address)
    return [pscustomobject][ordered]@{
        version = 1; id = $Id
        action = [pscustomobject][ordered]@{ version = 1; action = 1 }
        user_created = $true; direction = 0; priority = '4611686018427387903'
        profile_type = [pscustomobject][ordered]@{ version = 1; type = 0 }
        temporary = $false; local_network = $false; has_protocol = $false; has_uid = $false; has_process = $false
        local_ports = @(); remote_ports = @(); local_addresses = @()
        remote_addresses = @([pscustomobject][ordered]@{ version = 1; type = 4; ipv4 = [pscustomobject][ordered]@{ version = 1; value = $Address } })
    }
}

function Wait-FirewallRuleState {
    param([Parameter(Mandatory = $true)][string[]]$AffectedIds, [Parameter(Mandatory = $true)][bool]$ShouldExist)
    $deadline = (Get-Date).AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 500
        try {
            $document = Get-FirewallSettingsDocument
            $actual = @(Get-MatchingDenyRules $document $RemoteIPv4 | ForEach-Object { [string]$_.id })
            $presentCount = @($AffectedIds | Where-Object { $_ -in $actual }).Count
            if (($ShouldExist -and $presentCount -eq $AffectedIds.Count) -or (-not $ShouldExist -and $presentCount -eq 0)) {
                return [pscustomobject]@{ SettingsPath = $document.Path; FirewallEnabled = [bool]$document.Json.settings.Firewall.Backup.Settings.Settings.enabled; MatchingRuleIds = $actual; TotalRuleCount = @(Get-FirewallRules $document).Count }
            }
        }
        catch {}
    } until ((Get-Date) -ge $deadline)
    throw "Bitdefender did not persist the requested $Action operation for $RemoteIPv4 within 15 seconds."
}

function Invoke-FirewallIpAction {
    $document = Get-FirewallSettingsDocument
    $rules = @(Get-FirewallRules $document)
    $matching = @(Get-MatchingDenyRules $document $RemoteIPv4)
    if ($Action -eq 'BlockIp') {
        if ($matching.Count -gt 0) {
            return [pscustomobject]@{ Passed = $true; Changed = $false; Action = $Action; RemoteIPv4 = $RemoteIPv4; RuleIds = @($matching | ForEach-Object { [string]$_.id }); Verification = 'A matching user-created Bitdefender deny rule already exists.' }
        }
        $numericIds = @($rules | ForEach-Object { $value = [uint64]0; if ([uint64]::TryParse([string]$_.id, [ref]$value)) { $value } })
        [uint64]$newValue = if ($numericIds.Count) { ($numericIds | Measure-Object -Maximum).Maximum + 1 } else { 1 }
        $newId = [string]$newValue
        $document.Json.settings.Firewall.Backup.Settings.Rules.list = @($rules) + (New-FirewallDenyRule $newId $RemoteIPv4)
        $backup = Write-FirewallSettingsDocument $document ("before-add-{0}" -f $newId)
        return [pscustomobject]@{ Passed = $true; Changed = $true; Action = $Action; RemoteIPv4 = $RemoteIPv4; RuleIds = @($newId); BackupPath = $backup; Verification = Wait-FirewallRuleState @($newId) $true }
    }

    $selected = if ($RuleId) { @($matching | Where-Object { [string]$_.id -eq $RuleId }) } else { @($matching) }
    if ($selected.Count -eq 0) {
        return [pscustomobject]@{ Passed = $true; Changed = $false; Action = $Action; RemoteIPv4 = $RemoteIPv4; RuleIds = @(); Verification = 'No matching user-created Bitdefender deny rule exists.' }
    }
    $removeIds = @($selected | ForEach-Object { [string]$_.id })
    $document.Json.settings.Firewall.Backup.Settings.Rules.list = @($rules | Where-Object { [string]$_.id -notin $removeIds })
    $backup = Write-FirewallSettingsDocument $document ("before-remove-{0}" -f ($removeIds -join '-'))
    return [pscustomobject]@{ Passed = $true; Changed = $true; Action = $Action; RemoteIPv4 = $RemoteIPv4; RuleIds = $removeIds; BackupPath = $backup; Verification = Wait-FirewallRuleState $removeIds $false }
}

function Test-InteractiveAction {
    return $Action -in @('SetProtection', 'StartScan', 'StartVulnerabilityScan')
}

function Get-InteractiveUser {
    $user = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
    if (-not $user) { throw 'No interactive Windows user is logged on; this Bitdefender action cannot run in Session 0.' }
    return $user
}

function Add-WorkerArgument {
    param([Collections.Generic.List[string]]$List, [string]$Name, [string]$Value)
    if ($null -ne $Value -and $Value -ne '') { $List.Add("-$Name"); $List.Add($Value) }
}

function Quote-TaskArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    return '"' + ($Value -replace '"', '""') + '"'
}

function Set-RelayDirectoryAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$InteractiveSid,
        [Parameter(Mandatory = $true)][Security.AccessControl.FileSystemRights]$InteractiveRights
    )
    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $administratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $callerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($entry in @(
        [pscustomobject]@{ Sid = $systemSid; Rights = [Security.AccessControl.FileSystemRights]::FullControl },
        [pscustomobject]@{ Sid = $administratorsSid; Rights = [Security.AccessControl.FileSystemRights]::FullControl },
        [pscustomobject]@{ Sid = $callerSid; Rights = [Security.AccessControl.FileSystemRights]::FullControl },
        [pscustomobject]@{ Sid = $InteractiveSid; Rights = $InteractiveRights }
    )) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $entry.Sid,
            $entry.Rights,
            'ContainerInherit,ObjectInherit',
            'None',
            'Allow'
        )
        $acl.AddAccessRule($rule) | Out-Null
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-RelayWorkerAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$InteractiveSid
    )
    $systemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $administratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $callerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($entry in @(
        [pscustomobject]@{ Sid = $systemSid; Rights = [Security.AccessControl.FileSystemRights]::FullControl },
        [pscustomobject]@{ Sid = $administratorsSid; Rights = [Security.AccessControl.FileSystemRights]::FullControl },
        [pscustomobject]@{ Sid = $callerSid; Rights = [Security.AccessControl.FileSystemRights]::FullControl },
        [pscustomobject]@{ Sid = $InteractiveSid; Rights = [Security.AccessControl.FileSystemRights]::ReadAndExecute }
    )) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($entry.Sid, $entry.Rights, 'Allow')
        $acl.AddAccessRule($rule) | Out-Null
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Invoke-InInteractiveSession {
    $interactiveUser = Get-InteractiveUser
    $interactiveSid = (New-Object Security.Principal.NTAccount($interactiveUser)).Translate([Security.Principal.SecurityIdentifier])
    $jobId = [guid]::NewGuid().ToString('N')
    $jobDirectory = Join-Path $script:OutputRoot $jobId
    $workerScript = Join-Path $jobDirectory 'worker.ps1'
    $resultDirectory = Join-Path $jobDirectory 'result'
    $workerResult = Join-Path $resultDirectory 'result.json'
    $taskName = "Bitdefender-Orchestrator-$jobId"
    $rootFolder = $null
    try {
        New-Item -Path $jobDirectory -ItemType Directory -Force | Out-Null
        New-Item -Path $resultDirectory -ItemType Directory -Force | Out-Null
        Set-RelayDirectoryAcl -Path $jobDirectory -InteractiveSid $interactiveSid -InteractiveRights ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
        Set-RelayDirectoryAcl -Path $resultDirectory -InteractiveSid $interactiveSid -InteractiveRights ([Security.AccessControl.FileSystemRights]::Modify)
        Copy-Item -LiteralPath $script:SelfPath -Destination $workerScript -Force
        Set-RelayWorkerAcl -Path $workerScript -InteractiveSid $interactiveSid

        $argsList = New-Object Collections.Generic.List[string]
        $argsList.Add('-NoLogo'); $argsList.Add('-NoProfile'); $argsList.Add('-NonInteractive'); $argsList.Add('-ExecutionPolicy'); $argsList.Add('Bypass')
        $argsList.Add('-File'); $argsList.Add((Quote-TaskArgument $workerScript)); $argsList.Add('-Worker')
        Add-WorkerArgument $argsList 'Action' $Action
        if (Test-BoundParameter 'Feature') { Add-WorkerArgument $argsList 'Feature' $Feature }
        if (Test-BoundParameter 'State') { Add-WorkerArgument $argsList 'State' $State }
        if (Test-BoundParameter 'ScanType') { Add-WorkerArgument $argsList 'ScanType' $ScanType }
        if (Test-BoundParameter 'RemoteIPv4') { Add-WorkerArgument $argsList 'RemoteIPv4' $RemoteIPv4 }
        if (Test-BoundParameter 'RuleId') { Add-WorkerArgument $argsList 'RuleId' $RuleId }
        $argsList.Add('-ResultPath'); $argsList.Add((Quote-TaskArgument $workerResult))

        $scheduler = New-Object -ComObject 'Schedule.Service'; $scheduler.Connect(); $rootFolder = $scheduler.GetFolder('\'); $definition = $scheduler.NewTask(0)
        $definition.RegistrationInfo.Description = "Temporary Bitdefender orchestration action: $Action"
        $definition.Settings.Enabled = $true; $definition.Settings.AllowDemandStart = $true; $definition.Settings.StartWhenAvailable = $true; $definition.Settings.ExecutionTimeLimit = 'PT4M'
        $definition.Principal.UserId = $interactiveUser; $definition.Principal.LogonType = 3; $definition.Principal.RunLevel = 0
        $taskAction = $definition.Actions.Create(0); $taskAction.Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"; $taskAction.Arguments = $argsList -join ' '; $taskAction.WorkingDirectory = $jobDirectory
        $registered = $rootFolder.RegisterTaskDefinition($taskName, $definition, 6, $null, $null, 3, $null); $registered.Run($null) | Out-Null
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        do { Start-Sleep -Milliseconds 500 } until ((Test-Path -LiteralPath $workerResult) -or (Get-Date) -ge $deadline)
        if (-not (Test-Path -LiteralPath $workerResult)) { throw "Interactive action timed out after $TimeoutSeconds seconds." }
        $json = Get-Content -LiteralPath $workerResult -Raw
        $lastPath = Join-Path $script:OutputRoot ("last-{0}.json" -f $Action.ToLowerInvariant())
        [IO.File]::WriteAllText($lastPath, $json, (New-Object Text.UTF8Encoding($false)))
        if ($ResultPath) {
            $resultParent = Split-Path -Parent $ResultPath
            if ($resultParent -and -not (Test-Path -LiteralPath $resultParent)) {
                New-Item -Path $resultParent -ItemType Directory -Force | Out-Null
            }
            [IO.File]::WriteAllText($ResultPath, $json, (New-Object Text.UTF8Encoding($false)))
        }
        Write-Output $json
        if (-not ($json | ConvertFrom-Json).Passed) { exit 1 }
    }
    finally {
        if ($rootFolder) { try { $rootFolder.DeleteTask($taskName, 0) } catch {} }
        Start-Sleep -Milliseconds 250
        try { Remove-Item -LiteralPath $jobDirectory -Recurse -Force } catch {}
    }
}

function Invoke-AllowlistedAction {
    $mutex = New-Object Threading.Mutex($false, 'Global\BitdefenderOrchestrator')
    $acquired = $false
    try {
        $acquired = $mutex.WaitOne([timespan]::FromSeconds(10))
        if (-not $acquired) { throw 'Another Bitdefender orchestration action is already running.' }
        switch ($Action) {
            'GetCapabilities' { return Get-Capabilities }
            'SetProtection' { return Invoke-SetProtection }
            'StartScan' { return Invoke-StartScan }
            'StartVulnerabilityScan' { return Invoke-StartVulnerabilityScan }
            'BlockIp' { return Invoke-FirewallIpAction }
            'UnblockIp' { return Invoke-FirewallIpAction }
        }
    }
    finally {
        if ($acquired) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

try {
    Assert-ValidRequest
    $sessionId = (Get-Process -Id $PID).SessionId
    if (-not $Worker -and (Test-InteractiveAction) -and ($sessionId -eq 0 -or $ForceDispatch)) {
        Invoke-InInteractiveSession
        exit 0
    }
    Write-Result -InputObject (Invoke-AllowlistedAction) -Path $ResultPath
    exit 0
}
catch {
    Write-Result -InputObject ([pscustomobject]@{ Passed = $false; Changed = $false; Action = $Action; Timestamp = (Get-Date).ToString('o'); Error = $_.Exception.Message }) -Path $ResultPath
    exit 1
}
