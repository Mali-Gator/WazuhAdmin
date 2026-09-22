<#
.SYNOPSIS
Self-contained Bitdefender action launched from the Wazuh Analytics portal.

.DESCRIPTION
When the Analytics portal invokes this through the Wazuh agent in Session 0,
this script creates a temporary
Windows scheduled task using TASK_LOGON_INTERACTIVE_TOKEN. The task runs this
same script in the currently logged-on user's session, operates Bitdefender via
Windows UI Automation, verifies the product artifact, and writes JSON results
for the Wazuh-side process to return.

Uses only Windows PowerShell 5.1, Task Scheduler COM, WMI/CIM, and .NET Framework
assemblies included with Windows. No Python, debugger, package, or third-party
binary is required.
#>
[CmdletBinding()]
param(
    [switch]$Worker,
    [switch]$ForceDispatch,
    [string]$ResultPath,
    [ValidateRange(15, 180)]
    [int]$TimeoutSeconds = 60
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:SettingName = 'RansomwareRemediation'
$script:ControlId = '28'
$script:DesiredState = 'Off'
$script:ActionSlug = 'disable-ransomware-remediation'
$script:SelfPath = $PSCommandPath

function ConvertTo-ResultJson {
    param([Parameter(Mandatory = $true)]$InputObject)
    return ($InputObject | ConvertTo-Json -Depth 12)
}

function Write-WorkerResult {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [string]$Path
    )

    $json = ConvertTo-ResultJson -InputObject $InputObject
    if ($Path) {
        $directory = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $directory)) {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        }
        [System.IO.File]::WriteAllText(
            $Path,
            $json,
            (New-Object System.Text.UTF8Encoding($false))
        )
    }
    Write-Output $json
}

function Get-BitdefenderWindow {
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $windows = $root.FindAll(
        [System.Windows.Automation.TreeScope]::Children,
        [System.Windows.Automation.Condition]::TrueCondition
    )
    $window = $windows |
        Where-Object { $_.Current.Name -eq 'Bitdefender Security Center' } |
        Select-Object -First 1

    if (-not $window) {
        $securityCenter = 'C:\Program Files\Bitdefender\Bitdefender Security App\seccenter.exe'
        if (-not (Test-Path -LiteralPath $securityCenter)) {
            throw "Bitdefender Security Center was not found at $securityCenter"
        }

        Start-Process -FilePath $securityCenter
        $deadline = (Get-Date).AddSeconds(25)
        do {
            Start-Sleep -Milliseconds 500
            $windows = $root.FindAll(
                [System.Windows.Automation.TreeScope]::Children,
                [System.Windows.Automation.Condition]::TrueCondition
            )
            $window = $windows |
                Where-Object { $_.Current.Name -eq 'Bitdefender Security Center' } |
                Select-Object -First 1
        } until ($window -or (Get-Date) -ge $deadline)
    }

    if (-not $window) {
        throw 'Bitdefender Security Center did not become available in the interactive desktop.'
    }
    return $window
}

function Open-ProtectionOverview {
    $window = Get-BitdefenderWindow
    $condition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
        'liProtection'
    )
    $protection = $window.FindFirst(
        [System.Windows.Automation.TreeScope]::Descendants,
        $condition
    )
    if (-not $protection) {
        throw 'The Bitdefender Protection navigation control was not found.'
    }

    $invoke = $protection.GetCurrentPattern(
        [System.Windows.Automation.InvokePattern]::Pattern
    )
    $invoke.Invoke()
    Start-Sleep -Milliseconds 800
}

function Get-SettingCheckbox {
    $window = Get-BitdefenderWindow
    $windowBounds = $window.Current.BoundingRectangle
    $condition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
        $script:ControlId
    )
    $matches = $window.FindAll(
        [System.Windows.Automation.TreeScope]::Descendants,
        $condition
    )
    $checkbox = $matches |
        Where-Object {
            $bounds = $_.Current.BoundingRectangle
            $_.Current.ControlType -eq [System.Windows.Automation.ControlType]::CheckBox -and
            $bounds.Width -gt 0 -and
            $bounds.X -ge $windowBounds.X -and
            $bounds.X -lt ($windowBounds.X + $windowBounds.Width)
        } |
        Select-Object -First 1

    if (-not $checkbox) {
        throw "Bitdefender checkbox $($script:ControlId) was not found."
    }
    return $checkbox
}

function Get-UiState {
    $checkbox = Get-SettingCheckbox
    $toggle = $checkbox.GetCurrentPattern(
        [System.Windows.Automation.TogglePattern]::Pattern
    )
    if ($toggle.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::On) {
        return 'On'
    }
    return 'Off'
}

function Find-DesktopSettingsJson {
    $dataRoot = 'C:\ProgramData\Bitdefender\Desktop\.settings\data'
    $candidates = Get-ChildItem -LiteralPath $dataRoot -Filter '.data' -File -Recurse -ErrorAction SilentlyContinue
    foreach ($candidate in $candidates) {
        try {
            $json = Get-Content -LiteralPath $candidate.FullName -Raw | ConvertFrom-Json
            if ($json.settings.RansomwareRemediation -or $json.settings.Firewall) {
                return [pscustomobject]@{ Path = $candidate.FullName; Json = $json }
            }
        }
        catch {
            continue
        }
    }
    throw 'The Bitdefender Desktop settings JSON could not be located.'
}

function Get-AntispamXmlPath {
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $preferred = "C:\Program Files\Bitdefender\Bitdefender Security\settings\as\$sid\antispam.xml"
    if (Test-Path -LiteralPath $preferred) {
        return $preferred
    }
    $fallback = Get-ChildItem -LiteralPath 'C:\Program Files\Bitdefender\Bitdefender Security\settings\as' -Filter 'antispam.xml' -File -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($fallback) {
        return $fallback.FullName
    }
    return $preferred
}

function Get-ArtifactState {
    switch ($script:SettingName) {
        'RansomwareRemediation' {
            $settings = Find-DesktopSettingsJson
            $value = [int]$settings.Json.settings.RansomwareRemediation.Settings.module_state
            return [pscustomobject]@{
                Path = $settings.Path
                Value = $value
                Meaning = if ($value -eq 1) { 'On' } else { 'Off' }
            }
        }
        'Firewall' {
            $settings = Find-DesktopSettingsJson
            $value = [bool]$settings.Json.settings.Firewall.Backup.Settings.Settings.enabled
            return [pscustomobject]@{
                Path = $settings.Path
                Value = $value
                Meaning = if ($value) { 'On' } else { 'Off' }
            }
        }
        'Antispam' {
            $path = Get-AntispamXmlPath
            if (-not (Test-Path -LiteralPath $path)) {
                return [pscustomobject]@{ Path = $path; Value = $null; Meaning = 'NotCreated' }
            }
            [xml]$xml = Get-Content -LiteralPath $path -Raw
            $value = [int]$xml.settings.ScanSpam
            return [pscustomobject]@{
                Path = $path
                Value = $value
                Meaning = if ($value -eq 1) { 'On' } else { 'Off' }
                LastWriteUtc = (Get-Item -LiteralPath $path).LastWriteTimeUtc.ToString('o')
            }
        }
        'CryptominingProtection' {
            $path = 'C:\Program Files\Bitdefender\Bitdefender Security\settings\vshield.xml'
            $file = Get-Item -LiteralPath $path
            return [pscustomobject]@{
                Path = $path
                Value = $null
                Meaning = Get-UiState
                LastWriteUtc = $file.LastWriteTimeUtc.ToString('o')
                Length = $file.Length
            }
        }
    }
}

function Get-Snapshot {
    return [pscustomobject]@{
        Timestamp = (Get-Date).ToString('o')
        Setting = $script:SettingName
        UiState = Get-UiState
        Artifact = Get-ArtifactState
    }
}

function Invoke-BitdefenderChange {
    Add-Type -AssemblyName UIAutomationClient
    Add-Type -AssemblyName UIAutomationTypes

    Open-ProtectionOverview
    $before = Get-Snapshot
    if ($before.UiState -eq $script:DesiredState -and $before.Artifact.Meaning -eq $script:DesiredState) {
        return [pscustomobject]@{
            Passed = $true
            Changed = $false
            Setting = $script:SettingName
            RequestedState = $script:DesiredState
            Before = $before
            After = $before
        }
    }

    $checkbox = Get-SettingCheckbox
    $invoke = $checkbox.GetCurrentPattern(
        [System.Windows.Automation.InvokePattern]::Pattern
    )
    $invoke.Invoke()

    $deadline = (Get-Date).AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 500
        $after = Get-Snapshot
        $artifactMatches = $after.Artifact.Meaning -eq $script:DesiredState
        $cryptoFileChanged = $true
        if ($script:SettingName -eq 'CryptominingProtection') {
            $cryptoFileChanged = $after.Artifact.LastWriteUtc -ne $before.Artifact.LastWriteUtc
        }
        if ($after.UiState -eq $script:DesiredState -and $artifactMatches -and $cryptoFileChanged) {
            return [pscustomobject]@{
                Passed = $true
                Changed = $true
                Setting = $script:SettingName
                RequestedState = $script:DesiredState
                Before = $before
                After = $after
            }
        }
    } until ((Get-Date) -ge $deadline)

    throw "Bitdefender did not reach $($script:DesiredState) for $($script:SettingName). Last state: $($after | ConvertTo-Json -Depth 8 -Compress)"
}

function Get-InteractiveUser {
    $user = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
    if (-not $user) {
        throw 'No interactive Windows user is logged on. The Bitdefender UI action cannot run in Session 0.'
    }
    return $user
}

function Invoke-InInteractiveSession {
    $interactiveUser = Get-InteractiveUser
    $baseDirectory = Join-Path $env:ProgramData 'Wazuh\bitdefender-actions'
    $jobId = [guid]::NewGuid().ToString('N')
    $jobDirectory = Join-Path $baseDirectory $jobId
    $workerScript = Join-Path $jobDirectory 'worker.ps1'
    $workerResult = Join-Path $jobDirectory 'result.json'
    $lastResult = Join-Path $baseDirectory ("last-{0}.json" -f $script:ActionSlug)
    $taskName = "Wazuh-Bitdefender-$($script:ActionSlug)-$jobId"

    New-Item -Path $jobDirectory -ItemType Directory -Force | Out-Null
    $acl = Get-Acl -LiteralPath $jobDirectory
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $interactiveUser,
        'Modify',
        'ContainerInherit,ObjectInherit',
        'None',
        'Allow'
    )
    $acl.SetAccessRule($accessRule)
    Set-Acl -LiteralPath $jobDirectory -AclObject $acl
    Copy-Item -LiteralPath $script:SelfPath -Destination $workerScript -Force

    $scheduler = New-Object -ComObject 'Schedule.Service'
    $scheduler.Connect()
    $rootFolder = $scheduler.GetFolder('\')
    $definition = $scheduler.NewTask(0)
    $definition.RegistrationInfo.Description = "Temporary Wazuh Analytics Bitdefender action: $($script:SettingName) $($script:DesiredState)"
    $definition.Settings.Enabled = $true
    $definition.Settings.AllowDemandStart = $true
    $definition.Settings.StartWhenAvailable = $true
    $definition.Settings.ExecutionTimeLimit = 'PT2M'
    $definition.Principal.UserId = $interactiveUser
    $definition.Principal.LogonType = 3
    $definition.Principal.RunLevel = 0

    $action = $definition.Actions.Create(0)
    $action.Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $action.Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$workerScript`" -Worker -ResultPath `"$workerResult`""
    $action.WorkingDirectory = $jobDirectory

    $registeredTask = $rootFolder.RegisterTaskDefinition(
        $taskName,
        $definition,
        6,
        $null,
        $null,
        3,
        $null
    )
    $registeredTask.Run($null) | Out-Null

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 500
    } until ((Test-Path -LiteralPath $workerResult) -or (Get-Date) -ge $deadline)

    if (-not (Test-Path -LiteralPath $workerResult)) {
        try { $rootFolder.DeleteTask($taskName, 0) } catch {}
        throw "The interactive Bitdefender task did not return a result within $TimeoutSeconds seconds."
    }

    $json = Get-Content -LiteralPath $workerResult -Raw
    if (-not (Test-Path -LiteralPath $baseDirectory)) {
        New-Item -Path $baseDirectory -ItemType Directory -Force | Out-Null
    }
    [System.IO.File]::WriteAllText(
        $lastResult,
        $json,
        (New-Object System.Text.UTF8Encoding($false))
    )

    try { $rootFolder.DeleteTask($taskName, 0) } catch {}
    Start-Sleep -Milliseconds 500
    try { Remove-Item -LiteralPath $jobDirectory -Recurse -Force } catch {}

    Write-Output $json
    $parsed = $json | ConvertFrom-Json
    if (-not $parsed.Passed) {
        exit 1
    }
}

if ($Worker) {
    try {
        $workerOutput = Invoke-BitdefenderChange
        Write-WorkerResult -InputObject $workerOutput -Path $ResultPath
        exit 0
    }
    catch {
        $failure = [pscustomobject]@{
            Passed = $false
            Changed = $false
            Setting = $script:SettingName
            RequestedState = $script:DesiredState
            Timestamp = (Get-Date).ToString('o')
            Error = $_.Exception.Message
        }
        Write-WorkerResult -InputObject $failure -Path $ResultPath
        exit 1
    }
}

$currentSession = (Get-Process -Id $PID).SessionId
if ($currentSession -eq 0 -or $ForceDispatch) {
    Invoke-InInteractiveSession
    exit 0
}

try {
    $directOutput = Invoke-BitdefenderChange
    Write-WorkerResult -InputObject $directOutput -Path $ResultPath
    exit 0
}
catch {
    $failure = [pscustomobject]@{
        Passed = $false
        Changed = $false
        Setting = $script:SettingName
        RequestedState = $script:DesiredState
        Timestamp = (Get-Date).ToString('o')
        Error = $_.Exception.Message
    }
    Write-WorkerResult -InputObject $failure -Path $ResultPath
    exit 1
}
