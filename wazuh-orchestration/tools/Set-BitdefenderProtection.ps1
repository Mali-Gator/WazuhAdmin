<#
.SYNOPSIS
Controls four Bitdefender protection settings with inbox Windows PowerShell and
the Windows UI Automation assemblies.

.EXAMPLE
.\Set-BitdefenderProtection.ps1 -Setting Firewall -State Off

.EXAMPLE
.\Set-BitdefenderProtection.ps1 -Setting Antispam -State Cycle

.NOTES
Requires an interactive user desktop. A Windows service in Session 0, including
a default Wazuh agent service, cannot directly access the Bitdefender window.
No Python, Codex runtime, debugger, or third-party module is required.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('RansomwareRemediation', 'CryptominingProtection', 'Firewall', 'Antispam')]
    [string]$Setting,

    [Parameter(Mandatory = $true)]
    [ValidateSet('On', 'Off', 'Status', 'Cycle')]
    [string]$State
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$settingMap = @{
    RansomwareRemediation = '28'
    CryptominingProtection = '33'
    Firewall = '2'
    Antispam = '3'
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
        $deadline = (Get-Date).AddSeconds(20)
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

    if ($protection) {
        $invoke = $protection.GetCurrentPattern(
            [System.Windows.Automation.InvokePattern]::Pattern
        )
        $invoke.Invoke()
        Start-Sleep -Milliseconds 800
    }
}

function Get-SettingCheckbox {
    param([Parameter(Mandatory = $true)][string]$AutomationId)

    $window = Get-BitdefenderWindow
    $windowBounds = $window.Current.BoundingRectangle
    $condition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
        $AutomationId
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
        throw "Bitdefender checkbox $AutomationId was not found on the Protection screen."
    }

    return $checkbox
}

function Get-UiState {
    $checkbox = Get-SettingCheckbox -AutomationId $settingMap[$Setting]
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
                return [pscustomobject]@{
                    Path = $candidate.FullName
                    Json = $json
                }
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
    switch ($Setting) {
        'RansomwareRemediation' {
            $settings = Find-DesktopSettingsJson
            return [pscustomobject]@{
                Path = $settings.Path
                Value = [int]$settings.Json.settings.RansomwareRemediation.Settings.module_state
                Meaning = if ([int]$settings.Json.settings.RansomwareRemediation.Settings.module_state -eq 1) { 'On' } else { 'Off' }
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
                Meaning = (Get-UiState)
                LastWriteUtc = $file.LastWriteTimeUtc.ToString('o')
                Length = $file.Length
            }
        }
    }
}

function Get-Snapshot {
    return [pscustomobject]@{
        Timestamp = (Get-Date).ToString('o')
        Setting = $Setting
        UiState = Get-UiState
        Artifact = Get-ArtifactState
    }
}

function Set-UiState {
    param([Parameter(Mandatory = $true)][ValidateSet('On', 'Off')][string]$DesiredState)

    $before = Get-Snapshot
    if ($before.UiState -eq $DesiredState) {
        return $before
    }

    $checkbox = Get-SettingCheckbox -AutomationId $settingMap[$Setting]
    $invoke = $checkbox.GetCurrentPattern(
        [System.Windows.Automation.InvokePattern]::Pattern
    )
    $invoke.Invoke()

    $deadline = (Get-Date).AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 500
        $snapshot = Get-Snapshot
        $artifactMatches = $snapshot.Artifact.Meaning -eq $DesiredState
        if ($snapshot.UiState -eq $DesiredState -and $artifactMatches) {
            return $snapshot
        }
    } until ((Get-Date) -ge $deadline)

    throw "Bitdefender did not reach $DesiredState for $Setting within 15 seconds. Last observation: $($snapshot | ConvertTo-Json -Depth 6 -Compress)"
}

Open-ProtectionOverview
$initial = Get-Snapshot

if ($State -eq 'Status') {
    $initial | ConvertTo-Json -Depth 8
    exit 0
}

if ($State -eq 'Cycle') {
    $oppositeState = if ($initial.UiState -eq 'On') { 'Off' } else { 'On' }
    $opposite = Set-UiState -DesiredState $oppositeState
    $restored = Set-UiState -DesiredState $initial.UiState
    [pscustomobject]@{
        Setting = $Setting
        Requested = 'Cycle'
        Initial = $initial
        Opposite = $opposite
        Restored = $restored
        Passed = ($restored.UiState -eq $initial.UiState -and $restored.Artifact.Meaning -eq $initial.Artifact.Meaning)
    } | ConvertTo-Json -Depth 10
    exit 0
}

$result = Set-UiState -DesiredState $State
[pscustomobject]@{
    Setting = $Setting
    Requested = $State
    Result = $result
    Passed = ($result.UiState -eq $State -and $result.Artifact.Meaning -eq $State)
} | ConvertTo-Json -Depth 10
