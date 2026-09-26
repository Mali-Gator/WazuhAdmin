<#
.SYNOPSIS
Sets Bitdefender protection switches through Windows UI Automation.
.DESCRIPTION
Requires Windows PowerShell 5.1 and an unlocked interactive desktop.
Supports the original overview switches, Advanced Threat Defense, Exploit
Detection, and Antivirus > Advanced switches. Uses exact English UI labels
for new settings; fails if a control cannot be identified uniquely.
UI state is the verification source, not proof of the engine's internal state.
No service, driver, registry, or protected configuration changes are made.
.EXAMPLE
.\Set-BitdefenderProtection.ps1 -Setting AdvancedThreatDefense -State Off
.EXAMPLE
.\Set-BitdefenderProtection.ps1 -Setting ExploitDetection -State Off
.EXAMPLE
.\Set-BitdefenderProtection.ps1 -Setting ScanCommandLine -State On
.EXAMPLE
.\Set-BitdefenderProtection.ps1 -Setting ScanScripts -State Status -CurrentPage -ListControls
.NOTES
The Bitdefender window is launched and brought to the foreground as needed.
-CurrentPage and -ListControls are optional troubleshooting tools.
Bitdefender password, elevation, or disable-duration dialogs must be completed
manually. The script waits up to ConfirmationTimeoutSeconds (default 60).
Cycle temporarily changes the setting and attempts restoration in finally.
Do not run concurrently with another instance or interact with other pages.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        'RansomwareRemediation', 'CryptominingProtection', 'Firewall', 'Antispam',
        'AdvancedThreatDefense', 'ExploitDetection', 'BitdefenderShield',
        'ScanOnlyApplications', 'ScanPotentiallyUnwantedApplications',
        'ScanProcessMemory', 'ScanCommandLine', 'ScanScripts', 'ScanNetworkShares',
        'ScanArchives', 'ScanBootSectors', 'ScanOnlyNewAndModifiedFiles',
        'ScanKeyloggers', 'EarlyBootScan'
    )]
    [string]$Setting,

    [Parameter(Mandatory = $true)]
    [ValidateSet('On', 'Off', 'Status', 'Cycle')]
    [string]$State,

    [switch]$CurrentPage,
    [switch]$ListControls,

    # Optional override from -ListControls for builds with unnamed switches.
    # Only use an ID you have confirmed belongs to the intended switch.
    [string]$AutomationId,

    [ValidateRange(5, 600)]
    [int]$ConfirmationTimeoutSeconds = 60
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$settingMap = @{
    RansomwareRemediation = @{ Page = 'Overview'; Id = '28'; Labels = @('Ransomware Remediation') }
    CryptominingProtection = @{ Page = 'Overview'; Id = '33'; Labels = @('Cryptomining Protection') }
    Firewall = @{ Page = 'Overview'; Id = '2'; Labels = @('Firewall') }
    Antispam = @{ Page = 'Overview'; Id = '3'; Labels = @('Antispam') }
    AdvancedThreatDefense = @{ Page = 'ThreatDefense'; Id = 'idAtcState'; Labels = @('Advanced Threat Defense', 'Bitdefender Advanced Threat Defense') }
    ExploitDetection = @{ Page = 'ThreatDefense'; Id = 'idGemmaState'; Labels = @('Exploit Detection') }
    BitdefenderShield = @{ Page = 'Antivirus'; Id = 'real_time_protection'; Labels = @('Bitdefender Shield') }
    ScanOnlyApplications = @{ Page = 'Antivirus'; Id = 'scan_only_apps'; Labels = @('Scan only applications') }
    ScanPotentiallyUnwantedApplications = @{ Page = 'Antivirus'; Id = 'scan_pua'; Labels = @('Scan potentially unwanted applications') }
    ScanProcessMemory = @{ Page = 'Antivirus'; Id = 'scan_process_memory'; Labels = @('Scan process memory') }
    ScanCommandLine = @{ Page = 'Antivirus'; Id = 'scan_command_lines'; Labels = @('Scan command line') }
    ScanScripts = @{ Page = 'Antivirus'; Id = 'scan_scripts'; Labels = @('Scan scripts') }
    ScanNetworkShares = @{ Page = 'Antivirus'; Id = 'scan_networks'; Labels = @('Scan network shares') }
    ScanArchives = @{ Page = 'Antivirus'; Id = 'scan_archive_contents'; Labels = @('Scan archives') }
    ScanBootSectors = @{ Page = 'Antivirus'; Id = 'scan_boot_sectors'; Labels = @('Scan boot sectors') }
    ScanOnlyNewAndModifiedFiles = @{ Page = 'Antivirus'; Id = 'scan_different_files'; Labels = @('Scan only new and modified files') }
    ScanKeyloggers = @{ Page = 'Antivirus'; Id = 'scan_keyloggers'; Labels = @('Scan keyloggers') }
    EarlyBootScan = @{ Page = 'Antivirus'; Id = 'scan_early_boot'; Labels = @('Early boot scan') }
}
$definition = $settingMap[$Setting]

# WhatIf does not open or navigate the Bitdefender UI.
if ($WhatIfPreference) {
    [void]$PSCmdlet.ShouldProcess("Bitdefender / $Setting", "$State (page: $($definition.Page))")
    return
}

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

if (-not ('BitdefenderNativeMouse' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class BitdefenderNativeMouse {
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr window, int command);
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr window);
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")]
    public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extraInfo);
    public const uint LeftDown = 0x0002;
    public const uint LeftUp = 0x0004;
}
'@
}

# Keep window activation in a separate type: an earlier script version may
# already have loaded BitdefenderNativeMouse in this PowerShell session.
if (-not ('BitdefenderWindowFocus20260926' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class BitdefenderWindowFocus20260926 {
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr window, int command);
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr window);
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
}
'@
}

if (-not ('BitdefenderWindowClose20260926' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class BitdefenderWindowClose20260926 {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")]
    public static extern bool IsWindow(IntPtr window);
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr window);
}
'@
}

function Get-Elements {
    param($Root)
    $Root.FindAll(
        [System.Windows.Automation.TreeScope]::Descendants,
        [System.Windows.Automation.Condition]::TrueCondition
    ) | ForEach-Object { $_ }
}

function Get-Pattern {
    param($Element, $Pattern)
    $value = $null
    if ($Element.TryGetCurrentPattern($Pattern, [ref]$value)) { return $value }
    return $null
}

function Test-Visible {
    param($Element)
    $bounds = $Element.Current.BoundingRectangle
    return (-not $Element.Current.IsOffscreen -and $bounds.Width -gt 0 -and $bounds.Height -gt 0)
}

function Get-BitdefenderWindow {
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $deadline = (Get-Date).AddSeconds(20)
    $launched = $false
    do {
        $windows = @($root.FindAll(
            [System.Windows.Automation.TreeScope]::Children,
            [System.Windows.Automation.Condition]::TrueCondition
        ) | Where-Object { $_.Current.Name -eq 'Bitdefender Security Center' })
        if ($windows.Count -eq 1) { return $windows[0] }
        if ($windows.Count -gt 1) { throw 'Multiple Bitdefender windows found. Close extra windows and retry.' }
        if (-not $launched) {
            $path = 'C:\Program Files\Bitdefender\Bitdefender Security App\seccenter.exe'
            if (-not (Test-Path -LiteralPath $path)) { throw "Bitdefender was not found at $path. Open it manually and retry." }
            # Visible UI is required for this script's explicitly interactive operation.
            Start-Process -FilePath $path
            $launched = $true
        }
        Start-Sleep -Milliseconds 300
    } while ((Get-Date) -lt $deadline)
    throw 'Bitdefender window unavailable. Run in the signed-in user desktop, not a service session.'
}

function Focus-BitdefenderWindow {
    $window = Get-BitdefenderWindow
    $handle = [IntPtr]$window.Current.NativeWindowHandle
    if ($handle -eq [IntPtr]::Zero) { throw 'Bitdefender did not expose a native window handle.' }
    [void][BitdefenderWindowFocus20260926]::ShowWindow($handle, 9) # SW_RESTORE
    [void][BitdefenderWindowFocus20260926]::SetForegroundWindow($handle)
    Start-Sleep -Milliseconds 200
    if ([BitdefenderWindowFocus20260926]::GetForegroundWindow() -ne $handle) {
        $window.SetFocus()
        [void][BitdefenderWindowFocus20260926]::SetForegroundWindow($handle)
        Start-Sleep -Milliseconds 200
    }
    if ([BitdefenderWindowFocus20260926]::GetForegroundWindow() -ne $handle) {
        throw 'Bitdefender could not be brought to the foreground; no mouse input was sent.'
    }
    return $window
}

function Close-BitdefenderWindow {
    # WM_CLOSE asks the app to close its UI; it does not terminate services.
    # Discover the current window without calling Get-BitdefenderWindow, which
    # would launch a new window if the user had already closed it.
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $windows = @($root.FindAll(
        [System.Windows.Automation.TreeScope]::Children,
        [System.Windows.Automation.Condition]::TrueCondition
    ) | Where-Object { $_.Current.Name -eq 'Bitdefender Security Center' })
    if ($windows.Count -eq 0) { return }
    if ($windows.Count -ne 1) { throw 'Could not uniquely identify the Bitdefender window to close.' }
    $handle = [IntPtr]$windows[0].Current.NativeWindowHandle
    if ($handle -eq [IntPtr]::Zero) { throw 'Bitdefender did not expose a native window handle for closing.' }
    if (-not [BitdefenderWindowClose20260926]::PostMessage($handle, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)) {
        throw 'Bitdefender did not accept the window-close request.'
    }
    $deadline = (Get-Date).AddSeconds(5)
    do {
        if (-not [BitdefenderWindowClose20260926]::IsWindow($handle) -or
            -not [BitdefenderWindowClose20260926]::IsWindowVisible($handle)) { return }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    throw 'Bitdefender remained visible after the window-close request.'
}

function Invoke-Control {
    param($Element, [switch]$ForceMouseClick)
    if (-not $Element.Current.IsEnabled) { throw "Control is disabled: $($Element.Current.Name)" }
    if (-not $ForceMouseClick) {
        $select = Get-Pattern $Element ([System.Windows.Automation.SelectionItemPattern]::Pattern)
        if ($select) { $select.Select(); return }
        $invoke = Get-Pattern $Element ([System.Windows.Automation.InvokePattern]::Pattern)
        if ($invoke) { $invoke.Invoke(); return }
    }

    # Daybreak exposes module actions such as Open as Text controls without an
    # InvokePattern. Click only the center of the exact, already-matched element.
    $bounds = $Element.Current.BoundingRectangle
    if ($Element.Current.IsOffscreen -or $bounds.Width -le 0 -or $bounds.Height -le 0) {
        throw "Control has no supported action and is not clickable: $($Element.Current.Name)"
    }
    $windowBounds = (Focus-BitdefenderWindow).Current.BoundingRectangle
    $x = [int]($bounds.X + ($bounds.Width / 2))
    $y = [int]($bounds.Y + ($bounds.Height / 2))
    if ($x -lt $windowBounds.X -or $x -ge ($windowBounds.X + $windowBounds.Width) -or
        $y -lt $windowBounds.Y -or $y -ge ($windowBounds.Y + $windowBounds.Height)) {
        throw "Refusing to click outside the Bitdefender window: $($Element.Current.Name)"
    }
    if (-not [BitdefenderNativeMouse]::SetCursorPos($x, $y)) {
        throw "Could not position the mouse over: $($Element.Current.Name)"
    }
    [BitdefenderNativeMouse]::mouse_event([BitdefenderNativeMouse]::LeftDown, 0, 0, 0, [UIntPtr]::Zero)
    [BitdefenderNativeMouse]::mouse_event([BitdefenderNativeMouse]::LeftUp, 0, 0, 0, [UIntPtr]::Zero)
}

function Get-NamedAction {
    param($Root, [string[]]$Names)
    @(Get-Elements $Root | Where-Object {
        ($Names -contains ([string]$_.Current.Name).Trim()) -and (Test-Visible $_) -and
        ((Get-Pattern $_ ([System.Windows.Automation.InvokePattern]::Pattern)) -or
         (Get-Pattern $_ ([System.Windows.Automation.SelectionItemPattern]::Pattern)))
    })
}

function Wait-NamedAction {
    param($Root, [string[]]$Names)
    $deadline = (Get-Date).AddSeconds(8)
    do {
        $matches = @(Get-NamedAction $Root $Names)
        if ($matches.Count -eq 1) { return $matches[0] }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    throw "Could not uniquely identify '$($Names -join ' / ')'. Open the required page manually and use -CurrentPage."
}

function Wait-ActionByNameAndId {
    param($Root, [string]$Name, [string]$AutomationId, $ControlType)
    $deadline = (Get-Date).AddSeconds(8)
    do {
        $matches = @(Get-Elements $Root | Where-Object {
            ([string]$_.Current.Name).Trim() -eq $Name -and
            $_.Current.AutomationId -eq $AutomationId -and
            ($null -eq $ControlType -or $_.Current.ControlType -eq $ControlType) -and
            (Test-Visible $_)
        })
        if ($matches.Count -eq 1) { return $matches[0] }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    throw "Could not uniquely identify '$Name' (AutomationId $AutomationId)."
}

function Open-Module {
    param($Window, [string]$ModuleName)
    $moduleIds = @{
        'Antivirus' = '1'
        'Advanced Threat Defense' = '15'
    }
    $moduleId = $moduleIds[$ModuleName]
    if ($moduleId) {
        $directActions = @(Get-Elements $Window | Where-Object {
            ([string]$_.Current.Name).Trim() -eq 'Open' -and
            $_.Current.AutomationId -eq $moduleId -and
            (Test-Visible $_)
        })
        if ($directActions.Count -eq 1) {
            Invoke-Control $directActions[0]
            return
        }
        if ($directActions.Count -gt 1) {
            throw "Found multiple Open controls for $ModuleName (AutomationId $moduleId)."
        }
    }

    # Locate the module's own card before selecting its Open/Settings button.
    # Never select the first generic Open button on the whole screen.
    $labels = @(Get-Elements $Window | Where-Object {
        ([string]$_.Current.Name).Trim() -eq $ModuleName -and (Test-Visible $_)
    })
    $found = @{}
    foreach ($label in $labels) {
        $node = $label
        # Bitdefender/Daybreak has used both a button inside the card and an
        # invokable card container. Walk far enough to cover either layout.
        for ($level = 0; $level -lt 10 -and $null -ne $node; $level++) {
            if ([System.Windows.Automation.Automation]::Compare($node, $Window)) { break }

            $nodeSelect = Get-Pattern $node ([System.Windows.Automation.SelectionItemPattern]::Pattern)
            $nodeInvoke = Get-Pattern $node ([System.Windows.Automation.InvokePattern]::Pattern)
            if ($nodeSelect -or $nodeInvoke) {
                $found[($node.GetRuntimeId() -join '.')] = $node
                break
            }

            $actions = @(Get-NamedAction $node @('Open', 'Settings'))
            if ($actions.Count -eq 1) {
                $found[($actions[0].GetRuntimeId() -join '.')] = $actions[0]
                break
            }
            if ($actions.Count -gt 1) { break }
            $node = [System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($node)
        }
    }
    if ($found.Count -ne 1) {
        throw "Could not identify the $ModuleName card. Open it manually and use -CurrentPage."
    }
    Invoke-Control -Element (@($found.Values)[0])
}

function Open-SettingPage {
    if ($CurrentPage) { return }
    $window = Get-BitdefenderWindow
    $readyDeadline = (Get-Date).AddSeconds(30)
    do {
        $elements = @(Get-Elements $window)
        $serviceError = @($elements | Where-Object {
            $_.Current.AutomationId -eq 'idMsgTitle' -and
            ([string]$_.Current.Name) -eq 'Communication failure'
        })
        if ($serviceError.Count -gt 0) {
            throw 'Bitdefender reports a communication failure with its App Service. The app must reconnect before settings can be changed.'
        }
        $navigation = @($elements | Where-Object {
            $_.Current.AutomationId -eq 'liProtection' -and (Test-Visible $_)
        })
        if ($navigation.Count -eq 1) { break }
        Start-Sleep -Milliseconds 350
    } while ((Get-Date) -lt $readyDeadline)
    if ($navigation.Count -ne 1) { throw 'Bitdefender did not load its Protection navigation within 30 seconds.' }
    Invoke-Control -Element $navigation[0] -ForceMouseClick
    Start-Sleep -Milliseconds 800
    switch ($definition.Page) {
        'ThreatDefense' {
            Open-Module $window 'Advanced Threat Defense'
            Invoke-Control -Element (Wait-ActionByNameAndId $window 'Settings' '' ([System.Windows.Automation.ControlType]::RadioButton)) -ForceMouseClick
        }
        'Antivirus' {
            Open-Module $window 'Antivirus'
            Invoke-Control -Element (Wait-ActionByNameAndId $window 'Advanced' 'idTabButton' ([System.Windows.Automation.ControlType]::RadioButton)) -ForceMouseClick
        }
    }
    Start-Sleep -Milliseconds 500
    if ($definition.Page -ne 'Overview' -and $definition.Id) {
        # Daybreak updates the page asynchronously after a tab is selected.
        # Wait for the requested switch rather than assuming 500 ms is enough.
        $deadline = (Get-Date).AddSeconds(12)
        do {
            $loaded = @(Get-Switches (Get-BitdefenderWindow) | Where-Object {
                $_.Current.AutomationId -eq $definition.Id
            })
            if ($loaded.Count -eq 1) { return }
            Start-Sleep -Milliseconds 300
        } while ((Get-Date) -lt $deadline)
    }
}

function Get-Switches {
    param($Root)
    @(Get-Elements $Root | Where-Object {
        Get-Pattern $_ ([System.Windows.Automation.TogglePattern]::Pattern)
    })
}

function Get-SettingCheckbox {
    $window = Get-BitdefenderWindow
    $switches = @(Get-Switches $window)
    $id = if ($AutomationId) { $AutomationId } else { $definition.Id }
    $matches = @()
    if ($id) {
        $matches = @($switches | Where-Object { $_.Current.AutomationId -eq $id })
    } else {
        $matches = @($switches | Where-Object {
            $labelledBy = $_.Current.LabeledBy
            ($definition.Labels -contains ([string]$_.Current.Name).Trim()) -or
            ($null -ne $labelledBy -and $definition.Labels -contains ([string]$labelledBy.Current.Name).Trim())
        })
        if ($matches.Count -eq 0) {
            # Some builds expose an unnamed switch next to a separate text label.
            # Accept only a small ancestor row containing exactly one switch and
            # no other known setting labels. Never guess from screen coordinates.
            $found = @{}
            $labels = @(Get-Elements $window | Where-Object {
                $definition.Labels -contains ([string]$_.Current.Name).Trim()
            })
            $otherLabels = @($settingMap.Keys | Where-Object { $_ -ne $Setting } |
                ForEach-Object { $settingMap[$_].Labels })
            foreach ($label in $labels) {
                $node = [System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($label)
                for ($level = 0; $level -lt 3 -and $null -ne $node; $level++) {
                    if ([System.Windows.Automation.Automation]::Compare($node, $window)) { break }
                    $children = @(Get-Elements $node)
                    if (@($children | Where-Object { $otherLabels -contains ([string]$_.Current.Name).Trim() }).Count -gt 0) { break }
                    $rowSwitches = @(Get-Switches $node)
                    if ($rowSwitches.Count -eq 1) {
                        $found[($rowSwitches[0].GetRuntimeId() -join '.')] = $rowSwitches[0]
                        break
                    }
                    if ($rowSwitches.Count -gt 1) { break }
                    $node = [System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($node)
                }
            }
            $matches = @($found.Values)
        }
    }
    # Hidden duplicate pages sometimes remain in the automation tree.
    if ($matches.Count -gt 1) {
        $visible = @($matches | Where-Object { Test-Visible $_ })
        if ($visible.Count -eq 1) { $matches = $visible }
    }
    if ($matches.Count -ne 1) {
        $observedIds = @($switches | ForEach-Object { $_.Current.AutomationId } | Where-Object { $_ } | Sort-Object -Unique)
        $observedTabs = @(Get-Elements $window | Where-Object {
            $_.Current.ControlType -eq [System.Windows.Automation.ControlType]::RadioButton -and
            (Test-Visible $_)
        } | ForEach-Object { "$($_.Current.Name) [$($_.Current.AutomationId)]" } | Sort-Object -Unique)
        throw "Found $($matches.Count) matching switches for $Setting. Observed switch IDs: $($observedIds -join ', '). Observed tabs: $($observedTabs -join ', '). Open the intended page and retry with -CurrentPage if needed."
    }
    $control = $matches[0]
    if (-not (Test-Visible $control)) {
        $scroll = Get-Pattern $control ([System.Windows.Automation.ScrollItemPattern]::Pattern)
        if ($scroll) {
            $scroll.ScrollIntoView()
            Start-Sleep -Milliseconds 200
        }
    }
    if (-not (Test-Visible $control)) {
        throw "$Setting is not visible. Scroll it into view, then retry with -CurrentPage."
    }
    return $control
}

function Get-UiState {
    $control = Get-SettingCheckbox
    $toggle = Get-Pattern $control ([System.Windows.Automation.TogglePattern]::Pattern)
    switch ($toggle.Current.ToggleState.ToString()) {
        'On' { return 'On' }
        'Off' { return 'Off' }
        default { throw "$Setting has an indeterminate state; no change was attempted." }
    }
}

function Get-Snapshot {
    [pscustomobject]@{
        Timestamp = (Get-Date).ToString('o')
        Setting = $Setting
        UiState = Get-UiState
        VerificationSource = 'UIAutomation.ToggleState'
    }
}

function Test-ModalDialog {
    $window = Get-BitdefenderWindow
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $windows = @($root.FindAll(
        [System.Windows.Automation.TreeScope]::Children,
        [System.Windows.Automation.Condition]::TrueCondition
    ) | Where-Object { $_.Current.ProcessId -eq $window.Current.ProcessId })
    foreach ($element in @($windows) + @(Get-Elements $window)) {
        $pattern = Get-Pattern $element ([System.Windows.Automation.WindowPattern]::Pattern)
        if ($pattern -and $pattern.Current.IsModal) { return $true }
    }
    return $false
}

function Set-UiState {
    param([ValidateSet('On', 'Off')][string]$DesiredState)
    if ((Get-UiState) -eq $DesiredState) { return Get-Snapshot }
    $control = Get-SettingCheckbox
    if (-not $control.Current.IsEnabled) {
        throw "$Setting is disabled in the UI. Check its parent protection switch, account permissions, or Bitdefender policy."
    }
    # Preserve the original script's Invoke behavior where available.
    $invoke = Get-Pattern $control ([System.Windows.Automation.InvokePattern]::Pattern)
    if ($invoke) { $invoke.Invoke() }
    else {
        $toggle = Get-Pattern $control ([System.Windows.Automation.TogglePattern]::Pattern)
        $toggle.Toggle()
    }
    Write-Host "Waiting for $Setting = $DesiredState. Complete any Bitdefender confirmation, duration, or password dialog manually."
    $deadline = (Get-Date).AddSeconds($ConfirmationTimeoutSeconds)
    $consecutive = 0
    $lastObservation = 'No observation yet'
    do {
        Start-Sleep -Milliseconds 500
        try {
            $snapshot = Get-Snapshot
            $lastObservation = $snapshot.UiState
            $currentControl = Get-SettingCheckbox
            if ($snapshot.UiState -eq $DesiredState -and $currentControl.Current.IsEnabled -and -not (Test-ModalDialog)) {
                $consecutive++
                if ($consecutive -ge 3) { return $snapshot }
            } else { $consecutive = 0 }
        } catch {
            $consecutive = 0
            $lastObservation = $_.Exception.Message
        }
    } while ((Get-Date) -lt $deadline)
    throw "Could not verify $Setting = $DesiredState within $ConfirmationTimeoutSeconds seconds. Last observation: $lastObservation. Check the app and any pending dialog before retrying."
}

$commandCompleted = $false
try {
    $navigationError = $null
    if ($ListControls) {
        try { Open-SettingPage }
        catch { $navigationError = $_.Exception.Message }
    } else {
        Open-SettingPage
    }

    if ($ListControls) {
    $window = Get-BitdefenderWindow
    $controlInventory = @(Get-Elements $window | ForEach-Object {
        $toggle = Get-Pattern $_ ([System.Windows.Automation.TogglePattern]::Pattern)
        $bounds = $_.Current.BoundingRectangle
        $parent = [System.Windows.Automation.TreeWalker]::ControlViewWalker.GetParent($_)
        [pscustomobject]@{
            Name = $_.Current.Name
            AutomationId = $_.Current.AutomationId
            ControlType = $_.Current.ControlType.ProgrammaticName
            Enabled = $_.Current.IsEnabled
            Visible = Test-Visible $_
            ToggleState = if ($toggle) { $toggle.Current.ToggleState.ToString() } else { $null }
            CanInvoke = [bool](Get-Pattern $_ ([System.Windows.Automation.InvokePattern]::Pattern))
            CanSelect = [bool](Get-Pattern $_ ([System.Windows.Automation.SelectionItemPattern]::Pattern))
            X = [math]::Round($bounds.X)
            Y = [math]::Round($bounds.Y)
            Width = [math]::Round($bounds.Width)
            Height = [math]::Round($bounds.Height)
            ParentName = if ($parent) { $parent.Current.Name } else { $null }
            ParentAutomationId = if ($parent) { $parent.Current.AutomationId } else { $null }
        }
    })
    if ($navigationError) {
        @([pscustomobject]@{
            Name = 'NAVIGATION ERROR'
            NavigationError = $navigationError
            AutomationId = $null
            ControlType = 'Diagnostic'
            ToggleState = $null
        }) + $controlInventory | ConvertTo-Json -Depth 5
    } else {
        $controlInventory | ConvertTo-Json -Depth 5
    }
        $commandCompleted = $true
        return
    }

    $initial = Get-Snapshot
    if ($State -eq 'Status') {
        $initial | ConvertTo-Json -Depth 5
        $commandCompleted = $true
        return
    }
    if (-not $PSCmdlet.ShouldProcess("Bitdefender / $Setting", "Set state to $State")) {
        $commandCompleted = $true
        return
    }

    if ($State -eq 'Cycle') {
    $oppositeState = if ($initial.UiState -eq 'On') { 'Off' } else { 'On' }
    $opposite = $null
    $restored = $null
    try {
        $opposite = Set-UiState $oppositeState
    } finally {
        try { $restored = Set-UiState $initial.UiState }
        catch { throw "RESTORATION FAILED for $Setting. Restore $($initial.UiState) manually. $($_.Exception.Message)" }
    }
    [pscustomobject]@{
        Setting = $Setting; Requested = 'Cycle'
        Initial = $initial; Opposite = $opposite; Restored = $restored
        Passed = ($restored.UiState -eq $initial.UiState)
    } | ConvertTo-Json -Depth 8
    } else {
        $result = Set-UiState $State
        [pscustomobject]@{
            Setting = $Setting; Requested = $State; Result = $result
            Passed = ($result.UiState -eq $State)
        } | ConvertTo-Json -Depth 8
    }
    $commandCompleted = $true
} finally {
    if ($commandCompleted) { Close-BitdefenderWindow }
}


