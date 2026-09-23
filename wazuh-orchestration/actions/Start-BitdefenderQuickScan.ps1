<#
.SYNOPSIS
Starts a Bitdefender Quick Scan from a Wazuh Analytics action.

.DESCRIPTION
Discovers the local Quick Scan task identifier from Bitdefender's native
ondemandal.xml configuration, launches the same odscanui.exe command captured
from the Bitdefender UI, and verifies that Bitdefender accepted the request.

When invoked by the Wazuh agent in Session 0, the script relays itself through
a temporary Windows scheduled task using TASK_LOGON_INTERACTIVE_TOKEN. It uses
only Windows PowerShell 5.1, Task Scheduler COM, CIM, and .NET Framework.

The action verifies scan initiation. Scan completion must be monitored from a
new XML report under Bitdefender's Profiles\Logs\system\<task-guid> directory.
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

$script:ScanType = 'Quick Scan'
$script:NormalizedTaskName = 'quickscan'
$script:ActionSlug = 'start-quick-scan'
$script:SelfPath = $PSCommandPath
$script:ScannerPath = 'C:\Program Files\Bitdefender\Bitdefender Security App\odscanui.exe'

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

function Normalize-TaskName {
    param([string]$Name)
    if ($null -eq $Name) { return '' }
    return (($Name -replace '[^A-Za-z0-9]', '').ToLowerInvariant())
}

function Get-ScanTaskDefinition {
    $candidates = New-Object System.Collections.Generic.List[string]
    $primary = 'C:\Program Files\Bitdefender\Bitdefender Security\ondemandal.xml'
    if (Test-Path -LiteralPath $primary) {
        $candidates.Add($primary)
    }

    $profilesRoot = 'C:\Program Files\Bitdefender\Bitdefender Security\ProfilesData\system'
    if (Test-Path -LiteralPath $profilesRoot) {
        Get-ChildItem -LiteralPath $profilesRoot -Filter 'ondemandal.xml' -File -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object { $candidates.Add($_.FullName) }
    }

    foreach ($path in ($candidates | Select-Object -Unique)) {
        try {
            [xml]$xml = Get-Content -LiteralPath $path -Raw
            foreach ($task in @($xml.settings.tasks.task)) {
                if ((Normalize-TaskName -Name ([string]$task.name)) -ne $script:NormalizedTaskName) {
                    continue
                }

                $taskId = [string]$task.taskId
                $parsedGuid = [guid]::Empty
                if (-not [guid]::TryParse($taskId, [ref]$parsedGuid)) {
                    throw "Bitdefender returned an invalid task identifier: $taskId"
                }

                return [pscustomobject]@{
                    TaskId = $parsedGuid.ToString()
                    Name = [string]$task.name
                    ConfigurationPath = $path
                }
            }
        }
        catch {
            continue
        }
    }

    throw "The Bitdefender $($script:ScanType) task was not found in ondemandal.xml."
}

function Get-ScannerProcesses {
    return @(Get-CimInstance -ClassName Win32_Process -Filter "Name='odscanui.exe'" -ErrorAction SilentlyContinue |
        ForEach-Object {
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

    $reportDirectory = Join-Path 'C:\ProgramData\Bitdefender\Desktop\Profiles\Logs\system' $TaskId
    if (-not (Test-Path -LiteralPath $reportDirectory)) {
        return $null
    }

    return Get-ChildItem -LiteralPath $reportDirectory -Filter '*.xml' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -ge $NotBeforeUtc } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
}

function Invoke-BitdefenderScan {
    if (-not (Test-Path -LiteralPath $script:ScannerPath)) {
        throw "Bitdefender's on-demand scanner was not found at $($script:ScannerPath)"
    }

    $definition = Get-ScanTaskDefinition
    $before = Get-ScannerProcesses
    $existingActive = $before |
        Where-Object {
            $_.CommandLine -match [regex]::Escape($definition.TaskId) -and
            $_.CreationDateUtc -and
            -not (Get-NewScanReport -TaskId $definition.TaskId -NotBeforeUtc $_.CreationDateUtc)
        } |
        Select-Object -First 1
    if ($existingActive) {
        return [pscustomobject]@{
            Passed = $true
            Initiated = $false
            AlreadyRunning = $true
            ScanType = $script:ScanType
            TaskId = $definition.TaskId
            ConfigurationPath = $definition.ConfigurationPath
            VerifiedUtc = [datetime]::UtcNow.ToString('o')
            Verification = 'An existing task-specific Bitdefender process has no completion report newer than its creation time.'
            Process = $existingActive
        }
    }
    $beforeIds = @($before | ForEach-Object { $_.ProcessId })
    $requestedUtc = [datetime]::UtcNow
    $arguments = "/SystemScanTask $($definition.TaskId) /Source 1"

    $launcher = Start-Process -FilePath $script:ScannerPath -ArgumentList $arguments -PassThru
    try { $launcher.WaitForExit(5000) | Out-Null } catch {}

    $deadline = (Get-Date).AddSeconds(30)
    $candidateProcessId = $null
    $candidateFirstSeen = $null
    do {
        Start-Sleep -Milliseconds 500
        $process = Get-ScannerProcesses |
            Where-Object {
                $_.ProcessId -notin $beforeIds -and
                $_.CommandLine -match [regex]::Escape($definition.TaskId)
            } |
            Select-Object -First 1

        if ($process) {
            if ($candidateProcessId -ne $process.ProcessId) {
                $candidateProcessId = $process.ProcessId
                $candidateFirstSeen = Get-Date
            }
            elseif (((Get-Date) - $candidateFirstSeen).TotalSeconds -ge 10) {
                return [pscustomobject]@{
                Passed = $true
                Initiated = $true
                ScanType = $script:ScanType
                TaskId = $definition.TaskId
                ConfigurationPath = $definition.ConfigurationPath
                ScannerPath = $script:ScannerPath
                Arguments = $arguments
                RequestedUtc = $requestedUtc.ToString('o')
                VerifiedUtc = [datetime]::UtcNow.ToString('o')
                Verification = 'A new Bitdefender odscanui.exe process with the discovered task identifier remained active for at least 10 seconds.'
                ObservedDurationSeconds = 10
                Process = $process
            }
            }
        }
        else {
            $candidateProcessId = $null
            $candidateFirstSeen = $null
        }

        $report = Get-NewScanReport -TaskId $definition.TaskId -NotBeforeUtc $requestedUtc
        if ($report) {
            return [pscustomobject]@{
                Passed = $true
                Initiated = $true
                ScanType = $script:ScanType
                TaskId = $definition.TaskId
                ConfigurationPath = $definition.ConfigurationPath
                ScannerPath = $script:ScannerPath
                Arguments = $arguments
                RequestedUtc = $requestedUtc.ToString('o')
                VerifiedUtc = [datetime]::UtcNow.ToString('o')
                Verification = 'A new Bitdefender scan report was observed.'
                ReportPath = $report.FullName
            }
        }
    } until ((Get-Date) -ge $deadline)

    throw "Bitdefender did not expose a new $($script:ScanType) process or report within 30 seconds. Launcher exit status alone is not accepted as verification."
}

function Get-InteractiveUser {
    $user = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
    if (-not $user) {
        throw 'No interactive Windows user is logged on. The Bitdefender scan cannot be launched from Session 0.'
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
    $rootFolder = $null

    try {
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
        $task = $scheduler.NewTask(0)
        $task.RegistrationInfo.Description = "Temporary Wazuh Analytics Bitdefender action: $($script:ScanType)"
        $task.Settings.Enabled = $true
        $task.Settings.AllowDemandStart = $true
        $task.Settings.StartWhenAvailable = $true
        $task.Settings.ExecutionTimeLimit = 'PT2M'
        $task.Principal.UserId = $interactiveUser
        $task.Principal.LogonType = 3
        $task.Principal.RunLevel = 0

        $action = $task.Actions.Create(0)
        $action.Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $action.Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$workerScript`" -Worker -ResultPath `"$workerResult`""
        $action.WorkingDirectory = $jobDirectory

        $registered = $rootFolder.RegisterTaskDefinition($taskName, $task, 6, $null, $null, 3, $null)
        $registered.Run($null) | Out-Null

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        do {
            Start-Sleep -Milliseconds 500
        } until ((Test-Path -LiteralPath $workerResult) -or (Get-Date) -ge $deadline)

        if (-not (Test-Path -LiteralPath $workerResult)) {
            throw "The interactive Bitdefender task did not return a result within $TimeoutSeconds seconds."
        }

        $json = Get-Content -LiteralPath $workerResult -Raw
        [System.IO.File]::WriteAllText($lastResult, $json, (New-Object System.Text.UTF8Encoding($false)))
        Write-Output $json
        $parsed = $json | ConvertFrom-Json
        if (-not $parsed.Passed) { exit 1 }
    }
    finally {
        if ($rootFolder) {
            try { $rootFolder.DeleteTask($taskName, 0) } catch {}
        }
        Start-Sleep -Milliseconds 250
        try { Remove-Item -LiteralPath $jobDirectory -Recurse -Force } catch {}
    }
}

if ($Worker) {
    try {
        Write-WorkerResult -InputObject (Invoke-BitdefenderScan) -Path $ResultPath
        exit 0
    }
    catch {
        Write-WorkerResult -InputObject ([pscustomobject]@{
            Passed = $false
            Initiated = $false
            ScanType = $script:ScanType
            Timestamp = (Get-Date).ToString('o')
            Error = $_.Exception.Message
        }) -Path $ResultPath
        exit 1
    }
}

$currentSession = (Get-Process -Id $PID).SessionId
if ($currentSession -eq 0 -or $ForceDispatch) {
    Invoke-InInteractiveSession
    exit 0
}

try {
    Write-WorkerResult -InputObject (Invoke-BitdefenderScan) -Path $ResultPath
    exit 0
}
catch {
    Write-WorkerResult -InputObject ([pscustomobject]@{
        Passed = $false
        Initiated = $false
        ScanType = $script:ScanType
        Timestamp = (Get-Date).ToString('o')
        Error = $_.Exception.Message
    }) -Path $ResultPath
    exit 1
}
