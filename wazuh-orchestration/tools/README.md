# Set-BitdefenderProtection.ps1

`Set-BitdefenderProtection.ps1` changes individual Bitdefender protection switches through the Windows user interface. It supports Advanced Threat Defense, Exploit Detection, Antivirus advanced settings, and four switches on the Protection overview. It reads and verifies the switch state through Windows UI Automation; it does not edit Bitdefender configuration files or services.

Run it with **Windows PowerShell 5.1** in a signed-in, unlocked Windows desktop. The script opens Bitdefender if its window is closed, navigates to the requested setting, and closes the window after a successful command. A Windows service in Session 0 cannot use the interactive desktop. If a command fails, the window stays open so the error can be investigated.

From the folder containing the script, use:

```powershell
.\Set-BitdefenderProtection.ps1 -Setting AdvancedThreatDefense -State Off
```

`-Setting` and `-State` are required. The table below shows the complete **Off** command for every supported setting. In any row, replace `Off` with `On`, `Status`, or `Cycle` to use the other operations.

| Command | Setting affected | Bitdefender page |
|---|---|---|
| `.\Set-BitdefenderProtection.ps1 -Setting AdvancedThreatDefense -State Off` | Advanced Threat Defense | Protection → Advanced Threat Defense → Settings |
| `.\Set-BitdefenderProtection.ps1 -Setting ExploitDetection -State Off` | Exploit detection | Protection → Advanced Threat Defense → Settings |
| `.\Set-BitdefenderProtection.ps1 -Setting BitdefenderShield -State Off` | Bitdefender Shield / real-time antivirus protection | Protection → Antivirus → Advanced |
| `.\Set-BitdefenderProtection.ps1 -Setting ScanOnlyApplications -State Off` | Scan only applications | Protection → Antivirus → Advanced |
| `.\Set-BitdefenderProtection.ps1 -Setting ScanPotentiallyUnwantedApplications -State Off` | Scan potentially unwanted applications | Protection → Antivirus → Advanced |
| `.\Set-BitdefenderProtection.ps1 -Setting ScanProcessMemory -State Off` | Scan process memory | Protection → Antivirus → Advanced |
| `.\Set-BitdefenderProtection.ps1 -Setting ScanCommandLine -State Off` | Scan command line | Protection → Antivirus → Advanced |
| `.\Set-BitdefenderProtection.ps1 -Setting ScanScripts -State Off` | Scan scripts | Protection → Antivirus → Advanced |
| `.\Set-BitdefenderProtection.ps1 -Setting ScanNetworkShares -State Off` | Scan network shares | Protection → Antivirus → Advanced |
| `.\Set-BitdefenderProtection.ps1 -Setting ScanArchives -State Off` | Scan archives | Protection → Antivirus → Advanced |
| `.\Set-BitdefenderProtection.ps1 -Setting ScanBootSectors -State Off` | Scan boot sectors | Protection → Antivirus → Advanced |
| `.\Set-BitdefenderProtection.ps1 -Setting ScanOnlyNewAndModifiedFiles -State Off` | Scan only new and modified files | Protection → Antivirus → Advanced |
| `.\Set-BitdefenderProtection.ps1 -Setting ScanKeyloggers -State Off` | Scan keyloggers | Protection → Antivirus → Advanced |
| `.\Set-BitdefenderProtection.ps1 -Setting EarlyBootScan -State Off` | Early boot scan | Protection → Antivirus → Advanced |
| `.\Set-BitdefenderProtection.ps1 -Setting RansomwareRemediation -State Off` | Ransomware Remediation | Protection overview |
| `.\Set-BitdefenderProtection.ps1 -Setting CryptominingProtection -State Off` | Cryptomining Protection | Protection overview |
| `.\Set-BitdefenderProtection.ps1 -Setting Firewall -State Off` | Firewall | Protection overview |
| `.\Set-BitdefenderProtection.ps1 -Setting Antispam -State Off` | Antispam | Protection overview |

## States

| `-State` value | Behavior |
|---|---|
| `On` | Enable the selected switch. If it is already On, report its current state without toggling it. |
| `Off` | Disable the selected switch. If it is already Off, report its current state without toggling it. |
| `Status` | Read the selected switch without changing it. |
| `Cycle` | Change the switch to the opposite state, then attempt to restore its original state. Restoration is attempted even if the first change fails, but cannot be guaranteed if PowerShell is terminated. |

For example:

```powershell
.\Set-BitdefenderProtection.ps1 -Setting ExploitDetection -State On
.\Set-BitdefenderProtection.ps1 -Setting ScanScripts -State Status
.\Set-BitdefenderProtection.ps1 -Setting Firewall -State Cycle
```

## Optional parameters

| Parameter | Purpose | Example |
|---|---|---|
| `-WhatIf` | Show the requested operation without opening Bitdefender or changing a setting. | `.\Set-BitdefenderProtection.ps1 -Setting ExploitDetection -State Off -WhatIf` |
| `-ConfirmationTimeoutSeconds N` | Wait up to `N` seconds for a change or Bitdefender confirmation; default 60, allowed range 5–600. | `.\Set-BitdefenderProtection.ps1 -Setting BitdefenderShield -State Off -ConfirmationTimeoutSeconds 120` |
| `-ListControls` | Return a JSON inventory of accessible controls for troubleshooting. Use it with the required `-Setting` and `-State` arguments. | `.\Set-BitdefenderProtection.ps1 -Setting ExploitDetection -State Status -ListControls` |
| `-CurrentPage` | Skip automatic navigation when diagnosing a page already open in Bitdefender. Normal use does not need this. | `.\Set-BitdefenderProtection.ps1 -Setting ExploitDetection -State Status -CurrentPage` |
| `-AutomationId ID` | Override a switch's ID when investigating a different Bitdefender build. Use only after confirming the exact control with `-ListControls`. | `.\Set-BitdefenderProtection.ps1 -Setting ExploitDetection -State Status -CurrentPage -AutomationId idGemmaState` |
| `-Confirm` | Ask for PowerShell confirmation before a change. | `.\Set-BitdefenderProtection.ps1 -Setting Firewall -State Off -Confirm` |

## Results and limitations

Successful changes return JSON with `Requested`, `Result.UiState`, and `Passed: true`. A `Status` command returns a JSON snapshot with `UiState`. A `-ListControls` command returns a JSON control inventory; if navigation fails, its first entry includes `NavigationError`.

The script waits for three consecutive matching UI observations and checks for a modal Bitdefender dialog before reporting success. If Bitdefender asks for a password, elevation, or a disable duration, complete that prompt in the app; the script does not choose on your behalf. A disabled child switch may require its parent protection feature to be enabled first.

The control IDs were identified on Bitdefender Total Security build 27.0.62.355. Another version may expose different controls. Verification reflects the switch shown by Bitdefender's UI, rather than an independent test of its protection engine. Run one script instance at a time.
