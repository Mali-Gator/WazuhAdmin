# WazuhAdmin

WazuhAdmin is a small operational repository for building a Wazuh-based Windows endpoint telemetry deployment. It contains:

| File | Purpose | Where it runs |
| --- | --- | --- |
| `WazuhServerSetup` | A short bootstrap checklist for an all-in-one Wazuh server on an Azure Ubuntu VM. | The Ubuntu server |
| `GSC-Wazuh-Agent-Config.ps1` | The primary Windows endpoint bootstrap. It installs or rebuilds the Wazuh agent, deploys Sysmon, enables selected Windows telemetry, and safely updates the agent configuration. | Each Windows endpoint, as Administrator |
| `Invoke-GSC-SmokeTest.ps1` | A benign activity generator used after deployment to verify the collection pipeline. | A configured Windows endpoint |
| `README.md` | This deployment, operations, and file-reference guide. | Read before operating the deployment |

The primary deployment flow is:

```text
Azure Ubuntu VM
  └─ Wazuh manager, indexer, and dashboard
       ▲ TCP 1514 (agent events)
       ▲ TCP 1515 (agent enrollment; required for a rebuild)
Windows endpoint
  ├─ Wazuh agent sends Windows, Sysmon, FIM, and helper telemetry
  ├─ Sysmon creates detailed Windows event records
  └─ Smoke test creates ordinary, safe activity for validation
```

## Important operating and privacy considerations

This repository changes security telemetry on Windows endpoints. Test it on a non-production endpoint first, obtain authorization from the system owner, and use a separate staging Wazuh manager when possible.

The endpoint bootstrap must be run from **Windows PowerShell 5.1 or later as a local Administrator**. It downloads the Wazuh MSI from `packages.wazuh.com` and Sysmon from Microsoft Sysinternals, verifies their Authenticode signatures, installs services and scheduled tasks, changes local audit policy and registry settings, and writes files under `C:\ProgramData\GraniteShield`.

The deployment deliberately collects potentially sensitive information:

- Windows Security event 4688 command lines, PowerShell script blocks, and module activity can contain commands, script source, paths, tokens, or secrets passed on command lines.
- File Integrity Monitoring (FIM) can send content differences for selected script and source file types. The configured per-file content limit is 256 KB, but secrets embedded in eligible files can still be collected.
- Browser credential-database read auditing creates Security event 4663 records when a process reads selected Chrome and Edge databases. It records the read operation; it does **not** extract browser credentials.
- The LNK helper records shortcut paths, hashes, targets, arguments, owners, icons, descriptions, and working directories. Shortcut arguments may contain sensitive values.

Set suitable access controls, retention, encryption, and alerting policies in Wazuh before onboarding production endpoints. Do not expose the Wazuh dashboard or agent ports publicly without network restrictions.

## Requirements

### Wazuh server

1. An Ubuntu Azure VM with at least four vCPUs and 8 GB RAM for approximately 25 endpoints, as stated in `WazuhServerSetup`. Size storage and compute for the actual event rate and retention period; Sysmon and PowerShell collection can substantially increase ingestion volume.
2. A stable public or private DNS name/IP address that Windows endpoints can reach.
3. Inbound network rules allowing:
   - TCP **443** to administrators who use the Wazuh dashboard.
   - TCP **1514** from managed Windows endpoints to the Wazuh manager.
   - TCP **1515** from endpoints when installing or rebuilding agents.
   - SSH only from approved administrator addresses.
4. The initial Wazuh dashboard credentials retained in a password manager. Replace the installation-generated password where required by your organization.

### Windows endpoint

1. Windows 10, Windows 11, or a compatible Windows Server release.
2. Windows PowerShell 5.1 or later and an elevated PowerShell window.
3. Network access to the Wazuh manager's TCP 1514 port. A `-RebuildWazuh` deployment also requires TCP 1515.
4. Permission to install MSI packages, register scheduled tasks running as `SYSTEM`, write HKLM policy keys, update audit policy, and stop/start the Wazuh service.
5. TLS access to `packages.wazuh.com` and `download.sysinternals.com` while the bootstrap runs, unless those packages have been made available through an approved internal process. The current script downloads them directly.

## From-scratch deployment

### 1. Build the Wazuh server

`WazuhServerSetup` is intentionally a concise runbook, not an executable script. On the prepared Ubuntu VM:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

The `-a` option installs the all-in-one Wazuh deployment: manager, indexer, and dashboard. The installer prints the dashboard credentials when it finishes. Browse to `https://<Azure-VM-IP-or-DNS-name>`, accept the browser warning only after validating the certificate path appropriate to your environment, and sign in as `admin` using the installer-generated password.

Before deploying endpoints, confirm that the manager is healthy in the dashboard and that the firewall/security group admits the endpoint networks on ports 1514 and 1515. The endpoint bootstrap does its own TCP preflight and intentionally makes no Wazuh changes if TCP 1514 is unreachable.

### 2. Copy the repository to the endpoint

Copy `GSC-Wazuh-Agent-Config.ps1` and `Invoke-GSC-SmokeTest.ps1` to an administrator-controlled local directory on the endpoint, for example `C:\Install\WazuhAdmin`. Review the exact script revision before execution; the script’s default Wazuh agent version is `4.14.7-1`, while the server checklist downloads the Wazuh 4.14 installer. Keep the server and agent within a supported Wazuh compatibility combination.

Open **Windows PowerShell** with **Run as administrator**, change to the copied directory, and execute:

```powershell
Set-Location C:\Install\WazuhAdmin
.\GSC-Wazuh-Agent-Config.ps1 -ManagerAddress "wazuh.example.internal"
```

Replace `wazuh.example.internal` with the DNS name or IP address that resolves from the endpoint. This is an explicit script execution, not a permanent execution-policy change. If the local policy blocks the file and your organization permits a one-time bypass, use:

```powershell
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\GSC-Wazuh-Agent-Config.ps1 -ManagerAddress "wazuh.example.internal"
```

Use a unique, Wazuh-safe display name if the Windows computer name is not the desired agent name:

```powershell
.\GSC-Wazuh-Agent-Config.ps1 `
  -ManagerAddress "wazuh.example.internal" `
  -AgentName "CLIENT-PC-01"
```

For a controlled removal and reinstallation of an existing agent, use:

```powershell
.\GSC-Wazuh-Agent-Config.ps1 `
  -ManagerAddress "wazuh.example.internal" `
  -AgentName "CLIENT-PC-01" `
  -RebuildWazuh
```

`-RebuildWazuh` is not a repair switch. It removes a discovered Wazuh MSI installation, removes old GraniteShield helper/state artifacts, then installs a new agent. It verifies TCP 1514 and 1515 before beginning. If a duplicate agent name prevents enrollment after a rebuild, remove the stale agent record from Wazuh and rerun the command.

### 3. Choose optional collection deliberately

All three optional capabilities are enabled by default. These switches retain the rest of the bootstrap while omitting one capability:

| Switch | What it omits | When it may be appropriate |
| --- | --- | --- |
| `-SkipBrowserCredentialAuditing` | Audit SACLs and the `GraniteShield-BrowserAuditRefresh` task for Chrome/Edge credential-related databases. | Browser database access telemetry is not approved. |
| `-SkipScriptContentCapture` | Wazuh FIM `report_changes` collection for selected script/source extensions. | Script contents may contain data that must not leave the endpoint. |
| `-SkipLnkMetadata` | The shortcut metadata helper, state file, log, task, and Wazuh localfile entry. | Shortcut target/argument enrichment is unnecessary or not approved. |

For example, the following enables core Wazuh, Sysmon, event logs, audit policy, and ransomware-oriented FIM while excluding all optional high-sensitivity enrichments:

```powershell
.\GSC-Wazuh-Agent-Config.ps1 `
  -ManagerAddress "wazuh.example.internal" `
  -SkipBrowserCredentialAuditing `
  -SkipScriptContentCapture `
  -SkipLnkMetadata
```

### 4. Verify the endpoint and pipeline

At the end of a successful bootstrap, verify that:

```powershell
Get-Service WazuhSvc, Sysmon64, Sysmon -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName GraniteShield-BrowserAuditRefresh, GraniteShield-LnkMetadata -ErrorAction SilentlyContinue
Get-Content C:\ProgramData\GraniteShield\Telemetry\endpoint-bootstrap-report.txt
```

Only the tasks corresponding to enabled options should exist. A Wazuh service may be named `WazuhSvc`, `wazuh`, or another Wazuh-related name; the bootstrap searches those possibilities. Confirm the endpoint appears in the Wazuh dashboard and is actively reporting before continuing.

Then generate only normal, low-risk test activity:

```powershell
.\Invoke-GSC-SmokeTest.ps1
```

The default test resolves `example.com` and tests TCP 443. Override both values when an approved internal test target is required:

```powershell
.\Invoke-GSC-SmokeTest.ps1 -DnsName "test.example.internal" -TcpPort 443
```

Search the Wazuh dashboard for the endpoint and the test window. Expected evidence includes a process creation for `whoami.exe` or `hostname.exe`, PowerShell operational events containing `GSC_SMOKE_TEST_POWERSHELL`, DNS/network events for the requested name, a temporary `GraniteShield` user registry key, WMI/CIM activity, and file create/modify/delete events under `%TEMP%\GSC-SMOKE-TEST`. The smoke test intentionally does not test credential access, persistence, injection, security-control tampering, failed logons, service/task creation, executable copying, or destructive behavior.

## Primary bootstrap: `GSC-Wazuh-Agent-Config.ps1`

This 1,566-line PowerShell script is the deployment engine. It uses `Set-StrictMode -Version 2.0` and stops on unhandled errors, making missing variables and unexpected failures visible rather than silently continuing. It creates these working locations:

| Path | Contents |
| --- | --- |
| `C:\ProgramData\GraniteShield\Telemetry` | Bootstrap report, LNK metadata log, and LNK state JSON. |
| `C:\ProgramData\GraniteShield\Backups` | Timestamped pre-change `ossec.conf` backup and candidate configuration. |
| `C:\ProgramData\GraniteShield\Sysmon` | Downloaded Sysmon ZIP, extracted binaries, and generated `sysmon-gsc.xml`. |
| `C:\ProgramData\GraniteShield\Helpers` | Generated browser-audit and LNK-metadata PowerShell helper scripts. |
| `%TEMP%\GSC-Wazuh-Bootstrap` | Downloaded Wazuh MSI during installation. |

### Parameters and preflight

`-ManagerAddress` is required. `-AgentName` defaults to `$env:COMPUTERNAME`; `-WazuhVersion` defaults to `4.14.7-1`; `-ManagerPort` and `-RegistrationPort` default to 1514 and 1515. The two port values are constrained to 1–65535.

Before changing the endpoint, the script verifies that it is elevated, rejects pre-Windows-10 systems, enables TLS 1.2 when possible, creates its working directories, and checks manager TCP 1514. It checks TCP 1515 as well when `-RebuildWazuh` is selected. Failure at this stage prevents an uninstall or configuration change.

The script removes its own two helper tasks and an older `GraniteShield-RMM-Detection` task before re-registering applicable tasks. In rebuild mode it also removes and recreates the GraniteShield helper, Sysmon, and telemetry folders.

### Wazuh installation and rebuild behavior

If Wazuh is absent, the script downloads `wazuh-agent-<version>.msi`, verifies that the MSI signature is valid, silently installs it with manager address, event port, enrollment address/port, and agent name, then starts the discovered service. If the agent already exists and rebuild was not requested, the installation is preserved.

For rebuilds, it finds the Wazuh uninstall entry in the 32-bit and 64-bit uninstall registry views, derives an MSI product code, and runs `msiexec /x` silently. A missing product code is treated as a safety failure when a service or installation directory still exists: the script will not delete an unknown installation and leave a broken service. If removal fails before completion, it attempts to restore the old service. It accepts MSI return values 0, 1605, 1614, and 3010 where appropriate.

### Windows audit and PowerShell logging

The script configures Advanced Audit Policy with `auditpol.exe` for process creation, logons, special logons, account lockouts, credential validation, audit-policy changes, object access/file system, user account management, and security group management. Each category explicitly enables success and/or failure events as defined in the script. A failed individual `auditpol` update emits a warning so deployment can continue and show the partial result.

It also sets `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled` to `1`. This augments Security event 4688 with process command lines. Under `HKLM\Software\Policies\Microsoft\Windows\PowerShell`, it enables Script Block Logging and Module Logging for all module names. Those settings are persistent Windows policy registry settings, not temporary session options.

### Sysmon baseline

The bootstrap writes `sysmon-gsc.xml`, downloads the Sysmon ZIP from Sysinternals, selects `Sysmon64.exe` when present (otherwise `Sysmon.exe`), validates that the binary is Authenticode-signed by Microsoft, and installs (`-i`) or reconfigures (`-c`) Sysmon with the generated XML. The baseline uses SHA-256 and IMPHASH and focuses on:

- Process creation (event 1), remote thread creation (8), raw disk reads (9), process tampering (25), and executable creation (29).
- Network connections (3) and DNS queries (22), excluding common browser, OneDrive, and Teams executables to reduce high-volume endpoint noise.
- Non-Microsoft driver loads (6).
- Access to `lsass.exe` (10).
- Creation of executable, script, shortcut, and Startup-folder files (11).
- Run/RunOnce, Winlogon, Image File Execution Options, Silent Process Exit, AppInit/AppCert DLL, and service registry changes (12–14).
- File deletion detection under `C:\Users`, `C:\ProgramData`, and `C:\Windows\Temp` (26), without Sysmon copy-on-delete archiving.
- Alternate data streams (15), named pipes (17–18), and WMI persistence (19–21).

The XML uses `onmatch="exclude"` with no children to log all events for several categories, and `onmatch="include"` for intentionally narrowed categories such as LSASS access, high-value file creation, registry targets, and deletions. Updating an existing Sysmon installation replaces its configuration; preserve a copy of a different Sysmon policy before using this repository if it must remain authoritative.

### Event channel collection and retention

`Set-EventChannelCircular` enables non-core operational channels when possible, sets their mode to circular, and applies these local maximum sizes:

| Channel class | Maximum |
| --- | ---: |
| Security and Sysmon Operational | 128 MB each |
| PowerShell Operational | 64 MB |
| System, Application, Defender, Task Scheduler, WMI, Code Integrity, AppLocker, RDP, and BITS | 32 MB each |
| Discovered, enabled Bitdefender channels | 32 MB each |

The approximately 600 MB total is a local endpoint cap, not a Wazuh retention setting. The script does **not** clear event logs. When a log reaches its cap, Windows overwrites its oldest local entries. It dynamically discovers enabled Bitdefender channels and treats them the same way.

### Browser database access auditing

Unless skipped, the script writes `Refresh-BrowserCredentialAudit.ps1` and runs it once immediately. The generated helper enumerates local user profiles except system/default profiles, then finds Chrome and Edge `Login Data`, `Cookies`, `Network\Cookies`, `Web Data`, and `Local State` files. It adds a successful `ReadData` auditing rule for the Everyone SID only when equivalent auditing is not already present.

It registers `GraniteShield-BrowserAuditRefresh` as `SYSTEM` at startup and then every six hours for approximately ten years. This refresh is necessary because browsers can replace SQLite database files. Individual locked or unavailable database files are intentionally treated as best-effort and retried later. The helper does not read database contents. Security event 4663 can still be generated for normal browser reads, so investigation should correlate process identity and access path.

### Shortcut metadata enrichment

Unless skipped, the script writes `Collect-LnkMetadata.ps1`, creates `lnk-metadata.log`, and registers `GraniteShield-LnkMetadata` as `SYSTEM` every two minutes for approximately ten years. The first run uses `-InitializeOnly`: it records existing shortcut fingerprints without emitting historical shortcut data.

Subsequent runs recurse through each local user’s Desktop, Downloads, and Startup folder plus the common Startup folder. For new or changed `.lnk` files, the helper uses `WScript.Shell` to collect target path, arguments, working directory, icon, hotkey, and description. It additionally records timestamp, source path, size, SHA-256, and owner as one compressed JSON object per line. Wazuh is configured to collect this log as `syslog` and only future entries are read. A fingerprint of file timestamp and length avoids repeated records, and the helper retains the newest 5,000 lines if the local log exceeds 20 MB.

### FIM and managed `ossec.conf`

The script dynamically identifies existing user-profile directories rather than assuming every standard path exists. It configures:

- **Script content capture** for Downloads, Desktop, local Temp, and user/common Startup directories. Selected PowerShell, batch, script, registry, URL, and shortcut extensions use `check_all`, `whodata`, `report_changes`, and a 256 KB content-difference limit.
- **Ransomware-oriented FIM** for Documents, Pictures, and OneDrive. Selected office, PDF, text, image, archive, and database extensions use realtime checks, metadata/hashes, and `report_changes="no"` so document content is not copied.
- A Wazuh local `report_changes` disk quota of 64 MB and a 256 KB per-file FIM difference limit.

It removes only prior fragments bounded by `<!-- GSC BEGIN SYSCHECK -->` / `<!-- GSC END SYSCHECK -->` and `<!-- GSC BEGIN LOCALFILES -->` / `<!-- GSC END LOCALFILES -->`, then inserts updated fragments. It also removes an existing nested `<diff>` block with a disk quota so its bounded quota is authoritative. For enabled specialty Windows channels and discovered Bitdefender channels, it creates Wazuh `<localfile>` blocks only if an equivalent location is not already configured. Those blocks use `only-future-events`, avoiding an initial flood of historical Windows events.

### Safe activation, rollback, and report

Before replacing `ossec.conf`, the script saves a timestamped backup and writes its new content as a candidate file. It stops the Wazuh service, copies the candidate into place, runs `-t` configuration tests for available Wazuh agent, log collector, and syscheck executables, restarts the service, and confirms it is running. Any validation or recovery failure restores the backup and attempts to restart the original service before raising an error.

Final checks report the Sysmon service, Wazuh service, established TCP 1514 connections, and Sysmon Operational channel. The durable summary is written to `C:\ProgramData\GraniteShield\Telemetry\endpoint-bootstrap-report.txt`; it records deployment time, paths, selected skip switches, retention design, and declared telemetry coverage.

## Benign validator: `Invoke-GSC-SmokeTest.ps1`

This independent script is not an installer and does not require administrator privileges for its normal actions. It creates `%TEMP%\GSC-SMOKE-TEST` and performs the following deliberately non-adversarial activity:

| Test step | Activity | Expected collection signal |
| --- | --- | --- |
| Process creation | Runs signed `whoami.exe` and `hostname.exe`. | Security/Sysmon process creation. |
| PowerShell logging | Starts a child, non-interactive PowerShell that writes `GSC_SMOKE_TEST_POWERSHELL`, gets the date, and queries its own process. | PowerShell operational events and process creation. |
| File modification | Creates and appends to a `.txt` file and a harmless `.ps1` file under the temp test directory. | Sysmon/FIM file creation and script-content telemetry when the directory/type is in scope. |
| DNS and TCP | Resolves `-DnsName` as an A record, then runs `Test-NetConnection` to `-TcpPort`. | DNS and network telemetry when connectivity exists. |
| Registry | Creates then removes `HKCU:\Software\GraniteShield\TelemetryTest`. | User-registry activity; the current Sysmon registry filter may not include this benign path. |
| CIM/WMI | Queries `Win32_OperatingSystem` and `Win32_ComputerSystem`. | WMI activity where the relevant provider/channel reports it. |
| Deletion | Creates then deletes a temporary text file. | Sysmon file deletion detection if the temp location is covered. |

The script uses `$ErrorActionPreference = "Continue"` so a DNS or TCP failure is shown as a warning rather than preventing the remaining checks. It leaves the primary text and PowerShell test files in the temp folder for inspection and removes only its designated registry key and deletion-test file.

## Troubleshooting and recovery

| Symptom | Check | Correct response |
| --- | --- | --- |
| Bootstrap stops before changes | Test `Test-NetConnection <manager> -Port 1514`. For rebuilds, test 1515 too. | Correct DNS, routing, NSG/firewall, or manager listener configuration; rerun only after connectivity succeeds. |
| Access/registry/task errors | Confirm the shell is elevated with `([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`. | Run PowerShell as Administrator and verify endpoint-management policy permits the changes. |
| Wazuh agent is absent after MSI installation | Inspect Windows Installer events and `%TEMP%\GSC-Wazuh-Bootstrap`. | Verify the pinned version is available and its MSI signature validates; correct the version only after confirming it is supported. |
| Config activation fails | Read the thrown error, Wazuh logs, and the timestamped backup/candidate under `C:\ProgramData\GraniteShield\Backups`. | The script restores the pre-change `ossec.conf`; correct the source condition before retrying rather than manually copying an unvalidated candidate. |
| Duplicate agent after rebuild | Find the historical agent by name in Wazuh. | Remove the stale Wazuh agent record, then rerun with the intended unique `-AgentName`. |
| No browser or LNK data | Check the matching scheduled task and its enabled/last-run state. | Verify the feature was not skipped, then inspect its helper under `C:\ProgramData\GraniteShield\Helpers`. |
| Events exist locally but not in Wazuh | Confirm Wazuh service state, TCP 1514 session, agent status in dashboard, and `<localfile>` configuration. | Resolve manager reachability/enrollment first; then investigate Wazuh manager rules and indexer/dashboard ingestion. |

To remove a failed or unwanted managed Wazuh configuration manually, stop the Wazuh service, restore the appropriate timestamped `ossec.conf` backup, start the service, and validate it. Removing Sysmon, audit policy, registry policy, tasks, and helper files is a separate change-management activity; this repository does not provide an uninstall script for those components. Do not delete `ossec-agent` directories manually while the Wazuh MSI registration or service still exists.
