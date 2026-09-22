# Bitdefender artifacts and validated commands

Consolidated findings from this computer, September 21, 2026 PDT; some UTC timestamps fall on September 22. This reference supersedes preliminary conclusions in [historical investigation notes](bitdefender-investigation-history.md). Verified means observed on this installation in the stated execution context, not a portable or vendor-supported API. Recorded snapshots are not a new live audit.

## Capability status

| Activity | Monitoring evidence | Programmatic status |
|---|---|---|
| Quick AV scan | Completed XML and correlated report-path notification | Captured command replay succeeded, with a fresh clean report. |
| Full AV scan | Completed XML and matching notification pattern | Manual scan observed; task GUID identified; command replay untested. |
| Vulnerability scan | XML timestamps/counts, native findings, worker processes | GUI command verified when previous results window is closed. |
| Individual vulnerability fix | State changes and remediation-correlated events | Internal fix invocation not reproduced. Direct policy experiment reversed. |
| ATD/Exploit Detection | Semantic JSON state changes | Disable/re-enable observed; no dedicated change events found. No command tested. |
| Exclusions | Three JSON stores and corroborating XML | Additions/final removals observed; no dedicated native change events found. |
| Ransomware Remediation | Semantic JSON state change | Native Windows UI Automation control ID `28` validated through Windows PowerShell 5.1: off/on/off with matching `module_state` 0/1/0. |
| Cryptomining Protection | Protected `vshield.xml` metadata/content changes | Native Windows UI Automation control ID `33` validated: off/on/off; live file length and timestamp changed on both transitions. |
| Bitdefender Firewall | Semantic JSON state/rule changes and WFP enforcement trace | Native Windows UI Automation control ID `2` validated: on/off/on with matching persisted Boolean. Deny-rule enforcement and removal were also validated. |
| Antispam | Per-user `antispam.xml` state change | Native Windows UI Automation control ID `3` validated: on/off/on with matching `ScanSpam` 1/0/1. |
| VPN Connect | New tunnel adapter and running service | PowerShell tray command succeeded; already-connected guard verified. |
| VPN Disconnect | Manual disconnect observations | Separate tray handler identified; helper action not tested. |

## Monitoring artifact inventory

| Artifact | Established meaning and limitations |
|---|---|
| `C:\Program Files\Bitdefender\Bitdefender Security App\events\events.db` | Readable SQLite notifications. AV report paths and vulnerability findings/remediation-correlated records observed. `events` includes source/version blobs, Unix-second timestamp, common/specific flags, type, bin_data and big_blob_id; `big_blobs` also exists. Preserve raw bytes and source/version; useful UTF-16LE strings can be extracted. Numeric type alone is insufficient. Rows disappear and row IDs can be reused. |
| `C:\ProgramData\Bitdefender\Desktop\Profiles\Logs\system\<task GUID>\*.xml` | Completed Quick/Full AV reports. Watch recursively under Profiles\Logs; retry partial writes. Identify scan type from `ScanSession/@name`: `ScanSettings/@quickScan` was **1 in both** quick and full reports. |
| `C:\ProgramData\Bitdefender\Desktop\vuscan.xml` | `lastCheck/winUpdates` advanced on validated scans; `issues/iorOSIssues` and `issues/iorBrowserIssues` reflected findings/fixes. Normalize verified Unix timestamps. `state=1` did not distinguish running/completed. No reliable full vulnerability-scan completion marker established. |
| `C:\ProgramData\Bitdefender\Desktop\vudata.xml` | Supplemental vulnerability state; unchanged in several controlled tests. No change does not prove no scan occurred. |
| `C:\ProgramData\Bitdefender\Desktop\.settings\data\42a5f0b3-78a3-4b61-a9ef-d4192a8107b8\.data` | Readable protection/exclusion JSON. GUID is installation/user-specific. Compare selected fields semantically; all-zero GUID file was sometimes rewritten without semantic changes. |
| `C:\Program Files\Bitdefender\Bitdefender Security\settings\vshield.xml` and `settings\LGKC\vshield.xml` | Protected/live and corroborating copies changed during Cryptomining Protection tests. Administrative copy was required for the live file. `<scan_cryptominers>2</scan_cryptominers>` persisted in both enabled and disabled observations, so this element alone is not a Boolean state indicator. Live `<profile>` changed from `custom` after enable to `default` after disable; other concurrent profile settings were not independently controlled. |
| `C:\Program Files\Bitdefender\Bitdefender Security\settings\as\<user-SID>\antispam.xml` | Authoritative per-user Antispam state observed. `<ScanSpam>0</ScanSpam>` means disabled and `<ScanSpam>1</ScanSpam>` means enabled. The file was created on the first observed disable and rewritten on each transition. |
| Windows Filtering Platform diagnostic capture | A short `netsh wfp capture` correlated a user-created Bitdefender deny rule with `FWPM_NET_EVENT_TYPE_PUBLIC_CLASSIFY_DROP` events. Useful for targeted validation; full captures are too heavy for routine collection and can contain sensitive network metadata. |
| `C:\Program Files\Bitdefender\Bitdefender Security\settings\system\LGKC\excludemgr.xml` | Readable corroborating exclusion copy; authoritative/live role unproved. Main `settings\system\excludemgr.xml` content was denied, with matching metadata changes. `dciexclusions.json` content also denied. |
| `C:\ProgramData\Bitdefender\Desktop\Quarantine\cache.db` | Readable SQLite `entries`, empty when inspected. Fields include quarId, path, threat, status, size, quartime, acctime, modtime, scanflags, userSid, rcaId, sha256, dataExType. Units/status semantics need populated-record validation. Empty quarantine is not proof of a clean scan. |
| `C:\ProgramData\Bitdefender\Desktop\camactivity.db`, `micactivity.db` | Readable empty `sessions` tables. Potential session times, process/device details, notification/event IDs; camera includes allowed. Populated behavior untested. |
| Windows Application / SecurityCenter / event 15 | Bitdefender Antivirus/Firewall ON notifications; protection health, not scan history. |
| Windows System / Service Control Manager | Service installation/configuration events 7045/7040. Failed VPN service replay produced 7024. Supplement with live service polling. |
| Microsoft-Windows-Sysmon/Operational | Events 1/5 for processes and 17/18 for pipe metadata proved useful. Administrative read required here. Coverage depends on configuration; pipe events contain no message payloads. |
| `C:\ProgramData\Bitdefender\DTrace\version.log`, `patch_*.log` | Installation/update diagnostics, not AV results. |
| `C:\ProgramData\Bitdefender\Desktop\bdec\bdec.odscanui.json` | Telemetry configuration appearing at scan startup, not results. |
| `C:\ProgramData\Bitdefender\Desktop\Events\wlan\wevents.db` | 16-byte file/backup, format undecoded; extension does not establish SQLite. |
| `C:\ProgramData\Bitdefender\Desktop\EnginesTemp\` | Temporary engine activity; cannot establish scan type or outcome. |

Observed services: VSSERV, BDAppSrv, BDAuxSrv, BDProtSrv, UPDATESRV, ProductAgentService, bdredline, bdredline_agent, BDSafepaySrv, bdvpnservice. Initial provider/channel name searches found no dedicated Bitdefender event channel; that is not proof none exists.

## AV scan commands and reports

Verified Quick Scan:

```powershell
Start-Process -FilePath 'C:\Program Files\Bitdefender\Bitdefender Security App\odscanui.exe' -ArgumentList '/SystemScanTask da29f7c8-23b1-4974-8d11-209959ac694b /Source 1'
```

Verified outside the restricted execution environment under the interactive user: service-host-spawned UI followed by a fresh Quick Scan report. Bare odscanui.exe exited 0 without a demonstrated scan; a restricted-environment replay also exited 0 without scanning. **Exit code alone is insufficient.** `/SystemScanTask` does not mean full scan; this GUID selects Quick Scan. `/Source 1` semantics, GUID portability and Wazuh service-account execution are unvalidated.

Full System Scan report task GUID: `dcf483c4-26d0-4e6f-ba28-6a53a00adae1`. Command replay using it is untested.

| Report | Start / report time, Sept 21 PDT | Result |
|---|---|---|
| [Quick Scan](quickscan-report.xml) | 14:14:19 / 14:15:47 | Infected/suspicious 0; skipped 1085; I/O errors 0; duration 86890. |
| [Full System Scan](fullscan-report.xml) | 14:24:39 / 15:50:33 | Infected/suspicious 0; skipped 180946; I/O errors 0; duration 5153078. |
| [Replayed Quick Scan](quickscan-replay-report.xml) | 16:30:41 / 16:32:15 | Infected/suspicious 0; skipped 1838; I/O errors 0; duration 93328. |

Durations are consistent with milliseconds. Summed scanned-category counts were 3880 and 1456919 for original quick/full scans; category semantics are unmapped, so these are not asserted to be distinct-file counts. Full scan recorded scannedArchives=11522 and scannedPacked=28959. Preserve skipped/error and remediation details alongside zero detections. Canceled, failed and detection-positive report semantics remain untested. UI can remain open after completion.

Evidence: [quick completion](quickscan-completed.json), [full completion](fullscan-completed.json), [command trace](scan-process-commandlines.jsonl), [replay](quickscan-replay-result.json), [bare executable](odscanui-no-arguments.json).

## Vulnerability scans and fixes

Verified GUI orchestration:

```powershell
Start-Process -FilePath 'C:\Program Files\Bitdefender\Bitdefender Security App\bdtkexec.exe' -ArgumentList 'vuscan issue:0 fg'
```

Close the previous results window first. With it closed, replay produced a fresh GUI, SYSTEM workers and advanced winUpdates timestamp. With it open, replay could reuse results without scanning. `issue:0` is not a validated remediation selector. Unattended/session-0 GUI execution untested. [Replay evidence](vulnerability-gui-closed-replay-result.json).

Observed SYSTEM worker: `C:\Program Files\Bitdefender\Bitdefender Security\vulnerability.scan.exe`, launched by bdservicehost.exe using settings/services/configs/bdauxsrv_config.json:

```text
--application-updates --start --proxy-server= --proxy-username= --proxy-password=
--weak-passwords --start --events=enabled
--windows-updater --start
```

Current-user replay did not advance XML state. A temporary SYSTEM task advanced the Windows-update timestamp but did not establish full coverage of every UI stage; the task removed itself. These are not verified replacements for GUI orchestration. [Worker capture](vulnerability-sysmon-capture.json), [SYSTEM replay](vulnerability-system-state.json).

Initial scan reported one OS and four browser-policy findings. Native events include issue IDs, category vulnerability, descriptions/actions and the title “Potential device vulnerability detected.” An empty-payload event remains unclassified; no distinct full-scan completion event proved.

User-driven fixes correlated with:

- `all.drives.no.autorun.disabled`: OS count fell to zero; event at 23:46:10 UTC.
- `internet.settings.security.zones.map.edit.disabled`: browser count fell to three; event at September 22 00:01:34 UTC.

Remediation-correlated events retained the detection title and action `none`; type/title alone cannot establish resolution. No separate fix executable was captured. vswizard.dll contains `ior_fix`, `ior_fix_result`, `ior_fix_requires_restart`, routineId/routines, scan_id/fix_id, fix_enable_policy/fix_disable_policy and EPAAS execute imports. These are clues, **not a verified callable fix interface**. Normal and elevated debugger attaches to the vulnerability UI failed with 0xC0000022; cause unproved, protections not bypassed.

Direct Security_options_edit=1 policy test was **not** an internal Bitdefender fix. At user request it was removed, restoring prior absence; a fresh scan detected the issue again. [Historical policy script](fix-security-zone-policy.ps1) is not a recommended internal-fix deployment action. [Rollback](security-zone-policy-restored.json), [restored finding](restored-security-zone-finding.json), [fix capture](internal-fix-click-analysis.json), [attach failure](epaas-debugger-probe.txt).

## Protection toggles and exclusions

Fields below are within the user-specific JSON settings file:

| JSON field | Observation |
|---|---|
| settings.VShield.Settings.Enabled | Readable AV flag, true when inspected; independent toggle untested. |
| settings.Atd.Settings.enabled | 1 → 0 → 1 during paired ATD/Exploit Detection disable/re-enable. |
| settings.Atd.Settings.gemma | Same paired transition; independent mapping to Exploit Detection untested. |
| settings.ExcludeMgr.Settings | Downloads entry with flags 39, then empty. |
| settings.Atd.Settings.whitelist | Downloads entry with flags 5, then empty. |
| settings.AccountSettings.KALI.WebProtection.whitelist | Original/normalized Downloads paths, then empty. Enumerate account keys; KALI is not portable. |

Screenshot and final user correction corroborated an Antivirus exception with On-access scan, On-demand scan and Embedded scripts checked, associated with aggregate flag 39. Individual bits are unmapped. A retained WebProtection path disagreed with a disabled UI toggle; path presence alone does not prove an effective exception. Preserve original paths plus deliberate case/trailing-separator normalization.

First removal snapshot cleared ATD only. Final snapshot at **23:14:13 UTC / 16:14:13 PDT** showed all three stores empty, LGKC XML `<ExcList />`, and both ATD switches 1. No new/changed native events accompanied tested toggles/exclusions. We have timestamped **collector observations**, not exact native change timestamps or a count of deletion clicks. A collector can emit its own old/new events with the observation interval.

Evidence: [disabled](atd-disabled.json), [enabled](atd-reenabled.json), [added](exclusion-added.json), [first removal](exclusion-removed.json), [final removal](exclusion-final-removal.json).

Additional batch tests established these fields and behaviors:

| UI action | Artifact change | Observation |
|---|---|---|
| Enable Ransomware Remediation | `settings.RansomwareRemediation.Settings.module_state` | `0` to `1` at 01:52:53 UTC. |
| Disable Ransomware Remediation | Same field | `1` to `0` at 01:53:21 UTC. |
| Enable Cryptomining Protection | `settings\vshield.xml` and `settings\LGKC\vshield.xml` changed | Both contained `<scan_cryptominers>2</scan_cryptominers>` and live profile was `custom`. |
| Disable Cryptomining Protection | Live `settings\vshield.xml` changed | An administrative copy showed `<scan_cryptominers>2</scan_cryptominers>` still present while live profile was `default`; LGKC retained `custom`. Treat the full profile transition as evidence and do not map the numeric element alone to enabled/disabled. |
| Disable Bitdefender Firewall | `settings.Firewall.Backup.Settings.Settings.enabled` | `true` to `false` at 02:00:45 UTC. A type-2 empty-payload native event correlated, but its semantics are not independently established. |
| Enable Bitdefender Firewall | Same field | `false` to `true` at 02:03:20 UTC. The same database row ID was replaced by a type-1 empty-payload event with a different fingerprint, demonstrating row-ID reuse. |
| Add deny rule for `23.227.38.32` | `settings.Firewall.Backup.Settings.Rules.list` | Rule count 17 to 18; new user-created rule ID 283, `action.action=1`, remote IPv4 address only. |

The deny rule was functionally validated while the Bitdefender VPN was active. WFP recorded an outbound PowerShell TCP/443 classify drop and an ICMP classify drop from `100.112.1.117` to `23.227.38.32`, both attributed to **Bitdefender IGNIS Filter** ID 89357 whose address condition was exactly `23.227.38.32/32`. See [firewall deny-rule validation](firewall-deny-rule-test.md).

## VPN artifacts and control

Install root: `C:\Program Files\Bitdefender\Bitdefender VPN`.

| Artifact/interface | Finding |
|---|---|
| bdvpnservice.exe service | Persistent service; observed PID 4960 is historical, not constant. |
| bdvpnapp.exe startup | Tray client; PID 12444 during successful test. Static command strings include /show, /stop, /restart, /firstrun, /update, /startup, /getip, /debug, /agent:alt, /domains, /exit; not all validated. |
| bdvpnuiapp.exe, optionally systray | Observed UI launches. Opening UI is not Connect. bdvpnapp.exe getip appeared during UI activity. |
| WireGuard\amd64\VpnHostService.exe | Observed `/service "<install>\settings\wireguard\bdvpnservice_N.conf" <VPN-service-PID>`. |
| WireGuardTunnel$bdvpnservice_N; adapter bdvpnservice_N | Running service, Up adapter and routes provide activation evidence. Disabled start mode was observed while Running; start mode is not connection state. |
| settings\wireguard\bdvpnservice_1.conf and _2.conf | Generated 622-byte files; metadata only inspected, private contents not read. Files can persist after disconnect. |
| settings\bdvpn.xml | Changed during activity, content denied. |
| `\\.\pipe\local\msgbus\bdvpnservice` | UI/service IPC. Captured access 0xc0100080, share 0, native create options 0x400060. |
| Windows VPN profiles | No per-user/all-user Get-VpnConnection profiles returned; rasdial reported no connections. Generated WireGuard configs are not Windows RAS profiles. |

### Verified PowerShell Connect

[Invoke-BitdefenderVpn.ps1](Invoke-BitdefenderVpn.ps1):

```powershell
.\Invoke-BitdefenderVpn.ps1 -Action Status
.\Invoke-BitdefenderVpn.ps1 -Action Connect
```

Discovers class `bd_vpn_window_systray_plugin`, validates the owner as installed bdvpnapp.exe, and sends **WM_COMMAND 0x111, command 201**. Static analysis routes 201 to CSystray::OnBtnConnect; 202 to the separate disconnect handler. Disconnect is implemented but **untested**.

At **September 22 01:31:02 UTC / September 21 18:31:02 PDT**, after manual disconnect, command 201 created a new bdvpnservice_1 adapter Up. Independent verification found WireGuardTunnel$bdvpnservice_1 Running, PID 11676. A second Connect returned AlreadyConnected without another command. VPN was left connected. No debugger, injection or raw IPC replay was used for this successful test.

Helper pins bdvpnsystray.dll SHA256 `F6CF2BBA5D446597989BEEF54EAC4362A6B13BD0737E4B14C27B8B8503432CF1`; updates require revalidation. Internal tray command, not documented vendor API. Requires the logged-in session and running tray. Wazuh session-0 execution, user-session task integration, repeat reconnect/restart behavior and other protocols are untested. Adapter/service checks do not independently establish public-IP routing or internet reachability.

[Successful test](vpn-tray-connect-test.json), [verification](vpn-tray-connect-verification.json), [helper notes](bitdefender-vpn-tray-command.md).

### IPC findings and unsuccessful approaches

- Startup registers bus_name=bdvpnuiapp on msgbus_service_bdvpnservice, vpn.bdvpnservice.actions and vpn.bdvpnservice.events; replies identify bdvpnservice and client acknowledgements follow.
- Connect map: method=connect, module=bdvpnservice, karma=1, version=1, source containing main_ui; 240-byte frame. Disconnect: 256-byte frame with keep_kill_switch present; its value was not decoded in the initial capture.
- FlexBuffers maps reside inside a separate binary envelope whose complete session/type semantics remain unvalidated. connection_status 2 → 1 correlated with connecting → connected in this test; no complete enum. connection_error=103 also appeared; meaning unknown.
- PowerShell/native clients opened the pipe but failed before their first initialization write completed (broken pipe/error 232). Matching captured access/share/create options did not solve it; no independent status request reached the service.
- Libraries contain peer-PID rejection, trusted-client/path/parent and signature-validation machinery. Effective endpoint policy and specific rejection reason remain unproved; no trust controls altered.
- Direct VpnHostService replay with dynamic service PID did not connect. Temporary LocalSystem SCM replay failed with Access Denied/event 7024; temporary service and orphan removed. [Invoke-BitdefenderVpnReplay.ps1](Invoke-BitdefenderVpnReplay.ps1) is an **unsuccessful experimental helper**, distinct from the working tray helper.

[Decoded exchange](vpn-startup-and-connect-decoded.json), [initial frames](vpn-connect-disconnect-requests.json), [probe failures](vpn-status-probe-results.md), [direct replay](vpn-replay-verification.json), [SCM replay](vpn-service-retry.json).

## Capture tooling and retained evidence

WinDbg 1.2606.22001.0 was installed. VPN UI attach worked; vulnerability UI attach was denied. Initial VPN breakpoint condition was invalid and debugger exit likely terminated the UI; corrected capture used detach-on-exit. A later UI crash was reported; precise cause unproved. Passive Kernel-File ETW/Sysmon established timing but not handshake contents.

Task-local Frida 17.18.0 captured startup opens, requests and replies after a local pipe self-test. It recorded 97 writes and 342 completed reads without callback errors. Synchronous returns, completion/wait hooks and polling fallback were used; lossless capture is not proved. Graceful stop stalled, so controller was stopped; UI responsiveness and tunnel Up were verified afterward. This was not a verified graceful detach.

FlatBuffers, pefile and Capstone reside under work\capture-deps. Raw captures/intermediate scripts under work\vpn-api-capture may contain account/session data; selected output files omit account-state messages. PIDs, handles and module addresses are historical. No protection/trust settings were disabled. Direct policy experiment was reversed. All original evidence is retained in outputs or work; the [history](bitdefender-investigation-history.md) preserves intermediate observations and corrections.

## Wazuh collection and outstanding validation

1. Collect AV report XML, vulnerability state and selected protection/exclusion fields. Emit collector-generated old/new settings events with UTC observation times/intervals.
2. Read SQLite with mode=ro, short transactions, overlapping reads and fingerprints. Handle rotation/deletion; do not rely only on row counts, maximum row ID or mtime. Use SQLite-consistent backups for snapshots.
3. Correlate fresh parsed reports with report-path events. Preserve skipped/errors alongside zero detections; distinguish health, execution, results and remediation evidence.
4. Collect configured Windows/Sysmon process/service/pipe metadata without assuming payload or complete registry visibility.
5. Treat commands as installation-specific prototypes. Test identity/session, timeouts, duplicates, failures/aborts and updates before deployment. VPN control requires a separately tested logged-in-user task; none was installed. No before-login unattended activation is established.
6. Remaining tests: repeated VPN reconnects and restarts, Disconnect, Wazuh integration, full-scan command replay, positive/canceled AV reports, independently toggled protections/exclusion bits, and the internal per-issue fix interface.
