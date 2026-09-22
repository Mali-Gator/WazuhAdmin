# Bitdefender actions for the Wazuh Analytics portal

These are eight independent Windows PowerShell actions. Each script is
self-contained and idempotent: it exits successfully without changing anything
when Bitdefender is already in the requested state.

| Analytics action | Script | Verified artifact |
|---|---|---|
| Enable Ransomware Remediation | `Enable-BitdefenderRansomwareRemediation.ps1` | `module_state=1` |
| Disable Ransomware Remediation | `Disable-BitdefenderRansomwareRemediation.ps1` | `module_state=0` |
| Enable Cryptomining Protection | `Enable-BitdefenderCryptominingProtection.ps1` | UI state plus protected `vshield.xml` rewrite |
| Disable Cryptomining Protection | `Disable-BitdefenderCryptominingProtection.ps1` | UI state plus protected `vshield.xml` rewrite |
| Enable Firewall | `Enable-BitdefenderFirewall.ps1` | persisted `enabled=true` |
| Disable Firewall | `Disable-BitdefenderFirewall.ps1` | persisted `enabled=false` |
| Enable Antispam | `Enable-BitdefenderAntispam.ps1` | `ScanSpam=1` |
| Disable Antispam | `Disable-BitdefenderAntispam.ps1` | `ScanSpam=0` |

## Runtime behavior

The Wazuh Windows service normally runs in Session 0. Bitdefender's consumer UI
cannot be automated from that session. Each script therefore performs this
entire sequence itself:

1. Detect execution in Session 0.
2. Identify the currently logged-on Windows user.
3. Copy itself into a per-run directory under
   `%ProgramData%\Wazuh\bitdefender-actions`.
4. Create a temporary Task Scheduler task using Windows
   `TASK_LOGON_INTERACTIVE_TOKEN`.
5. Run the action in the logged-on user's session using inbox Windows
   PowerShell 5.1 and .NET UI Automation.
6. Verify the Bitdefender UI state and the independent product artifact.
7. Return structured JSON, remove the temporary task and job directory, and
   preserve the latest result as `last-<action>.json`.

The scripts return exit code `0` only after verification. They return exit code
`1` with JSON error details if no user is logged on, Bitdefender is unavailable,
the control cannot be found, or the requested state is not verified.

## Requirements

- Windows PowerShell 5.1.
- Wazuh Windows agent.
- Bitdefender Total Security with the tested Protection screen controls.
- A logged-on interactive Windows user when the action executes.

No Python, debugger, downloaded executable, PowerShell module, package manager,
or third-party runtime is used.

## Endpoint placement

The installed agent on the validation endpoint uses:

```text
C:\Program Files (x86)\ossec-agent\active-response\bin
```

Copy each required `.ps1` file into that directory through the same deployment
process used for the existing Analytics portal actions. Configure each portal
action to launch its corresponding script with inbox Windows PowerShell:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
  -File <absolute-path-to-action.ps1>
```

The local endpoint already contains a `gsc-response.exe`/`gsc-response.ps1`
PowerShell action launcher. If the Analytics portal routes scripts through that
launcher, map the eight action names above to their corresponding `.ps1` files.
The Bitdefender scripts do not depend on that launcher's internal logic.

Wazuh 4.x Windows agents do not reliably execute `.ps1` files directly as an
active-response executable, so the Analytics action must invoke the script
through `powershell.exe` or the site's existing PowerShell-capable Wazuh
launcher. This uses only components already present on the endpoint.

## Local smoke test

Run an individual script from an elevated Windows PowerShell prompt:

```powershell
& 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
  -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File '.\Enable-BitdefenderFirewall.ps1'
```

`-ForceDispatch` is available for testing the same interactive-session relay
that the Wazuh Session 0 process uses. It is unnecessary during normal Wazuh
execution.

## Validation

All eight scripts passed twice on the validation endpoint:

- Directly under Windows PowerShell 5.1.
- Through the forced Session 0/interactive-token scheduled-task relay.

Every run produced matching UI and product-artifact states. Testing finished
with Ransomware Remediation off, Cryptomining Protection off, Firewall on, and
Antispam on. No temporary scheduled tasks or job directories remained.
