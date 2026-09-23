# Wazuh Windows agent with antivirus selection

Use the accompanying `GSC-Wazuh-Agent-Config.ps1` from an elevated Windows PowerShell 5.1 prompt on Windows 10 or 11. The default manager is `analytics.graniteshieldcyber.com` and the default antivirus choice is Defender.

```powershell
.\GSC-Wazuh-Agent-Config.ps1
.\GSC-Wazuh-Agent-Config.ps1 -av Defender
.\GSC-Wazuh-Agent-Config.ps1 -av Bitdefender
.\GSC-Wazuh-Agent-Config.ps1 -av Other
```

`-ManagerAddress` can still override the manager hostname. The hostname must accept Wazuh agent traffic on TCP 1514 and enrollment on TCP 1515 for a new agent. HTTPS dashboard access alone does not confirm those ports are open.

The script checks Windows Security Center for an active product matching `-av`. It stops before agent installation when no antivirus is active or the selected antivirus is not active. On Defender endpoints it also checks real-time protection and enables scheduled quick scans when the configured scan day is Never. Its existing Wazuh configuration collects `Microsoft-Windows-Windows Defender/Operational`; Wazuh includes built-in Defender detection and remediation rules.

On Bitdefender endpoints, the script embeds and installs the read-only collector tested with Bitdefender Total Security. It writes structured incidents to `C:\ProgramData\BitdefenderWazuh\events-*.jsonl` and configures Wazuh to collect those records. It checks the manager's shared agent configuration before adding the local source, avoiding a duplicate when the agent already belongs to the `bitdefender_consumer` group. The manager at `analytics.graniteshieldcyber.com` already has the matching incident rules. A different manager needs those rules from the separate Bitdefender package.

Bitdefender's consumer RCA storage is undocumented. The collector requires `C:\ProgramData\Bitdefender\Bitdefender Security App\ctc\rca` and will stop if this layout is absent. It does not install Bitdefender. `-av Other` validates another active product but currently collects only the script's general Windows telemetry; vendor-specific incident feeds require a separate integration.

Microsoft's **limited periodic scanning** is a separate Defender mode offered when a third-party antivirus is active. Microsoft documents enabling it in the Windows Security app and says it cannot be managed by policy. The script checks for the `SxS Passive Mode` state on Bitdefender endpoints and reports when the setting needs manual attention. It does not claim to have switched it on through an unsupported registry setting. Defender as the active antivirus uses normal scheduled scans instead.

Defender alerts contain threat, path, process, and remediation details when present in Defender's events. Sysmon provides process creation records that can be investigated alongside them. Defender events do not contain Bitdefender's proprietary RCA graph or its hypothetical “alternative outcome”; those fields cannot be promised on Defender endpoints.

The script passed Windows PowerShell parsing and an exact embedded-collector comparison against the locally tested source. It has not been run end-to-end on a fresh Windows 10 or 11 machine in this revision.
