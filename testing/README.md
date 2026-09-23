# Antivirus-aware Wazuh agent test

This directory contains the candidate Windows agent configuration and its setup guide. Test it on a Windows 10 or 11 endpoint before replacing the production script at the repository root.

Run from an elevated Windows PowerShell prompt:

```powershell
.\GSC-Wazuh-Agent-Config.ps1 -av Defender
.\GSC-Wazuh-Agent-Config.ps1 -av Bitdefender
```

The default manager is `analytics.graniteshieldcyber.com`. Defender is the default AV selection. See `Wazuh-agent-AV-setup.md` for collection details and the Defender limited periodic scanning limitation.
