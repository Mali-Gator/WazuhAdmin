# Wazuh Server Setup

This runbook installs an all-in-one Wazuh deployment on an Ubuntu Azure virtual machine. The Wazuh installation assistant installs the Wazuh manager, indexer, and dashboard on the same server. Complete this runbook before deploying the Windows agents documented in [README.md](README.md).

> **Scope:** This is a server installation guide, not an Azure infrastructure-as-code template. Create and secure the VM, network security group, DNS record, and backup strategy according to your organization's standards before proceeding.

## Requirements

For an environment with up to approximately 25 endpoints, provision an Azure VM with:

| Resource | Minimum |
| --- | --- |
| Operating system | Supported Ubuntu release |
| CPU | 4 vCPUs |
| Memory | 8 GB RAM |
| Network | Stable DNS name or IP address reachable by managed endpoints |
| Administrator access | SSH access with `sudo` permission |

Size disk capacity, compute, and memory for the actual event volume and retention period. Windows Sysmon, Security auditing, and PowerShell telemetry can produce substantially more data than a basic endpoint deployment.

Allow only the required inbound traffic in the Azure network security group and any host firewall:

| Port | Protocol | Source | Purpose |
| --- | --- | --- | --- |
| 22 | TCP | Approved administrator networks only | SSH administration |
| 443 | TCP | Approved dashboard users | Wazuh dashboard |
| 1514 | TCP | Managed endpoint networks | Wazuh agent event traffic |
| 1515 | TCP | Managed endpoint networks | Wazuh agent enrollment and rebuilds |

Do not expose SSH, agent ports, or the dashboard to the public Internet without source restrictions and an approved access-control design.

## Installation

1. Connect to the Ubuntu VM through SSH.
2. Review the current [Wazuh quickstart documentation](https://documentation.wazuh.com/current/quickstart.html) for supported operating systems, sizing, and version-specific prerequisites.
3. Download the Wazuh installation assistant and run it as root:

   ```bash
   curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
   sudo bash ./wazuh-install.sh -a
   ```

   The `-a` option installs the all-in-one deployment. The command downloads and executes the Wazuh installer, so run it only from a trusted administrative session on the intended server.

4. Wait for the installer to complete successfully. It prints the generated dashboard credentials in its output. Store the password in an approved password manager; do not place it in this repository, a shell-history file, or a ticket comment.

## Access and verify the dashboard

1. In a browser, open:

   ```text
   https://<Azure-VM-IP-or-DNS-name>
   ```

2. Sign in with:

   | Field | Value |
   | --- | --- |
   | Username | `admin` |
   | Password | The password printed by the Wazuh installer |

3. Confirm the dashboard loads and that the manager, indexer, and dashboard report healthy status before enrolling endpoints.
4. From a Windows endpoint network, verify that TCP 1514 is reachable. Also verify TCP 1515 before running a Windows agent deployment with `-RebuildWazuh`.

## Next step

Deploy and validate Windows agents using [README.md](README.md). The endpoint bootstrap requires the manager address and checks TCP 1514 before it changes the endpoint. Rebuild deployments require TCP 1515 as well.
