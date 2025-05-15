# SIEM Lab: Splunk and Wazuh Setup, Configuration, and Attack Simulation


## 📖 Overview
This project demonstrates the setup, configuration, and testing of two Security Information and Event Management (SIEM) tools—**Splunk Enterprise** (community edition) and **Wazuh**—on an Ubuntu server. It includes deploying agents on Windows 10 and Kali Linux target machines, simulating brute-force attacks, and analyzing the resulting logs to detect security events.

## 🎯 Objectives
- Install and configure Splunk and Wazuh SIEMs on an Ubuntu server.
- Deploy Splunk Universal Forwarder and Wazuh agents on Windows 10 and Kali Linux.
- Simulate brute-force attacks on SMB, RDP, SSH, FTP, and HTTP services, plus an LLMNR attack.
- Capture and analyze logs using Splunk and Wazuh to identify security incidents.

## 🛠️ Lab Environment
The lab is configured with the following machines on the 192.168.254.0/24 internal network:

| Machine        | Role                | IP Address(es)                     | Network Interfaces                     | Enabled Services                     |
|----------------|---------------------|------------------------------------|----------------------------------------|--------------------------------------|
| SIEM Server    | SIEM Host (Splunk/Wazuh) | 192.168.19.137 (NAT)<br>192.168.254.129 (Host-only) | NAT: Internet access<br>Host-only: Internal network gateway | Splunk, Wazuh (on separate snapshots) |
| Target 1       | Windows 10 Target   | 192.168.254.150                   | Host-only                              | SMBv1, LLMNR, SSH (OpenSSH), RDP     |
| Target 2       | Kali Linux Target   | 192.168.254.140                   | Host-only                              | SSH, FTP (vsftpd), Apache2           |
| Attacker       | Kali Linux Attacker | 192.168.254.130                   | Host-only                              | Hydra, Responder (attack tools)      |

**Notes**:
- The SIEM Server acts as the gateway for the internal network.
- Splunk and Wazuh are installed on separate Ubuntu server snapshots.

## 📋 Prerequisites
- Virtualization software (e.g., VirtualBox, VMware)
- ISOs for Ubuntu Server, Windows 10, and Kali Linux
- Basic knowledge of Linux, Windows, networking, and SIEM tools
- Internet access for downloading Splunk and Wazuh packages
- Tools: `wget`, `curl`, `hydra`, `responder` (on attacker machine)

## 🚀 Installation
### 1. Splunk Setup
Automate Splunk Enterprise setup on the Ubuntu server:
```bash
sudo ./scripts/splunk_setup.sh
```
- Access the Splunk web interface at `http://192.168.254.129:8000` (username: `splunk`, password: `salam123`).
- Configures Splunk to receive logs on port 9997.

### 2. Wazuh Setup
Automate Wazuh SIEM setup on a separate Ubuntu server snapshot:
```bash
sudo ./scripts/wazuh_setup.sh
```
- Access the Wazuh dashboard at `https://192.168.254.129:443` (credentials in `/tmp/wazuh-installation-credentials.txt`).

## 🛠️ Agent Configuration
### Splunk Universal Forwarder
- **Windows 10**:
  - Copy `configs/splunk/inputs_windows.conf` to `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`.
  - Restart the forwarder:
    ```bash
    "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" restart
    ```
- **Kali Linux**:
  - Copy `configs/splunk/inputs_kali.conf` to `/opt/splunkforwarder/etc/system/local/inputs.conf`.
  - Restart the forwarder:
    ```bash
    sudo /opt/splunkforwarder/bin/splunk restart
    ```

### Wazuh Agent
- **Windows 10**:
  - Copy `configs/wazuh/ossec_windows.conf` to `C:\Program Files (x86)\ossec-agent\ossec.conf`.
  - Restart the agent:
    ```bash
    net stop wazuh
    net start wazuh
    ```
- **Kali Linux**:
  - Copy `configs/wazuh/ossec_kali.conf` to `/var/ossec/etc/ossec.conf`.
  - Restart the agent:
    ```bash
    sudo systemctl restart wazuh-agent
    ```

## 🔍 Attack Simulation
Simulate brute-force attacks from the Kali Linux attacker machine (192.168.254.130):
```bash
sudo ./scripts/attack_simulation.sh
```
- Targets:
  - Windows 10: SMB, RDP, SSH, LLMNR (using Responder)
  - Kali Linux: SSH, FTP, HTTP GET
- Logs are captured by Splunk and Wazuh for analysis.

## 📊 Log Analysis
- **Splunk**:
  - Search logs in the Splunk web interface (`index=main`).
  - Windows 10: Look for `sourcetype=WinEventLog:Security` (e.g., EventCode 4625 for failed logins).
  - Kali Linux: Look for `sourcetype=linux_secure` (SSH) and `sourcetype=vsftpd_log` (FTP).
- **Wazuh**:
  - View alerts in the Wazuh dashboard under **Security Events**.
  - Windows 10: Alerts for brute-force (e.g., Rule ID 60103).
  - Kali Linux: Alerts for SSH/FTP (e.g., Rule ID 5710) and HTTP scanning (e.g., Rule ID 31101).

## 📸 Screenshots
| Screenshot | Description |
|------------|-------------|
| ![Lab Setup](Docs/images/overview/lab_setup.png) | Network topology of the lab environment (SIEM Server, targets, attacker). |
| ![Splunk Dashboard](Docs/images/splunk/splunk_dashboard.png) | Splunk web interface showing the main dashboard after setup. |
| ![Wazuh Dashboard](Docs/images/wazuh/wazuh_dashboard.png) | Wazuh dashboard displaying security events and alerts. |
| ![SMB Attack](Docs/images/attacks/attack_hydra_smb.jpeg) | Hydra brute-force attack output targeting Windows 10 SMB service. |
| ![Windows Logs](Docs/images/splunk/splunk_logs_windows.png) | Splunk analysis of Windows 10 Security Event Logs (e.g., failed logins). |

## 📝 Documentation
Detailed setup, configuration, and testing steps are in [docs/LAB2.md](Docs/LAB2.md) (Markdown) or [docs/LAB2.docx](Docs/LAB2.docx) (Word format).

## 🛡️ Security Note
This project is for **educational purposes only**. Do not use in production environments or against systems without explicit permission.

## 📜 License
This project is licensed under the [MIT License](LICENSE).

## 🙌 Acknowledgments
- [Splunk Community](https://www.splunk.com/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- My instructors and peers for their support.

## 📬 Contact
For questions or feedback, reach out to [gunel.salamova@example.com](mailto:gunel.salamova@example.com).
