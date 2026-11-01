# Sample report

[`Sample-Report-Infected-FIN-WS-0142.html`](Sample-Report-Infected-FIN-WS-0142.html) is a real IR-Investigator report generated from a **fully synthetic** case. Download it and open it in any modern browser - it is a single offline file with no external requests.

> All data is fabricated. The host, user, hashes and timestamps are invented. IP addresses are from the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and domains use reserved names such as `.example`. Nothing in this file points to real infrastructure.

## Scenario

A finance workstation, `FIN-WS-0142`, used by `j.morris`. Between 2026-10-28 and 2026-10-31 the user downloads "cracked" software, and the machine ends up running several malware families at once.

| Stage | What happened | What the report shows |
|---|---|---|
| Initial access | Cracked installers and keygens (`adobe_photoshop_2024_crack.exe`, `IDM_Crack_Keygen.exe`, `office_2024_activator.cmd`) downloaded from crack sites | Cracked-software / keygen findings, Mark-of-the-Web downloads, piracy domains |
| Infostealer | **Lumma Stealer** dropped as `AppData\Roaming\WinUpdate\updater.exe`, runs encoded PowerShell, reads browser credential stores, talks to C2 | Defender detection that failed to remediate, encoded PowerShell decoding, browser / password store access, C2 connections |
| Defense evasion | Defender exclusions added, real-time protection disabled, firewall turned off | Defender tampering and firewall findings |
| Persistence | Run key, scheduled task, and a new service `WinUpdateSvc` | Persistence findings and autostart entries |
| Remote access | **AsyncRAT** (`AppData\Local\Temp\winlog.exe`) launched by `updater.exe`, plus a reverse tunnel | Process tree, Defender detection, tunneling |
| Credential access | LSASS memory access and WDigest enabled | Credential-dumping findings |
| Impact | **XMRig** cryptominer connecting to a mining pool | Cryptomining incident, mining-pool DNS |
| Exfiltration | **rclone** syncing data to cloud storage, Telegram API traffic | Exfiltration and cloud-sync findings |

Resulting report: **66 findings** (5 critical, 24 high), grouped into **5 incidents**, verdict **Compromise likely (100/100)**, 29 IOCs.

## Things to try in the report

- **Overview** - verdict, attack chain across ATT&CK tactics, activity histogram.
- **Incidents** - open `INC-01` for the chronological narrative and its own incident graph.
- **Graph** - search for `updater.exe`, open it, and switch to the **Process tree** tab to see the parent chain (`updater.exe` -> `powershell.exe` -> `conhost.exe`, and `updater.exe` -> `winlog.exe`).
- **Timeline** - filter by severity or click a day in the overview histogram.
- **MITRE ATT&CK** - the full matrix with the observed techniques highlighted.
- **Evidence** - the raw records behind every finding.
- **Recommendations** - containment and remediation steps generated per incident.
