<div align="center">

# IR-Investigator

**Windows incident response and forensic triage in a single PowerShell script.**

Collect the evidence. Detect the attacker. Map it to MITRE ATT&CK. Hand over one offline HTML report.

![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server-0078D6?logo=windows&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-C8102E)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

[Quick start](#quick-start) ·
[What it collects](#what-it-collects) ·
[What it does with it](#what-it-does-with-the-evidence) ·
[The report](#the-report) ·
[Sample report](Sample-Report-Infected-FIN-WS-0142.html) ·
[Full documentation](DOCUMENTATION.md)

</div>

---

![Report overview](overview.png)

## Overview

IR-Investigator automates the first hours of a Windows investigation. Run it on a suspect host and it:

| Step | What happens |
|---|---|
| **1. Collect** | Captures volatile live state, exports the complete event logs, and copies raw forensic artifacts unmodified - with a SHA-256 manifest for chain of custody. |
| **2. Analyze** | Runs detection rules over every event log, the live state and the parsed artifacts, then correlates events across sources (brute force, Kerberoasting, discovery bursts, ...). |
| **3. Map** | Tags every finding with a MITRE ATT&CK technique and tactic, a severity, and the exact evidence it came from. |
| **4. Correlate** | Merges findings that share an account, IP, process, file, hash or domain into **incidents** with a timeline and narrative. |
| **5. Report** | Writes a self-contained HTML dashboard: verdict, incidents, entity graph, timeline, ATT&CK matrix, evidence, IOCs and recommendations. |
| **6. Package** | Zips (or RAR-encrypts) the case and hashes the archive, ready to hand over. |

Nothing to install. No modules, no external binaries, no internet access. One `.ps1` file that collects on the victim host and can re-analyze the same case later on an analyst workstation.

> **See the output first:** download [`Sample-Report-Infected-FIN-WS-0142.html`](Sample-Report-Infected-FIN-WS-0142.html) and open it in a browser. It was generated from a synthetic workstation infected with an infostealer, a RAT, a cryptominer and an exfiltration tool. [What the sample shows](SAMPLE-REPORT.md).

---

## Quick start

From an **elevated** PowerShell prompt:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Unblock-File .\IR-Investigator.ps1

.\IR-Investigator.ps1
```

This collects with the `Standard` profile, analyzes the last 30 days, writes the report, packages the case under `D:\IRCollection` (or `C:\Windows\Temp\IRCollection` if there is no `D:`), and opens the report.

```powershell
# Minimal footprint: collect only, straight to a share
.\IR-Investigator.ps1 -Mode Collect -Profile Quick -OutputRoot \\ir-share\cases

# Analyze a collected case on your workstation (no admin needed), last 90 days
.\IR-Investigator.ps1 -Mode Analyze -CasePath D:\Cases\HOST01_20261031_120000Z.zip -Days 90

# Everything, encrypted archive, case metadata in the report
.\IR-Investigator.ps1 -Profile Full -Archive Rar -ArchivePassword 'S3cret!' -CaseLabel INC-2026-044 -Examiner 'Jane Doe'
```

---

## What it collects

Collection runs as 18 isolated steps. A failing step is logged and the rest continue. Each table shows which **profile** (`Quick` / `Standard` / `Full`) includes the item.

### Live system state &nbsp;<sub>saved as normalized JSON in `live\`</sub>

| Area | Exactly what is captured | Q | S | F |
|---|---|:-:|:-:|:-:|
| **System** | OS build, domain and role, time zone and UTC offset, IP addresses, who ran the script, collection start and end time | ✓ | ✓ | ✓ |
| **Processes** | PID, parent PID, full command line, owner, start time, image path, **SHA-256** and Authenticode signature | ✓ | ✓ | ✓ |
| **Network** | TCP/UDP connections mapped to their owning process, DNS cache, ARP cache, IP configuration, SMB shares and sessions, `hosts` file, proxy settings, `netsh` port proxies, network connection history | ✓ | ✓ | ✓ |
| **Accounts** | Local users, privileged group members, logged-on sessions, user profiles | ✓ | ✓ | ✓ |
| **Services & drivers** | Every service and driver with binary path, `ServiceDll`, state, start mode, account and signature (SHA-256 in Standard / Full) | ✓ | ✓ | ✓ |
| **Autostart (ASEP)** | Run / RunOnce, Winlogon, IFEO, SilentProcessExit, AppInit DLLs, LSA packages, BootExecute, Netsh helpers, print monitors, screensaver, COM hijacks, Office test key, Startup folders | ✓ | ✓ | ✓ |
| **Scheduled tasks** | Command, arguments, author, registration date, run-as account and level, triggers, hidden flag, signature of the target | ✓ | ✓ | ✓ |
| **WMI persistence** | Event filters, consumers and bindings | ✓ | ✓ | ✓ |
| **Defender & firewall** | Protection status, preferences, **exclusions**, detection history, firewall profiles and rules | ✓ | ✓ | ✓ |
| **Security posture** | WDigest, UAC, LSA RunAsPPL, SMBv1, RDP NLA, PowerShell logging settings, audit policy | ✓ | ✓ | ✓ |
| **Execution evidence** | Prefetch listing, BAM, UserAssist, ShimCache (decoded from the live registry) | ✓ | ✓ | ✓ |
| **User activity** | PowerShell (PSReadLine) history, recent files, MRU lists, USB device history, Recycle Bin | ✓ | ✓ | ✓ |
| **Software** | Installed programs and hotfixes | ✓ | ✓ | ✓ |
| **Recent files** | Executables, scripts and archives created or changed within `-Days` in Downloads, Desktop, Temp, AppData, ProgramData, Public, PerfLogs, System32 and more - with hash, signature and **Mark-of-the-Web** (`ZoneId`, `HostUrl`) | 1.5k | 5k | 15k |
| **Alternate data streams** | Non-standard ADS in every user's Downloads, Desktop, Documents, Temp and Roaming folders | | | ✓ |

### Event logs &nbsp;<sub>exported as complete `.evtx` files to `eventlogs\`</sub>

| Scope | Q | S | F |
|---|:-:|:-:|:-:|
| Key logs: Security, System, Application, PowerShell (Operational + Windows PowerShell), Sysmon, RDP (LocalSessionManager, RemoteConnectionManager, RDPClient), Defender, Task Scheduler, WMI-Activity, BITS, WinRM, Firewall, SMBServer, NTLM | ✓ | ✓ | ✓ |
| **Every other non-empty log** on the system | | ✓ | ✓ |

Logs are exported with `wevtutil epl`, so the original records are preserved for Hayabusa, Chainsaw or Event Viewer. Each log's size, retention mode and oldest event are recorded to detect rolled-over logs.

### Raw forensic artifacts &nbsp;<sub>copied unmodified to `artifacts\`</sub>

| Artifact | Source | Q | S | F |
|---|---|:-:|:-:|:-:|
| Registry hives | `SYSTEM`, `SOFTWARE`, every user's `NTUSER.DAT` and `UsrClass.dat` | | ✓ | ✓ |
| Credential hives | `SAM`, `SECURITY` (contain password hashes - protect the archive) | | | ✓ |
| Prefetch | `C:\Windows\Prefetch\*.pf` | | ✓ | ✓ |
| Amcache | `Amcache.hve` + transaction logs, `RecentFileCache.bcf` | | ✓ | ✓ |
| SRUM | `SRUDB.dat` + logs (per-app network and resource usage) | | ✓ | ✓ |
| Jump Lists & LNK | Automatic / Custom Destinations, `Recent\*.lnk`, Office recent | | ✓ | ✓ |
| Browser history | Chrome, Edge, Brave (`History`) and Firefox (`places.sqlite`) for every profile | | ✓ | ✓ |
| Windows Timeline | `ActivitiesCache.db` | | ✓ | ✓ |
| Other | Recycle Bin `$I` files, `System32\Tasks` XML, `setupapi.dev.log`, firewall logs, Defender `MPLog` / `MPDetection` | | ✓ | ✓ |
| Deep artifacts | WMI repository, thumbcache / iconcache, RDP bitmap cache | | | ✓ |

### How collection protects the evidence

- **Prefetch is captured first**, before the script launches any helper process that would create new `.pf` files.
- **Read-only.** Files are copied, never opened in place. Locked files fall back to `robocopy /B`, then to a **temporary Volume Shadow Copy** that is deleted as soon as the step ends. Existing restore points are never touched.
- **Hashed.** `manifest.csv` records the SHA-256 of every collected file. The archive gets its own `.sha256`, and `Analyze` re-verifies the manifest before reading the case.
- **Transparent.** `collection.log` and the report's *Collection* tab list every step with status, duration, item count and any error.
- **Self-aware.** The script recognizes its own processes, script blocks and Defender alerts and excludes them from the analysis, so it never reports itself.

---

## What it does with the evidence

Analysis reads only the case folder, so the same case gives the same result on any machine, at any time. The analysis window is measured back from the **collection time**, not the time of analysis.

### Detection by source

| Source | What it looks for | Examples |
|---|---|---|
| **Security log** | Logons (by type), failed logons, explicit credentials, process creation, account and group changes, service and task creation, log clearing, Kerberos anomalies, admin share access | 4624, 4625, 4648, 4688, 4720, 4732, 4697, 4698, 1102, 4769 (RC4), 5140 |
| **Sysmon** | Process creation, network connections, driver loads, remote threads, **LSASS access**, file creation, registry persistence, DNS queries, process tampering | Event IDs 1, 3, 6, 8, 10, 11, 13, 22, 25 |
| **PowerShell** | Script Block Logging (split blocks are reassembled), PowerShell 2.0 downgrade | 4104, 400 |
| **System / RDP / WinRM / WMI / BITS / Tasks** | New services, RDP logons and outbound RDP, remote PowerShell, WMI consumers, BITS jobs, task execution | 7045, 1149, 21-25, 91, 5861, 59, 106/140/141 |
| **Defender / Firewall** | Detections, failed remediation, protection disabled, exclusions added, firewall rule changes | 1116-1119, 5001, 5007, 2004-2006 |
| **Command lines** <sub>(events, live processes, services, tasks, autoruns, PS history)</sub> | Credential dumping, encoded / obfuscated PowerShell, download cradles, LOLBins (certutil, mshta, rundll32, regsvr32 ...), lateral movement tools, defense evasion, shadow copy deletion, discovery commands | Encoded PowerShell is **decoded and re-scanned** by every rule |
| **Process lineage** | Suspicious parent-child pairs | Office -> shell, web server -> cmd, WMI -> process |
| **Names & paths** | Known attacker / dual-use tools, masquerading, typosquatting, double extensions, execution from staging folders | Mimikatz, Rubeus, SharpHound, Cobalt Strike, ngrok, rclone, AnyDesk, XMRig |
| **Network & DNS** | LOLBins talking to the internet, C2 ports, inbound from public IPs, tunneling, dynamic DNS, file-sharing / paste sites, Telegram / Discord, mining pools | Sysmon 3 / 22, live connections, DNS cache, browser URLs |
| **Live state** | Unsigned or invalidly signed binaries in autostarts, Defender exclusions, WMI consumers, vulnerable drivers (BYOVD), weak security settings | |

### Raw artifact parsing (built in, no external tools)

| Artifact | Parsed into | Used to detect |
|---|---|---|
| Browser history | Visits and downloads with URL, referrer, path and Safe Browsing verdict | Executables downloaded from raw IPs, dangerous downloads, malicious domains |
| Amcache | Program path, **SHA-1**, publisher, first-seen time | Programs that ran from staging folders, known tools |
| ShellBags | Every folder opened in Explorer (local, network, USB) - even if deleted | Access to admin shares, tool folders |
| Offline `NTUSER.DAT` | UserAssist, RunMRU, typed paths, RDP MRU, mapped drives for users not logged on | Activity of users who were not logged in during collection |
| Jump Lists | Files per application, run count, arguments, volume and machine IDs | Outbound RDP (`mstsc /v:`), admin shares |
| SRUM | Bytes sent / received per program per hour | Large uploads (1 GB+), staging-folder programs using the network |

### Correlation across events

| Rule | Logic |
|---|---|
| Brute force / password spray | 10+ failures from one source in 30 minutes, or across 5+ accounts |
| Brute force success | A successful logon from the same source within 6 hours of the failures |
| Kerberoasting | RC4 service tickets for 5+ services from one client within 10 minutes |
| Discovery burst | 5+ different discovery commands by one account within 10 minutes |
| Short-lived task | Scheduled task created and deleted within an hour |
| New admin account | Account created and added to a privileged group within 24 hours |
| Credential spread | One account using explicit credentials against 3+ hosts |

### From findings to a verdict

1. **Finding:** each detection becomes a finding with a rule ID, severity (`critical` / `high` / `medium` / `low`), **ATT&CK technique and tactic**, first / last seen, hit count, every source that reported it, and the raw evidence.
2. **De-duplication:** the same behavior seen in several sources (for example Prefetch, BAM and 4688) is one finding with multiple sources, not three.
3. **Incidents:** findings that share an entity (account, IP, process, file, hash, domain) are merged with union-find. Each incident gets a title derived from its tactics (for example *Credential theft and lateral movement*), a chronological narrative, its entities and a graph.
4. **Verdict:** a 0-100 risk score from the weighted findings and a verdict such as *Compromise likely* or *Needs review*.
5. **Visibility gaps:** what could **not** be seen - not elevated, Sysmon missing, logs rolled over, command-line auditing or Script Block Logging disabled, Tamper Protection off - so absence of evidence is not read as evidence of absence.
6. **Recommendations and IOCs:** containment and remediation steps per technique and per incident, plus an IOC table (hashes, IPs, domains, files) with CSV export.

---

## The report

A single offline HTML file (`report\IR-Report.html`) - no CDN, no external requests. It can be attached to a ticket or opened on an air-gapped machine.

| Tab | Contents |
|---|---|
| **Overview** | Verdict and score, severity counts, ATT&CK kill chain, activity histogram, top findings and incidents |
| **Incidents** | Global entity graph, then each incident with its narrative, tactics, entities and its own graph |
| **Findings** | Every finding with severity, technique, sources, hit count and evidence |
| **Timeline** | All events and artifacts in one chronological view, filterable by severity and source, UTC or host local time |
| **Graph** | Interactive entity graph: search any host, account, IP, file or domain, expand neighbors, view **process trees** with parent chains |
| **MITRE ATT&CK** | Full matrix with observed techniques colored by severity, linked to their findings |
| **Evidence** | Every collected dataset as a searchable table |
| **Recommendations** | Prioritized actions per technique and incident |
| **Collection** | Step log, integrity check result, visibility gaps, filtered self-activity |

| Incidents | Entity graph |
|---|---|
| ![Incidents](incidents.png) | ![Graph](graph.png) |
| **Entity details** | **Process tree** |
| ![Entity details](entity-popup.png) | ![Process tree](process-tree.png) |

---

## Output

```
<OutputRoot>\
├── HOST01_20261031_120000Z\              case folder (removed after packaging unless -KeepCaseFolder)
│   ├── live\*.json                        normalized live state (~40 datasets)
│   ├── eventlogs\*.evtx                   complete event logs
│   ├── artifacts\...                      raw artifacts, copied unmodified
│   ├── report\IR-Report.html              the dashboard
│   ├── manifest.csv                       SHA-256 of every collected file
│   └── collection.log                     every step: status, duration, errors
├── HOST01_20261031_120000Z.zip            packaged case
├── HOST01_20261031_120000Z.zip.sha256     archive hash
└── HOST01_20261031_120000Z_IR-Report.html copy of the report next to the archive
```

Case names are `<HOSTNAME>_<yyyyMMdd_HHmmss>Z`, always in UTC.

---

## Usage reference

### Modes

| Mode | Use it when |
|---|---|
| `All` *(default)* | You want collection, analysis and the report on the host in one run. |
| `Collect` | You want the lightest footprint on a compromised host, or are collecting from many hosts. |
| `Analyze` | You have a case folder or `.zip` and want the report on your own workstation. No elevation, nothing changed. |

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Mode` | `All` | `All`, `Collect` or `Analyze` |
| `-Profile` | `Standard` | `Quick`, `Standard` or `Full` (alias of `-CollectionProfile`) |
| `-OutputRoot` | `D:\IRCollection` | Where the case is written. UNC paths work. |
| `-CasePath` | | Case folder or `.zip` for `Analyze` |
| `-Days` | `30` | Analysis window, in days before the collection time |
| `-MaxEventsPerLog` | `50000` | Maximum events parsed per query, newest first |
| `-Archive` | `Zip` | `Zip`, `Rar` (encrypted names and content) or `None` |
| `-ArchivePassword` | `infected` | Password for `Rar`. Visible in process-creation logs. |
| `-KeepCaseFolder` | | Keep the case folder after packaging |
| `-CaseLabel` | | Case / ticket ID shown in the report |
| `-Examiner` | | Examiner name shown in the report |
| `-NoOpen` | | Do not open the report when finished |

Built-in help: `Get-Help .\IR-Investigator.ps1 -Full`

### Requirements

- Windows 10 / 11 or Windows Server with Windows PowerShell 5.1 (PowerShell 7 also works).
- **Administrator** rights for `Collect` and `All`. Without them the script still runs, but reports the missing visibility.
- Optional: WinRAR / `rar.exe` for `-Archive Rar`.

---

## Antivirus / EDR note

The rule tables contain the command lines and tool names of real attacker techniques (for example `sekurlsa::`, download cradles, Defender exclusion commands) as plain text. Some antivirus and EDR products may flag the **script file itself**, even though it never executes them. If that happens, verify the hash, review the source, and use a scoped temporary exclusion or a code-signing certificate according to your policy.

Running the collector also generates telemetry (PowerShell, process creation, file access) that your SOC will see. Coordinate before running it on monitored hosts.

## Limitations

- **Triage, not a verdict.** The analysis is heuristic. Every finding links to its evidence and must be confirmed by an analyst.
- **Only as good as the logging.** Missing Sysmon, disabled PowerShell logging or small log sizes limit detection; the report lists these as visibility gaps.
- **No memory acquisition.** Pair it with a dedicated memory tool when volatile evidence matters.
- **Lightweight artifact parsing.** Raw artifacts are kept so they can be processed with validated tools (EZ Tools, RegRipper, Hayabusa, Chainsaw).

Details: [Limitations](DOCUMENTATION.md#14-limitations) and [Troubleshooting](DOCUMENTATION.md#15-troubleshooting).

## Documentation

[`DOCUMENTATION.md`](DOCUMENTATION.md) covers the architecture, every collection step, every event ID and rule, the ATT&CK mapping, scoring, the incident algorithm, the report and troubleshooting.

## Disclaimer

For **authorized** incident response, forensic investigation and security assessment only. Run it only on systems you own or are explicitly permitted to investigate. Provided as-is, without warranty.

## License

[MIT](LICENSE)
