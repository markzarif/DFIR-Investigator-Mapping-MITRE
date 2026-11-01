# IR-Investigator - Full Documentation

**Version:** `1.0.0` | **File:** `IR-Investigator.ps1` | **Requirements:** Windows 10 / 11 / Server 2016+ and PowerShell 5.1 or later

---

## Contents

1. [What the tool does](#1-what-the-tool-does)
2. [Quick start](#2-quick-start)
3. [Modes, profiles and parameters](#3-modes-profiles-and-parameters)
4. [Output layout](#4-output-layout)
5. [Collection phase](#5-collection-phase)
6. [Analysis phase](#6-analysis-phase)
7. [MITRE ATT&CK mapping in detail](#7-mitre-attck-mapping-in-detail)
8. [Severity, score and verdict](#8-severity-score-and-verdict)
9. [Grouping findings into incidents](#9-grouping-findings-into-incidents)
10. [Timeline](#10-timeline)
11. [The report (dashboard)](#11-the-report-dashboard)
12. [Evidence integrity (chain of custody)](#12-evidence-integrity-chain-of-custody)
13. [Detection rule reference](#13-detection-rule-reference)
14. [Limitations](#14-limitations)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. What the tool does

`IR-Investigator.ps1` is a single PowerShell script that does the work an incident responder / forensic analyst does on a suspect Windows host:

1. **Collects** the evidence from the host:
   - Live state: processes, network, accounts.
   - Persistence, evidence of execution and user activity.
   - Complete event logs as `.evtx`.
   - Raw artifacts such as registry hives, Amcache, SRUM and browser databases.
2. **Analyzes** that evidence with more than 200 detection rules plus cross-event correlation. This includes parsing the raw artifacts themselves: browsers, Amcache, ShellBags, Jump Lists and SRUM (section 6.8).
3. **Maps** every finding to a technique and tactic in **MITRE ATT&CK**.
4. **Groups** related findings into **incidents**, each with a chronological narrative and a graph.
5. **Writes one self-contained HTML report** that works offline, with:
   - The verdict.
   - The timeline.
   - The ATT&CK matrix.
   - All evidence tables.
   - Recommendations.
   - An IOC table.
6. **Preserves the evidence:** SHA-256 of every file, packaged into a hashed archive.

> **Important:** the analysis is **automated, heuristic triage**. Every finding links back to the evidence it came from and must be confirmed by an analyst. The raw artifacts get a basic in-script parse and are kept in the case for validated forensic tools such as EZ Tools, Hayabusa and Chainsaw.

### Why a single script?

- Nothing to install: PowerShell ships with every Windows.
- One file to carry on a USB stick or share and run.
- The same file collects on the victim host and analyzes later on the analyst workstation.

---

## 2. Quick start

Open PowerShell **as Administrator** and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\IR-Investigator.ps1
```

This command:
1. Collects with the `Standard` profile.
2. Analyzes the last 30 days.
3. Writes the report.
4. Packages everything into `D:\IRCollection` (falls back to `C:\Windows\Temp\IRCollection` when `D:` does not exist).
5. Opens the report in the browser.

More examples:

```powershell
# Quick collection straight to a share, no analysis on the victim host
.\IR-Investigator.ps1 -Mode Collect -Profile Quick -OutputRoot \\ir-server\cases

# Analyze a previously collected case on the analyst workstation, last 90 days
.\IR-Investigator.ps1 -Mode Analyze -CasePath D:\Cases\HOST01_20261031_120000Z.zip -Days 90

# Full collection with an encrypted RAR archive and case metadata
.\IR-Investigator.ps1 -Profile Full -Archive Rar -ArchivePassword 'S3cret!' -CaseLabel 'INC-2026-044' -Examiner 'Ahmed'
```

---

## 3. Modes, profiles and parameters

### Modes (`-Mode`)

| Mode | What it does | When to use it |
|---|---|---|
| `All` (default) | Collect, analyze, write the report, package | Fast investigation of a single host |
| `Collect` | Collect and package only | Lightest footprint on a compromised host, or collecting from many hosts |
| `Analyze` | Analyze a case folder or `.zip` | On the analyst workstation. Needs no elevation and changes nothing on that machine |

### Profiles (`-Profile` or `-CollectionProfile`)

| Profile | What it collects |
|---|---|
| `Quick` | All live state, the key event logs only, file scan up to 1,500 files. Takes a few minutes |
| `Standard` (default) | Everything in Quick, plus every non-empty event log, the hives (SYSTEM, SOFTWARE, NTUSER, UsrClass), Prefetch, Amcache, SRUM, Jump Lists, LNK, browsers, PowerShell history, Recycle Bin, task files and Defender logs. File scan up to 5,000 files |
| `Full` | Everything in Standard, plus SAM and SECURITY, thumbcache, RDP bitmap cache and alternate data streams. Deeper file scan, up to 15,000 files |

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Mode` | `All` | `All`, `Collect` or `Analyze` |
| `-Profile` | `Standard` | `Quick`, `Standard` or `Full` |
| `-OutputRoot` | `D:\IRCollection` | Where the case folder is created. UNC paths work |
| `-CasePath` | - | Analyze mode: a case folder or `.zip`. Extract a `.rar` first |
| `-Days` | `30` | Analysis window in days before the collection time (1 to 3650) |
| `-MaxEventsPerLog` | `50000` | Upper bound of events per query, newest first |
| `-Archive` | `Zip` | `Zip`, `Rar` (encrypted with `-hp`) or `None` |
| `-ArchivePassword` | `infected` | RAR password. Note that it is visible in process-creation telemetry |
| `-KeepCaseFolder` | - | Keep the case folder after the archive is created |
| `-CaseLabel` | - | Case / ticket identifier shown in the report |
| `-Examiner` | - | Examiner name shown in the report |
| `-NoOpen` | - | Do not open the report at the end. By default it opens in the default browser through `explorer.exe`, so even when the script runs elevated the browser runs as the normal user. It never opens when running as SYSTEM |

> When started from 32-bit PowerShell, the script relaunches itself under 64-bit PowerShell automatically. A 32-bit process is redirected to `SysWOW64` and does not see the real registry.

---

## 4. Output layout

```
<OutputRoot>\
|-- HOST01_20261031_120000Z\               case folder (deleted after packaging unless -KeepCaseFolder)
|   |-- live\*.json                         normalized live state (about 40 datasets)
|   |-- eventlogs\*.evtx                    complete event logs
|   |-- artifacts\...                       raw artifacts, copied unmodified
|   |-- report\IR-Report.html               the report (All and Analyze modes)
|   |-- manifest.csv                        SHA-256 of every file
|   `-- collection.log                      every step: done or failed, and why
|-- HOST01_20261031_120000Z.zip             the archive
|-- HOST01_20261031_120000Z.zip.sha256      archive hash
|-- HOST01_20261031_120000Z_IR-Report.html  copy of the report next to the archive
`-- HOST01_20261031_120000Z_collection.log  full log up to the last step
```

The case name is `<HOSTNAME>_<yyyyMMdd_HHmmss>Z`, always in **UTC**.

---

## 5. Collection phase

Every step runs in isolation inside `Invoke-IRStep`. If one step fails the rest continue, and the failure is recorded in `collection.log` and in the `collection_steps` table (status `ok`, `partial` or `error`, duration and item count).

| # | Step | Datasets | Notes |
|---|---|---|---|
| 1 | System information | `system` | OS, domain, role, timezone, IPs, who ran the script, collection time |
| 2 | **Prefetch** | `prefetch` | **First step after system info**, because anything the script runs afterwards creates new `.pf` files |
| 3 | Running processes | `processes` | PID, parent, command line, user, SHA-256, signature |
| 4 | Network state | `network_connections`, `dns_cache`, `arp_cache`, `ip_configuration`, `smb_shares`, `smb_sessions`, `hosts_file`, `proxy_settings`, `port_proxy`, `network_history` | Every connection is tied to its process |
| 5 | Accounts | `local_users`, `group_members`, `sessions`, `user_profiles` | |
| 6 | Services and drivers | `services`, `drivers` | With signature and hash |
| 7 | Autostart locations | `autoruns` | Run/RunOnce, Winlogon, IFEO, SilentProcessExit, AppInit, LSA packages, BootExecute, Netsh helpers, Print monitors, Screensaver, COM hijack, Office test, Startup folders |
| 8 | Scheduled tasks | `scheduled_tasks` | Command, author, run-as, signature. Reads the XML files in `System32\Tasks`; without admin (folder not accessible) it falls back to the Task Scheduler API (`Get-ScheduledTask`) |
| 9 | WMI subscriptions | `wmi_persistence` | Filters, consumers, bindings |
| 10 | Defender and firewall | `defender_status`, `defender_preferences`, `defender_exclusions`, `defender_threats`, `firewall_profiles`, `firewall_rules` | |
| 11 | Security configuration | `security_config`, `audit_policy` | WDigest, UAC, RunAsPPL, LSA, SMB1, NLA, PowerShell logging |
| 12 | Execution evidence | `bam`, `userassist`, `shimcache` | ShimCache is decoded from the live registry (`10ts` format on Windows 10/11) and works without admin |
| 13 | User activity | `powershell_history`, `recent_files`, `user_mru`, `usb_devices`, `recycle_bin` | |
| 14 | Software | `installed_software`, `hotfixes` | |
| 15 | File scan | `file_scan` | Executables, scripts and archives created or modified in the last `-Days` days in Downloads, Desktop, Temp, AppData, ProgramData, Public, PerfLogs, System32 and more. Per file: hash, signature and **Mark-of-the-Web** (`ZoneId`, `HostUrl`) |
| 16 | Alternate data streams | `alternate_data_streams` | `Full` only |
| 17 | **Event logs** | `event_logs` + `eventlogs\*.evtx` | Uses `wevtutil epl`. Quick exports the key logs only; Standard and Full export every non-empty log. Records each log's size and oldest event |
| 18 | Raw artifacts | `artifacts\` | Standard and Full: hives, Amcache, SRUM, Jump Lists, LNK, Chrome/Edge/Brave/Firefox history, ActivitiesCache, Recycle Bin `$I` files |

**Locked files:** copying tries three methods in order:
1. A normal copy.
2. `robocopy /B` (backup mode). This bypasses ACLs only, not sharing locks.
3. **Volume Shadow Copy (VSS):** if the file is still exclusively locked (for example `Amcache.hve`, `SRUDB.dat` or an open browser database) and the script runs elevated, one shadow copy of C: is created the first time it is needed and the file is copied from it.
   - The shadow copy is deleted as soon as the raw-artifact step finishes, and again in the script's `finally` block if something fails. The host's existing shadow copies (restore points) are never touched.
   - If VSS is unavailable, the file is logged as `could not copy` and the missing analysis is listed in the visibility gaps.

**Long paths:** any file whose path is longer than 240 characters is renamed before packaging, and the old and new names are logged. These files are found with `\\?\` paths, because `Get-ChildItem` on PowerShell 5.1 does not see paths longer than 260 characters. Example: Action Center shortcuts in `Recent` (136 such files were renamed during testing).

---

## 6. Analysis phase

Analysis only reads the case folder, so it can run on any machine. The flow:

```
load live\*.json
        |
        v
1. Event logs (eventlogs\*.evtx)          --+
2. Raw artifacts (artifacts\)               |
3. Live state and artifacts                 +--> Findings (rule + technique + severity + evidence)
4. Cross-event correlation                --+           |
5. Visibility gaps                                      v
                                          sorted and numbered F001, F002, ...
                                                        |
                                                        v
                                     Incidents -> Verdict -> Recommendations -> IOCs
                                                        |
                                                        v
                                                IR-Report.html
```

### 6.1 Analysis window

- The **reference time** is the `collection_start` recorded in `system.json`, **not** the time the analysis runs. Analyzing the same case a month later gives the same result.
- **Window start** = reference time minus `-Days`.

### 6.2 Event log analysis

- Events are read from the collected `.evtx` files, not the live host, with `EventLogReader`. Every event and reader is disposed after reading so the files stay deletable (`Get-WinEvent -Path` kept them open until the process exited).
- **XPath filters** on event ID and time are used, so not everything is read.
- High-volume events (4624, 4688, Sysmon 1 and 3) get their own queries, so the `-MaxEventsPerLog` cap cannot crowd out rare, high-value events.
- A query that reaches the cap is reported as a visibility gap.

| Log | Event IDs |
|---|---|
| **Security** | 4624 (logon types 2/3/8/9/10/11/12), 4625, 4771, 4776 (failures only), 4648, 4688, 1102, 4719, 4720, 4722, 4724, 4725, 4726, 4728, 4732, 4756, 4740, 4697, 4698, 4699, 4702, 4778, 4779, 4768 (no pre-auth), 4769 (RC4 `0x17`), 5140 (`ADMIN$` and `C$`) |
| **System** | 7045, 7040, 104, 6005, 6006, 6008, 1074 |
| **PowerShell/Operational** | 4104 (Script Block Logging, split blocks are reassembled) |
| **Windows PowerShell** | 400 (detects the 2.0 engine) |
| **Sysmon** | 1, 3, 6, 8, 10 (target lsass only), 11, 13, 22, 25 |
| **RDP** | LocalSessionManager 21/22/24/25, RemoteConnectionManager 1149, RDPClient 1024/1102 |
| **Defender** | 1006, 1015, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012, 5013 |
| **TaskScheduler** | 106, 140, 141 |
| **WMI-Activity** | 5861 |
| **BITS** | 59 |
| **WinRM** | 91 |
| **Firewall** | 2003, 2004, 2005, 2006, 2052, 2097, 2099 |
| **SMBServer/Security** | 551 |
| **Application** | ESENT 325/326/327 (ntds.dit), MsiInstaller 1033/11707 |

Every event is normalized to: UTC time, log, ID, record, provider, SID and a dictionary of `EventData` / `UserData`.

### 6.3 The script filters out its own activity

So that the tool does not report itself as an attack (it runs PowerShell and commands itself):

- The code contains a **hidden marker** (`SelfMarker`). Any 4104 script block containing it, or whose path is `IR-Investigator*.ps1`, is dropped entirely, including every part with the same `ScriptBlockId`.
- Processes whose parent is the **script's PID**, between collection start and collection end plus 10 minutes, are dropped from 4688 and Sysmon 1.
- Live processes whose PID or PPID is the script's PID are dropped.
- Any command line containing `IR-Investigator` is dropped.
- Short script blocks (under 1,500 characters) that only launch `IR-Investigator*.ps1` are dropped.
- Defender detections (1006/1015/1116-1119 and the live detection history) whose resource is the script itself are dropped. AMSI may flag the script because its rules contain attacker tool names.
- Script blocks Windows generates for CDXML modules (containing `$__cmdletization_objectModelWrapper` and no path) are dropped: they are Microsoft code and produce many false positives.
- The number of filtered items is shown on the report's **Collection** tab (Own activity filtered, Generated module code skipped).

> **Important:** on hosts with Defender or an EDR, AMSI may quarantine the script when it runs (`HackTool:PowerShell/Mimikatz` and `MpTamperSrvDisableAV` were seen during testing). This is caused by rule text such as `sekurlsa::`, not by malicious behavior. If it happens, add a temporary exclusion for the script path or sign it with a code-signing certificate.

### 6.4 Rule types

| Type | Runs on | Examples |
|---|---|---|
| **Command-line rules** (about 65) | 4688, Sysmon 1, 4104, PowerShell history, service / task / autorun commands | Mimikatz, LSASS dump, encoded PowerShell, certutil, PsExec, log clearing |
| **Discovery rules** (12) | Same sources | whoami, net user, ipconfig, systeminfo, nltest |
| **Parent-child rules** (9) | 4688 and Sysmon 1 | Office spawning a shell, web server spawning cmd, WMI spawning a process |
| **Tool-name rules** (16 groups) | Process, file, Prefetch and BAM names | Rubeus, SharpHound, Cobalt Strike, ngrok, rclone, AnyDesk |
| **Path rules** | Any file or process path | Masquerading, execution from staging folders, double extensions, typosquatting |
| **Network rules** | Sysmon 3 and live connections | LOLBin talking to the Internet, C2 ports, inbound from public IPs |
| **Domain rules** (6) | Sysmon 22, DNS cache, URLs | File sharing, tunneling, dynamic DNS, Telegram/Discord, mining pools |
| **Registry rules** (13) | Sysmon 13 | IFEO, Winlogon, WDigest, Defender, UAC hijack, LSA |
| **Event-specific rules** | Each event ID has its own logic | 1102 log cleared, 7045 service, 4720 new account, 1116 Defender detection |
| **Correlation rules** (8) | Groups of events | Brute force, password spray, Kerberoasting, discovery burst |
| **Live-state rules** | The datasets in `live\` | Invalid signature, Defender exclusions, WMI consumer, BYOVD |

### 6.5 Encoded PowerShell

When `PS-ENCODED` detects `-EncodedCommand`, it:
1. Decodes the base64 (UTF-16LE).
2. Adds the decoded text to the finding's evidence.
3. **Runs the decoded text through every rule again**, so a download cradle or Mimikatz inside it produces its own finding.

### 6.6 Correlation

| Rule | Condition | Severity | Technique |
|---|---|---|---|
| `BRUTE-FORCE` | 10+ failed logons from one source (IP or workstation name) within 30 minutes, or 30+ in the whole window | high | T1110.001 |
| `PASSWORD-SPRAY` | Same condition across 5+ different accounts | high | T1110.003 |
| `BRUTE-SUCCESS` | Successful logon from the same IP within 6 hours after the failures | **critical** | T1078 |
| `KERBEROAST` | RC4 tickets for 5+ different services from one client within 10 minutes | high | T1558.003 |
| `DISCOVERY-BURST` | 5+ different discovery commands covering at least 3 techniques, by one account, within 10 minutes (high at 10+) | medium or high | The most frequent technique in the burst, e.g. T1033, T1087, T1016 |
| `TASK-CREATE-DELETE` | Task created and deleted within an hour | high | T1053.005 |
| `NEW-ADMIN-ACCOUNT` | Account created and added to a privileged group within 24 hours | high | T1136.001 |
| `EXPLICIT-CRED-SPREAD` | One account used explicit credentials against 3+ hosts | medium | T1078 |

### 6.7 Visibility gaps

The report states what **could not be seen**, so that absence of evidence is not mistaken for evidence of absence:
- The script did not run elevated.
- A key log is missing or disabled, or its oldest event is newer than the window start (the log rolled over).
- Sysmon is not installed.
- Command lines are not recorded in 4688.
- PowerShell Script Block Logging is disabled.
- RunAsPPL is off, RDP runs without NLA, or SMB1 is enabled.
- The audit policy is missing: Logon, Process Creation, Account Management, Security Group Management, Other Object Access, Audit Policy Change.
- Tamper Protection is off.
- A query reached `-MaxEventsPerLog`.
- A raw artifact was not collected or not analyzed (section 6.8).

### 6.8 Raw artifact analysis

In Standard and Full, the script parses the raw files in `artifacts\` itself, without external tools and without admin on the analyst machine:
- **The parsers are written in C#** inside the script (`Add-Type`) and are read-only.
- **SQLite and ESE databases are opened from a temporary copy** in `%TEMP%\IRArt_*`, because opening them applies the journal/WAL. The temporary folder is deleted at the end and the case is never modified (integrity stays verified).
- **Each artifact is independent:** if one fails or is missing (for example in Quick), the others continue and the reason is written to the log, the gaps and the `artifact_notes` table.

| Artifact | Source in the case | How it is read | Datasets | What it produces |
|---|---|---|---|---|
| **Browsers** | `Users\<user>\Browsers\<Edge/Chrome/Brave>\<profile>\History` and `Firefox\<profile>\places.sqlite` | SQLite through `winsqlite3.dll`, which ships with Windows 10/11 | `browser_history`, `browser_downloads` | Visits in the window (up to 20,000 per profile; the report shows the newest 15,000) and downloads with URL, referrer, path, state and Safe Browsing verdict |
| **Amcache** | `Amcache\Amcache.hve` + `.LOG1/.LOG2` | regf parser, replays transaction logs when the hive is dirty | `amcache_files`, `amcache_programs` | Path, **SHA-1**, publisher, version and registration time of every program, plus installed programs |
| **ShellBags** | `Users\<user>\UsrClass.dat` and `NTUSER.DAT` | regf parser + shell item decoding (`BagMRU`) | `shellbags` | Every folder the user opened in Explorer (local, network or USB), even if it was deleted later |
| **Offline NTUSER** | `Users\<user>\NTUSER.DAT` | regf parser | Added to `userassist` and `user_mru` | UserAssist, RunMRU, TypedPaths, RDP MRU and mapped drives **for users whose profile was not loaded** at collection time (loaded profiles are collected live) |
| **Jump Lists** | `Users\<user>\JumpLists\AutomaticDestinations` and `CustomDestinations` | OLE compound file parser + LNK parser + DestList | `jump_lists` | Files opened per application, last time and count, arguments (e.g. `mstsc /v:host`), drive type, volume serial, machine ID |
| **SRUM** | `SRUM\SRUDB.dat` + `SRU*.log` | `esentutl /r` on the temporary copy, then ESE reading through `esent.dll` | `srum_network_summary`, `srum_network`, `srum_app_usage` | Bytes sent and received per program per hour and per user, plus CPU and disk usage per program |

**Artifact rules:**

| Rule | Severity | Technique | Condition |
|---|---|---|---|
| `BROWSER-IP-FILE` | medium | T1105 | The browser downloaded a file (exe, ps1, zip, iso ...) directly from a public IP |
| `BROWSER-IP-URL` | low | T1071.001 | A public IP was visited directly, without a domain |
| `BROWSER-DL-DANGER` | medium | T1204.002 | The browser marked the download as dangerous (dangerous, uncommon, potentially unwanted, or the user accepted the warning) |
| `BROWSER-DL-EXEC` | low | T1105 | An executable or script downloaded from an untrusted site |
| `AMCACHE-SUSP-DIR` | low | T1204.002 | A program in a staging folder (Temp, Public, ProgramData ...) recorded in Amcache |
| `SRUM-NET-SUSP-DIR` | medium | T1071.001 | A program from a staging folder used the network |
| `SRUM-LARGE-UPLOAD` | medium (low for known sync / backup software) | T1048 | A program sent 1 GB or more in the window and sent more than it received |

The existing rules also run on these artifacts: known tool names (`TOOL-*`: a file, folder or program named mimikatz, rclone, nmap ...), `DOUBLE-EXT`, `ADMIN-SHARE` (opening `\\host\C$` seen in ShellBags or Jump Lists), `EXEC-SUSP-DIR`, `RDP-OUTBOUND` (from the mstsc Jump List), `TYPOSQUAT`, and the domain rules (file sharing, tunneling, dynamic DNS) on every visited or download URL.

**Timeline:** downloads, Amcache entries outside Windows / Program Files, ShellBags, Jump Lists, the first SRUM appearance of every untrusted program, and any hour in which a program sent 200 MB or more. Visits enter the timeline only when a finding is attached.

---

## 7. MITRE ATT&CK mapping in detail

### 7.1 The idea

Every detection rule carries a **fixed technique ID**, chosen by the rule author for the behavior the rule detects, not the tool. LSASS dumped with `procdump`, `comsvcs.dll` or `nanodump` is always `T1003.001`.

```
Detected behavior              Rule                 Technique        Tactic
-----------------------------  -------------------  ---------------  -------------------
procdump -ma lsass.exe     --> CRED-LSASS-DUMP  --> T1003.001    --> Credential Access
vssadmin delete shadows    --> INHIBIT-RECOVERY --> T1490        --> Impact
schtasks /create ...       --> SCHTASKS-CREATE  --> T1053.005    --> Execution
Word -> powershell.exe     --> CHILD-OFFICE     --> T1204.002    --> Execution
Sysmon 22: x.ngrok.io      --> DNS-TUNNEL       --> T1572        --> Command and Control
```

### 7.2 The catalog

The script contains a `$Script:Mitre` catalog of more than 100 techniques. Each line is:

```
T1003.001|OS Credential Dumping: LSASS Memory|credential-access
```

That is: **ID | name | primary tactic**.

The 12 tactics in kill-chain order:

| Tactic | ID |
|---|---|
| Initial Access | TA0001 |
| Execution | TA0002 |
| Persistence | TA0003 |
| Privilege Escalation | TA0004 |
| Defense Evasion | TA0005 |
| Credential Access | TA0006 |
| Discovery | TA0007 |
| Lateral Movement | TA0008 |
| Collection | TA0009 |
| Command and Control | TA0011 |
| Exfiltration | TA0010 |
| Impact | TA0040 |

> **Note:** in ATT&CK some techniques belong to several tactics. For example `T1053.005` Scheduled Task is in Execution, Persistence and Privilege Escalation. The tool maps each technique to **one primary tactic**, so every finding lands in exactly one matrix column and is counted once.

### 7.3 Mapping steps

1. **Detection:** a rule matches an event or artifact.
2. **Finding creation:** `Add-IRFinding -Rule X -Technique T#### ...`.
3. **Enrichment:** the technique is looked up in the catalog and the finding gets:
   - `technique`: the ID, e.g. `T1003.001`.
   - `technique_name`: the full name.
   - `tactic`: the primary tactic.
   - `recommendation`: from `Get-IRAdvice`, which looks for advice for the exact technique and falls back to the parent technique (`T1003.001` -> `T1003`).
4. **Matrix aggregation:** findings are grouped tactic -> technique. For each technique:
   - **Color** = the highest severity among its findings.
   - **hits** = total occurrences.
   - **findings** = the finding IDs, clickable.
5. **Kill chain on the Overview:** each tactic shows its finding count and highest severity.
6. **Recommendations:** one card per parent technique observed, with the advice and the finding IDs.
7. **Incident title:** derived from the **set of tactics and techniques** in the incident (section 9).

### 7.4 Full example

A 4688 event in the Security log:
```
NewProcessName: C:\Users\Public\p.exe
CommandLine:    p.exe -accepteula -ma lsass.exe C:\Users\Public\l.dmp
ParentProcess:  C:\Windows\System32\cmd.exe
SubjectUser:    CORP\j.smith
```

produces:

| Finding | Why | Technique | Tactic | Severity |
|---|---|---|---|---|
| `CRED-LSASS-DUMP` | `-ma lsass` in the command line | T1003.001 | Credential Access | critical |
| `EXEC-SUSP-DIR` | Execution from `\Users\Public\` | T1204.002 | Execution | medium |

And if Sysmon 11 records that `l.dmp` was written:

| `LSASS-DUMP-FILE` | LSASS dump file | T1003.001 | Credential Access | critical |

These three findings share the file `\users\public\p.exe` and the user `j.smith`, so they form **one incident** titled "Credential access". If PsExec to another host follows, the title becomes "Credential theft and lateral movement".

### 7.5 Techniques covered per tactic

| Tactic | Example techniques |
|---|---|
| Initial Access | T1078, T1078.001, T1078.003, T1133, T1566.001 |
| Execution | T1059.001, T1059.003, T1059.005, T1047, T1053.005, T1569.002, T1204.002 |
| Persistence | T1543.003, T1547.001, T1547.004, T1547.005, T1547.010, T1546.002/003/007/008/010/012/015, T1136.001, T1098, T1505.003 |
| Privilege Escalation | T1548.002, T1068, T1134 |
| Defense Evasion | T1027, T1036.005, T1036.007, T1070.001/003/004/006, T1112, T1140, T1197, T1218.005/007/010/011, T1127.001, T1553.005, T1562.001/002/004/010, T1564.001/003/004, T1055, T1055.012, T1014 |
| Credential Access | T1003.001/002/003/006, T1110.001/003, T1552.001, T1555.003, T1557.001, T1558.003/004 |
| Discovery | T1033, T1087, T1087.002, T1069, T1082, T1016, T1049, T1057, T1018, T1135, T1007, T1201, T1482, T1046, T1518.001 |
| Lateral Movement | T1021.001, T1021.002, T1021.006, T1550.002, T1570 |
| Collection | T1560.001 |
| Command and Control | T1071.001, T1090, T1102, T1105, T1219, T1571, T1572 |
| Exfiltration | T1567.002, T1048 |
| Impact | T1486, T1489, T1490, T1496, T1565.001 |

The full catalog is available in the report: **MITRE ATT&CK** tab -> **"Show every technique the analyzer can detect"**.

---

## 8. Severity, score and verdict

### 8.1 Severity levels

| Level | Meaning | Score weight |
|---|---|---|
| `critical` | Strong evidence of compromise: credential dumping, ransomware, web shell, successful brute force | 40 |
| `high` | Clear attacker behavior that needs immediate investigation | 15 |
| `medium` | Suspicious, but may be administrative | 5 |
| `low` | Useful context, e.g. an internal RDP logon or a firewall rule | 1 |
| `info` | Documentation only | 0 |

### 8.2 De-duplication

- Every finding has a key `rule|key`, for example `EXEC-SUSP-DIR|\users\public\p.exe`.
- When the same thing appears again, from the same or another source, **no new finding is created**. Instead:
  - `hits` increases.
  - `first_seen` and `last_seen` are updated.
  - The new source is added to `sources` (up to 10).
  - The new evidence is added (up to 8).
  - The severity is **raised** if the new occurrence is more severe.
- When one rule produces more than 40 distinct keys, the rest are folded into one finding with the key `__more__`, so the report is not flooded.
- Known tools are keyed by name without extension, so `rubeus` from Prefetch, BAM and 4688 is **one finding** with three sources.
- `SERVICE-INSTALLED` keys have version numbers removed, so every update of the same program (e.g. `App_26.1023.6123.0`) is one finding with a count, not one finding per update.
- `PS-SUSPICIOUS-BLOCK` keys have GUIDs in file names removed, and interactive commands without a path are grouped into one finding.

### 8.2.1 False-positive reduction

- `DOUBLE-EXT` does not fire on `Recent\*.lnk`, because Windows names them `file.pdf.lnk`.
- `EXEC-SUSP-DIR` from UserAssist ignores `.lnk`, and `C:\Users\Public\Desktop` is not treated as a staging folder.
- `DEFENDER-SETTING-DISABLED` from 5007 is **high** only when the key is under `Policies`, `Real-Time Protection` or `Spynet`, or is `DisableAntiSpyware`, `DisableAntiVirus` or `TamperProtection`. Any other `Disable*` value (such as the ones Defender changes during updates) is **medium**.
- COM hijack fires when the path is suspicious, or when the file is unsigned and outside `Program Files\WindowsApps`.
- A hidden scheduled task is not `TASK-SUSPICIOUS` when its program has a `Valid` signature and lives in a trusted folder (`Program Files` or `System32`), such as GoogleUpdater and EdgeUpdate.

### 8.3 Numbering

Findings are sorted by severity (highest first), then by first seen, and numbered `F001`, `F002` and so on.

### 8.4 Verdict

```
score = min(100, critical + high + min(30, medium) + min(10, low))
```

Each part is the sum of the weights of the findings at that level. Medium is capped at 30 and low at 10, so many small items on a clean host (such as service updates) cannot raise the verdict on their own.

| Verdict | Condition |
|---|---|
| **Compromise likely** | At least one critical finding, **or** score 60+ **and** at least one high |
| **Suspicious activity** | At least one high, **or** score 40+ |
| **Needs review** | At least one medium |
| **No significant findings** | Otherwise |

---

## 9. Grouping findings into incidents

### 9.1 Algorithm (union-find over entities)

1. From every finding (except `info`) the **entities** are extracted:
   - **Strong:** IP, file (path normalized, drive letter removed), SHA-256, domain, process outside trusted Windows folders.
   - **Weak:** user.
2. **Linking:**
   - Findings that share a strong entity are linked **immediately**.
   - Findings that share only a user are linked when **consecutive findings are 24 hours or less apart**.
   - High and critical findings from the **PSReadLine history of the same user** are linked, because the history has no timestamps and one user's history is a single command stream.
   - An entity that appears in more than 60 findings is **ignored** (for example the DC's IP), so it does not glue everything together.
   - Command-line rules extract entities from the command text itself: IPs, the domain of any URL, and paths of executables, scripts and archives. So `certutil ... http://203.0.113.50/upd.exe C:\Users\Public\upd.exe` and `schtasks /tr C:\Users\Public\upd.exe` are linked through the file.
   - Findings with **no entity at all** (host-wide settings: Defender disabled, firewall disabled, WDigest, Defender exclusions) are grouped into **one incident per tactic** instead of one incident per setting.
3. Every linked group becomes an **incident** if it contains **one high or critical finding**, or **at least two findings with medium as the highest**. Groups that are all low, or a single medium, do not become incidents.
4. Incidents are sorted by severity, then score, and numbered `INC-01`, `INC-02` and so on.

### 9.2 Incident content

- **Title** from the tactics and techniques:

| When it contains | Title |
|---|---|
| A destructive technique (`T1485` `T1486` `T1488` `T1489` `T1490` `T1491` `T1495` `T1529` `T1561`) | Possible ransomware / destructive activity |
| Credential Access + Lateral Movement | Credential theft and lateral movement |
| C2 or Exfiltration | Command-and-control / data exfiltration |
| Credential Access + Initial Access | Credential attack against remote access |
| Credential Access | Credential access |
| Lateral Movement | Lateral movement |
| Persistence + Execution | Malicious execution with persistence |
| Defense Evasion + something else | Defense evasion with follow-on activity |
| Persistence / Initial Access / Defense Evasion / Discovery | Persistence / Suspicious remote access / Defense evasion / Reconnaissance |
| Mining only (`T1496`) | Cryptocurrency mining (resource hijacking) |
| Impact without destruction (e.g. `T1565` hosts file change) | Data manipulation |

- Impact alone no longer means ransomware: a coin miner (`T1496`) and a hosts-file change (`T1565`) are Impact too. When mining is part of an incident with another title, ` + cryptomining` is appended (e.g. `Command-and-control / data exfiltration + cryptomining`).
- **Headline:** the most severe finding in the incident.
- **Severity:** the highest severity in it. **Score:** sum of the weights, capped at 100.
- **Summary:** duration, finding count, tactics in order, users and IPs.
- **Narrative:** one line per finding in chronological order: `time | tactic | title (technique) - occurrences`.
- **Graph:** nodes are the host, the findings (colored by severity), users, IPs, files and domains; edges show what is linked to what.

### 9.3 Recommendations

- **Containment:** built from the tactics seen in **high or critical** findings only. When there are none, the report says no containment is needed:
  - Any high or critical: isolate the host and capture memory before any reboot.
  - Credential Access: reset passwords; with a DC involved, reset krbtgt twice.
  - Lateral Movement: add the other hosts to the investigation.
  - C2 or Exfiltration: block the IOCs.
  - Impact: protect the backups.
  - And so on for the other tactics.
- **Next steps:** manual review, Hayabusa/Chainsaw, EZ Tools, hashes against threat intel, hunting, disk image.
- **By technique:** remediation advice per parent technique.
- **Gaps:** section 6.7.
- **IOCs:** IPs (public and internal), domains, SHA-256 hashes, files and accounts, from medium-or-higher findings only.

---

## 10. Timeline

- Every event read becomes a row: time (UTC), source (e.g. `Security 4688`), category, summary and user.
- If the event's rule wrote a readable summary (such as "RDP session logon" or "Defender configuration changed"), that summary is shown. Otherwise a generic row is built from the first 8 `EventData` fields with the category `event`. So **every** analyzed event is in the timeline.
- **Rows linked to findings** (`fk`) are colored by the finding's severity and link to it.
- Timeline sources: event logs, Prefetch, BAM, UserAssist, LNK, the file scan, the Recycle Bin, USB and anything else with a timestamp.
- Rows **not linked to findings** and older than the window start are dropped.
- **The report holds at most 30,000 rows.** Beyond that:
  - **Every row linked to a finding is kept**.
  - Only the newest of the rest are kept.
  - The report says it was truncated.

---

## 11. The report (dashboard)

A single HTML file with all data embedded in `<script type="application/json">`. It works **offline** in any modern browser.

| Tab | Content |
|---|---|
| **Overview** | Verdict and risk score, finding counts by severity, the attack chain (12 tactics), daily activity chart (click a day to open it in the timeline), most severe findings, incidents, host and case details |
| **Incidents** | A graph of all incidents together, then one card per incident with the narrative, findings, entities and its own graph. Nodes can be dragged; clicking a finding opens it |
| **Findings** | All findings. A card expands to show description, recommendation, ATT&CK, sources, entities and evidence. Filter by severity, tactic and incident, search, CSV export |
| **Timeline** | Filters by source, category, severity, finding, incident and day, a "linked to findings only" switch, pages of 250 rows, CSV export |
| **Graph** | One graph of every entity in the report (details in 11.1) |
| **MITRE ATT&CK** | A 12-column matrix colored by severity; clicking a technique lists its findings. An option shows the whole catalog |
| **Evidence** | About 40 datasets in groups (Network, Accounts, Persistence, Execution, ...) with search, column sorting, pages of 500 and CSV export. Each table shows up to 25,000 rows; the complete data is in `live\*.json` |
| **Recommendations** | Containment, next steps, eradication per technique, visibility gaps and the IOC table with CSV |
| **Collection** | Analysis information, evidence integrity check, collection steps and event log statistics |

**Other features:**
- **Time display** switches between UTC and the collected host's local time (from `utc_offset_minutes`).
- **Safety:** all data is rendered with `textContent` only, so no text from the evidence is ever executed as HTML. The JSON escapes `< > &`. CSV export protects against CSV injection (prefixes `'` before `= + - @`).

### 11.1 The Graph tab

The graph is built in the browser when the tab is opened, from data already in the report, so the file does not grow. For a case with about 33,000 rows it builds in under half a second.

**Entity (node) types:**

| Type | Comes from |
|---|---|
| Host | The host itself, with its IPs |
| Finding / Incident | Findings (colored by severity) and incidents |
| ATT&CK technique | Each finding's technique |
| Account | Any column named `user`, `account`, `run_as`, `by`, `member`, ... |
| File / process | Any column with a full path (`path`, `image`, `target`, `app`, `program`, ...), plus bare process names (Prefetch, network) |
| Hash | `sha256`, `sha1`, `md5` |
| IP address | `remote_address`, `address`, `source_ip`, DNS `data`, ... (excluding loopback and link-local) |
| Domain / remote host | The host of any URL (history, downloads, `host_url`), the DNS cache, the hosts file, RDP servers |
| Service / driver, Scheduled task, Autostart entry, USB, Share, Group, Defender detection | Their own datasets |

**Paths are normalized** like `Get-IRPathKey`: lowercase, without the drive letter, `\device\harddiskvolumeN\`, `\\?\` or `\??\`, and `%SystemRoot%`-style variables are expanded. The same file in Amcache (lowercase), SRUM and the process list is therefore one node. A bare process name (such as `POWERSHELL.EXE` in Prefetch) that has only one full path in the case is merged into it.

**Links:** entities that appear in the same row are linked to that row's "primary entity" (for example, in `processes` the primary is the process file, linked to the user, the hash, and the parent process through `ppid`). Each link carries the dataset and column name and references to the rows. A finding is linked to its users, IPs, files, hashes and domains, and to any IP, URL or executable path mentioned in its title or evidence. **A link means the two appeared together in the same evidence, not that one caused the other.**

**Layouts** (toolbar menu):
- **Columns by type** (default): columns in this order: Host; Incidents and findings; Techniques and accounts; Processes and files; Persistence and detections; Hashes, network and devices. Each column has a header and a count. Nodes in a column are sorted by type and then by the average position of their neighbors (barycenter, 4 passes) to reduce crossings. Large columns split into sub-columns, and edges are curved.
- **Tree from the selected entity:** a left-to-right tree rooted at the selected entity, with Step 1, Step 2 ... headers (BFS). Tree edges are highlighted and other links are dimmed; anything not connected to the root is placed below under its own header.
- **Free (force):** a force-directed layout.
- Nodes animate to their new positions. A dragged node stays where it is dropped; **Tidy up** returns it to the layout.

**Usage:**
- The graph starts with the host, the findings, the incidents and what is directly linked to them. With no findings, it starts with the host and its 40 nearest entities.
- **Single click** on a node (or its label) opens the **details popup**. **Double click** adds its neighbors; **Expand: N steps** sets how many steps (1 to 3). Each node adds up to 40 neighbors per step, preferring those linked to findings. The whole graph is capped at 3,000 nodes.
- **Search** covers every entity (not only the visible ones); clicking a result adds it with its neighbors.
- **Type filters** (checkboxes) and a **date filter** (Seen from / to, or the Analysis window button). Undated nodes stay visible.
- Also **Fit**, **Tidy up**, **Reset**, **Clear** and **Export PNG**; the mouse wheel zooms.

**The entity popup** (closes with Esc, Close or a click outside):
- **Summary:** type and full value, first and last seen, number of linked entities and evidence rows, and the datasets it appears in. Plus:
  - **Findings** linked directly, and findings linked through one intermediate entity (shown as "via ...").
  - **Attributes from the evidence** per type. For a file: signature, signer, sha256, MotW zone, host_url, last run, run count. For a service: state, start mode, account, command. For a user: SID, last logon, logon type, source IP.
  - All linked entities grouped by type.
  - For a finding node: rule, ATT&CK, description, evidence and recommendation.
- **Relationship tree:** a lazily expanded tree: the entity, groups by type, then entities, each of which can be expanded. Under each name the link source is shown (dataset: column); entities already on the branch are not repeated.
- **Process tree** (for files that had a running process at collection time): the parent chain through `ppid`, with a start-time check so a reused PID is not trusted as the parent. Below it, every instance of the file (highlighted) and everything it started, with PID, user, start time, signature and command line.
- **Evidence:** every evidence row that mentions the entity (first 300, 50 per dataset), with an Open in Evidence button.
- **Timeline:** related timeline rows (first 200), with an Open in Timeline button.
- **Buttons:** Back (navigation inside the popup is recorded), Show as tree on the graph, Expand and Focus on the graph, Open finding / incident, Copy value. Clicking any name in the popup opens its details.
- Drawing uses `<canvas>` and stays around 60 fps with 500+ visible nodes.

**Not part of the graph:** the event log inventory, audit policy, firewall profiles, Defender status/preferences, hotfixes, installed software, PowerShell history (free-text commands), proxy settings and artifact notes. They contain no useful linking entities; their data is on the Evidence tab.

---

## 12. Evidence integrity (chain of custody)

1. **`manifest.csv`:** path, size, SHA-256 and modification time of every file in the case.
2. **Log freeze:** before the manifest is written, `collection.log` inside the case is closed and later messages go to the log next to the archive, so its hash stays valid.
3. **Archive:**
   - `zip` (unencrypted), or `rar` with `-hp`, which encrypts content and file names.
   - After creation the archive is **tested**: file count for zip, `rar t` for rar.
4. **`.sha256`:** contains the archive hash.
   - Hashes are not printed to the console: the manifest line goes to the log only, and the archive line is shown on the console without the `sha256`. The full values are in `collection.log`, `manifest.csv` and the `.sha256` file.
5. **The case folder is deleted only after the archive is verified.**
6. **In Analyze mode** the SHA-256 of every file is recomputed and compared with the manifest (except `report\`), and the result is shown on the Collection tab:
   - `verified`: everything matches.
   - `FAILED`: files changed or are missing; their names are listed.

---

## 13. Detection rule reference

### 13.1 Command-line rules

| Rule | Severity | Technique | Detects |
|---|---|---|---|
| CRED-MIMIKATZ | critical | T1003.001 | Mimikatz commands (`sekurlsa::`, `lsadump::`, ...) |
| CRED-LSASS-DUMP | critical | T1003.001 | comsvcs MiniDump, procdump lsass, nanodump, createdump |
| CRED-HIVE-SAVE | high | T1003.002 | `reg save HKLM\SAM/SECURITY/SYSTEM` |
| CRED-NTDS | high | T1003.003 | ntdsutil IFM, vssadmin create shadow, ntds.dit |
| CRED-DCSYNC | critical | T1003.006 | DCSync, secretsdump |
| CRED-KERBEROS | high | T1558.003 | Rubeus, Invoke-Kerberoast, GetUserSPNs |
| CRED-STORES | high | T1555.003 | Browser password theft (LaZagne, copying Login Data) |
| CRED-FILES | medium | T1552.001 | Searching files for passwords, cmdkey /list |
| PS-ENCODED | high | T1027 | `-EncodedCommand`, decoded and re-analyzed |
| PS-DOWNLOAD-EXEC | high | T1059.001 | `IEX (New-Object Net.WebClient).DownloadString` and similar cradles |
| INGRESS-DOWNLOAD | medium | T1105 | Downloads with curl, wget, iwr, BITS |
| CERTUTIL-ABUSE | high | T1105 | `certutil -urlcache`, `-decode` |
| BITSADMIN | high | T1197 | `bitsadmin /transfer` |
| MSHTA | high | T1218.005 | mshta with a URL or javascript |
| REGSVR32 | high | T1218.010 | Squiblydoo |
| RUNDLL32 | medium | T1218.011 | rundll32 javascript or a DLL from Users |
| MSIEXEC-REMOTE | high | T1218.007 | msiexec from a URL |
| DEV-UTIL-PROXY | medium | T1127.001 | msbuild, installutil, regasm with suspicious files |
| WMI-EXEC | high | T1047 | `wmic process call create`, `/node:` |
| PSEXEC | high | T1569.002 | PsExec, PAExec against `\\host` |
| WINRM-REMOTE | medium | T1021.006 | winrs, Invoke-Command -ComputerName |
| SC-REMOTE | high | T1569.002 | `sc \\host create` |
| SC-CREATE | medium | T1543.003 | `sc create binpath=` |
| SCHTASKS-CREATE / SCHTASKS-REMOTE | medium / high | T1053.005 | `schtasks /create`, `/s` |
| REG-RUNKEY | high | T1547.001 | Writes to Run keys and Winlogon |
| REG-IFEO | high | T1546.012 | IFEO Debugger, SilentProcessExit |
| ACCESSIBILITY-BACKDOOR | critical | T1546.008 | sethc / utilman backdoor |
| ACCOUNT-CREATE | high | T1136.001 | `net user /add` |
| GROUP-ADD | high | T1098 | `net localgroup administrators /add` |
| LOG-CLEAR | high | T1070.001 | `wevtutil cl`, Clear-EventLog, auditpol /clear |
| USN-DELETE | high | T1070.004 | `fsutil usn deletejournal` |
| INHIBIT-RECOVERY | critical | T1490 | `vssadmin delete shadows`, wbadmin, bcdedit |
| DEFENDER-TAMPER | high | T1562.001 | Set-MpPreference -Disable*, exclusions |
| AMSI-BYPASS | high | T1562.001 | AmsiUtils, amsiInitFailed |
| ETW-TAMPER | high | T1562.002 | EtwEventWrite, logman stop |
| FIREWALL-OFF / FIREWALL-RULE | high / low | T1562.004 | `netsh advfirewall set state off` |
| PORTPROXY | high | T1090 | `netsh interface portproxy add` |
| RDP-ENABLE | medium | T1021.001 | fDenyTSConnections=0 |
| SECSVC-STOP | high | T1562.001 | Stopping WinDefend, Sysmon, EDR |
| SVC-STOP-IMPACT | high | T1489 | Stopping VSS, SQL, Veeam, backup services |
| ARCHIVE / ARCHIVE-PASSWORD | low / medium | T1560.001 | 7z, rar, password-protected archives |
| EXFIL-TOOL | high | T1567.002 | rclone, mega, transfer.sh, curl -T |
| TUNNEL | high | T1572 | ngrok, chisel, plink -R, cloudflared |
| ANTI-FORENSICS | medium | T1070.004 | `cipher /w`, sdelete, Prefetch deletion |
| TIMESTOMP | medium | T1070.006 | Changing CreationTime / LastWriteTime |
| HISTORY-CLEAR | medium | T1070.003 | Clearing PSReadLine history |
| UAC-BYPASS | high | T1548.002 | ms-settings, fodhelper, sdclt |
| WDIGEST | high | T1112 | UseLogonCredential=1 |
| REG-WEAKEN | medium | T1112 | LocalAccountTokenFilterPolicy, EnableLUA=0 |
| PS-DOWNGRADE | medium | T1562.010 | `powershell -version 2` |
| PS-HIDDEN | low | T1564.003 | `-WindowStyle Hidden` |
| PS-OBFUSCATION | medium | T1140 | FromBase64String with IEX, gzip, char join |
| PROC-INJECTION | high | T1055 | VirtualAlloc, WriteProcessMemory, CreateRemoteThread |
| OFFENSIVE-PS | high | T1059.001 | PowerSploit, Nishang, PowerUp |
| AD-RECON | high | T1087.002 | SharpHound, AdFind, PowerView |
| TRUST-DISCOVERY | medium | T1482 | `nltest /domain_trusts` |
| NET-SCAN | medium | T1046 | nmap, masscan, ping sweeps |
| ADMIN-SHARE | medium | T1021.002 | `\\host\C$`, `ADMIN$` |
| SCRIPT-USERDIR | high | T1059.005 | wscript / cscript running a script from Downloads or Temp |
| DOUBLE-EXT | high | T1036.007 | `invoice.pdf.exe` |
| HIDE-FILE | low | T1564.001 | `attrib +h` |
| RANSOM-NOTE | high | T1486 | how_to_decrypt, `.locked` / `.lockbit` extensions |
| MINER-CMD | high | T1496 | Miner command lines (`stratum+tcp://`, `--donate-level`, ...) |
| RMM-TOOL | medium | T1219 | AnyDesk, TeamViewer, ScreenConnect, ... |

### 13.2 Discovery (for DISCOVERY-BURST)

T1033 (whoami, quser), T1087 (net user), T1069 (net localgroup, gpresult), T1082 (systeminfo), T1016 (ipconfig /all, route print), T1049 (netstat, net use), T1057 (tasklist), T1018 (net view, nltest, arp -a), T1135 (net share), T1007 (sc query), T1201 (net accounts), T1518.001 (AntiVirusProduct, fltmc).

### 13.3 Parent-child

| Rule | Parent -> child | Severity | Technique |
|---|---|---|---|
| CHILD-OFFICE | Word, Excel, Outlook, Acrobat -> shell or LOLBin | high | T1204.002 |
| CHILD-WEBSERVER | w3wp, httpd, tomcat, sqlservr -> shell | critical | T1505.003 |
| CHILD-WMI | wmiprvse -> shell | medium | T1047 |
| CHILD-WINRM | wsmprovhost -> shell | medium | T1021.006 |
| CHILD-SERVICES | services.exe -> shell | medium | T1569.002 |
| CHILD-SCRIPTHOST | wscript, cscript, mshta -> shell | high | T1059.005 |
| CHILD-UACBYPASS | fodhelper, computerdefaults, eventvwr -> shell | high | T1548.002 |
| CHILD-SPOOLER | spoolsv -> shell | high | T1068 |
| CHILD-LSASS | lsass -> anything | high | T1003.001 |

### 13.4 Known tools by name

| Group | Severity | Technique | Examples |
|---|---|---|---|
| TOOL-CRED | critical | T1003 | mimikatz, lazagne, nanodump, secretsdump |
| TOOL-PROCDUMP | high | T1003.001 | procdump |
| TOOL-KERBEROS | high | T1558.003 | rubeus, kerbrute |
| TOOL-ADRECON | high | T1087.002 | sharphound, adfind, pingcastle |
| TOOL-SCANNER | medium | T1046 | nmap, advanced ip scanner, netscan |
| TOOL-LATERAL | high | T1570 | wmiexec, crackmapexec, impacket |
| TOOL-PSEXEC | medium | T1569.002 | psexec, paexec |
| TOOL-C2 | critical | T1071.001 | cobalt strike, sliver, havoc, brute ratel |
| TOOL-TUNNEL | high | T1572 | ngrok, chisel, netcat, plink |
| TOOL-EXFIL | medium | T1567.002 | rclone, megasync, winscp |
| TOOL-PRIVESC | high | T1068 | winpeas, potatoes, certify |
| TOOL-EVASION | high | T1562.001 | defendercontrol, backstab, edrsilencer |
| TOOL-CRACK | high | T1557.001 | responder, inveigh, hashcat |
| TOOL-MINER | high | T1496 | xmrig, phoenixminer, lolminer, nbminer |
| TOOL-PIRACY | medium | T1204.002 | kmspico, kmsauto, keygens, cracks, activators (common malware lures) |
| TOOL-RANSOM | critical | T1486 | lockbit, akira, blackbasta |
| TOOL-RMM | medium | T1219 | anydesk, teamviewer, rustdesk |
| TOOL-ADMIN | low | T1057 | processhacker, systeminformer |

### 13.5 Network and domains

| Rule | Severity | Technique | Condition |
|---|---|---|---|
| INBOUND-PUBLIC / RDP-PUBLIC / NET-LOGON-PUBLIC | high | T1133 | RDP, SMB, WinRM or a logon from a public IP |
| LOLBIN-NET | high | T1071.001 | mshta, rundll32, regsvr32 ... talking to the Internet |
| SHELL-NET | medium | T1071.001 | powershell, cmd, certutil, curl ... talking to the Internet |
| SUSPDIR-NET | high | T1071.001 | A program from a staging folder talking to the Internet |
| LISTEN-SUSP-DIR | high | T1571 | A program from a staging folder listening on a port |
| SUSP-PORT | medium | T1571 | Ports 4444, 1337, 31337, 8888, 50050, ... |
| DNS-FILESHARE | medium | T1567.002 | transfer.sh, mega, pastebin, gofile |
| DNS-TUNNEL | high | T1572 | ngrok, trycloudflare |
| DNS-DYNDNS | medium | T1071.001 | duckdns, no-ip, webhook.site, interact.sh |
| DNS-C2-SERVICE | medium | T1102 | Telegram API, Discord, raw.githubusercontent |
| DNS-MINING | high | T1496 | Mining pools (supportxmr, nanopool, 2miners, ...) |
| DNS-IPCHECK | low | T1016 | ipify, ifconfig.me |

### 13.6 Registry (Sysmon 13)

REGSET-IFEO (T1546.012), REGSET-WINLOGON (T1547.004), REGSET-WDIGEST (T1112), REGSET-DEFENDER (T1562.001), REGSET-UAC-HIJACK (T1548.002), REGSET-LSA (T1547.005), REGSET-APPINIT (T1546.010), REGSET-NETSH (T1546.007), REGSET-PRINTMON (T1547.010), REGSET-RDP (T1021.001), REGSET-WEAKEN (T1112), REGSET-LOGON-SCRIPT (T1547.001), REGSET-RUNKEY (T1547.001).

### 13.7 Event-specific rules (examples)

| Rule | Source | Severity | Technique |
|---|---|---|---|
| LOG-CLEARED | Security 1102, System 104 | high | T1070.001 |
| AUDIT-POLICY-CHANGED | 4719 | medium | T1562.002 |
| ACCOUNT-CREATED | 4720 | medium | T1136.001 |
| PRIV-GROUP-ADD | 4728, 4732, 4756 to a privileged group | high | T1098 |
| ACCOUNT-LOCKOUT | 4740 | medium | T1110 |
| LOGON-NEWCRED | 4624 type 9 | medium | T1550.002 |
| ASREP-ROAST | 4768 PreAuthType=0 | medium | T1558.004 |
| ADMIN-SHARE-ACCESS | 5140 | medium | T1021.002 |
| SERVICE-INSTALLED | 7045, 4697 | low to high | T1543.003 or T1569.002 |
| SECSVC-DISABLED | 7040 | high | T1562.001 |
| PS-V2-ENGINE | Windows PowerShell 400 | medium | T1562.010 |
| DRIVER-UNSIGNED-LOAD / BYOVD | Sysmon 6 | high | T1014 or T1068 |
| REMOTE-THREAD | Sysmon 8 | high | T1055 |
| LSASS-ACCESS | Sysmon 10 | critical | T1003.001 |
| PROCESS-TAMPER | Sysmon 25 | medium | T1055.012 |
| DEFENDER-DETECTION | Defender 1116, 1117 | depends on the threat | depends on the threat type |
| DEFENDER-RTP-OFF / EXCLUSION-ADDED / TAMPER-BLOCKED | Defender 5001, 5007, 5013 | high | T1562.001 |
| WMI-SUBSCRIPTION | WMI 5861 | low or high | T1546.003 |
| BITS-JOB | BITS 59 | medium | T1197 |
| FIREWALL-DISABLED-EVENT | Firewall 2003 | high | T1562.004 |
| NTDS-COPY | ESENT 325, 326, 327 | high | T1003.003 |

### 13.8 Live-state rules

SIG-MISMATCH, UNSIGNED-USERDIR-PROC, PORTPROXY-CONFIG, LOCAL-PROXY, GUEST-ENABLED, NO-PASSWORD-REQUIRED, SERVICE-SUSPICIOUS, BYOVD, DRIVER-UNSIGNED, AUTORUN-* (Winlogon, IFEO, AppInit, LSA, COM hijack, ...), TASK-SUSPICIOUS, TASK-UNSIGNED, WMI-CONSUMER, DEFENDER-AV-OFF, DEFENDER-EXCLUSION, FIREWALL-PROFILE-OFF, FW-RULE-SUSP, CFG-WDIGEST, CFG-UAC-OFF, CFG-LATFP, SHIMCACHE-SUSP-DIR, FILE-SIG-MISMATCH, FILE-SUSP-DIR, SYSDIR-UNSIGNED, DISK-IMAGE-DOWNLOAD (T1553.005), RISKY-DOWNLOAD, UNSIGNED-DOWNLOAD, HIDDEN-EXE, ADS-HIDDEN (T1564.004).

---

## 14. Limitations

- **This is triage, not a final verdict:** the rules are heuristics and can produce false positives (admin tools, installers, security software itself). Confirm every finding against its evidence.
- **Event logs:** reading starts from the newest event and stops at `-MaxEventsPerLog` per query. For very large logs, raise the limit or analyze the `.evtx` files with Hayabusa.
- **Without Administrator:** the Security log, hives, other users' files and locked files are not collected; the report says so in the gaps.
- **Without Sysmon:** no per-process network evidence, no LSASS access and no registry/file events. Only live evidence and 4688.
- **No memory forensics:** the script does not capture memory. Use WinPMem or Magnet RAM Capture **before** running it when it matters.
- **Raw artifact analysis (section 6.8) is basic, not complete:**
  - Amcache in the Windows 10/11 format only (`InventoryApplicationFile`).
  - Hives are read without deleted records.
  - Prefetch comes from the live state only.
  - ActivitiesCache and thumbcache are not analyzed.
  - Firefox downloads are available only when recorded in `moz_annos`.
  - **A ShellBag key's last-write time** is the last change to the folder or its contents, not exactly the time it was opened. **FAT times** inside shell items are in the host's local time.
  - For full depth use EZ Tools and Hindsight.
- **Amcache and SRUM need Administrator at collection time** because of the shadow copy. Without admin they are not collected and the reason is listed in the gaps.
- **Each technique has one primary tactic** in the mapping (section 7.2).
- **Release status:** version `1.0.0` was tested end-to-end on Windows 11 (PowerShell 5.1):
  - **Clean host, not elevated (Quick, 30 days):** collection took about 4.5 minutes and analysis about 30 seconds. 2,299 events were analyzed and the timeline had 2,627 rows. 13 findings (3 medium, 10 low), 0 incidents, verdict **Needs review**. Integrity 53/53 verified.
  - **Staged attack scenario** (certutil, schtasks, net user, vssadmin and wevtutil commands placed in the PSReadLine history): 1 critical and 4 high, grouped into **one incident** of 6 findings linked by IP and file, verdict **Compromise likely**.
  - **Elevated (Standard, 7 days):** collection took about 4 minutes and 17 of 17 steps succeeded. The Security log was read (4624, 4648, 4688), Prefetch 500, BAM 66, ShimCache 1,024, 245 scheduled tasks; hives, Amcache and SRUM were collected. The archive (86 MB) was verified, and analysis straight from the zip reported integrity 1,652/1,652.
  - **Raw artifact analysis (elevated, Standard, 30 days):**
    - A shadow copy was created and deleted; the host's 4 existing shadow copies were untouched.
    - Results:

      | Artifact | Result |
      |---|---|
      | Browsers | Brave: 2,624 visits and 30 downloads. Chrome: 226 visits |
      | Amcache | 1,265 files and 222 programs, 200 pages replayed from the logs |
      | ShellBags | 884 folders |
      | Jump Lists | 2,335 entries |
      | SRUM | 5,534 network records and 20,273 application usage records |

    - Artifact analysis took about 40 seconds with no parsing failures.
    - The verdict stayed **Needs review**; the artifacts added one low finding.
    - Analysis of the case also worked without admin.
  - Not yet tested **with Sysmon** or against real attacks. Test in a lab first.

---

## 15. Troubleshooting

| Problem | Solution |
|---|---|
| `running scripts is disabled on this system` | Run `Set-ExecutionPolicy -Scope Process Bypass -Force` first, or `powershell -ExecutionPolicy Bypass -File .\IR-Investigator.ps1` |
| `D:` does not exist | The script falls back to `C:\Windows\Temp\IRCollection` automatically, or set `-OutputRoot` |
| The EDR blocked the script | Expected: the script contains attacker-tool patterns (in order to detect them). Get a hash or path exception from the EDR team, or run Analyze mode on the analyst machine against `.evtx` files collected another way |
| Analysis is slow | Lower `-Days` or `-MaxEventsPerLog`, or use `-Profile Quick` |
| The report is very large | Caused by large evidence tables (up to 25,000 rows each). Use a smaller `-Days` |
| `.rar` in Analyze mode | Extract it with the password first and pass the folder to `-CasePath` |
| Analysis failed in All mode | The collected evidence is intact and packaged. Run `-Mode Analyze -CasePath <zip>` on another machine and share the log |
| Converting to EXE | `Install-Module ps2exe`, then `Invoke-PS2EXE .\IR-Investigator.ps1 .\IR-Investigator.exe -requireAdmin`. An EXE is more likely to be flagged by AV than the `.ps1` |
| Exit codes | `0` success, `1` fatal error, `2` collection succeeded but analysis failed (evidence intact), `3` archive failed or did not pass verification (the case folder is kept) |
