#Requires -Version 5.1
<#
.SYNOPSIS
    IR-Investigator - one PowerShell script for Windows incident response and forensic triage.
    Collects live state, raw artifacts and the complete event logs, analyzes them the way a DFIR
    analyst would, maps every finding to MITRE ATT&CK, groups related findings into incidents and
    writes a self-contained HTML dashboard (evidence, timeline, incident graph, ATT&CK matrix).

.DESCRIPTION
    MODES
      All      (default) collect on this host, analyze, write the report, then package the case.
      Collect  collect and package only - the lightest footprint on a suspect host.
      Analyze  analyze an existing case folder or .zip (for example on the analyst workstation)
               and write the report. Needs no elevation and changes nothing on the analyst host.

    PROFILES (Collect / All)
      Quick     live state + the key event logs. A few minutes.
      Standard  + every non-empty event log, registry hives (SYSTEM, SOFTWARE, per-user NTUSER and
                UsrClass), Prefetch, Amcache, SRUM, Jump Lists, LNK, browser history, PowerShell
                history, Recycle Bin metadata, scheduled task files, Defender logs.   (default)
      Full      + SAM and SECURITY hives, thumbcache, WMI repository, RDP bitmap cache, alternate
                data streams and a deeper file scan.

    OUTPUT  <OutputRoot>\<HOST>_<yyyyMMdd_HHmmss>Z\
      live\*.json            normalized live state (processes, network, persistence, ...)
      eventlogs\*.evtx       complete event logs
      artifacts\...          raw artifacts copied unmodified (EZ Tools, RegRipper, Hindsight, ...)
      report\IR-Report.html  the dashboard (Analyze / All)
      manifest.csv           SHA-256 of every collected file (chain of custody)
      collection.log         what ran, what failed
    The case folder is packaged into a .zip (or a password-protected .rar) with a .sha256 file.

    The analysis is heuristic triage: every finding links back to the evidence it came from and
    must be confirmed by an analyst. Raw artifacts are kept for validated forensic parsers.

.PARAMETER Mode
    All | Collect | Analyze. Default All.

.PARAMETER CollectionProfile
    Quick | Standard | Full. Alias -Profile. Default Standard.

.PARAMETER OutputRoot
    Where the case folder is created. Default D:\IRCollection, falls back to
    C:\Windows\Temp\IRCollection when D: is missing. UNC paths work.

.PARAMETER CasePath
    Analyze mode: a case folder or the .zip produced by Collect.

.PARAMETER Days
    Analysis window in days before the collection time (events, file scan). Default 30.

.PARAMETER MaxEventsPerLog
    Upper bound of events parsed per log during analysis (newest first). Default 50000.

.PARAMETER Archive
    Zip (default) | Rar | None. Rar needs WinRAR/rar.exe and encrypts names + content with -hp.

.PARAMETER ArchivePassword
    Password for -Archive Rar. Default 'infected'. Visible in process-creation telemetry.

.PARAMETER KeepCaseFolder
    Keep the case folder after the archive has been verified.

.PARAMETER CaseLabel
    Case / ticket identifier shown in the report (for example INC-2026-044).

.PARAMETER Examiner
    Name of the examiner shown in the report.

.PARAMETER NoOpen
    Do not open the report in the browser when finished.

.EXAMPLE
    .\IR-Investigator.ps1
    Collect (Standard), analyze the last 30 days, write the report and package everything.

.EXAMPLE
    .\IR-Investigator.ps1 -Mode Collect -Profile Quick -OutputRoot \\ir-share\cases
    Fast live triage collection only, straight to a share.

.EXAMPLE
    .\IR-Investigator.ps1 -Mode Analyze -CasePath D:\IRCollection\HOST01_20261031_120000Z.zip -Days 90
    Analyze a collected case on the analyst workstation.
#>
[CmdletBinding()]
param(
    [ValidateSet('All', 'Collect', 'Analyze')]
    [string]$Mode = 'All',

    [Alias('Profile')]
    [ValidateSet('Quick', 'Standard', 'Full')]
    [string]$CollectionProfile = 'Standard',

    [string]$OutputRoot = 'D:\IRCollection',

    [string]$CasePath = '',

    [ValidateRange(1, 3650)]
    [int]$Days = 30,

    [ValidateRange(100, 5000000)]
    [int]$MaxEventsPerLog = 50000,

    [ValidateSet('Zip', 'Rar', 'None')]
    [string]$Archive = 'Zip',

    [string]$ArchivePassword = 'infected',

    [switch]$KeepCaseFolder,

    [string]$CaseLabel = '',

    [string]$Examiner = '',

    [switch]$NoOpen
)

# A 32-bit host process (some EDR agents) is redirected to SysWOW64 and misses the 64-bit
# registry and System32, so relaunch under the native 64-bit PowerShell.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and $PSCommandPath) {
    $native = Join-Path $env:SystemRoot 'sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $native) {
        $relaunch = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        foreach ($kv in $PSBoundParameters.GetEnumerator()) {
            if ($kv.Value -is [System.Management.Automation.SwitchParameter]) {
                if ($kv.Value.IsPresent) { $relaunch += "-$($kv.Key)" }
            } else {
                $relaunch += "-$($kv.Key)"; $relaunch += [string]$kv.Value
            }
        }
        & $native @relaunch
        exit $LASTEXITCODE
    }
}

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Script:Version = '1.0.0'
# Lets the analyzer recognize (and ignore) this script's own PowerShell script-block logging.
$Script:SelfMarker = 'IRINV-SELF-MARKER-0b7e41'
$Script:Inv = [Globalization.CultureInfo]::InvariantCulture
$Script:LogFile = $null
$Script:Steps = [System.Collections.Generic.List[object]]::new()
$Script:SigCache = @{}
$Script:HashCache = @{}
$Script:SidCache = @{}
$Script:CurrentItems = 0
$Script:StepWarnings = 0
$Script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

#region ===== Core helpers =====

function Write-IRLog {
    param([Parameter(Mandatory)][string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')][string]$Level = 'INFO', [switch]$NoConsole, [string]$Console)
    $stamp = '[{0}][{1}] ' -f [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss', $Script:Inv), $Level
    if ($Script:LogFile) { try { [IO.File]::AppendAllText($Script:LogFile, $stamp + $Message + "`r`n") } catch { } }
    if ($Level -eq 'WARN') { $Script:StepWarnings++ }
    if ($NoConsole) { return }
    $color = switch ($Level) { 'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'OK' { 'Green' } default { 'Gray' } }
    Write-Host ($stamp + $(if ($Console) { $Console } else { $Message })) -ForegroundColor $color
}

# explorer.exe hands the file to the signed-in user's shell, so an elevated run still opens the
# report in the user's normal (non-elevated) browser.
function Open-IRReport([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) { return }
    Write-IRLog "Opening the report: $Path"
    try { Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList ('"{0}"' -f $Path) -ErrorAction Stop }
    catch {
        try { Invoke-Item -LiteralPath $Path -ErrorAction Stop } catch { Write-IRLog "Could not open the report automatically: $($_.Exception.Message)" 'WARN' }
    }
}

function New-IRDir([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { [void](New-Item -ItemType Directory -Path $Path -Force) }
    return $Path
}

function ConvertTo-IRTime($Value) {
    if ($null -eq $Value -or '' -eq $Value) { return $null }
    try {
        if ($Value -is [DateTime]) { $dt = $Value } else { $dt = [DateTime]::Parse([string]$Value, $Script:Inv) }
        if ($dt.Year -lt 1971 -or $dt.Year -gt 2100) { return $null }
        return $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $Script:Inv)
    } catch { return $null }
}

function Get-IRDate($Value) {
    if ($null -eq $Value -or '' -eq $Value) { return $null }
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime() }
    try { return [DateTime]::Parse([string]$Value, $Script:Inv, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal') } catch { return $null }
}

# Live JSON timestamps are ISO strings on PowerShell 5.1 but DateTime objects on PowerShell 7.
function Get-IRIso($Value) {
    if ($null -eq $Value -or '' -eq $Value) { return $null }
    if ($Value -is [DateTime]) { return ConvertTo-IRTime $Value }
    return [string]$Value
}

function Limit-IRText([string]$Text, [int]$Max = 300) {
    if (-not $Text) { return $Text }
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max) + '...' }
    return $t
}

function Resolve-IRSid([string]$Sid) {
    if (-not $Sid) { return $null }
    if ($Script:SidCache.ContainsKey($Sid)) { return $Script:SidCache[$Sid] }
    $name = $Sid
    try { $name = (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value } catch { }
    $Script:SidCache[$Sid] = $name
    return $name
}

# --- JSON -------------------------------------------------------------------------------------
# A small serializer instead of ConvertTo-Json: identical output on PowerShell 5.1 and 7, ISO
# dates, no depth surprises, and '<' '>' '&' escaped so evidence text can never break out of the
# <script> block it is embedded in inside the HTML report.
$Script:JsonEscape = New-Object System.Text.RegularExpressions.Regex('[\x00-\x1f"\\<>&\u2028\u2029]')
$Script:JsonEval = [System.Text.RegularExpressions.MatchEvaluator] {
    param($m)
    $c = $m.Value
    if ($c -eq '"') { return '\"' }
    if ($c -eq '\') { return '\\' }
    return '\u{0:x4}' -f [int][char]$c
}

function Add-IRJson([System.Text.StringBuilder]$Sb, $V, [int]$Depth) {
    if ($null -eq $V -or $V -is [DBNull]) { [void]$Sb.Append('null'); return }
    if ($V -is [string] -or $V -is [char]) {
        [void]$Sb.Append('"').Append($Script:JsonEscape.Replace([string]$V, $Script:JsonEval)).Append('"'); return
    }
    if ($V -is [bool]) { [void]$Sb.Append($(if ($V) { 'true' } else { 'false' })); return }
    if ($V -is [DateTime]) { [void]$Sb.Append('"').Append($V.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $Script:Inv)).Append('"'); return }
    if ($V -is [enum]) { Add-IRJson $Sb ([string]$V) $Depth; return }
    if ($V -is [int] -or $V -is [long] -or $V -is [double] -or $V -is [decimal] -or $V -is [single] -or
        $V -is [uint32] -or $V -is [uint64] -or $V -is [int16] -or $V -is [uint16] -or $V -is [byte] -or $V -is [sbyte]) {
        if (($V -is [double] -or $V -is [single]) -and ([double]::IsNaN($V) -or [double]::IsInfinity($V))) { [void]$Sb.Append('null'); return }
        [void]$Sb.Append([Convert]::ToString($V, $Script:Inv)); return
    }
    if ($Depth -gt 12) { Add-IRJson $Sb ([string]$V) $Depth; return }
    if ($V -is [System.Collections.IDictionary]) {
        [void]$Sb.Append('{'); $first = $true
        foreach ($k in $V.Keys) {
            if (-not $first) { [void]$Sb.Append(',') }; $first = $false
            Add-IRJson $Sb ([string]$k) $Depth; [void]$Sb.Append(':'); Add-IRJson $Sb $V[$k] ($Depth + 1)
        }
        [void]$Sb.Append('}'); return
    }
    if ($V -is [byte[]]) { Add-IRJson $Sb ([Convert]::ToBase64String($V)) $Depth; return }
    if ($V -is [System.Collections.IEnumerable]) {
        [void]$Sb.Append('['); $first = $true
        foreach ($i in $V) {
            if (-not $first) { [void]$Sb.Append(',') }; $first = $false
            if ($null -eq $i) { [void]$Sb.Append('null') }
            elseif ($i -is [string]) { [void]$Sb.Append('"').Append($Script:JsonEscape.Replace($i, $Script:JsonEval)).Append('"') }
            else { Add-IRJson $Sb $i ($Depth + 1) }
        }
        [void]$Sb.Append(']'); return
    }
    if ($V -is [System.Management.Automation.PSCustomObject]) {
        [void]$Sb.Append('{'); $first = $true
        foreach ($p in $V.PSObject.Properties) {
            if (-not $first) { [void]$Sb.Append(',') }; $first = $false
            Add-IRJson $Sb $p.Name $Depth; [void]$Sb.Append(':'); Add-IRJson $Sb $p.Value ($Depth + 1)
        }
        [void]$Sb.Append('}'); return
    }
    Add-IRJson $Sb ([string]$V) $Depth
}

function ConvertTo-IRJson($Value) {
    $sb = New-Object System.Text.StringBuilder 65536
    Add-IRJson $sb $Value 0
    return $sb.ToString()
}

function Save-IRData([string]$Name, $Data) {
    $path = Join-Path $Script:Case.Live "$Name.json"
    [IO.File]::WriteAllText($path, (ConvertTo-IRJson $Data), (New-Object System.Text.UTF8Encoding($false)))
    if ($Data -is [System.Collections.ICollection]) { $Script:CurrentItems += $Data.Count } elseif ($null -ne $Data) { $Script:CurrentItems++ }
}

function Read-IRData([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $text = [IO.File]::ReadAllText($Path)
    if (-not $text.Trim()) { return $null }
    try { return (ConvertFrom-Json -InputObject $text) } catch {
        Add-Type -AssemblyName System.Web.Extensions
        $js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $js.MaxJsonLength = [int]::MaxValue
        return $js.DeserializeObject($text)
    }
}

# --- Steps ------------------------------------------------------------------------------------
function Invoke-IRStep {
    param(
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [Parameter(Position = 1)][string]$Category = 'general',
        [Parameter(Mandatory, Position = 2)][scriptblock]$Action,
        [string[]]$Profiles = @('Quick', 'Standard', 'Full')
    )
    if ($Profiles -notcontains $CollectionProfile) { return }
    Write-IRLog "> $Name"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $Script:CurrentItems = 0
    $Script:StepWarnings = 0
    $status = 'ok'; $err = $null
    try { & $Action } catch {
        $status = 'error'; $err = $_.Exception.Message
        Write-IRLog "  $Name failed: $err" 'ERROR'
    }
    $sw.Stop()
    if ($status -eq 'ok' -and $Script:StepWarnings -gt 0) { $status = 'partial' }
    $Script:Steps.Add([pscustomobject]@{
            name = $Name; category = $Category; status = $status; seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            items = $Script:CurrentItems; warnings = $Script:StepWarnings; error = $err
        })
}

# --- Files and registry -------------------------------------------------------------------------
function Copy-IRFile {
    param([string]$Source, [string]$DestDir, [string]$Name)
    if (-not $Source -or -not (Test-Path -LiteralPath $Source -PathType Leaf)) { return $false }
    New-IRDir $DestDir | Out-Null
    $leaf = Split-Path -Leaf $Source
    if (-not $Name) { $Name = $leaf }
    $dest = Join-Path $DestDir $Name
    try { [IO.File]::Copy($Source, $dest, $true); $Script:CurrentItems++; return $true } catch { }
    # Locked files (hives, ESE databases, open logs): robocopy in backup mode reads them anyway.
    $rcArgs = @((Split-Path -Parent $Source), $DestDir, $leaf, '/R:0', '/W:0', '/NP', '/NFL', '/NDL', '/NJH', '/NJS', '/COPY:DAT')
    if ($Script:IsAdmin) { $rcArgs += '/B' }
    $null = & robocopy.exe @rcArgs
    $rcOut = Join-Path $DestDir $leaf
    if ($rcOut -ne $dest -and (Test-Path -LiteralPath $rcOut)) { Move-Item -LiteralPath $rcOut -Destination $dest -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $dest) { $Script:CurrentItems++; return $true }
    $snap = Get-IRShadowPath $Source
    if ($snap) {
        try { [IO.File]::Copy($snap, $dest, $true); $Script:CurrentItems++; return $true } catch { }
    }
    Write-IRLog "  could not copy (locked or access denied): $Source" 'WARN'
    return $false
}

# Exclusively locked files (Amcache.hve, SRUDB.dat, open browser databases) cannot be read even
# with backup privilege; one shadow copy of the system volume is created on first need.
function Get-IRShadowPath([string]$Path) {
    if (-not $Script:IsAdmin -or $Script:ShadowFailed) { return $null }
    $vol = [IO.Path]::GetPathRoot($env:SystemRoot)
    if (-not $Path.StartsWith($vol, [StringComparison]::OrdinalIgnoreCase)) { return $null }
    if (-not $Script:Shadow) {
        try {
            $r = ([wmiclass]'root\cimv2:Win32_ShadowCopy').Create($vol, 'ClientAccessible')
            if ($r.ReturnValue -ne 0) { throw "Win32_ShadowCopy.Create returned $($r.ReturnValue)" }
            $sc = Get-WmiObject Win32_ShadowCopy -Filter "ID='$($r.ShadowID)'"
            $Script:Shadow = @{ id = [string]$r.ShadowID; root = [string]$sc.DeviceObject }
            Write-IRLog "  shadow copy created for locked files: $($Script:Shadow.root)"
        } catch {
            $Script:ShadowFailed = $true
            Write-IRLog "  shadow copy not available, locked files are skipped: $($_.Exception.Message)" 'WARN'
            return $null
        }
    }
    return $Script:Shadow.root + '\' + $Path.Substring($vol.Length)
}

function Remove-IRShadow {
    if (-not $Script:Shadow) { return }
    try {
        Get-WmiObject Win32_ShadowCopy -Filter "ID='$($Script:Shadow.id)'" | ForEach-Object { $_.Delete() }
        Write-IRLog "  shadow copy removed: $($Script:Shadow.root)"
    } catch { Write-IRLog "  could not remove shadow copy $($Script:Shadow.id): $($_.Exception.Message)" 'WARN' }
    $Script:Shadow = $null
}

function Copy-IRFolder {
    param([string]$Source, [string]$DestDir, [string[]]$Masks = @('*.*'), [switch]$Recurse, [int]$MaxAgeDays = 0)
    if (-not $Source -or -not (Test-Path -LiteralPath $Source -PathType Container)) { return 0 }
    New-IRDir $DestDir | Out-Null
    $rcArgs = @($Source, $DestDir) + $Masks + @('/R:0', '/W:0', '/NP', '/NFL', '/NDL', '/NJH', '/NJS', '/XJ', '/COPY:DAT', '/DCOPY:T')
    if ($Script:IsAdmin) { $rcArgs += '/B' }
    if ($Recurse) { $rcArgs += '/E' }
    if ($MaxAgeDays -gt 0) { $rcArgs += "/MAXAGE:$MaxAgeDays" }
    $null = & robocopy.exe @rcArgs
    if (-not $Recurse) {
        $before = $Script:CurrentItems
        $cut = (Get-Date).AddDays(-$MaxAgeDays)
        foreach ($m in $Masks) {
            foreach ($f in @(Get-ChildItem -LiteralPath $Source -Filter $m -File -Force -ErrorAction SilentlyContinue)) {
                if ($MaxAgeDays -gt 0 -and $f.LastWriteTime -lt $cut) { continue }
                $to = Join-Path $DestDir $f.Name
                if ($f.FullName.Length -ge 260 -or $to.Length -ge 260 -or [IO.File]::Exists('\\?\' + $to)) { continue }
                Copy-IRFile $f.FullName $DestDir | Out-Null
            }
        }
        $Script:CurrentItems = $before
    }
    $n = @(Get-ChildItem -LiteralPath $DestDir -Recurse -File -Force -ErrorAction SilentlyContinue).Count
    if ($n -eq 0) { Remove-Item -LiteralPath $DestDir -Recurse -Force -ErrorAction SilentlyContinue }
    $Script:CurrentItems += $n
    return $n
}

function Save-IRHive([string]$Key, [string]$DestFile) {
    New-IRDir (Split-Path -Parent $DestFile) | Out-Null
    $out = & reg.exe save $Key $DestFile /y 2>&1
    if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $DestFile)) { $Script:CurrentItems++; return $true }
    Write-IRLog "  reg save $Key failed: $out" 'WARN'
    return $false
}

function Get-IRRegValues([string]$Path) {
    $k = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $k) { return }
    foreach ($n in $k.GetValueNames()) {
        $v = $k.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
        if ($v -is [string[]]) { $v = ($v | Where-Object { $_ }) -join '; ' }
        [pscustomobject]@{ name = $(if ($n) { $n } else { '(Default)' }); value = $v }
    }
}

function Get-IRRegValue([string]$Path, [string]$Name) {
    $k = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $k) { return $null }
    $v = $k.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
    if ($v -is [string[]]) { $v = ($v | Where-Object { $_ }) -join '; ' }
    # The comma keeps a REG_BINARY byte[] from being unrolled into separate bytes.
    return , $v
}

function Get-IRSignature([string]$Path) {
    if (-not $Path) { return [pscustomobject]@{ status = $null; signer = $null } }
    if ($Script:SigCache.ContainsKey($Path)) { return $Script:SigCache[$Path] }
    $r = [pscustomobject]@{ status = 'FileMissing'; signer = $null }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        try {
            $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $signer = $null
            if ($s.SignerCertificate) { $signer = $s.SignerCertificate.Subject -replace '^CN="?([^",]+).*$', '$1' }
            $r = [pscustomobject]@{ status = [string]$s.Status; signer = $signer }
        } catch { $r = [pscustomobject]@{ status = 'Error'; signer = $null } }
    }
    $Script:SigCache[$Path] = $r
    return $r
}

function Get-IRHash([string]$Path, [int]$MaxMB = 100) {
    if (-not $Path) { return $null }
    if ($Script:HashCache.ContainsKey($Path)) { return $Script:HashCache[$Path] }
    $h = $null
    try {
        $fi = New-Object IO.FileInfo($Path)
        if ($fi.Exists -and $fi.Length -le ($MaxMB * 1MB)) { $h = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() }
    } catch { }
    $Script:HashCache[$Path] = $h
    return $h
}

# Extracts the executable from a service ImagePath / Run value / task action.
function Resolve-IRImagePath([string]$Command) {
    if (-not $Command) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    $c = $c -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', "$env:SystemRoot\" -replace '^(?i)system32\\', "$env:SystemRoot\System32\"
    if ($c -match '^"([^"]+)"') { $p = $Matches[1] }
    elseif ($c -match '^(.+?\.(exe|com|scr|bat|cmd|dll|sys|ps1|vbs|vbe|js|jse|hta|cpl|msc|wsf|pif))(\s|,|$)') { $p = $Matches[1] }
    else { $p = ($c -split '\s+')[0] }
    if ($p -and $p -notmatch '[\\/]') {
        foreach ($dir in @("$env:SystemRoot\System32", $env:SystemRoot)) {
            foreach ($cand in @((Join-Path $dir $p), (Join-Path $dir "$p.exe"))) {
                if (Test-Path -LiteralPath $cand -PathType Leaf) { return $cand }
            }
        }
    }
    return $p
}

function Get-IRUserProfiles {
    $rows = foreach ($p in @(Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue)) {
        if ($p.Special -or -not $p.LocalPath -or $p.SID -notmatch '^S-1-5-21-') { continue }
        $loaded = Test-Path -LiteralPath "Registry::HKEY_USERS\$($p.SID)"
        [pscustomobject]@{
            sid = $p.SID; user = (Resolve-IRSid $p.SID); name = (Split-Path -Leaf $p.LocalPath); path = $p.LocalPath
            loaded = $loaded; last_use = ConvertTo-IRTime $p.LastUseTime; exists = (Test-Path -LiteralPath $p.LocalPath)
        }
    }
    return @($rows)
}

# Registry roots to inspect: HKLM plus every user hive currently loaded under HKEY_USERS.
function Get-IRHiveRoots {
    $roots = @([pscustomobject]@{ root = 'HKLM:'; user = 'MACHINE'; sid = $null })
    foreach ($k in @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        $sid = $k.PSChildName
        if ($sid -notmatch '^S-1-5-21-[\d-]+$') { continue }
        $roots += [pscustomobject]@{ root = "Registry::HKEY_USERS\$sid"; user = (Resolve-IRSid $sid); sid = $sid }
    }
    return $roots
}

function Test-IRPublicIp([string]$Ip) {
    if (-not $Ip -or $Ip -in @('-', '::1', '127.0.0.1', '0.0.0.0', '::', 'LOCAL')) { return $false }
    $a = $null
    if (-not [Net.IPAddress]::TryParse(($Ip -replace '^::ffff:', ''), [ref]$a)) { return $false }
    $b = $a.GetAddressBytes()
    if ($b.Length -eq 4) {
        if ($b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -eq 0 -or $b[0] -ge 224 -or
            ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168) -or
            ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127)) { return $false }
        return $true
    }
    if ($a.IsIPv6LinkLocal -or $a.IsIPv6SiteLocal -or $a.IsIPv6Multicast -or $a.Equals([Net.IPAddress]::IPv6Loopback)) { return $false }
    if (($b[0] -band 0xfe) -eq 0xfc) { return $false }
    return $true
}

#endregion

#region ===== MITRE ATT&CK catalog =====

$Script:Tactics = @(
    [ordered]@{ key = 'initial-access'; id = 'TA0001'; name = 'Initial Access' }
    [ordered]@{ key = 'execution'; id = 'TA0002'; name = 'Execution' }
    [ordered]@{ key = 'persistence'; id = 'TA0003'; name = 'Persistence' }
    [ordered]@{ key = 'privilege-escalation'; id = 'TA0004'; name = 'Privilege Escalation' }
    [ordered]@{ key = 'defense-evasion'; id = 'TA0005'; name = 'Defense Evasion' }
    [ordered]@{ key = 'credential-access'; id = 'TA0006'; name = 'Credential Access' }
    [ordered]@{ key = 'discovery'; id = 'TA0007'; name = 'Discovery' }
    [ordered]@{ key = 'lateral-movement'; id = 'TA0008'; name = 'Lateral Movement' }
    [ordered]@{ key = 'collection'; id = 'TA0009'; name = 'Collection' }
    [ordered]@{ key = 'command-and-control'; id = 'TA0011'; name = 'Command and Control' }
    [ordered]@{ key = 'exfiltration'; id = 'TA0010'; name = 'Exfiltration' }
    [ordered]@{ key = 'impact'; id = 'TA0040'; name = 'Impact' }
)

$Script:Mitre = @{}
@'
T1078|Valid Accounts|initial-access
T1078.001|Valid Accounts: Default Accounts|initial-access
T1133|External Remote Services|initial-access
T1566.001|Phishing: Spearphishing Attachment|initial-access
T1059.001|Command and Scripting Interpreter: PowerShell|execution
T1059.003|Command and Scripting Interpreter: Windows Command Shell|execution
T1059.005|Command and Scripting Interpreter: Visual Basic|execution
T1047|Windows Management Instrumentation|execution
T1053.005|Scheduled Task/Job: Scheduled Task|execution
T1569.002|System Services: Service Execution|execution
T1204.002|User Execution: Malicious File|execution
T1543.003|Create or Modify System Process: Windows Service|persistence
T1547.001|Boot or Logon Autostart: Registry Run Keys / Startup Folder|persistence
T1547.004|Boot or Logon Autostart: Winlogon Helper DLL|persistence
T1547.005|Boot or Logon Autostart: Security Support Provider|persistence
T1547.010|Boot or Logon Autostart: Port Monitors|persistence
T1546.002|Event Triggered Execution: Screensaver|persistence
T1546.003|Event Triggered Execution: WMI Event Subscription|persistence
T1546.007|Event Triggered Execution: Netsh Helper DLL|persistence
T1546.008|Event Triggered Execution: Accessibility Features|persistence
T1546.010|Event Triggered Execution: AppInit DLLs|persistence
T1546.012|Event Triggered Execution: Image File Execution Options Injection|persistence
T1546.015|Event Triggered Execution: Component Object Model Hijacking|persistence
T1137.002|Office Application Startup: Office Test|persistence
T1136.001|Create Account: Local Account|persistence
T1098|Account Manipulation|persistence
T1197|BITS Jobs|persistence
T1548.002|Abuse Elevation Control: Bypass User Account Control|privilege-escalation
T1055|Process Injection|privilege-escalation
T1055.012|Process Injection: Process Hollowing|privilege-escalation
T1014|Rootkit|defense-evasion
T1027|Obfuscated Files or Information|defense-evasion
T1036.005|Masquerading: Match Legitimate Name or Location|defense-evasion
T1036.007|Masquerading: Double File Extension|defense-evasion
T1070.001|Indicator Removal: Clear Windows Event Logs|defense-evasion
T1070.004|Indicator Removal: File Deletion|defense-evasion
T1070.006|Indicator Removal: Timestomp|defense-evasion
T1112|Modify Registry|defense-evasion
T1140|Deobfuscate/Decode Files or Information|defense-evasion
T1218.005|System Binary Proxy Execution: Mshta|defense-evasion
T1218.010|System Binary Proxy Execution: Regsvr32|defense-evasion
T1218.011|System Binary Proxy Execution: Rundll32|defense-evasion
T1562.001|Impair Defenses: Disable or Modify Tools|defense-evasion
T1562.002|Impair Defenses: Disable Windows Event Logging|defense-evasion
T1562.004|Impair Defenses: Disable or Modify System Firewall|defense-evasion
T1562.010|Impair Defenses: Downgrade Attack|defense-evasion
T1564.001|Hide Artifacts: Hidden Files and Directories|defense-evasion
T1003|OS Credential Dumping|credential-access
T1003.001|OS Credential Dumping: LSASS Memory|credential-access
T1003.002|OS Credential Dumping: Security Account Manager|credential-access
T1003.003|OS Credential Dumping: NTDS|credential-access
T1110|Brute Force|credential-access
T1110.001|Brute Force: Password Guessing|credential-access
T1110.003|Brute Force: Password Spraying|credential-access
T1552.001|Unsecured Credentials: Credentials In Files|credential-access
T1555|Credentials from Password Stores|credential-access
T1558.003|Steal or Forge Kerberos Tickets: Kerberoasting|credential-access
T1558.004|Steal or Forge Kerberos Tickets: AS-REP Roasting|credential-access
T1016|System Network Configuration Discovery|discovery
T1018|Remote System Discovery|discovery
T1033|System Owner/User Discovery|discovery
T1046|Network Service Discovery|discovery
T1057|Process Discovery|discovery
T1069|Permission Groups Discovery|discovery
T1082|System Information Discovery|discovery
T1087|Account Discovery|discovery
T1087.002|Account Discovery: Domain Account|discovery
T1482|Domain Trust Discovery|discovery
T1021.001|Remote Services: Remote Desktop Protocol|lateral-movement
T1021.002|Remote Services: SMB/Windows Admin Shares|lateral-movement
T1021.006|Remote Services: Windows Remote Management|lateral-movement
T1550.002|Use Alternate Authentication Material: Pass the Hash|lateral-movement
T1560.001|Archive Collected Data: Archive via Utility|collection
T1071.001|Application Layer Protocol: Web Protocols|command-and-control
T1090|Proxy|command-and-control
T1102|Web Service|command-and-control
T1105|Ingress Tool Transfer|command-and-control
T1219|Remote Access Software|command-and-control
T1571|Non-Standard Port|command-and-control
T1572|Protocol Tunneling|command-and-control
T1052.001|Exfiltration Over Physical Medium: USB|exfiltration
T1567.002|Exfiltration Over Web Service: To Cloud Storage|exfiltration
T1485|Data Destruction|impact
T1486|Data Encrypted for Impact|impact
T1496|Resource Hijacking|impact
T1489|Service Stop|impact
T1490|Inhibit System Recovery|impact
T1531|Account Access Removal|impact
T1565.001|Data Manipulation: Stored Data Manipulation|impact
'@ -split "`r?`n" | Where-Object { $_ } | ForEach-Object {
    $p = $_.Split('|')
    $Script:Mitre[$p[0]] = [ordered]@{ id = $p[0]; name = $p[1]; tactic = $p[2] }
}

$Script:TechniqueAdvice = [ordered]@{
    'T1110'     = 'Block the source addresses at the perimeter, confirm the lockout policy, require MFA for remote access and review every successful logon from the same sources.'
    'T1078'     = 'Confirm with the account owners whether these logons were legitimate; disable or reset compromised accounts.'
    'T1133'     = 'Remove direct Internet exposure of remote services (RDP/WinRM/SMB); put them behind VPN with MFA.'
    'T1566'     = 'Retrieve the original email/attachment, block the sender and URLs, and search other mailboxes for the same message.'
    'T1204'     = 'Find how the file arrived (email, browser download, USB), hash it, check its reputation and hunt for it on other hosts.'
    'T1021'     = 'Identify the source host and account of the remote session and bring that host into scope.'
    'T1550'     = 'Treat the account as compromised: reset its password, and look for the same logon pattern on other hosts.'
    'T1569'     = 'Find the host that created the remote service and include it in scope; restrict remote service creation and admin shares.'
    'T1003'     = 'Assume every credential used on this host is compromised: reset those passwords, enable LSA protection (RunAsPPL) and Credential Guard.'
    'T1558'     = 'Reset the targeted service account passwords to long random values and enforce AES-only Kerberos for them.'
    'T1555'     = 'Rotate credentials saved in browsers and password stores on this host.'
    'T1552'     = 'Rotate any credentials found in files on this host.'
    'T1059'     = 'Retrieve and decode the full command or script, determine what it downloaded or ran, and block it.'
    'T1047'     = 'Review the WMI process chain (source, parent, command) and restrict remote WMI where it is not needed.'
    'T1105'     = 'Identify the downloaded file and its source URL/IP, block the source and hunt for the file hash fleet-wide.'
    'T1218'     = 'Review the proxied execution chain and block the abused system binary with ASR rules or AppLocker if it is not needed.'
    'T1197'     = 'List BITS jobs (bitsadmin /list /allusers /verbose), remove malicious ones and block the remote URL.'
    'T1543'     = 'Capture the service binary and registry key as evidence, then remove the service and its binary.'
    'T1547'     = 'Capture the autostart entry and the file it launches as evidence, then remove both; check other hosts for the same entry.'
    'T1546'     = 'Capture the trigger configuration (registry/WMI) and payload as evidence, then remove them.'
    'T1053'     = 'Export the task XML as evidence, delete the task and the payload it runs; check other hosts for the same task name.'
    'T1137'     = 'Remove the Office startup persistence and the referenced DLL.'
    'T1136'     = 'Confirm the account with its supposed owner; disable unauthorized accounts.'
    'T1098'     = 'Remove unauthorized group memberships and reset the affected accounts.'
    'T1531'     = 'Restore the deleted/disabled accounts and find who made the change.'
    'T1548'     = 'Find how UAC was bypassed; keep UAC enabled and use separate admin accounts.'
    'T1055'     = 'Acquire memory before rebooting and analyse the source and target processes.'
    'T1014'     = 'Acquire memory and the driver file; an unsigned kernel driver needs immediate analysis.'
    'T1036'     = 'Hash the binary and check reputation; a system binary name in the wrong place is strongly suspicious.'
    'T1070'     = 'Recover the missing logs from SIEM/forwarders/backups; treat log clearing as deliberate anti-forensics.'
    'T1562'     = 'Re-enable the impaired protection (Defender, firewall, logging), remove unauthorized exclusions and enable tamper protection.'
    'T1027'     = 'Decode the content to reveal the real payload and search for the same string on other hosts.'
    'T1140'     = 'Decode the content to reveal the real payload and search for the same string on other hosts.'
    'T1112'     = 'Revert the registry change and identify the process and user that made it.'
    'T1564'     = 'Inspect the hidden files; attackers hide tools and staged data this way.'
    'T1087'     = 'Discovery normally follows a foothold: identify the user/process that ran it and what happened right before.'
    'T1069'     = 'Discovery normally follows a foothold: identify the user/process that ran it and what happened right before.'
    'T1082'     = 'Discovery normally follows a foothold: identify the user/process that ran it and what happened right before.'
    'T1016'     = 'Discovery normally follows a foothold: identify the user/process that ran it and what happened right before.'
    'T1018'     = 'Discovery normally follows a foothold: identify the user/process that ran it and what happened right before.'
    'T1033'     = 'Discovery normally follows a foothold: identify the user/process that ran it and what happened right before.'
    'T1046'     = 'Network scanning from this host means lateral movement is likely being prepared; review its connections.'
    'T1057'     = 'Discovery normally follows a foothold: identify the user/process that ran it and what happened right before.'
    'T1482'     = 'Domain trust discovery is typical of AD-wide compromise preparation; escalate to the AD team.'
    'T1560'     = 'Find the archive, what it contains and whether it left the host.'
    'T1567'     = 'Determine what data was transferred and where; preserve proxy/firewall logs and assess notification obligations.'
    'T1052'     = 'Identify the USB device and what was copied to it.'
    'T1071'     = 'Block the remote endpoint and review network logs for beaconing to it from other hosts.'
    'T1090'     = 'Remove the proxy/port forwarding configuration and block the remote endpoint.'
    'T1102'     = 'Block the web service destination and review which process contacted it.'
    'T1219'     = 'Confirm the remote access tool is sanctioned; if not, remove it and review its connection logs.'
    'T1571'     = 'Block the remote endpoint and identify the listening/connecting binary.'
    'T1572'     = 'Kill and remove the tunneling tool, block its endpoints and review what was reached through it.'
    'T1485'     = 'Possible destructive activity: isolate the host, protect backups and engage the full IR process.'
    'T1486'     = 'Possible ransomware: isolate the host, protect backups and engage the full IR process.'
    'T1489'     = 'Possible ransomware preparation: isolate the host and protect backups.'
    'T1490'     = 'Possible ransomware preparation: isolate the host immediately and protect backups.'
    'T1496'     = 'Kill and remove the miner and its persistence, block the mining pool domains/IPs and check how it arrived (usually cracked software).'
    'T1565'     = 'Review and restore the modified data (e.g. hosts file).'
    'MALWARE'   = 'Collect the detected file, check what Defender did with it, and find how it arrived and whether it ran.'
}

function Get-IRAdvice([string]$Technique) {
    if (-not $Technique) { return $Script:TechniqueAdvice['MALWARE'] }
    $base = $Technique.Split('.')[0]
    if ($Script:TechniqueAdvice.Contains($base)) { return $Script:TechniqueAdvice[$base] }
    return 'Review the evidence and confirm whether this activity was authorized.'
}

#endregion

#region ===== Collection =====

# Logs the analyzer parses; Quick collects only these, Standard/Full collect every non-empty log.
$Script:KeyLogs = @(
    'Security', 'System', 'Application',
    'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
    'Microsoft-Windows-TerminalServices-RDPClient/Operational',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-WMI-Activity/Operational',
    'Microsoft-Windows-Bits-Client/Operational',
    'Microsoft-Windows-WinRM/Operational',
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
    'Microsoft-Windows-SMBServer/Security',
    'Microsoft-Windows-NTLM/Operational'
)

$Script:ScanExt = New-Object 'System.Collections.Generic.HashSet[string]' ([string[]]@(
        '.exe', '.dll', '.scr', '.com', '.pif', '.cpl', '.sys', '.ocx', '.msi', '.msc', '.ps1', '.psm1', '.bat', '.cmd',
        '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.lnk', '.jar', '.iso', '.img', '.vhd', '.vhdx',
        '.zip', '.7z', '.rar', '.one', '.docm', '.xlsm', '.pptm', '.xll', '.reg', '.url', '.library-ms', '.appx', '.msix'),
    [StringComparer]::OrdinalIgnoreCase)
$Script:PeExt = New-Object 'System.Collections.Generic.HashSet[string]' ([string[]]@('.exe', '.dll', '.scr', '.com', '.cpl', '.sys', '.ocx', '.msi'), [StringComparer]::OrdinalIgnoreCase)

function Initialize-IRCase {
    $root = $OutputRoot
    try {
        if ($root -match '^([A-Za-z]):') {
            $letter = $Matches[1]
            $ready = [IO.DriveInfo]::GetDrives() | Where-Object { $_.Name -eq "${letter}:\" -and $_.IsReady }
            if (-not $ready) {
                $root = Join-Path $env:SystemRoot 'Temp\IRCollection'
                Write-Host "Output drive ${letter}: is not available - using $root" -ForegroundColor Yellow
            }
        }
    } catch { }
    $start = [DateTime]::UtcNow
    $name = '{0}_{1}Z' -f $env:COMPUTERNAME, $start.ToString('yyyyMMdd_HHmmss')
    $caseRoot = Join-Path $root $name
    $Script:Case = @{
        Root = $caseRoot; Name = $name; OutputRoot = $root; Started = $start
        Live = (Join-Path $caseRoot 'live'); Events = (Join-Path $caseRoot 'eventlogs')
        Artifacts = (Join-Path $caseRoot 'artifacts'); Report = (Join-Path $caseRoot 'report')
    }
    foreach ($k in 'Root', 'Live', 'Events', 'Artifacts') { New-IRDir $Script:Case[$k] | Out-Null }
    $Script:LogFile = Join-Path $caseRoot 'collection.log'
}

$Script:KnownFolders = @{
    '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' = '%System32%'; '{6D809377-6AF0-444B-8957-A3773F02200E}' = '%ProgramFiles%'
    '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}' = '%ProgramFiles(x86)%'; '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' = '%Windows%'
    '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}' = '%SysWOW64%'; '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}' = '%CommonPrograms%'
    '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}' = '%Programs%'; '{9E3995AB-1F9C-4F13-B827-48B24B6C7174}' = '%UserPinned%'
}

function ConvertFrom-IRRot13([string]$Text) {
    $chars = $Text.ToCharArray()
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $c = [int]$chars[$i]
        if ($c -ge 65 -and $c -le 90) { $chars[$i] = [char](65 + ($c - 65 + 13) % 26) }
        elseif ($c -ge 97 -and $c -le 122) { $chars[$i] = [char](97 + ($c - 97 + 13) % 26) }
    }
    return -join $chars
}

function ConvertFrom-IRSystemTime($Bytes) {
    if ($Bytes -isnot [byte[]] -or $Bytes.Length -lt 16) { return $null }
    try {
        $dt = [DateTime]::new([int][BitConverter]::ToUInt16($Bytes, 0), [int][BitConverter]::ToUInt16($Bytes, 2), [int][BitConverter]::ToUInt16($Bytes, 6),
            [int][BitConverter]::ToUInt16($Bytes, 8), [int][BitConverter]::ToUInt16($Bytes, 10), [int][BitConverter]::ToUInt16($Bytes, 12), [DateTimeKind]::Local)
        return ConvertTo-IRTime $dt
    } catch { return $null }
}

function ConvertFrom-IRFileTime([long]$FileTime) {
    if ($FileTime -le 0) { return $null }
    try { return ConvertTo-IRTime ([DateTime]::FromFileTimeUtc($FileTime)) } catch { return $null }
}

# AppCompatCache (ShimCache) from the live SYSTEM hive, Windows 10/11 format. On these builds an
# entry proves the file existed on disk, not that it ran; the order is most-recent first.
function Get-IRShimCache {
    $bytes = Get-IRRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' 'AppCompatCache'
    if ($bytes -isnot [byte[]] -or $bytes.Length -lt 52) { return @() }
    $hdr = [BitConverter]::ToInt32($bytes, 0)
    if ($hdr -ne 0x30 -and $hdr -ne 0x34) {
        Write-IRLog ('  ShimCache format 0x{0:x} is not decoded here (the raw SYSTEM hive is collected)' -f $hdr)
        return @()
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    $off = $hdr; $i = 0
    while ($off + 14 -lt $bytes.Length) {
        if ([Text.Encoding]::ASCII.GetString($bytes, $off, 4) -ne '10ts') { break }
        $entryLen = [BitConverter]::ToInt32($bytes, $off + 8)
        $p = $off + 12
        $pathLen = [BitConverter]::ToUInt16($bytes, $p); $p += 2
        if ($p + $pathLen + 8 -gt $bytes.Length) { break }
        $path = [Text.Encoding]::Unicode.GetString($bytes, $p, $pathLen); $p += $pathLen
        $rows.Add([pscustomobject]@{ order = $i; path = $path; file_modified = (ConvertFrom-IRFileTime ([BitConverter]::ToInt64($bytes, $p))) })
        $off += 12 + $entryLen; $i++
    }
    return $rows
}

function Find-IRFiles([string]$Root, [int]$MaxDepth, [DateTime]$Since, $Out, $Seen, [int]$Max) {
    if (-not $Root -or -not [IO.Directory]::Exists($Root)) { return }
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@($Root, 0))
    while ($stack.Count -gt 0 -and $Out.Count -lt $Max) {
        $item = $stack.Pop(); $dir = [string]$item[0]; $depth = [int]$item[1]
        try {
            foreach ($f in [IO.Directory]::GetFiles($dir)) {
                if (-not $Script:ScanExt.Contains([IO.Path]::GetExtension($f))) { continue }
                if (-not $Seen.Add($f)) { continue }
                $fi = New-Object IO.FileInfo($f)
                if ($fi.CreationTimeUtc -lt $Since -and $fi.LastWriteTimeUtc -lt $Since) { continue }
                $Out.Add($fi)
                if ($Out.Count -ge $Max) { break }
            }
            if ($depth -lt $MaxDepth) {
                foreach ($d in [IO.Directory]::GetDirectories($dir)) {
                    if (([IO.File]::GetAttributes($d) -band [IO.FileAttributes]::ReparsePoint) -eq 0) { $stack.Push(@($d, ($depth + 1))) }
                }
            }
        } catch { }
    }
}

function Add-IRAutorun($List, [string]$Category, [string]$Location, [string]$Name, $Value, [string]$User, $Time = $null) {
    if ($null -eq $Value -or $Value -is [byte[]]) { return }
    $v = [string]$Value
    if (-not $v.Trim()) { return }
    $img = Resolve-IRImagePath $v
    $sig = Get-IRSignature $img
    $List.Add([pscustomobject]@{
            category = $Category; location = $Location; name = $Name; command = $v; image = $img; user = $User
            signature = $sig.status; signer = $sig.signer; sha256 = (Get-IRHash $img); modified = $Time
        })
}

function Find-IRWinRar {
    $c = [System.Collections.Generic.List[string]]::new()
    if ($PSScriptRoot) { $c.Add((Join-Path $PSScriptRoot 'rar.exe')); $c.Add((Join-Path $PSScriptRoot 'WinRAR.exe')) }
    foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) { if ($pf) { $c.Add((Join-Path $pf 'WinRAR\rar.exe')); $c.Add((Join-Path $pf 'WinRAR\WinRAR.exe')) } }
    foreach ($k in 'HKLM:\SOFTWARE\WinRAR', 'HKLM:\SOFTWARE\WOW6432Node\WinRAR') {
        foreach ($n in 'exe64', 'exe32') { $v = Get-IRRegValue $k $n; if ($v) { $c.Add($v) } }
    }
    foreach ($p in $c) { if (Test-Path -LiteralPath $p -PathType Leaf) { return $p } }
    $cmd = Get-Command 'rar.exe', 'WinRAR.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    return $null
}

# Start-Process -Wait blocks until WinRAR (console or GUI binary) has really finished.
function Invoke-IRWinRar([string]$Exe, [string]$Arguments, [string]$WorkDir) {
    $o = [IO.Path]::GetTempFileName(); $e = [IO.Path]::GetTempFileName()
    try {
        $p = Start-Process -FilePath $Exe -ArgumentList $Arguments -WorkingDirectory $WorkDir -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
        $text = ((Get-Content -LiteralPath $o -Raw -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath $e -Raw -ErrorAction SilentlyContinue))
        return [pscustomobject]@{ ExitCode = $p.ExitCode; Output = $text }
    } finally { Remove-Item -LiteralPath $o, $e -Force -ErrorAction SilentlyContinue }
}

function New-IRZip([string]$Folder) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $out = "$Folder.zip"
    if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force }
    [IO.Compression.ZipFile]::CreateFromDirectory($Folder, $out, [IO.Compression.CompressionLevel]::Optimal, $true)
    $z = [IO.Compression.ZipFile]::OpenRead($out)
    try { $entries = @($z.Entries | Where-Object { $_.Name }).Count } finally { $z.Dispose() }
    $files = @(Get-ChildItem -LiteralPath $Folder -Recurse -File -Force).Count
    return [pscustomobject]@{ path = $out; verified = ($entries -eq $files); kind = 'zip (not encrypted)' }
}

function New-IRArchive([string]$Folder) {
    if ($Archive -eq 'None') { return $null }
    if ($Archive -eq 'Rar') {
        $rar = Find-IRWinRar
        if ($rar) {
            $out = "$Folder.rar"; $parent = Split-Path -Parent $Folder; $leaf = Split-Path -Leaf $Folder
            Write-IRLog 'WinRAR mode: the archive password is visible in process-creation telemetry.' 'WARN'
            $r = Invoke-IRWinRar $rar "a -r -ep1 -m5 -y -inul `"-hp$ArchivePassword`" `"$out`" `"$leaf`"" $parent
            if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $out)) {
                Write-IRLog "WinRAR failed (exit $($r.ExitCode)): $($r.Output)" 'ERROR'
                return $null
            }
            $t = Invoke-IRWinRar $rar "t -y -inul `"-p$ArchivePassword`" `"$out`"" $parent
            return [pscustomobject]@{ path = $out; verified = ($t.ExitCode -eq 0); kind = 'rar (password protected, -hp)' }
        }
        Write-IRLog 'WinRAR not found - producing a .zip instead.' 'WARN'
    }
    return (New-IRZip $Folder)
}

# Renames files whose full path would exceed MAX_PATH so the archive step cannot fail on them.
# Get-ChildItem on PowerShell 5.1 silently skips paths over 260 characters, so enumerate with \\?\ paths.
function Repair-IRLongPaths([string]$Folder) {
    $root = $Folder.TrimEnd('\')
    if (-not $root.StartsWith('\\?\')) { $root = '\\?\' + $root }
    try { $files = [IO.Directory]::GetFiles($root, '*', [IO.SearchOption]::AllDirectories) } catch {
        Write-IRLog "Long path scan failed: $($_.Exception.Message)" 'WARN'; return
    }
    $md5 = [Security.Cryptography.MD5]::Create()
    foreach ($fp in $files) {
        if ($fp.Length - 4 -le 240) { continue }
        $dir = [IO.Path]::GetDirectoryName($fp); $name = [IO.Path]::GetFileName($fp); $ext = [IO.Path]::GetExtension($name)
        if ($ext.Length -gt 12) { $ext = '' }
        $tag = -join ($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($name))[0..3] | ForEach-Object { $_.ToString('x2') })
        $budget = [math]::Max(8, 240 - ($dir.Length - 4) - $ext.Length - 10)
        $base = $name.Substring(0, $name.Length - $ext.Length)
        if ($base.Length -gt $budget) { $base = $base.Substring(0, $budget) }
        $new = "${base}_$tag$ext"
        try { [IO.File]::Move($fp, [IO.Path]::Combine($dir, $new)); Write-IRLog "Long path shortened: '$name' -> '$new'" }
        catch { Write-IRLog "Could not shorten '$name': $($_.Exception.Message)" 'WARN' }
    }
}

function Remove-IRFolder([string]$Folder) {
    if (-not (Test-Path -LiteralPath $Folder)) { return $true }
    # Get-WinEvent -Path keeps .evtx handles open until their readers are finalized.
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    Get-ChildItem -LiteralPath $Folder -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { try { $_.Attributes = 'Normal' } catch { } }
    Remove-Item -LiteralPath $Folder -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $Folder) {
        $empty = Join-Path $env:TEMP ('empty_' + [Guid]::NewGuid().ToString('N'))
        New-IRDir $empty | Out-Null
        $null = & robocopy.exe $empty $Folder /MIR /R:1 /W:1 /NP /NFL /NDL /NJH /NJS
        Remove-Item -LiteralPath $empty, $Folder -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $Folder) { & cmd.exe /c "rd /s /q `"$Folder`"" 2>&1 | Out-Null }
    return -not (Test-Path -LiteralPath $Folder)
}

function Write-IRManifest([string]$Root) {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('path,size,sha256,modified_utc')
    $n = 0
    foreach ($f in @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        if ($f.Name -eq 'manifest.csv' -and $f.DirectoryName -eq $Root) { continue }
        $rel = $f.FullName.Substring($Root.Length + 1)
        $h = $null
        try { $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch { }
        [void]$sb.AppendLine(('"{0}",{1},{2},{3}' -f ($rel -replace '"', '""'), $f.Length, $h, $f.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ', $Script:Inv)))
        $n++
    }
    [IO.File]::WriteAllText((Join-Path $Root 'manifest.csv'), $sb.ToString(), (New-Object Text.UTF8Encoding($false)))
    return $n
}

function Invoke-IRCollection {
    Initialize-IRCase
    Write-IRLog "===== IR-Investigator v$($Script:Version) | mode=$Mode | profile=$CollectionProfile | host=$env:COMPUTERNAME ====="
    Write-IRLog "Case folder: $($Script:Case.Root)"
    if (-not $Script:IsAdmin) {
        Write-IRLog 'Not elevated: the Security log, registry hives, other users and locked files will be missing. Run as Administrator or SYSTEM.' 'WARN'
    }
    $Script:Profiles = @(Get-IRUserProfiles)
    $A = $Script:Case.Artifacts

    Invoke-IRStep 'System information' 'system' {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $ips = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue |
                ForEach-Object { $_.IPAddress } | Where-Object { $_ -and $_ -notmatch '^fe80' })
        $roles = @('Standalone workstation', 'Member workstation', 'Standalone server', 'Member server', 'Backup domain controller', 'Primary domain controller')
        $Script:SystemInfo = [ordered]@{
            hostname = $env:COMPUTERNAME; domain = $cs.Domain; part_of_domain = [bool]$cs.PartOfDomain
            role = $(if ($null -ne $cs.DomainRole) { $roles[[int]$cs.DomainRole] } else { $null })
            os = $os.Caption; os_version = $os.Version; os_build = $os.BuildNumber; architecture = $os.OSArchitecture
            install_date = ConvertTo-IRTime $os.InstallDate; last_boot = ConvertTo-IRTime $os.LastBootUpTime
            timezone = [TimeZoneInfo]::Local.Id; utc_offset_minutes = [int][TimeZoneInfo]::Local.GetUtcOffset([DateTime]::Now).TotalMinutes
            manufacturer = $cs.Manufacturer; model = $cs.Model; serial = $bios.SerialNumber
            memory_gb = $(if ($cs.TotalPhysicalMemory) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) } else { $null })
            ip_addresses = $ips; run_as = $id.Name; is_system = $id.IsSystem; elevated = $Script:IsAdmin
            ps_version = $PSVersionTable.PSVersion.ToString(); collector_pid = $PID; script_path = $PSCommandPath
            tool = 'IR-Investigator'; tool_version = $Script:Version; profile = $CollectionProfile
            case_label = $CaseLabel; examiner = $Examiner; case_name = $Script:Case.Name
            collection_start = $Script:Case.Started.ToString('yyyy-MM-ddTHH:mm:ssZ', $Script:Inv); collection_end = $null
        }
        Save-IRData 'system' $Script:SystemInfo
    }

    # Prefetch first: every helper program this script starts afterwards updates its own .pf file.
    Invoke-IRStep 'Prefetch (before any helper program runs)' 'execution' {
        $dir = Join-Path $env:SystemRoot 'Prefetch'
        $pf = foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.pf' -File -ErrorAction SilentlyContinue)) {
            [pscustomobject]@{
                executable = ($f.Name -replace '-[0-9A-F]{8}\.pf$', ''); file = $f.Name; size = $f.Length
                first_run_approx = ConvertTo-IRTime $f.CreationTimeUtc; last_run_approx = ConvertTo-IRTime $f.LastWriteTimeUtc
            }
        }
        Save-IRData 'prefetch' @($pf)
        if ($CollectionProfile -ne 'Quick') { Copy-IRFolder $dir (Join-Path $A 'Prefetch') -Masks '*.pf' | Out-Null }
        $cfg = Get-IRRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' 'EnablePrefetcher'
        if ($null -ne $cfg -and [int]$cfg -eq 0) { Write-IRLog '  Prefetch is disabled on this host (EnablePrefetcher=0)' 'WARN' }
    }

    Invoke-IRStep 'Running processes' 'execution' {
        $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop)
        $byPid = @{}
        foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }
        $rows = foreach ($p in $procs) {
            $owner = $null
            try {
                $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
                if ($o.ReturnValue -eq 0) { $owner = "$($o.Domain)\$($o.User)" }
            } catch { }
            $parent = $byPid[[int]$p.ParentProcessId]
            $parentName = $null
            if ($parent -and (-not $p.CreationDate -or -not $parent.CreationDate -or $parent.CreationDate -le $p.CreationDate)) { $parentName = $parent.Name }
            $sig = Get-IRSignature $p.ExecutablePath
            [pscustomobject]@{
                pid = [int]$p.ProcessId; ppid = [int]$p.ParentProcessId; name = $p.Name; parent_name = $parentName
                path = $p.ExecutablePath; command_line = $p.CommandLine; user = $owner; session = [int]$p.SessionId
                started = ConvertTo-IRTime $p.CreationDate; sha256 = (Get-IRHash $p.ExecutablePath)
                signature = $sig.status; signer = $sig.signer
            }
        }
        Save-IRData 'processes' @($rows)
    }

    Invoke-IRStep 'Network state' 'network' {
        $pmap = @{}
        foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) { $pmap[[int]$p.ProcessId] = $p }
        $rows = [System.Collections.Generic.List[object]]::new()
        try {
            foreach ($c in @(Get-NetTCPConnection -ErrorAction Stop)) {
                $p = $pmap[[int]$c.OwningProcess]
                $rows.Add([pscustomobject]@{
                        protocol = 'TCP'; local_address = $c.LocalAddress; local_port = [int]$c.LocalPort
                        remote_address = $c.RemoteAddress; remote_port = [int]$c.RemotePort; state = [string]$c.State
                        pid = [int]$c.OwningProcess; process = $p.Name; path = $p.ExecutablePath; created = ConvertTo-IRTime $c.CreationTime
                    })
            }
            foreach ($c in @(Get-NetUDPEndpoint -ErrorAction Stop)) {
                $p = $pmap[[int]$c.OwningProcess]
                $rows.Add([pscustomobject]@{
                        protocol = 'UDP'; local_address = $c.LocalAddress; local_port = [int]$c.LocalPort
                        remote_address = $null; remote_port = $null; state = 'Listen'
                        pid = [int]$c.OwningProcess; process = $p.Name; path = $p.ExecutablePath; created = ConvertTo-IRTime $c.CreationTime
                    })
            }
        } catch {
            foreach ($line in @(& netstat.exe -ano)) {
                if ($line -notmatch '^\s*(TCP|UDP)\s+(\S+):(\d+)\s+(\S+):(\S+)\s+(?:(\S+)\s+)?(\d+)\s*$') { continue }
                $proto = $Matches[1]; $la = $Matches[2]; $lp = $Matches[3]; $ra = $Matches[4]; $rp = $Matches[5]; $st = $Matches[6]; $procId = [int]$Matches[7]
                $p = $pmap[$procId]
                $rows.Add([pscustomobject]@{
                        protocol = $proto; local_address = $la.Trim('[', ']'); local_port = [int]$lp
                        remote_address = $ra.Trim('[', ']'); remote_port = $(if ($rp -match '^\d+$') { [int]$rp } else { $null })
                        state = $(if ($st) { $st } else { 'Listen' }); pid = $procId; process = $p.Name; path = $p.ExecutablePath; created = $null
                    })
            }
        }
        Save-IRData 'network_connections' $rows

        try {
            Save-IRData 'dns_cache' @(Get-DnsClientCache -ErrorAction Stop | ForEach-Object {
                    $type = switch ([int]$_.Type) { 1 { 'A' } 5 { 'CNAME' } 12 { 'PTR' } 28 { 'AAAA' } 33 { 'SRV' } default { [string]$_.Type } }
                    [pscustomobject]@{ name = $_.Entry; record = $_.Name; type = $type; data = $_.Data; ttl = [int]$_.TimeToLive }
                })
        } catch { Write-IRLog "  DNS cache: $($_.Exception.Message)" 'WARN' }
        try {
            Save-IRData 'arp_cache' @(Get-NetNeighbor -ErrorAction Stop | Where-Object { $_.State -ne 'Unreachable' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(00-){5}00$|^(FF-){5}FF$' } |
                    ForEach-Object { [pscustomobject]@{ address = $_.IPAddress; mac = $_.LinkLayerAddress; state = [string]$_.State; interface = $_.InterfaceAlias } })
        } catch { Write-IRLog "  ARP cache: $($_.Exception.Message)" 'WARN' }
        try {
            Save-IRData 'ip_configuration' @(Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object {
                    [pscustomobject]@{
                        interface = $_.InterfaceAlias; description = $_.InterfaceDescription
                        ipv4 = (@($_.IPv4Address | ForEach-Object { $_.IPAddress }) -join ', ')
                        gateway = (@($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ', ')
                        dns = (@($_.DNSServer | ForEach-Object { $_.ServerAddresses }) -join ', ')
                    }
                })
        } catch { Write-IRLog "  IP configuration: $($_.Exception.Message)" 'WARN' }
        try {
            Save-IRData 'smb_shares' @(Get-SmbShare -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ name = $_.Name; path = $_.Path; description = $_.Description; special = [bool]$_.Special } })
            Save-IRData 'smb_sessions' @(Get-SmbSession -ErrorAction Stop | ForEach-Object {
                    [pscustomobject]@{ client = $_.ClientComputerName; user = $_.ClientUserName; opens = [int]$_.NumOpens; dialect = $_.Dialect
                        connected_since = ConvertTo-IRTime ([DateTime]::Now.AddSeconds(-1 * [double]$_.SecondsExists)) }
                })
        } catch { Write-IRLog "  SMB: $($_.Exception.Message)" 'WARN' }

        $hostsRows = foreach ($l in @(Get-Content -LiteralPath (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -ErrorAction SilentlyContinue)) {
            if ($l -notmatch '^\s*[^#\s]') { continue }
            $parts = @($l.Trim() -split '\s+')
            [pscustomobject]@{ address = $parts[0]; names = $(if ($parts.Count -gt 1) { ($parts[1..($parts.Count - 1)] | Where-Object { $_ -notmatch '^#' }) -join ' ' } else { '' }) }
        }
        Save-IRData 'hosts_file' @($hostsRows)

        $proxy = [System.Collections.Generic.List[object]]::new()
        $wh = ((& netsh.exe winhttp show proxy 2>$null) -join ' ') -replace '\s+', ' '
        $proxy.Add([pscustomobject]@{ scope = 'WinHTTP'; enabled = $null; server = $wh.Trim(); autoconfig = $null })
        foreach ($r in @(Get-IRHiveRoots | Where-Object sid)) {
            $is = "$($r.root)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            $proxy.Add([pscustomobject]@{ scope = $r.user; enabled = (Get-IRRegValue $is 'ProxyEnable'); server = (Get-IRRegValue $is 'ProxyServer'); autoconfig = (Get-IRRegValue $is 'AutoConfigURL') })
        }
        Save-IRData 'proxy_settings' $proxy
        $pp = foreach ($fam in 'v4tov4', 'v4tov6', 'v6tov4', 'v6tov6') {
            foreach ($v in @(Get-IRRegValues "HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\$fam\tcp")) { [pscustomobject]@{ type = $fam; listen = $v.name; connect = $v.value } }
        }
        Save-IRData 'port_proxy' @($pp)
        $nets = foreach ($k in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles' -ErrorAction SilentlyContinue)) {
            [pscustomobject]@{
                name = (Get-IRRegValue $k.PSPath 'ProfileName'); description = (Get-IRRegValue $k.PSPath 'Description')
                first_connected = (ConvertFrom-IRSystemTime (Get-IRRegValue $k.PSPath 'DateCreated'))
                last_connected = (ConvertFrom-IRSystemTime (Get-IRRegValue $k.PSPath 'DateLastConnected'))
            }
        }
        Save-IRData 'network_history' @($nets)
    }

    Invoke-IRStep 'Accounts, groups and sessions' 'accounts' {
        try {
            $users = foreach ($u in @(Get-LocalUser -ErrorAction Stop)) {
                [pscustomobject]@{
                    name = $u.Name; enabled = [bool]$u.Enabled; sid = [string]$u.SID; last_logon = ConvertTo-IRTime $u.LastLogon
                    password_last_set = ConvertTo-IRTime $u.PasswordLastSet; password_required = [bool]$u.PasswordRequired; description = $u.Description
                }
            }
        } catch {
            $users = foreach ($u in @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction SilentlyContinue)) {
                [pscustomobject]@{ name = $u.Name; enabled = -not $u.Disabled; sid = $u.SID; last_logon = $null; password_last_set = $null; password_required = [bool]$u.PasswordRequired; description = $u.Description }
            }
        }
        Save-IRData 'local_users' @($users)

        $members = foreach ($gsid in 'S-1-5-32-544', 'S-1-5-32-555', 'S-1-5-32-580', 'S-1-5-32-551') {
            $gname = $null
            try { $gname = (New-Object Security.Principal.SecurityIdentifier($gsid)).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1] } catch { continue }
            try {
                $grp = [ADSI]"WinNT://./$gname,group"
                foreach ($m in @($grp.Invoke('Members'))) {
                    $adsPath = $m.GetType().InvokeMember('AdsPath', 'GetProperty', $null, $m, $null)
                    $cls = $m.GetType().InvokeMember('Class', 'GetProperty', $null, $m, $null)
                    [pscustomobject]@{ group = $gname; group_sid = $gsid; member = (($adsPath -replace '^WinNT://', '') -replace '/', '\'); type = $cls }
                }
            } catch { Write-IRLog "  group ${gname}: $($_.Exception.Message)" 'WARN' }
        }
        Save-IRData 'group_members' @($members)

        $sessions = foreach ($line in @(& quser.exe 2>$null | Select-Object -Skip 1)) {
            if ($line -match '^\s*>?(\S+)\s+(.*)$') { [pscustomobject]@{ user = $Matches[1]; detail = ($Matches[2] -replace '\s{2,}', ' | ').Trim() } }
        }
        Save-IRData 'sessions' @($sessions)
        Save-IRData 'user_profiles' @($Script:Profiles)
    }

    Invoke-IRStep 'Services and drivers' 'persistence' {
        $rows = foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction Stop)) {
            $img = Resolve-IRImagePath $s.PathName
            $dll = Get-IRRegValue "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters" 'ServiceDll'
            if ($dll) { $dll = [Environment]::ExpandEnvironmentVariables($dll) }
            $target = if ($dll) { $dll } else { $img }
            $sig = Get-IRSignature $target
            [pscustomobject]@{
                name = $s.Name; display_name = $s.DisplayName; state = $s.State; start_mode = $s.StartMode; account = $s.StartName
                command = $s.PathName; image = $img; service_dll = $dll; signature = $sig.status; signer = $sig.signer
                sha256 = $(if ($CollectionProfile -ne 'Quick') { Get-IRHash $target } else { $null })
            }
        }
        Save-IRData 'services' @($rows)
        $drv = foreach ($d in @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue)) {
            $img = Resolve-IRImagePath $d.PathName
            $sig = Get-IRSignature $img
            [pscustomobject]@{ name = $d.Name; display_name = $d.DisplayName; state = $d.State; start_mode = $d.StartMode; path = $img; signature = $sig.status; signer = $sig.signer }
        }
        Save-IRData 'drivers' @($drv)
    }

    Invoke-IRStep 'Autostart locations' 'persistence' {
        $list = [System.Collections.Generic.List[object]]::new()
        $runKeys = @(
            'Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'Software\Microsoft\Windows\CurrentVersion\RunServices', 'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',
            'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run', 'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        foreach ($r in @(Get-IRHiveRoots)) {
            foreach ($k in $runKeys) {
                foreach ($v in @(Get-IRRegValues "$($r.root)\$k")) { Add-IRAutorun $list 'Run key' "$($r.user)\$k" $v.name $v.value $r.user }
            }
            foreach ($sub in @(Get-ChildItem -LiteralPath "$($r.root)\Software\Microsoft\Windows\CurrentVersion\RunOnceEx" -ErrorAction SilentlyContinue)) {
                foreach ($v in @(Get-IRRegValues $sub.PSPath)) { Add-IRAutorun $list 'Run key' "$($r.user)\RunOnceEx\$($sub.PSChildName)" $v.name $v.value $r.user }
            }
            $wl = "$($r.root)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
            foreach ($n in 'Shell', 'Userinit', 'Taskman', 'AppSetup') {
                $v = Get-IRRegValue $wl $n
                if ($v) { Add-IRAutorun $list 'Winlogon' "$($r.user)\...\Winlogon" $n $v $r.user }
            }
            $wn = "$($r.root)\Software\Microsoft\Windows NT\CurrentVersion\Windows"
            foreach ($n in 'Load', 'Run') {
                $v = Get-IRRegValue $wn $n
                if ($v) { Add-IRAutorun $list 'Windows Load/Run' "$($r.user)\...\Windows" $n $v $r.user }
            }
            $v = Get-IRRegValue "$($r.root)\Software\Microsoft\Office test\Special\Perf" ''
            if ($v) { Add-IRAutorun $list 'Office test' "$($r.user)\Software\Microsoft\Office test\Special\Perf" '(Default)' $v $r.user }
            if ($r.sid) {
                $v = Get-IRRegValue "$($r.root)\Control Panel\Desktop" 'SCRNSAVE.EXE'
                if ($v) { Add-IRAutorun $list 'Screensaver' "$($r.user)\Control Panel\Desktop" 'SCRNSAVE.EXE' $v $r.user }
                foreach ($c in @(Get-ChildItem -LiteralPath "Registry::HKEY_USERS\$($r.sid)_Classes\CLSID" -ErrorAction SilentlyContinue | Select-Object -First 1000)) {
                    foreach ($srv in 'InprocServer32', 'LocalServer32') {
                        $v = Get-IRRegValue "$($c.PSPath)\$srv" ''
                        if ($v) { Add-IRAutorun $list 'COM object (user)' "$($r.user)\Classes\CLSID\$($c.PSChildName)\$srv" $c.PSChildName $v $r.user }
                    }
                }
            }
        }
        foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
            foreach ($k in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
                $v = Get-IRRegValue $k.PSPath 'Debugger'
                if ($v) { Add-IRAutorun $list 'IFEO debugger' $k.Name $k.PSChildName $v 'MACHINE' }
            }
        }
        foreach ($k in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue)) {
            $v = Get-IRRegValue $k.PSPath 'MonitorProcess'
            if ($v) { Add-IRAutorun $list 'SilentProcessExit monitor' $k.Name $k.PSChildName $v 'MACHINE' }
        }
        foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
            $v = Get-IRRegValue $base 'AppInit_DLLs'
            if ($v) { Add-IRAutorun $list 'AppInit DLL' $base "AppInit_DLLs (LoadAppInit_DLLs=$(Get-IRRegValue $base 'LoadAppInit_DLLs'))" $v 'MACHINE' }
        }
        $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        foreach ($pair in @(@($lsa, 'Authentication Packages'), @($lsa, 'Notification Packages'), @($lsa, 'Security Packages'), @("$lsa\OSConfig", 'Security Packages'))) {
            $v = Get-IRRegValue $pair[0] $pair[1]
            foreach ($pkg in @(([string]$v) -split ';\s*' | Where-Object { $_ -and $_ -ne '""' })) { Add-IRAutorun $list 'LSA package' "$($pair[0])\$($pair[1])" $pkg $pkg 'MACHINE' }
        }
        $v = Get-IRRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'BootExecute'
        if ($v) { Add-IRAutorun $list 'BootExecute' 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' 'BootExecute' $v 'MACHINE' }
        foreach ($base in 'HKLM:\SOFTWARE\Microsoft\NetSh', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\NetSh') {
            foreach ($v in @(Get-IRRegValues $base)) { Add-IRAutorun $list 'Netsh helper' $base $v.name $v.value 'MACHINE' }
        }
        foreach ($k in @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -ErrorAction SilentlyContinue)) {
            $v = Get-IRRegValue $k.PSPath 'Driver'
            if ($v) { Add-IRAutorun $list 'Print monitor' $k.Name $k.PSChildName $v 'MACHINE' }
        }
        $shell = $null
        try { $shell = New-Object -ComObject WScript.Shell } catch { }
        $startupDirs = @([pscustomobject]@{ dir = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"; user = 'All users' })
        foreach ($p in $Script:Profiles) { $startupDirs += [pscustomobject]@{ dir = (Join-Path $p.path 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'); user = $p.user } }
        foreach ($s in $startupDirs) {
            foreach ($f in @(Get-ChildItem -LiteralPath $s.dir -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
                $cmd = $f.FullName
                if ($f.Extension -eq '.lnk' -and $shell) {
                    try { $sc = $shell.CreateShortcut($f.FullName); if ($sc.TargetPath) { $cmd = ('"{0}" {1}' -f $sc.TargetPath, $sc.Arguments).Trim() } } catch { }
                }
                Add-IRAutorun $list 'Startup folder' $f.FullName $f.Name $cmd $s.user (ConvertTo-IRTime $f.CreationTimeUtc)
            }
        }
        Save-IRData 'autoruns' $list
    }

    Invoke-IRStep 'Scheduled tasks' 'persistence' {
        $root = Join-Path $env:SystemRoot 'System32\Tasks'
        $rows = foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            try { $x = [xml][IO.File]::ReadAllText($f.FullName) } catch { continue }
            $t = $x.Task
            if (-not $t) { continue }
            $execs = @($t.Actions.Exec | Where-Object { $_ })
            $cmds = @($execs | ForEach-Object { ('{0} {1}' -f $_.Command, $_.Arguments).Trim() })
            $com = @($t.Actions.ComHandler | Where-Object { $_ } | ForEach-Object { "COM handler $($_.ClassId)" })
            $first = $null
            if ($execs.Count) { $first = Resolve-IRImagePath $execs[0].Command }
            $sig = Get-IRSignature $first
            $principal = @($t.Principals.Principal)[0]
            $runAs = $null
            if ($principal) { $runAs = if ($principal.UserId) { $principal.UserId } else { $principal.GroupId } }
            if ($runAs -match '^S-1-') { $runAs = Resolve-IRSid $runAs }
            [pscustomobject]@{
                path = $f.FullName.Substring($root.Length); author = $t.RegistrationInfo.Author; registered = (ConvertTo-IRTime $t.RegistrationInfo.Date)
                enabled = ($t.Settings.Enabled -ne 'false'); hidden = ($t.Settings.Hidden -eq 'true'); run_as = $runAs
                run_level = $(if ($principal) { $principal.RunLevel } else { $null })
                triggers = (@($t.Triggers.ChildNodes | Where-Object { $_.LocalName -and $_.LocalName -ne '#comment' } | ForEach-Object { $_.LocalName }) -join ', ')
                command = (@($cmds) + @($com)) -join ' | '; image = $first; signature = $sig.status; signer = $sig.signer
                file_created = ConvertTo-IRTime $f.CreationTimeUtc; file_modified = ConvertTo-IRTime $f.LastWriteTimeUtc
            }
        }
        if (-not @($rows).Count) {
            $rows = foreach ($tk in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
                $execs = @($tk.Actions | Where-Object { $_.Execute })
                $cmds = @($execs | ForEach-Object { ('{0} {1}' -f $_.Execute, $_.Arguments).Trim() })
                $first = $null
                if ($execs.Count) { $first = Resolve-IRImagePath $execs[0].Execute }
                $sig = Get-IRSignature $first
                [pscustomobject]@{
                    path = "$($tk.TaskPath)$($tk.TaskName)"; author = $tk.Author; registered = (ConvertTo-IRTime $tk.Date)
                    enabled = ([string]$tk.State -ne 'Disabled'); hidden = [bool]$tk.Settings.Hidden; run_as = $tk.Principal.UserId
                    run_level = [string]$tk.Principal.RunLevel
                    triggers = (@($tk.Triggers | Where-Object { $_ } | ForEach-Object { $_.CimClass.CimClassName -replace '^MSFT_Task|Trigger$', '' }) -join ', ')
                    command = ($cmds -join ' | '); image = $first; signature = $sig.status; signer = $sig.signer; file_created = $null; file_modified = $null
                }
            }
            if (@($rows).Count) { Write-IRLog '  System32\Tasks is not readable (not elevated) - task list taken from the Task Scheduler API instead' }
        }
        Save-IRData 'scheduled_tasks' @($rows)
    }

    Invoke-IRStep 'WMI event subscriptions' 'persistence' {
        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($ns in 'root/subscription', 'root/default') {
            foreach ($i in @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue)) {
                $rows.Add([pscustomobject]@{ namespace = $ns; type = 'EventFilter'; name = $i.Name; detail = $i.Query; extra = $i.EventNamespace })
            }
            foreach ($i in @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction SilentlyContinue)) {
                $cls = $i.CimClass.CimClassName
                $detail = switch ($cls) {
                    'CommandLineEventConsumer' { ("$($i.ExecutablePath) $($i.CommandLineTemplate)").Trim() }
                    'ActiveScriptEventConsumer' { if ($i.ScriptText) { $i.ScriptText } else { $i.ScriptFileName } }
                    'NTEventLogEventConsumer' { "EventID $($i.EventID) source $($i.SourceName)" }
                    'LogFileEventConsumer' { $i.Filename }
                    default { '' }
                }
                $rows.Add([pscustomobject]@{ namespace = $ns; type = $cls; name = $i.Name; detail = $detail; extra = $i.ScriptingEngine })
            }
            foreach ($i in @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)) {
                $rows.Add([pscustomobject]@{ namespace = $ns; type = 'Binding'; name = ''; detail = [string]$i.Filter; extra = [string]$i.Consumer })
            }
        }
        Save-IRData 'wmi_persistence' $rows
    }

    Invoke-IRStep 'Microsoft Defender and firewall' 'defense' {
        try {
            $s = Get-MpComputerStatus -ErrorAction Stop
            Save-IRData 'defender_status' @([pscustomobject]@{
                    antivirus_enabled = $s.AntivirusEnabled; realtime_protection = $s.RealTimeProtectionEnabled; behavior_monitor = $s.BehaviorMonitorEnabled
                    ioav_protection = $s.IoavProtectionEnabled; tamper_protected = $s.IsTamperProtected; running_mode = $s.AMRunningMode
                    signature_version = $s.AntivirusSignatureVersion; signature_updated = ConvertTo-IRTime $s.AntivirusSignatureLastUpdated
                    quick_scan_end = ConvertTo-IRTime $s.QuickScanEndTime; full_scan_end = ConvertTo-IRTime $s.FullScanEndTime
                })
        } catch { Write-IRLog "  Defender status: $($_.Exception.Message)" 'WARN' }
        $ex = [System.Collections.Generic.List[object]]::new()
        $seen = @{}
        try {
            $p = Get-MpPreference -ErrorAction Stop
            $map = [ordered]@{ Path = $p.ExclusionPath; Process = $p.ExclusionProcess; Extension = $p.ExclusionExtension; IpAddress = $p.ExclusionIpAddress }
            foreach ($k in $map.Keys) {
                foreach ($v in @($map[$k])) {
                    if ($v -and $v -notmatch '^N/A' -and -not $seen.ContainsKey("$k|$v")) { $seen["$k|$v"] = 1; $ex.Add([pscustomobject]@{ type = $k; value = $v; source = 'Get-MpPreference' }) }
                }
            }
            Save-IRData 'defender_preferences' @([pscustomobject]@{
                    disable_realtime_monitoring = $p.DisableRealtimeMonitoring; disable_behavior_monitoring = $p.DisableBehaviorMonitoring
                    disable_ioav_protection = $p.DisableIOAVProtection; disable_script_scanning = $p.DisableScriptScanning
                    disable_block_at_first_seen = $p.DisableBlockAtFirstSeen; maps_reporting = [int]$p.MAPSReporting
                    submit_samples_consent = [int]$p.SubmitSamplesConsent; pua_protection = [int]$p.PUAProtection
                    controlled_folder_access = [int]$p.EnableControlledFolderAccess; network_protection = [int]$p.EnableNetworkProtection
                })
        } catch { Write-IRLog "  Defender preferences: $($_.Exception.Message)" 'WARN' }
        $typeMap = @{ Paths = 'Path'; Processes = 'Process'; Extensions = 'Extension'; IpAddresses = 'IpAddress' }
        foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions') {
            foreach ($t in $typeMap.Keys) {
                foreach ($v in @(Get-IRRegValues "$base\$t")) {
                    $key = "$($typeMap[$t])|$($v.name)"
                    if ($v.name -ne '(Default)' -and -not $seen.ContainsKey($key)) { $seen[$key] = 1; $ex.Add([pscustomobject]@{ type = $typeMap[$t]; value = $v.name; source = $base }) }
                }
            }
        }
        Save-IRData 'defender_exclusions' $ex
        try {
            $names = @{}
            foreach ($t in @(Get-MpThreat -ErrorAction Stop)) { $names[[string]$t.ThreatID] = $t }
            $rows = foreach ($d in @(Get-MpThreatDetection -ErrorAction Stop)) {
                $t = $names[[string]$d.ThreatID]
                [pscustomobject]@{
                    threat = $t.ThreatName; severity_id = $t.SeverityID; detected = ConvertTo-IRTime $d.InitialDetectionTime
                    remediated = ConvertTo-IRTime $d.RemediationTime; action_success = $d.ActionSuccess; process = $d.ProcessName
                    user = $d.DomainUser; resources = (@($d.Resources) -join '; ')
                }
            }
            Save-IRData 'defender_threats' @($rows)
        } catch { Write-IRLog "  Defender threat history: $($_.Exception.Message)" 'WARN' }

        try {
            Save-IRData 'firewall_profiles' @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
                    [pscustomobject]@{ profile = $_.Name; enabled = [string]$_.Enabled; default_inbound = [string]$_.DefaultInboundAction; default_outbound = [string]$_.DefaultOutboundAction; log_blocked = [string]$_.LogBlocked; log_file = $_.LogFileName }
                })
            $apps = @{}; foreach ($a in @(Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue)) { $apps[$a.InstanceID] = $a.Program }
            $ports = @{}; foreach ($pf in @(Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue)) { $ports[$pf.InstanceID] = $pf }
            $addrs = @{}; foreach ($af in @(Get-NetFirewallAddressFilter -All -ErrorAction SilentlyContinue)) { $addrs[$af.InstanceID] = $af }
            $rules = foreach ($r in @(Get-NetFirewallRule -ErrorAction Stop)) {
                if ($r.Group -and $CollectionProfile -ne 'Full') { continue }
                $pf = $ports[$r.InstanceID]; $af = $addrs[$r.InstanceID]
                [pscustomobject]@{
                    name = $r.DisplayName; direction = [string]$r.Direction; action = [string]$r.Action; enabled = [string]$r.Enabled
                    profile = [string]$r.Profile; program = $apps[$r.InstanceID]; protocol = $pf.Protocol
                    local_port = (@($pf.LocalPort) -join ','); remote_address = (@($af.RemoteAddress) -join ','); group = $r.Group
                }
            }
            Save-IRData 'firewall_rules' @($rules)
        } catch { Write-IRLog "  Firewall: $($_.Exception.Message)" 'WARN' }
    }

    Invoke-IRStep 'Security configuration and audit policy' 'defense' {
        $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        $ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
        Save-IRData 'security_config' @([pscustomobject][ordered]@{
                wdigest_use_logon_credential = Get-IRRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
                lsa_run_as_ppl = Get-IRRegValue $lsa 'RunAsPPL'
                credential_guard_lsa_cfg_flags = Get-IRRegValue $lsa 'LsaCfgFlags'
                lm_compatibility_level = Get-IRRegValue $lsa 'LmCompatibilityLevel'
                disable_restricted_admin = Get-IRRegValue $lsa 'DisableRestrictedAdmin'
                uac_enable_lua = Get-IRRegValue $pol 'EnableLUA'
                uac_consent_prompt_admin = Get-IRRegValue $pol 'ConsentPromptBehaviorAdmin'
                local_account_token_filter_policy = Get-IRRegValue $pol 'LocalAccountTokenFilterPolicy'
                process_cmdline_auditing = Get-IRRegValue "$pol\Audit" 'ProcessCreationIncludeCmdLine_Enabled'
                rdp_deny_connections = Get-IRRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
                rdp_nla_required = Get-IRRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
                rdp_port = Get-IRRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'PortNumber'
                smb1_server = Get-IRRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
                ps_script_block_logging = Get-IRRegValue "$ps\ScriptBlockLogging" 'EnableScriptBlockLogging'
                ps_module_logging = Get-IRRegValue "$ps\ModuleLogging" 'EnableModuleLogging'
                ps_transcription = Get-IRRegValue "$ps\Transcription" 'EnableTranscripting'
                sysmon_installed = [bool](Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)
                winrm_service = [string](Get-Service -Name WinRM -ErrorAction SilentlyContinue).Status
                remote_registry_service = [string](Get-Service -Name RemoteRegistry -ErrorAction SilentlyContinue).Status
            })
        $ap = @(& auditpol.exe /get /category:* /r 2>$null)
        if ($LASTEXITCODE -eq 0 -and $ap.Count -gt 1) {
            Save-IRData 'audit_policy' @($ap | Where-Object { $_ } | ConvertFrom-Csv | ForEach-Object {
                    [pscustomobject]@{ subcategory = $_.Subcategory; guid = $_.'Subcategory GUID'; setting = $_.'Inclusion Setting' }
                })
        } else { Write-IRLog '  auditpol could not be read (needs elevation)' 'WARN' }
    }

    Invoke-IRStep 'Execution evidence (BAM, UserAssist, ShimCache)' 'execution' {
        $bam = [System.Collections.Generic.List[object]]::new()
        foreach ($base in 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings',
            'HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\dam\UserSettings') {
            foreach ($k in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
                $key = Get-Item -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                if (-not $key) { continue }
                foreach ($n in $key.GetValueNames()) {
                    $v = $key.GetValue($n)
                    if ($v -isnot [byte[]] -or $v.Length -lt 8) { continue }
                    $bam.Add([pscustomobject]@{
                            source = $(if ($base -match '\\bam\\') { 'BAM' } else { 'DAM' }); user = (Resolve-IRSid $k.PSChildName)
                            path = $n; last_run = (ConvertFrom-IRFileTime ([BitConverter]::ToInt64($v, 0)))
                        })
                }
            }
        }
        Save-IRData 'bam' $bam

        $folders = $Script:KnownFolders
        $ua = [System.Collections.Generic.List[object]]::new()
        foreach ($r in @(Get-IRHiveRoots | Where-Object sid)) {
            foreach ($g in @(Get-ChildItem -LiteralPath "$($r.root)\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" -ErrorAction SilentlyContinue)) {
                $key = Get-Item -LiteralPath "$($g.PSPath)\Count" -ErrorAction SilentlyContinue
                if (-not $key) { continue }
                foreach ($n in $key.GetValueNames()) {
                    $name = ConvertFrom-IRRot13 $n
                    if ($name -match '^UEME_') { continue }
                    foreach ($guid in $folders.Keys) { if ($name.StartsWith($guid, [StringComparison]::OrdinalIgnoreCase)) { $name = $folders[$guid] + $name.Substring($guid.Length) } }
                    $v = $key.GetValue($n)
                    $count = $null; $focus = $null; $last = $null
                    if ($v -is [byte[]] -and $v.Length -ge 68) {
                        $count = [BitConverter]::ToInt32($v, 4)
                        $focus = [math]::Round([BitConverter]::ToInt32($v, 12) / 1000)
                        $last = ConvertFrom-IRFileTime ([BitConverter]::ToInt64($v, 60))
                    }
                    $ua.Add([pscustomobject]@{ user = $r.user; program = $name; run_count = $count; focus_seconds = $focus; last_run = $last })
                }
            }
        }
        Save-IRData 'userassist' $ua
        Save-IRData 'shimcache' @(Get-IRShimCache)
    }

    Invoke-IRStep 'User activity (PowerShell history, recent files, MRU, USB, Recycle Bin)' 'user-activity' {
        $hist = [System.Collections.Generic.List[object]]::new()
        foreach ($p in $Script:Profiles) {
            $dir = Join-Path $p.path 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
            foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*history.txt' -File -Force -ErrorAction SilentlyContinue)) {
                $i = 0
                foreach ($l in @(Get-Content -LiteralPath $f.FullName -Tail 5000 -ErrorAction SilentlyContinue)) {
                    $i++
                    if ($l.Trim()) { $hist.Add([pscustomobject]@{ user = $p.user; file = $f.Name; line = $i; command = $l; file_modified = ConvertTo-IRTime $f.LastWriteTimeUtc }) }
                }
            }
        }
        Save-IRData 'powershell_history' $hist

        $shell = $null
        try { $shell = New-Object -ComObject WScript.Shell } catch { }
        $recent = [System.Collections.Generic.List[object]]::new()
        foreach ($p in $Script:Profiles) {
            $dir = Join-Path $p.path 'AppData\Roaming\Microsoft\Windows\Recent'
            foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.lnk' -File -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 2000)) {
                $target = $null
                if ($shell) { try { $target = $shell.CreateShortcut($f.FullName).TargetPath } catch { } }
                $recent.Add([pscustomobject]@{ user = $p.user; name = $f.BaseName; target = $target; first_opened = ConvertTo-IRTime $f.CreationTimeUtc; last_opened = ConvertTo-IRTime $f.LastWriteTimeUtc })
            }
        }
        Save-IRData 'recent_files' $recent

        $mru = [System.Collections.Generic.List[object]]::new()
        foreach ($r in @(Get-IRHiveRoots | Where-Object sid)) {
            foreach ($pair in @(@('RunMRU', 'Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'), @('TypedPaths', 'Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'), @('RDP MRU', 'Software\Microsoft\Terminal Server Client\Default'))) {
                foreach ($v in @(Get-IRRegValues "$($r.root)\$($pair[1])")) {
                    if ($v.name -eq 'MRUList') { continue }
                    $mru.Add([pscustomobject]@{ user = $r.user; type = $pair[0]; name = $v.name; value = [string]$v.value })
                }
            }
            foreach ($s in @(Get-ChildItem -LiteralPath "$($r.root)\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue)) {
                $mru.Add([pscustomobject]@{ user = $r.user; type = 'RDP server'; name = $s.PSChildName; value = (Get-IRRegValue $s.PSPath 'UsernameHint') })
            }
            foreach ($s in @(Get-ChildItem -LiteralPath "$($r.root)\Network" -ErrorAction SilentlyContinue)) {
                $mru.Add([pscustomobject]@{ user = $r.user; type = 'Mapped drive'; name = $s.PSChildName; value = ('{0} as {1}' -f (Get-IRRegValue $s.PSPath 'RemotePath'), (Get-IRRegValue $s.PSPath 'UserName')) })
            }
        }
        Save-IRData 'user_mru' $mru

        $usb = foreach ($dev in @(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue)) {
            foreach ($inst in @(Get-ChildItem -LiteralPath $dev.PSPath -ErrorAction SilentlyContinue)) {
                [pscustomobject]@{ device = $dev.PSChildName; serial = $inst.PSChildName; friendly_name = (Get-IRRegValue $inst.PSPath 'FriendlyName') }
            }
        }
        Save-IRData 'usb_devices' @($usb)

        # Recycle Bin $I records: original path, size and deletion time of every deleted file.
        $rb = [System.Collections.Generic.List[object]]::new()
        foreach ($drive in @([IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady })) {
            $root = Join-Path $drive.RootDirectory.FullName '$Recycle.Bin'
            foreach ($sidDir in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue)) {
                foreach ($f in @(Get-ChildItem -LiteralPath $sidDir.FullName -Filter '$I*' -File -Force -ErrorAction SilentlyContinue)) {
                    try {
                        $b = [IO.File]::ReadAllBytes($f.FullName)
                        if ($b.Length -lt 28) { continue }
                        $ver = [BitConverter]::ToInt64($b, 0)
                        if ($ver -eq 2) { $len = [BitConverter]::ToInt32($b, 24); $name = [Text.Encoding]::Unicode.GetString($b, 28, [math]::Min($len * 2, $b.Length - 28)) }
                        else { $name = [Text.Encoding]::Unicode.GetString($b, 24, [math]::Min(520, $b.Length - 24)) }
                        $rb.Add([pscustomobject]@{
                                user = (Resolve-IRSid $sidDir.Name); original_path = $name.Split([char]0)[0]; size = [BitConverter]::ToInt64($b, 8)
                                deleted = (ConvertFrom-IRFileTime ([BitConverter]::ToInt64($b, 16))); record = $f.Name
                                content_present = (Test-Path -LiteralPath (Join-Path $sidDir.FullName ('$R' + $f.Name.Substring(2))))
                            })
                    } catch { }
                }
            }
        }
        Save-IRData 'recycle_bin' $rb
    }

    Invoke-IRStep 'Installed software and updates' 'system' {
        $rows = [System.Collections.Generic.List[object]]::new()
        $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
        foreach ($r in @(Get-IRHiveRoots | Where-Object sid)) { $keys += "$($r.root)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
        foreach ($k in $keys) {
            foreach ($s in @(Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue)) {
                $n = Get-IRRegValue $s.PSPath 'DisplayName'
                if (-not $n) { continue }
                $d = [string](Get-IRRegValue $s.PSPath 'InstallDate')
                $inst = $null
                if ($d -match '^(\d{4})(\d{2})(\d{2})$') { $inst = '{0}-{1}-{2}T00:00:00Z' -f $Matches[1], $Matches[2], $Matches[3] }
                $rows.Add([pscustomobject]@{
                        name = $n; version = (Get-IRRegValue $s.PSPath 'DisplayVersion'); publisher = (Get-IRRegValue $s.PSPath 'Publisher')
                        installed = $inst; location = (Get-IRRegValue $s.PSPath 'InstallLocation'); scope = $(if ($k -like 'HKLM*') { 'machine' } else { 'user' })
                    })
            }
        }
        Save-IRData 'installed_software' $rows
        Save-IRData 'hotfixes' @(Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject]@{ id = $_.HotFixID; description = $_.Description; installed = (ConvertTo-IRTime $_.InstalledOn); by = $_.InstalledBy }
            })
    }

    Invoke-IRStep "Recently created executables, scripts and archives (last $Days days)" 'files' {
        $since = $Script:Case.Started.AddDays(-$Days)
        $max = switch ($CollectionProfile) { 'Quick' { 1500 } 'Standard' { 5000 } default { 15000 } }
        $deep = if ($CollectionProfile -eq 'Full') { 2 } else { 0 }
        $found = [System.Collections.Generic.List[object]]::new()
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $roots = [System.Collections.Generic.List[object]]::new()
        foreach ($p in $Script:Profiles) {
            if (-not $p.exists) { continue }
            foreach ($sub in @(@('Downloads', 4), @('Desktop', 3), @('Documents', 3), @('AppData\Local\Temp', 4), @('AppData\Roaming', (3 + $deep)),
                    @('AppData\Local', (2 + $deep)), @('AppData\LocalLow', 3), @('Music', 2), @('Pictures', 2), @('Videos', 2))) {
                $roots.Add(@((Join-Path $p.path $sub[0]), $sub[1]))
            }
        }
        foreach ($s in @(@("$env:SystemRoot\Temp", 4), @($env:PUBLIC, 4), @($env:ProgramData, (2 + $deep)), @("$env:SystemDrive\PerfLogs", 4),
                @("$env:SystemRoot\Tasks", 2), @("$env:SystemDrive\Intel", 3), @("$env:SystemRoot\System32\spool\drivers\color", 1),
                @("$env:SystemDrive\`$Recycle.Bin", 3), @("$env:SystemDrive\", 0), @($env:SystemRoot, 0), @("$env:SystemRoot\System32", 0),
                @("$env:SystemRoot\SysWOW64", 0), @("$env:SystemRoot\System32\drivers", 0))) {
            $roots.Add($s)
        }
        foreach ($r in $roots) { Find-IRFiles -Root $r[0] -MaxDepth $r[1] -Since $since -Out $found -Seen $seen -Max $max }
        $rows = foreach ($fi in $found) {
            $sig = $null
            if ($Script:PeExt.Contains($fi.Extension)) { $sig = Get-IRSignature $fi.FullName }
            $zone = $null; $hostUrl = $null; $refUrl = $null
            try {
                foreach ($l in @(Get-Content -LiteralPath $fi.FullName -Stream 'Zone.Identifier' -ErrorAction Stop)) {
                    if ($l -match '^ZoneId=(\d+)') { $zone = [int]$Matches[1] }
                    elseif ($l -match '^HostUrl=(.+)$') { $hostUrl = $Matches[1] }
                    elseif ($l -match '^ReferrerUrl=(.+)$') { $refUrl = $Matches[1] }
                }
            } catch { }
            [pscustomobject]@{
                path = $fi.FullName; name = $fi.Name; size = $fi.Length; created = ConvertTo-IRTime $fi.CreationTimeUtc
                modified = ConvertTo-IRTime $fi.LastWriteTimeUtc; sha256 = (Get-IRHash $fi.FullName 50)
                signature = $sig.status; signer = $sig.signer; zone_id = $zone; host_url = $hostUrl; referrer_url = $refUrl
                hidden = [bool]($fi.Attributes -band [IO.FileAttributes]::Hidden)
            }
        }
        Save-IRData 'file_scan' @($rows)
        if ($found.Count -ge $max) { Write-IRLog "  file scan stopped at $max files (raise the profile for a deeper scan)" 'WARN' }
    }

    Invoke-IRStep 'Alternate data streams' 'files' -Profiles 'Full' {
        $rows = [System.Collections.Generic.List[object]]::new()
        $ignore = @(':$DATA', 'Zone.Identifier', 'SmartScreen', 'ms-properties', 'com.dropbox.attrs', 'OECustomProperty', 'encryptable', 'favicon')
        foreach ($p in $Script:Profiles) {
            foreach ($sub in 'Downloads', 'Desktop', 'Documents', 'AppData\Local\Temp', 'AppData\Roaming') {
                foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $p.path $sub) -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object -First 20000)) {
                    foreach ($s in @(Get-Item -LiteralPath $f.FullName -Stream * -ErrorAction SilentlyContinue)) {
                        if ($ignore -notcontains $s.Stream) { $rows.Add([pscustomobject]@{ path = $f.FullName; stream = $s.Stream; size = $s.Length }) }
                    }
                }
            }
        }
        Save-IRData 'alternate_data_streams' $rows
    }

    Invoke-IRStep 'Event logs (complete .evtx export)' 'eventlogs' {
        $inv = [System.Collections.Generic.List[object]]::new()
        $all = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue)
        $names = @{}
        foreach ($l in $all) {
            $names[$l.LogName] = 1
            $isKey = $Script:KeyLogs -contains $l.LogName
            if (-not $isKey -and ($CollectionProfile -eq 'Quick' -or -not $l.RecordCount)) { continue }
            $file = (($l.LogName -replace '/', '%4') -replace '[\\:*?"<>|]', '_') + '.evtx'
            $dest = Join-Path $Script:Case.Events $file
            $ok = $false
            if ($l.RecordCount) {
                & wevtutil.exe epl $l.LogName $dest /ow:true 2>$null
                $ok = ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $dest))
                if ($ok) { $Script:CurrentItems++ } else { Write-IRLog "  export failed: $($l.LogName)" 'WARN' }
            }
            $oldest = $null
            if ($isKey -and $ok) {
                $rd = $null
                try {
                    $rd = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($dest, [System.Diagnostics.Eventing.Reader.PathType]::FilePath)
                    $first = $rd.ReadEvent()
                    if ($first) { $oldest = ConvertTo-IRTime $first.TimeCreated; $first.Dispose() }
                } catch { } finally { if ($rd) { $rd.Dispose() } }
            }
            $inv.Add([pscustomobject]@{
                    log = $l.LogName; file = $(if ($ok) { $file } else { $null }); records = $l.RecordCount
                    size_mb = [math]::Round(([double]$l.FileSize) / 1MB, 1); max_size_mb = [math]::Round(([double]$l.MaximumSizeInBytes) / 1MB, 1)
                    enabled = $l.IsEnabled; mode = [string]$l.LogMode; last_write = ConvertTo-IRTime $l.LastWriteTime; oldest_event = $oldest; key = $isKey; missing = $false
                })
        }
        foreach ($k in $Script:KeyLogs) {
            if (-not $names.ContainsKey($k)) {
                $inv.Add([pscustomobject]@{ log = $k; file = $null; records = 0; size_mb = 0; max_size_mb = 0; enabled = $false; mode = $null; last_write = $null; oldest_event = $null; key = $true; missing = $true })
            }
        }
        Save-IRData 'event_logs' $inv
    }

    Invoke-IRStep 'Raw artifacts (hives, Amcache, SRUM, user artifacts, browsers)' 'artifacts' -Profiles 'Standard', 'Full' {
        Copy-IRFolder (Join-Path $env:SystemRoot 'AppCompat\Programs') (Join-Path $A 'Amcache') -Masks 'Amcache.hve*', 'RecentFileCache.bcf' | Out-Null
        Copy-IRFolder (Join-Path $env:SystemRoot 'System32\sru') (Join-Path $A 'SRUM') | Out-Null
        Copy-IRFolder (Join-Path $env:SystemRoot 'System32\Tasks') (Join-Path $A 'Tasks') -Recurse | Out-Null
        Copy-IRFile (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') (Join-Path $A 'System') | Out-Null
        Copy-IRFile (Join-Path $env:SystemRoot 'INF\setupapi.dev.log') (Join-Path $A 'System') | Out-Null
        Copy-IRFolder (Join-Path $env:SystemRoot 'System32\LogFiles\Firewall') (Join-Path $A 'System\FirewallLogs') | Out-Null
        Copy-IRFolder "$env:ProgramData\Microsoft\Windows Defender\Support" (Join-Path $A 'Defender') -Masks 'MPLog-*.log', 'MPDetection-*.log' | Out-Null
        Save-IRHive 'HKLM\SYSTEM' (Join-Path $A 'Registry\SYSTEM') | Out-Null
        Save-IRHive 'HKLM\SOFTWARE' (Join-Path $A 'Registry\SOFTWARE') | Out-Null
        if ($CollectionProfile -eq 'Full') {
            Save-IRHive 'HKLM\SAM' (Join-Path $A 'Registry\SAM') | Out-Null
            Save-IRHive 'HKLM\SECURITY' (Join-Path $A 'Registry\SECURITY') | Out-Null
            Write-IRLog '  SAM and SECURITY contain local password hashes - protect the archive accordingly.'
            Copy-IRFolder (Join-Path $env:SystemRoot 'System32\wbem\Repository') (Join-Path $A 'WMIRepository') | Out-Null
        }
        foreach ($p in $Script:Profiles) {
            if (-not $p.exists) { continue }
            $u = Join-Path $A "Users\$($p.name)"
            if ($p.loaded) {
                Save-IRHive "HKU\$($p.sid)" (Join-Path $u 'NTUSER.DAT') | Out-Null
                Save-IRHive "HKU\$($p.sid)_Classes" (Join-Path $u 'UsrClass.dat') | Out-Null
            } else {
                Copy-IRFile (Join-Path $p.path 'NTUSER.DAT') $u | Out-Null
                Copy-IRFile (Join-Path $p.path 'AppData\Local\Microsoft\Windows\UsrClass.dat') $u | Out-Null
            }
            $rec = Join-Path $p.path 'AppData\Roaming\Microsoft\Windows\Recent'
            Copy-IRFolder $rec (Join-Path $u 'Recent') -Masks '*.lnk' | Out-Null
            Copy-IRFolder (Join-Path $rec 'AutomaticDestinations') (Join-Path $u 'JumpLists\AutomaticDestinations') | Out-Null
            Copy-IRFolder (Join-Path $rec 'CustomDestinations') (Join-Path $u 'JumpLists\CustomDestinations') | Out-Null
            Copy-IRFolder (Join-Path $p.path 'AppData\Roaming\Microsoft\Office\Recent') (Join-Path $u 'OfficeRecent') | Out-Null
            Copy-IRFolder (Join-Path $p.path 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine') (Join-Path $u 'PSReadLine') | Out-Null
            Copy-IRFolder (Join-Path $p.path 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') (Join-Path $u 'Startup') -Recurse | Out-Null
            foreach ($cdp in @(Get-ChildItem -LiteralPath (Join-Path $p.path 'AppData\Local\ConnectedDevicesPlatform') -Directory -ErrorAction SilentlyContinue)) {
                Copy-IRFile (Join-Path $cdp.FullName 'ActivitiesCache.db') (Join-Path $u "WindowsTimeline\$($cdp.Name)") | Out-Null
            }
            $browsers = [ordered]@{
                Edge = 'AppData\Local\Microsoft\Edge\User Data'; Chrome = 'AppData\Local\Google\Chrome\User Data'; Brave = 'AppData\Local\BraveSoftware\Brave-Browser\User Data'
            }
            foreach ($b in $browsers.Keys) {
                foreach ($prof in @(Get-ChildItem -LiteralPath (Join-Path $p.path $browsers[$b]) -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })) {
                    foreach ($fn in 'History', 'History-journal') { Copy-IRFile (Join-Path $prof.FullName $fn) (Join-Path $u "Browsers\$b\$($prof.Name)") | Out-Null }
                }
            }
            foreach ($prof in @(Get-ChildItem -LiteralPath (Join-Path $p.path 'AppData\Roaming\Mozilla\Firefox\Profiles') -Directory -ErrorAction SilentlyContinue)) {
                foreach ($fn in 'places.sqlite', 'places.sqlite-wal') { Copy-IRFile (Join-Path $prof.FullName $fn) (Join-Path $u "Browsers\Firefox\$($prof.Name)") | Out-Null }
            }
            if ($CollectionProfile -eq 'Full') {
                Copy-IRFolder (Join-Path $p.path 'AppData\Local\Microsoft\Windows\Explorer') (Join-Path $u 'ThumbCache') -Masks 'thumbcache_*.db', 'iconcache_*.db' | Out-Null
                Copy-IRFolder (Join-Path $p.path 'AppData\Local\Microsoft\Terminal Server Client\Cache') (Join-Path $u 'RDPBitmapCache') | Out-Null
            }
        }
        foreach ($drive in @([IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady })) {
            $rbRoot = Join-Path $drive.RootDirectory.FullName '$Recycle.Bin'
            foreach ($sidDir in @(Get-ChildItem -LiteralPath $rbRoot -Directory -Force -ErrorAction SilentlyContinue)) {
                Copy-IRFolder $sidDir.FullName (Join-Path $A "RecycleBin\$($drive.Name.Substring(0, 1))\$($sidDir.Name)") -Masks '$I*' | Out-Null
            }
        }
    }
    Remove-IRShadow

    $Script:SystemInfo.collection_end = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', $Script:Inv)
    Save-IRData 'system' $Script:SystemInfo
    Save-IRData 'collection_steps' $Script:Steps
    $failed = @($Script:Steps | Where-Object { $_.status -eq 'error' }).Count
    Write-IRLog ("Collection finished: {0} steps, {1} failed, {2} partial" -f $Script:Steps.Count, $failed, @($Script:Steps | Where-Object { $_.status -eq 'partial' }).Count) 'OK'
}

#endregion

#region ===== Analysis: rules =====

@'
T1003.006|OS Credential Dumping: DCSync|credential-access
T1547|Boot or Logon Autostart Execution|persistence
T1007|System Service Discovery|discovery
T1036|Masquerading|defense-evasion
T1048|Exfiltration Over Alternative Protocol|exfiltration
T1049|System Network Connections Discovery|discovery
T1068|Exploitation for Privilege Escalation|privilege-escalation
T1070.003|Indicator Removal: Clear Command History|defense-evasion
T1078.003|Valid Accounts: Local Accounts|initial-access
T1127.001|Trusted Developer Utilities Proxy Execution: MSBuild|defense-evasion
T1135|Network Share Discovery|discovery
T1201|Password Policy Discovery|discovery
T1218.007|System Binary Proxy Execution: Msiexec|defense-evasion
T1505.003|Server Software Component: Web Shell|persistence
T1518.001|Software Discovery: Security Software Discovery|discovery
T1553.005|Subvert Trust Controls: Mark-of-the-Web Bypass|defense-evasion
T1555.003|Credentials from Password Stores: Credentials from Web Browsers|credential-access
T1557.001|Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning|credential-access
T1564.003|Hide Artifacts: Hidden Window|defense-evasion
T1564.004|Hide Artifacts: NTFS File Attributes|defense-evasion
T1570|Lateral Tool Transfer|lateral-movement
'@ -split "`r?`n" | Where-Object { $_ } | ForEach-Object {
    $p = $_.Split('|')
    $Script:Mitre[$p[0]] = [ordered]@{ id = $p[0]; name = $p[1]; tactic = $p[2] }
}
foreach ($kv in @(
        @('T1505', 'Locate the web shell under the web root, preserve it with the web server logs, and identify the vulnerability that let it be written.'),
        @('T1553', 'Container files (ISO/IMG/VHD) strip Mark-of-the-Web: retrieve the file, check what it contained and whether it was opened.'),
        @('T1570', 'Find where the tool was copied from/to and hunt for the same file on other hosts.'),
        @('T1127', 'Review the project/inline task file that was executed and block the developer utility where it is not needed.'),
        @('T1068', 'Identify the exploited component or vulnerable driver, patch or block it (Microsoft vulnerable driver blocklist) and treat SYSTEM-level access as achieved.'),
        @('T1048', 'Determine what data was transferred and where; preserve proxy/firewall logs.'),
        @('T1135', 'Discovery normally follows a foothold: identify the user/process that ran it and what happened right before.'),
        @('T1049', 'Discovery normally follows a foothold: identify the user/process that ran it and what happened right before.'),
        @('T1007', 'Discovery normally follows a foothold: identify the user/process that ran it and what happened right before.'),
        @('T1201', 'Discovery normally follows a foothold: identify the user/process that ran it and what happened right before.'),
        @('T1518', 'Security software discovery often precedes an attempt to disable it; check for defense-evasion findings.'),
        @('T1557', 'Disable LLMNR and NBT-NS, enforce SMB signing and reset credentials of accounts seen on the poisoned host.')
    )) { $Script:TechniqueAdvice[$kv[0]] = $kv[1] }

$Script:SevRank = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }
$Script:SevWeight = @{ info = 0; low = 1; medium = 5; high = 15; critical = 40 }
$Script:RxOpt = [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'

function New-IRRule([string]$Id, [string]$Sev, [string]$Tech, [string]$Scope, [string]$Title, [string]$Pattern) {
    [pscustomobject]@{ id = $Id; sev = $Sev; tech = $Tech; scope = $Scope; title = $Title; rx = New-Object Text.RegularExpressions.Regex($Pattern, $Script:RxOpt) }
}

# Command-line / script rules. Scope 'any' also runs on PowerShell script-block text (4104);
# 'proc' only on process command lines, shell history, and service/task/autorun commands.
$Script:CmdRules = @(
    New-IRRule ('CRED-MIMI' + 'KATZ') critical 'T1003.001' any ('Mimi' + 'katz or a Mimi' + 'katz-style credential theft module') 'seku(?:)rlsa::|lsad(?:)ump::|kerbe(?:)ros::(ptt|golden|list)|privilege::debug|token::elevate|vault::cred|dpapi::|crypto::capi|misc::memssp|invoke-mimik(?:)atz|\bmimik(?:)atz\b|invoke-k(?:)atz|safetyk(?:)atz|pypyk(?:)atz'
    New-IRRule 'CRED-LSASS-DUMP' critical 'T1003.001' any 'LSASS memory dump' 'comsvcs(\.dll)?[\s,"'']+#?(minidump|24)\b|minidump\W.{0,80}lsass|procd(?:)ump(64)?(\.exe)?\s.{0,80}(lsass|-ma\s+\d{2,6})|lsass\S{0,20}\.dmp|out-minidump|nanod(?:)ump|sqldumper(\.exe)?\s.{0,40}0x0110|rdrleakdiag.{0,40}/fullmemdmp|createdump(\.exe)?\s.{0,40}-f\s|tttracer.{0,40}-dumpfull'
    New-IRRule 'CRED-HIVE-SAVE' high 'T1003.002' proc 'Registry hive saved for offline credential extraction' 'reg(\.exe)?["'']?\s+(save|export)\s+["'']?(hklm|hkey_local_machine)\\(sam|security|system)\b'
    New-IRRule 'CRED-NTDS' high 'T1003.003' any 'Active Directory database (NTDS.dit) access or shadow copy creation' 'ntdsutil(\.exe)?.{0,80}(\bifm\b|create\s+full)|\\ntds\.dit|vssadmin(\.exe)?\s+create\s+shadow|diskshadow(\.exe)?\s|esentutl(\.exe)?.{0,40}/(y|vss).{0,80}ntds|wmic(\.exe)?.{0,40}shadowcopy\s+call\s+create'
    New-IRRule 'CRED-DCSYNC' critical 'T1003.006' any 'DCSync / remote secrets dump' 'lsad(?:)ump::dcsync|invoke-dcsync|secretsd(?:)ump|drsuapi.{0,40}getncchanges'
    New-IRRule 'CRED-KERBEROS' high 'T1558.003' any 'Kerberoasting / Kerberos ticket abuse' 'invoke-kerberoast|rube(?:)us(\.exe)?\s|\b(kerberoast|asreproast|asktgt|asktgs|s4u)\b.{0,60}/(user|rc4|aes256|domain|outfile|nowrap|ticket)|getuserspns|setspn(\.exe)?\s+-[tq]\s.{0,20}\*/\*|kerberosrequestorsecuritytoken'
    New-IRRule 'CRED-STORES' high 'T1555.003' any 'Browser / password store credential theft' 'laza(?:)gne|sharpchrome|sharpweb|hackbrowserdata|chromepass|webbrowserpassview|get-chromedump|(copy|esentutl|get-content|type|xcopy|robocopy)\s.{0,160}\\(login data|logins\.json|key4\.db)\b'
    New-IRRule 'CRED-FILES' medium 'T1552.001' proc 'Searching files or credential stores for passwords' 'findstr(\.exe)?\s.{0,40}/s.{0,60}(password|passwd|pwd|cpassword)|select-string.{0,80}(password|cpassword)|cmdkey(\.exe)?\s+/list|vaultcmd(\.exe)?\s+/list|get-gpppassword|\bunattend\.xml|sysprep\.(xml|inf)'
    New-IRRule 'PS-ENCODED' high 'T1027' any 'PowerShell encoded command' '(powershell|pwsh)(\.exe)?["'']?\s.{0,200}\s[-/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?\s+["'']?[a-z0-9+/]{20,}'
    New-IRRule 'PS-DOWNLOAD-EXEC' high 'T1059.001' any 'PowerShell download-and-execute cradle' '(iex|invoke-expression)\b.{0,120}(downloadstring|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|bitstransfer)|(downloadstring|downloaddata|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b).{0,250}\|\s*(iex|invoke-expression)\b'
    New-IRRule 'INGRESS-DOWNLOAD' medium 'T1105' proc 'File downloaded with a command-line tool' 'net\.webclient\)?\.download(file|data|string)|downloadfile\(|invoke-webrequest.{0,200}-outf(ile)?\b|\biwr\b.{0,200}-o(utfile)?\b|start-bitstransfer|curl(\.exe)?\s.{0,200}(\s-o\s|--output|\s-O\s)|wget(\.exe)?\s.{0,100}https?://|certreq(\.exe)?\s+-post|hh(\.exe)?\s+https?://'
    New-IRRule 'CERTUTIL-ABUSE' high 'T1105' any 'certutil used to download or decode a file' 'certutil(\.exe)?\s.{0,60}[-/](urlcache|verifyctl|decode|decodehex)\b'
    New-IRRule 'BITSADMIN' high 'T1197' proc 'bitsadmin transfer / job manipulation' 'bitsadmin(\.exe)?\s.{0,60}/(transfer|addfile|setnotifycmdline|create|resume)\b'
    New-IRRule 'MSHTA' high 'T1218.005' any 'mshta executing remote or inline script' 'mshta(\.exe)?["'']?\s+["'']?(https?:|javascript:|vbscript:|about:|\\\\)|mshta(\.exe)?\s.{0,120}\.hta\b'
    New-IRRule 'REGSVR32' high 'T1218.010' any 'regsvr32 scriptlet / remote COM execution (Squiblydoo)' 'regsvr32(\.exe)?\s.{0,80}[/-]i:\s*["'']?(https?|\\\\|ftp)|regsvr32.{0,120}scrobj\.dll'
    New-IRRule 'RUNDLL32' medium 'T1218.011' proc 'Suspicious rundll32 execution' 'rundll32(\.exe)?["'']?\s+["'']?(javascript:|vbscript:|\\\\)|rundll32(\.exe)?\s.{0,40}(url\.dll.{0,20}(openurl|fileprotocolhandler)|advpack\.dll.{0,20}(launchinfsection|registerocx)|ieadvpack|shell32\.dll.{0,10}shellexec_rundll|pcwutl\.dll|zipfldr\.dll.{0,10}routethecall|desk\.cpl.{0,20}installscreensaver|dfshim\.dll)|rundll32(\.exe)?["'']?\s+["'']?[a-z]:\\(users|programdata|windows\\temp|perflogs)\\[^,]+,'
    New-IRRule 'MSIEXEC-REMOTE' high 'T1218.007' proc 'msiexec installing a package from a URL' 'msiexec(\.exe)?["'']?\s.{0,60}/(i|package|q)\b.{0,60}https?://|msiexec(\.exe)?["'']?\s.{0,40}/y\s'
    New-IRRule 'DEV-UTIL-PROXY' medium 'T1127.001' proc 'Developer utility used to proxy code execution' '(msbuild|installutil|regasm|regsvcs|msxsl|cmstp|odbcconf|ieexec|presentationhost|xwizard|mavinject|syncappvpublishingserver)(\.exe)?["'']?\s.{0,160}(\\(users|programdata|temp|perflogs|public)\\|https?:|\.(xml|csproj|proj|sct|inf)\b|/u\b|/s\b|/logfile=|inject)'
    New-IRRule 'WMI-EXEC' high 'T1047' any 'WMI used to start a process (local or remote)' 'wmic(\.exe)?\s.{0,120}process\s+call\s+create|wmic(\.exe)?\s.{0,40}/node:\s*["'']?[^\s"'']+|invoke-wmimethod.{0,120}win32_process.{0,40}create|invoke-cimmethod.{0,120}win32_process.{0,40}create|\[wmiclass\].{0,40}win32_process'
    New-IRRule 'PSEXEC' high 'T1569.002' proc 'PsExec-style remote service execution' '(psexec|paexec|csexec|remcom)(64)?(\.exe)?["'']?\s.{0,60}\\\\[^\\\s]+|\\psexesvc\.exe|-accepteula\s.{0,60}\\\\'
    New-IRRule 'WINRM-REMOTE' medium 'T1021.006' any 'Remote command execution over WinRM / PowerShell remoting' 'winrs(\.exe)?\s.{0,40}[-/]r(emote)?:|invoke-command\s.{0,200}-computername|enter-pssession\s|new-pssession\s.{0,100}-computername'
    New-IRRule 'SC-REMOTE' high 'T1569.002' proc 'Service created or started on a remote host' '(^|[\\\s"''])sc(\.exe)?["'']?\s+\\\\\S+\s+(create|config|start)\b'
    New-IRRule 'SC-CREATE' medium 'T1543.003' proc 'Service created or reconfigured from the command line' '(^|[\\\s"''])sc(\.exe)?["'']?\s+(create|config)\s+\S+.{0,80}binpath\s*=|new-service\s.{0,80}-binarypathname'
    New-IRRule 'SCHTASKS-CREATE' medium 'T1053.005' proc 'Scheduled task created from the command line' 'schtasks(\.exe)?["'']?\s.{0,40}/create\b|register-scheduledtask\s'
    New-IRRule 'SCHTASKS-REMOTE' high 'T1053.005' proc 'Scheduled task created on a remote host' 'schtasks(\.exe)?["'']?\s.{0,40}/create\b.{0,200}\s/s\s+\S+|(^|[\\\s"''])at(\.exe)?\s+\\\\\S+\s+\d'
    New-IRRule 'REG-RUNKEY' high 'T1547.001' proc 'Autostart registry key written from the command line' '(reg(\.exe)?["'']?\s+add|set-itemproperty|new-itemproperty).{0,120}\\(currentversion\\(run|runonce|runservices|policies\\explorer\\run)\b|winlogon["''\s\\]|currentversion\\windows["''\s\\].{0,40}\b(load|run)\b)'
    New-IRRule 'REG-IFEO' high 'T1546.012' any 'Image File Execution Options / SilentProcessExit hijack' 'image file execution options\\[^\\]+.{0,60}(debugger|globalflag)|silentprocessexit\\[^\\]+.{0,60}monitorprocess'
    New-IRRule 'ACCESSIBILITY-BACKDOOR' critical 'T1546.008' any 'Accessibility feature backdoor (sticky keys / utilman)' 'image file execution options\\(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe|(copy|move|xcopy|replace)\s.{0,80}(cmd|powershell)\.exe.{0,80}\\(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe|takeown.{0,40}(sethc|utilman)\.exe'
    New-IRRule 'ACCOUNT-CREATE' high 'T1136.001' proc 'Local account created from the command line' 'net1?(\.exe)?["'']?\s+user\s+\S+\s+\S+.{0,40}/add\b|new-localuser\s'
    New-IRRule 'GROUP-ADD' high 'T1098' proc 'Account added to a group from the command line' 'net1?(\.exe)?["'']?\s+(localgroup|group)\s+.{0,80}\s/add\b|add-localgroupmember\s|add-adgroupmember\s'
    New-IRRule 'LOG-CLEAR' high 'T1070.001' any 'Event logs cleared or auditing removed' 'wevtutil(\.exe)?["'']?\s+(cl|clear-log)\b|clear-eventlog\s|remove-eventlog\s|eventlogsession\].{0,80}clearlog|auditpol(\.exe)?\s.{0,40}/(clear|remove)\b|auditpol(\.exe)?\s.{0,80}/(success|failure):disable'
    New-IRRule 'USN-DELETE' high 'T1070.004' any 'USN change journal deleted' 'fsutil(\.exe)?\s+usn\s+deletejournal'
    New-IRRule 'INHIBIT-RECOVERY' critical 'T1490' any 'Shadow copies / backups deleted or recovery disabled' 'vssadmin(\.exe)?["'']?\s.{0,20}(delete\s+shadows|resize\s+shadowstorage)|wmic(\.exe)?\s.{0,20}shadowcopy\s+delete|wbadmin(\.exe)?\s.{0,20}delete\s+(catalog|systemstatebackup|backup)|bcdedit(\.exe)?\s.{0,60}(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|win32_shadowcopy.{0,80}\.delete\(|win32_shadowcopy.{0,60}remove-(wmi|cim)\w*|diskshadow.{0,60}delete\s+shadows'
    New-IRRule 'DEFENDER-TAMPER' high 'T1562.001' any 'Microsoft Defender disabled or excluded' 'set-mppr(?:)eference.{0,120}-disable(realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning|intrusionpreventionsystem|blockatfirstseen|archivescanning)\s+(\$true|1|true)|(add|set)-mppr(?:)eference.{0,60}-exclusion(path|process|extension|ipaddress)|mpcm(?:)drun(\.exe)?\s.{0,40}-removed(?:)efinitions|unin(?:)stall-windowsfeature.{0,40}defender|disablea(?:)ntispyware|disabler(?:)ealtimemonitoring'
    New-IRRule 'AMSI-BYPASS' high 'T1562.001' any 'AMSI bypass' 'amsiu(?:)tils|amsii(?:)nitfailed|amsis(?:)canbuffer|amsic(?:)ontext|amsi\.dll.{0,80}(virtualprotect|patch)'
    New-IRRule 'ETW-TAMPER' high 'T1562.002' any 'Event logging / ETW tampering' 'etweventwrite|psetwlogprovider|logman(\.exe)?\s.{0,40}(stop|delete).{0,40}(eventlog|sysmon|defender)|\\control\\minint\b'
    New-IRRule 'FIREWALL-OFF' high 'T1562.004' any 'Windows Firewall disabled' 'netsh(\.exe)?["'']?\s.{0,40}(advfirewall\s+set\s+\S+\s+state\s+off|firewall\s+set\s+opmode\s+(mode=)?disable)|set-netfirewallprofile.{0,80}-enabled\s+(\$?false|0)'
    New-IRRule 'FIREWALL-RULE' low 'T1562.004' proc 'Firewall rule added from the command line' 'netsh(\.exe)?["'']?\s.{0,40}firewall\s+add\s+(rule|allowedprogram|portopening)|new-netfirewallrule\s'
    New-IRRule 'PORTPROXY' high 'T1090' any 'Port forwarding configured (netsh portproxy)' 'netsh(\.exe)?["'']?\s.{0,40}interface\s+portproxy\s+(add|set)'
    New-IRRule 'RDP-ENABLE' medium 'T1021.001' any 'Remote Desktop enabled or weakened' 'fdenytsconnections.{0,60}(/d\s+0|-value\s+0|\b0x0\b)|\\rdp-tcp.{0,40}userauthentication.{0,60}(/d\s+0|-value\s+0)|enable-netfirewallrule.{0,60}remote\s*desktop|disablerestrictedadmin.{0,60}(/d\s+0|-value\s+0)'
    New-IRRule 'SECSVC-STOP' high 'T1562.001' proc 'Security tool stopped or disabled' '(net1?|sc)(\.exe)?["'']?\s+(stop|delete|config)\s+["'']?(wind(?:)efend|wdni(?:)ssvc|wdbo(?:)ot|wdfi(?:)lter|sense|mpssvc|eventlog|sysmon\w*|wscsvc|securityh(?:)ealthservice|msse(?:)nse|csagent|csfalconservice|sentinelagent|cbdefense|savservice|sophos\w*|ekrn|avp|mcafee\w*|symantec\w*)\b|stop-service.{0,40}(wind(?:)efend|sense|eventlog|sysmon|mpssvc)|taskkill(\.exe)?\s.{0,60}(msmp(?:)eng|msse(?:)nse|sysmon|csfalcon|sentinel|ekrn|avp)'
    New-IRRule 'SVC-STOP-IMPACT' high 'T1489' proc 'Backup / database services stopped (ransomware preparation)' '(net1?|sc)(\.exe)?["'']?\s+(stop|config)\s+["'']?(vss|swprv|wbengine|sql\w*|mssql\w*|msexchange\w*|veeam\w*|backup\w*|acronis\w*|bedbg|memtas|mepocs)\b|stop-service.{0,60}(vss|sql|veeam|backup|exchange)|taskkill(\.exe)?\s.{0,60}(sqlservr|oracle|veeam)\.exe'
    New-IRRule 'ARCHIVE' low 'T1560.001' proc 'Data archived with a command-line tool' '(\b7z|7za|7zr|7zg|rar|winrar)(\.exe)?["'']?\s+a\s|compress-archive\s|makecab(\.exe)?\s|tar(\.exe)?["'']?\s+-?[a-z]*c[a-z]*f\s'
    New-IRRule 'ARCHIVE-PASSWORD' medium 'T1560.001' proc 'Password-protected archive created' '(\b7z|7za|7zr|rar|winrar)(\.exe)?["'']?\s+a\s.{0,160}\s"?-(p|hp)[^\s"]+'
    New-IRRule 'EXFIL-TOOL' high 'T1567.002' proc 'Data transfer to cloud storage / file-sharing service' 'rclone(\.exe)?["'']?\s+(copy|sync|move|copyto|config)|megacmd|mega-(put|login)|megatools|transfer\.sh|file\.io|gofile\.io|anonfiles|temp\.sh|bashupload|filebin\.net|curl(\.exe)?\s.{0,120}(-T\s|--upload-file|-F\s+["'']?\w+=@|--data-binary\s+@)|invoke-(webrequest|restmethod).{0,160}-method\s+(put|post).{0,120}-infile'
    New-IRRule 'TUNNEL' high 'T1572' proc 'Tunneling / reverse proxy tool' '\bngrok(\.exe)?\s+(tcp|http|start|authtoken)|chisel(\.exe)?\s+(client|server)|plink(\.exe)?\s.{0,80}\s-R\s|ssh(\.exe)?\s.{0,80}\s-[RD]\s+\d|frpc(\.exe)?\s|cloudflared(\.exe)?\s.{0,20}tunnel|ligolo|revsocks|\bgost(\.exe)?\s+-L|iox(\.exe)?\s+(fwd|proxy)'
    New-IRRule 'ANTI-FORENSICS' medium 'T1070.004' any 'Secure deletion / artifact wiping' 'cipher(\.exe)?\s+/w:|sdelete(64)?(\.exe)?\s|del\s.{0,40}\\windows\\prefetch\\|remove-item.{0,80}\\(prefetch|panther)\\|clear-recyclebin.{0,20}-force'
    New-IRRule 'TIMESTOMP' medium 'T1070.006' any 'File timestamps modified (timestomping)' '\.(creationtime|lastwritetime|lastaccesstime)(utc)?\s*=\s*[^=]|\btimestomp\b|setmace'
    New-IRRule 'HISTORY-CLEAR' medium 'T1070.003' any 'PowerShell command history cleared' 'clear-history\b|remove-item.{0,120}(consolehost_history|psreadline)|set-psreadlineoption.{0,60}historysavestyle\s+savenothing'
    New-IRRule 'UAC-BYPASS' high 'T1548.002' any 'UAC bypass registry hijack' '(ms-settings|mscfile|exefile|launcher\.systemsettings|piffile)\\shell\\open\\command|\bdelegateexecute\b|\\environment\\windir.{0,60}(/d|-value)|sdclt(\.exe)?\s+/kickoffelev|cmstplua|icmluautil'
    New-IRRule 'WDIGEST' high 'T1112' any 'WDigest cleartext credential caching enabled' 'wdigest.{0,80}uselogoncredential.{0,40}(/d\s+1|-value\s+1|\b1\b)'
    New-IRRule 'REG-WEAKEN' medium 'T1112' any 'Security-relevant registry setting weakened' 'localaccounttokenfilterpolicy.{0,40}(/d\s+1|-value\s+1)|enablelua.{0,40}(/d\s+0|-value\s+0)|runasppl.{0,40}(/d\s+0|-value\s+0)|lsacfgflags.{0,40}(/d\s+0|-value\s+0)|consentpromptbehavioradmin.{0,40}(/d\s+0|-value\s+0)'
    New-IRRule 'PS-DOWNGRADE' medium 'T1562.010' proc 'PowerShell version 2 downgrade (bypasses logging)' '(powershell|pwsh)(\.exe)?["'']?\s.{0,40}-v(ersion)?\s+2(\.0)?\b'
    New-IRRule 'PS-HIDDEN' low 'T1564.003' proc 'PowerShell started with a hidden window' '(powershell|pwsh)(\.exe)?["'']?\s.{0,200}\s-w(i|in|ind|indo|indow|indows|indowst|indowsty|indowstyl|indowstyle)?\s+(h|hi|hid|hidd|hidde|hidden|1)\b'
    New-IRRule 'PS-OBFUSCATION' medium 'T1140' any 'Obfuscated / dynamically decoded PowerShell' '\[convert\]::frombase64string\s*\(.{0,200}(iex|invoke-expression|\[reflection\.assembly\]|-bxor|gzipstream|deflatestream)|io\.compression\.(gzipstream|deflatestream).{0,300}(iex|invoke-expression|readtoend)|-join\s*\(?\s*\[char\[\]\]|(\[char\]\s*0?x?[0-9a-f]{2,3}\s*\+\s*){4,}|-bxor\s*0?x?[0-9a-f]+.{0,200}(iex|invoke-expression)|\$\{?env:comspec\}?\[\d+,\s*\d+|invoke-obfuscation'
    New-IRRule 'PROC-INJECTION' high 'T1055' any 'Process injection API usage in a script' '(virtualalloc(ex)?|writeprocessmemory|ntmapviewofsection|queueuserapc|rtlcreateuserthread|setthreadcontext).{0,800}(createthread|createremotethread|getdelegateforfunctionpointer|ntcreatethreadex)|invoke-(shellc(?:)ode|reflectivep(?:)einjection|dllinjection)|\[reflection\.assembly\]::load\s*\(\s*\[convert\]::frombase64'
    New-IRRule 'OFFENSIVE-PS' high 'T1059.001' any 'Offensive PowerShell framework / tool' 'invoke-(powershelltcp|powershelludp|tokenmanipulation|smbe(?:)xec|wmie(?:)xec|thehash|inve(?:)igh|sharefinder|userhunter|allchecks|privescaudit|portscan|bloodh(?:)ound|seatb(?:)elt|rube(?:)us|eterna(?:)lblue|psinject|sharpsecd(?:)ump|ninjacopy|credentialinjection)|powers(?:)ploit|powerup\.ps1|nish(?:)ang|powerc(?:)at|out-encryptedscript|get-keystrokes|get-timedscreenshot|get-vaultcredential|privesccheck|jaws-enum|sherlock\.ps1|winp(?:)eas|invoke-sharp\w+'
    New-IRRule 'AD-RECON' high 'T1087.002' any 'Active Directory reconnaissance tooling' 'sharph(?:)ound|bloodh(?:)ound|adfind(\.exe)?["'']?\s|powerview|get-net(user|group|computer|domain|session|loggedon|localgroup|forest)\b|get-domain(user|computer|group|trust|controller|policy|gpo)\b|find-localadminaccess|find-domainshare|dsquery(\.exe)?\s+(\*|user|computer|group)|adrecon|pingcastle|ldapdomaindump'
    New-IRRule 'TRUST-DISCOVERY' medium 'T1482' proc 'Domain trust discovery' 'nltest(\.exe)?["'']?\s.{0,20}/(domain_trusts|dclist|all_trusts|trusted_domains)|get-adtrust|getalltrustrelationships\(\)|dsquery.{0,40}trusteddomain'
    New-IRRule 'NET-SCAN' medium 'T1046' proc 'Network scanning' '\bnmap(\.exe)?\s|masscan|advanced_ip_scanner|angryip|ipscan\d*\.exe|netscan(\.exe)?\s|test-netconnection.{0,80}-port|for\s+/l\s.{0,80}ping|\b1\.\.254\b.{0,80}(ping|test-connection|test-netconnection)|nbtscan|rustscan'
    New-IRRule 'ADMIN-SHARE' medium 'T1021.002' proc 'Admin share used from the command line' '(copy|xcopy|robocopy|move|net\s+use|dir|type|start|cmd\s+/c)\s.{0,80}\\\\[^\\\s]+\\(admin|c|d|ipc)\$'
    New-IRRule 'SCRIPT-USERDIR' high 'T1059.005' proc 'Windows Script Host running a script from a user / temp folder' '(wscript|cscript)(\.exe)?["'']?\s.{0,60}\\(users\\[^\\]+\\(downloads|desktop|documents|appdata)|temp|public|programdata)\\[^"'']+\.(js|jse|vbs|vbe|wsf|wsh)\b'
    New-IRRule 'DOUBLE-EXT' high 'T1036.007' proc 'Double file extension' '\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|rtf|csv|zip)\.(exe|scr|com|pif|js|jse|vbs|vbe|bat|cmd|hta|lnk|ps1|msi)\b'
    New-IRRule 'HIDE-FILE' low 'T1564.001' proc 'File or folder hidden with attrib' 'attrib(\.exe)?["'']?\s.{0,20}\+h\b'
    New-IRRule 'RANSOM-NOTE' high 'T1486' any 'Ransom note or encrypted-file naming pattern' 'how_to_decrypt|how_to_restore|readme_for_decrypt|decrypt_instructions|restore_files_|recover-files|restore-my-files|!!!readme|\.(lockbit|locked|encrypted|crypted|ryk|akira|basta|alphv|deadbolt)(\s|$|["''])'
    New-IRRule 'MINER-CMD' high 'T1496' any 'Cryptocurrency miner command line' 'stratum\+(tcp|ssl|tls)://|--donate-level|--cpu-max-threads-hint|--randomx-|\s-a\s+(rx/0|cn/r|kawpow|ethash|autolykos2?)\b|--coin[= ]+(monero|xmr)\b|\s-o\s+\S*(pool|xmr|monero)\S*:\d+'
    New-IRRule 'RMM-TOOL' medium 'T1219' proc 'Remote access software executed or configured' '(?<![a-z])(anydesk|teamviewer|screenconnect|connectwisecontrol|atera(agent)?|splashtop|rustdesk|meshagent|rutserv|rfusclient|netsupport|client32\.exe|ammyy|aa_v3|supremo|tacticalrmm|simplehelp|zohoassist|dwagent|getscreen|ultraviewer|radmin|tvnserver|winvnc|vncserver|remotepc|bomgar|ninjarmm|pulseway)(?![a-z])'
)

# Discovery commands are normal one at a time; a burst of them from one account is not.
$Script:DiscoveryRules = @(
    @('T1033', '\bwhoami(\.exe)?\b|\bquser(\.exe)?\b|\bqwinsta(\.exe)?\b|query\s+(user|session)\b'),
    @('T1087', 'net1?(\.exe)?["'']?\s+(user|accounts)\b|get-localuser|wmic.{0,20}useraccount|get-aduser'),
    @('T1069', 'net1?(\.exe)?["'']?\s+(localgroup|group)\b|get-localgroup|gpresult|whoami(\.exe)?\s+/(groups|all)|get-adgroup'),
    @('T1082', '\bsysteminfo\b|\bhostname(\.exe)?\s*$|wmic.{0,20}\b(os|computersystem|bios|qfe)\b|get-computerinfo|get-hotfix'),
    @('T1016', 'ipconfig(\.exe)?["'']?\s*/all|\broute(\.exe)?\s+print|netsh(\.exe)?\s+(interface|wlan)\s+show|nslookup|get-netipconfiguration'),
    @('T1049', 'netstat(\.exe)?["'']?\s|net1?(\.exe)?\s+(use|session|file)\b|get-nettcpconnection'),
    @('T1057', '\btasklist(\.exe)?\b|wmic.{0,20}process\s+(list|get)'),
    @('T1018', 'net1?(\.exe)?["'']?\s+view\b|nltest|ping(\.exe)?\s+-n\s+1\b|get-adcomputer|\barp(\.exe)?\s+-a'),
    @('T1135', 'net1?(\.exe)?["'']?\s+share\b|get-smbshare'),
    @('T1007', '\bsc(\.exe)?["'']?\s+query|wmic.{0,20}\bservice\b'),
    @('T1201', 'net1?(\.exe)?["'']?\s+accounts\b|get-addefaultdomainpasswordpolicy'),
    @('T1518.001', 'wmic.{0,60}antivirusproduct|\bfltmc(\.exe)?\b|sc(\.exe)?\s+query\s+windefend')
) | ForEach-Object { [pscustomobject]@{ tech = $_[0]; rx = New-Object Text.RegularExpressions.Regex($_[1], $Script:RxOpt) } }

function New-IRTool([string]$Id, [string]$Sev, [string]$Tech, [string]$Title, [string]$Names) {
    [pscustomobject]@{ id = $Id; sev = $Sev; tech = $Tech; title = $Title; rx = New-Object Text.RegularExpressions.Regex("(?<![a-z])(?:$Names)(?![a-z])", $Script:RxOpt) }
}

# Known attacker / dual-use tool names, matched against file names from every artifact source
# (process, Prefetch, BAM, UserAssist, ShimCache, file scan, Recycle Bin, services, ...).
$Script:ToolRules = @(
    New-IRTool 'TOOL-CRED' critical 'T1003' 'Credential theft tool' 'mimik(?:)atz|mimil(?:)ib|mimid(?:)rv|kek(?:)eo|safetyk(?:)atz|sharpk(?:)atz|pypyk(?:)atz|laza(?:)gne|nanod(?:)ump|dumpert|pwdump\d*|fgdump|gsecdump|quarkspwdump|secretsd(?:)ump|sharpdump|handlekatz|ppldump|lsassy|wce(32|64)?\.exe|sharpsecd(?:)ump'
    New-IRTool 'TOOL-PROCDUMP' high 'T1003.001' 'ProcDump (frequently used to dump LSASS)' 'procd(?:)ump(64|64a)?\.exe'
    New-IRTool 'TOOL-KERBEROS' high 'T1558.003' 'Kerberos attack tool' 'rube(?:)us|kerbrute|sharproast|asreproast|kerberoast'
    New-IRTool 'TOOL-ADRECON' high 'T1087.002' 'Active Directory reconnaissance tool' 'sharph(?:)ound|bloodh(?:)ound|azurehound|adfind|adrecon|pingcastle|ldapdomaindump'
    New-IRTool 'TOOL-SCANNER' medium 'T1046' 'Network scanner' 'nmap|zenmap|masscan|advanced_ip_scanner|advanced ip scanner|angry ?ip|ipscan\d*|netscan(64)?|softperfect|nbtscan|rustscan'
    New-IRTool 'TOOL-LATERAL' high 'T1570' 'Lateral movement tool' 'wmie(?:)xec|smbe(?:)xec|ate(?:)xec|dcome(?:)xec|crackm(?:)apexec|netexec|nxc\.exe|cme\.exe|evil-w(?:)inrm|impac(?:)ket|sharprdp|sharpwmi|sharpmove'
    New-IRTool 'TOOL-PSEXEC' medium 'T1569.002' 'PsExec-style remote execution tool' 'psexec(64)?(\.exe)?|psexesvc|paexec|csexec|remcom'
    New-IRTool 'TOOL-C2' critical 'T1071.001' 'Command-and-control framework artifact' 'cobalts(?:)trike|cobalt_s(?:)trike|beacon(_x64|_x86|64|32)?\.(exe|dll|bin)|meterp(?:)reter|sli(?:)ver|hav(?:)oc|brute(?:)ratel|brc4|covenant|poshc2|metasploit|msfvenom|sharpshooter'
    New-IRTool 'TOOL-TUNNEL' high 'T1572' 'Tunneling / proxy tool' 'ngrok|chisel|frpc|frps|ligolo|revsocks|rsocx|iox\.exe|stowaway|htran|earthworm|gost\.exe|nc(64)?\.exe|ncat|netcat|socat|plink|cloudflared'
    New-IRTool 'TOOL-EXFIL' medium 'T1567.002' 'File transfer / cloud sync tool' 'rclone|megasync|megacmd|mega-cmd|megatools|winscp|pscp|filezilla|restic|s3browser|cyberduck|freefilesync'
    New-IRTool 'TOOL-PRIVESC' high 'T1068' 'Privilege escalation tool' 'winp(?:)eas|seatb(?:)elt|sharpup|powerup|privesccheck|juicypotato(ng)?|printspoofer|godpotato|sweetpotato|roguepotato|efspotato|badpotato|localpotato|certify|certipy|whisker|krbrelayup|sharpgpoabuse|spoolsample|petitpotam|coercer'
    New-IRTool 'TOOL-EVASION' high 'T1562.001' 'Security tool killer / defense evasion tool' 'defenderc(?:)ontrol|dcon(?:)trol|backstab|edrsandblast|edrsilencer|edrkillshifter|aukill|spyboy|truesightkiller|killav|gmer|pchunter|powertool(64)?|iobitunlocker|blackbone'
    New-IRTool 'TOOL-CRACK' high 'T1557.001' 'Credential poisoning / cracking tool' 'respo(?:)nder|inve(?:)igh|hashcat|thc-hydra|hydra|ncrack|domainpasswordspray|sharpspray'
    New-IRTool 'TOOL-MINER' high 'T1496' 'Cryptocurrency miner' 'xmrig\w*|xmr-stak\w*|phoenixminer|t-rex|lolminer|nbminer|gminer|ethminer|cgminer|bfgminer|nanominer|srbminer\w*|teamredminer|nicehashminer'
    New-IRTool 'TOOL-PIRACY' medium 'T1204.002' 'Cracked software / keygen / activator (common malware lure)' 'kmspico|kmsauto\w*|autokms|kms_?vl_?all\w*|kmsnano|kmscleaner|kms-?tools|aact(_x64)?|re-?loader\w*|\w*keygen\w*|\w*crack\w*|\w*activator(_x64)?'
    New-IRTool 'TOOL-RANSOM' critical 'T1486' 'Ransomware-related file name' 'lockbit|ryuk|blackcat|alphv|akira|blackbasta|revil|sodinokibi|babuk|phobos|dharma|egregor|rhysida|qilin|wannacry|wanacry|wncry|notpetya|darkside|blackmatter|ragnarlocker|avaddon'
    New-IRTool 'TOOL-RMM' medium 'T1219' 'Remote access software' 'anydesk|teamviewer|screenconnect|connectwise|atera(agent)?|splashtop|rustdesk|meshagent|remoteutilities|rutserv|rfusclient|netsupport|client32\.exe|ammyy|aa_v3|supremo|tacticalrmm|simplehelp|zohoassist|dwagent|getscreen|ultraviewer|radmin|tightvnc|ultravnc|realvnc|winvnc|tvnserver|remotepc|bomgar|ninjarmm|pulseway'
    New-IRTool 'TOOL-ADMIN' low 'T1057' 'System administration tool commonly abused by attackers' 'processhacker|systeminformer|kprocesshacker|psloggedon|pskill|pssuspend'
)

$Script:VulnDriverRx = New-Object Text.RegularExpressions.Regex('(?<![a-z])(rtcore(32|64)|dbutil_2_3|gdrv|aswarpot|kprocesshacker|procexp152|mhyprot2?|zamguard64|zam64|iqvw64e?|asrdrv10[1-6]?|atillk64|winring0(x64)?|gmer64|truesight|kevp64|nalfpt|wnbios|elrawdsk|amifldrv64|rentdrv2|hwrwdrv|physmem|asio(32|64)|glckio2|piddrv64|ntiolib(_x64)?|viragt64|ene)\.sys$', $Script:RxOpt)

# Folders legitimate software rarely executes from; attackers stage tools here.
$Script:SuspDirRx = New-Object Text.RegularExpressions.Regex('\\(users\\public\\(?!desktop\\)|perflogs\\|\$recycle\.bin\\|windows\\(tasks|debug|fonts|help|repair|addins|tracing|registration\\crmlog)\\|system32\\(tasks|spool\\drivers\\color|com)\\|programdata\\[^\\]+$|intel\\|windows\\temp\\[^\\]+$|appdata\\local\\temp\\[^\\]+$|appdata\\roaming\\[^\\]+$|users\\[^\\]+\\(music|videos|pictures|contacts|favorites|links|saved games|searches)\\)', $Script:RxOpt)
$Script:UserWritableRx = New-Object Text.RegularExpressions.Regex('\\(users|programdata|windows\\temp|perflogs|\$recycle\.bin)\\', $Script:RxOpt)
$Script:TrustedDirRx = New-Object Text.RegularExpressions.Regex('^([a-z]:|\\device\\harddiskvolume\d+)\\(windows\\(system32|syswow64|winsxs|servicing|systemapps|immersivecontrolpanel|microsoft\.net)\\|program files( \(x86\))?\\|programdata\\microsoft\\windows defender\\)', $Script:RxOpt)
$Script:InterpRx = New-Object Text.RegularExpressions.Regex('(^|[\\\s"''])(cmd|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|msbuild|installutil|certutil|bitsadmin|curl|wmic|forfiles)(\.exe)?["'']?(\s|$)', $Script:RxOpt)
$Script:RansomRx = ($Script:CmdRules | Where-Object { $_.id -eq 'RANSOM-NOTE' }).rx
$Script:EncRx = New-Object Text.RegularExpressions.Regex('\s[-/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?\s+["'']?([a-z0-9+/=]{20,})', $Script:RxOpt)

$Script:Shells = @{}; foreach ($n in 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'msbuild.exe', 'schtasks.exe', 'wmic.exe', 'bash.exe', 'curl.exe', 'whoami.exe', 'net.exe', 'net1.exe', 'msiexec.exe', 'installutil.exe', 'hh.exe') { $Script:Shells[$n] = 1 }
$Script:OfficeApps = @{}; foreach ($n in 'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'onenote.exe', 'msaccess.exe', 'mspub.exe', 'visio.exe', 'eqnedt32.exe', 'wordpad.exe', 'acrord32.exe', 'acrobat.exe', 'foxitpdfreader.exe') { $Script:OfficeApps[$n] = 1 }
$Script:WebServers = @{}; foreach ($n in 'w3wp.exe', 'httpd.exe', 'nginx.exe', 'tomcat.exe', 'tomcat8.exe', 'tomcat9.exe', 'php-cgi.exe', 'php.exe', 'sqlservr.exe', 'umworkerprocess.exe', 'umservice.exe', 'jboss.exe', 'weblogic.exe') { $Script:WebServers[$n] = 1 }
$Script:UacBins = @{}; foreach ($n in 'fodhelper.exe', 'computerdefaults.exe', 'sdclt.exe', 'eventvwr.exe', 'slui.exe', 'wsreset.exe', 'changepk.exe') { $Script:UacBins[$n] = 1 }
$Script:LolNetHigh = @{}; foreach ($n in 'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe', 'msbuild.exe', 'installutil.exe', 'regasm.exe', 'regsvcs.exe', 'notepad.exe', 'calc.exe', 'cmstp.exe', 'hh.exe', 'odbcconf.exe', 'mavinject.exe', 'werfault.exe', 'dllhost.exe', 'searchprotocolhost.exe') { $Script:LolNetHigh[$n] = 1 }
$Script:LolNetMed = @{}; foreach ($n in 'powershell.exe', 'pwsh.exe', 'cmd.exe', 'bitsadmin.exe', 'certutil.exe', 'curl.exe', 'wmic.exe', 'msiexec.exe') { $Script:LolNetMed[$n] = 1 }
$Script:SystemNames = @{}; foreach ($n in 'svchost.exe', 'lsass.exe', 'services.exe', 'csrss.exe', 'smss.exe', 'wininit.exe', 'winlogon.exe', 'spoolsv.exe', 'taskhostw.exe', 'lsaiso.exe', 'dllhost.exe', 'conhost.exe', 'rundll32.exe', 'regsvr32.exe', 'cmd.exe', 'powershell.exe', 'searchindexer.exe', 'sihost.exe', 'ctfmon.exe', 'dwm.exe', 'wmiprvse.exe', 'taskmgr.exe', 'mshta.exe', 'certutil.exe', 'explorer.exe', 'userinit.exe', 'wuauclt.exe') { $Script:SystemNames[$n] = 1 }
$Script:TyposquatRx = New-Object Text.RegularExpressions.Regex('^(svch0st|svhost|scvhost|svchosts|svchost32|svcchost|lsas|lsasss|lssas|isass|lsasvc|csrsss|csrs|smsss|winlogin|winiti|wininit32|explorer32|expl0rer|explore|iexplorer|taskhost32|spoolsvc|rundl32|rundll64|serviceshost|svchostt|scvh0st|mmsc)\.exe$', $Script:RxOpt)
$Script:SusPorts = @{}; foreach ($n in 4444, 4445, 5555, 1337, 31337, 6666, 6667, 6697, 9001, 9030, 9050, 9051, 1080, 8888, 7777, 12345, 2222, 4443, 8081, 50050) { $Script:SusPorts[$n] = 1 }
$Script:PrivGroupRx = New-Object Text.RegularExpressions.Regex('^(administrators|administratoren|administrateurs|administradores|domain admins|enterprise admins|schema admins|account operators|server operators|backup operators|print operators|remote desktop users|remote management users|dnsadmins|group policy creator owners|hyper-v administrators|enterprise key admins|key admins|event log readers|distributed com users)$', $Script:RxOpt)
$Script:SecSvcRx = New-Object Text.RegularExpressions.Regex('(windefend|wdnissvc|sense|mpssvc|eventlog|sysmon|wscsvc|securityhealthservice|windows defender|microsoft defender|windows firewall|windows event log|security center)', $Script:RxOpt)
$Script:BenignInjectRx = New-Object Text.RegularExpressions.Regex('\\windows\\(system32|syswow64)\\(csrss|wininit|services|svchost|lsass|smss|dwm|wbem\\wmiprvse|conhost|winlogon|audiodg|taskmgr|lsaiso|searchindexer|mrt|wermgr|werfault|vmcompute|vmwp)\.exe$|\\(msmpeng|nissrv|mssense|sensecncproxy|mpdefendercoreservice|vmtoolsd|vboxservice|vboxtray|procexp64|procexp)\.exe$|\\program files( \(x86\))?\\(windows defender|microsoft security client|vmware|oracle\\virtualbox|microsoft office)\\', $Script:RxOpt)

$Script:DomainRules = @(
    @('DNS-FILESHARE', 'medium', 'T1567.002', 'File-sharing / paste service contacted', '(^|\.)(transfer\.sh|file\.io|gofile\.io|anonfiles\.com|temp\.sh|bashupload\.com|filebin\.net|pastebin\.com|paste\.ee|hastebin\.com|rentry\.co|mega\.(nz|io|co\.nz)|ufile\.io|sendspace\.com|wetransfer\.com|catbox\.moe|0x0\.st)$'),
    @('DNS-TUNNEL', 'high', 'T1572', 'Tunneling / reverse-proxy service contacted', '(^|\.)(ngrok(-free)?\.(io|app|dev)|ngrok\.com|trycloudflare\.com|serveo\.net|localhost\.run|loca\.lt|localtunnel\.me|portmap\.(io|host)|playit\.gg|pinggy\.io|bore\.pub|tunnelto\.dev)$'),
    @('DNS-DYNDNS', 'medium', 'T1071.001', 'Dynamic DNS / out-of-band interaction domain contacted', '(^|\.)(duckdns\.org|no-ip\.(com|org|biz)|ddns\.net|hopto\.org|zapto\.org|sytes\.net|dynu\.(com|net)|freedns\.afraid\.org|webhook\.site|requestbin\.(com|net)|pipedream\.net|interact\.sh|oast\.(fun|me|pro|live|site|online)|burpcollaborator\.net|canarytokens\.com)$'),
    @('DNS-C2-SERVICE', 'medium', 'T1102', 'Web service commonly abused for C2 / exfiltration contacted', '(^|\.)(api\.telegram\.org|discord(app)?\.com|cdn\.discordapp\.com|raw\.githubusercontent\.com|gist\.githubusercontent\.com)$'),
    @('DNS-MINING', 'high', 'T1496', 'Cryptocurrency mining pool contacted', '(^|\.)(supportxmr\.com|moneroocean\.stream|nanopool\.org|2miners\.com|minexmr\.com|hashvault\.pro|c3pool\.(com|org)|xmrpool\.eu|f2pool\.com|herominers\.com|unmineable\.com|nicehash\.com|ethermine\.org|minergate\.com|xmrig\.com|kryptex\.network)$'),
    @('DNS-IPCHECK', 'low', 'T1016', 'External IP lookup service contacted', '(^|\.)(ipify\.org|ifconfig\.(me|co)|icanhazip\.com|ipinfo\.io|checkip\.amazonaws\.com|myexternalip\.com|ip-api\.com|wtfismyip\.com|ipecho\.net)$')
) | ForEach-Object { [pscustomobject]@{ id = $_[0]; sev = $_[1]; tech = $_[2]; title = $_[3]; rx = New-Object Text.RegularExpressions.Regex($_[4], $Script:RxOpt) } }
$Script:TrustedUrlRx = New-Object Text.RegularExpressions.Regex('^https?://([^/]+\.)?(microsoft\.com|windowsupdate\.com|windows\.com|msedge\.net|office\.com|office\.net|live\.com|bing\.com|msn\.com|azureedge\.net|akamaized\.net|gvt1\.com|google\.com|googleapis\.com|mozilla\.(org|net)|adobe\.com|dell\.com|hp\.com|lenovo\.com|nvidia\.com|intel\.com|apple\.com|xboxlive\.com|skype\.com|onedrive\.com|sharepoint\.com|azure\.com|windows\.net|digicert\.com|sectigo\.com|visualstudio\.com|sfx\.ms|delivery\.mp\.microsoft\.com)(:\d+)?/', $Script:RxOpt)

# Registry value writes (Sysmon 13) worth flagging: pattern on "<key>\<value> = <data>".
$Script:RegRules = @(
    @('REGSET-IFEO', 'high', 'T1546.012', 'Image File Execution Options debugger / SilentProcessExit set', '\\image file execution options\\[^\\]+\\debugger\s=|\\silentprocessexit\\[^\\]+\\monitorprocess\s='),
    @('REGSET-WINLOGON', 'high', 'T1547.004', 'Winlogon Shell / Userinit / Notify modified', '\\winlogon\\(shell|userinit|taskman|notify\\[^\\]+\\dllname)\s='),
    @('REGSET-WDIGEST', 'high', 'T1112', 'WDigest UseLogonCredential enabled', '\\wdigest\\uselogoncredential\s=\s*dword\s*\(0x00000001\)'),
    @('REGSET-DEFENDER', 'high', 'T1562.001', 'Microsoft Defender disabled or excluded in the registry', '\\windows defender\\(exclusions\\|disableantispyware\s=\s*dword\s*\(0x00000001\)|real-time protection\\disable\w+\s=\s*dword\s*\(0x00000001\))'),
    @('REGSET-UAC-HIJACK', 'high', 'T1548.002', 'UAC bypass handler registered', '\\(ms-settings|mscfile|exefile|launcher\.systemsettings|folder)\\shell\\open\\command\\(\(default\)|delegateexecute)\s='),
    @('REGSET-LSA', 'high', 'T1547.005', 'LSA authentication / security package list modified', '\\control\\lsa\\(osconfig\\)?(authentication packages|security packages|notification packages)\s='),
    @('REGSET-APPINIT', 'high', 'T1546.010', 'AppInit_DLLs modified', '\\windows nt\\currentversion\\windows\\appinit_dlls\s=\s*\S'),
    @('REGSET-NETSH', 'high', 'T1546.007', 'Netsh helper DLL registered', '\\software\\(wow6432node\\)?microsoft\\netsh\\[^\\]+\s='),
    @('REGSET-PRINTMON', 'high', 'T1547.010', 'Print monitor registered', '\\control\\print\\monitors\\[^\\]+\\driver\s='),
    @('REGSET-RDP', 'medium', 'T1021.001', 'Remote Desktop enabled in the registry', '\\terminal server\\fdenytsconnections\s=\s*dword\s*\(0x00000000\)'),
    @('REGSET-WEAKEN', 'medium', 'T1112', 'Security-relevant registry setting weakened', '\\policies\\system\\(localaccounttokenfilterpolicy\s=\s*dword\s*\(0x00000001\)|enablelua\s=\s*dword\s*\(0x00000000\))|\\control\\lsa\\(runasppl|disablerestrictedadmin)\s=\s*dword\s*\(0x00000000\)'),
    @('REGSET-LOGON-SCRIPT', 'high', 'T1547.001', 'Logon script / COR profiler environment hijack', '\\environment\\(userinitmprlogonscript|cor_profiler_path|cor_profiler)\s='),
    @('REGSET-RUNKEY', 'medium', 'T1547.001', 'Run key value written', '\\currentversion\\(run|runonce|runservices|policies\\explorer\\run)\\[^\\]+\s=')
) | ForEach-Object { [pscustomobject]@{ id = $_[0]; sev = $_[1]; tech = $_[2]; title = $_[3]; rx = New-Object Text.RegularExpressions.Regex($_[4], $Script:RxOpt) } }

$Script:LogonTypes = @{ 0 = 'System'; 2 = 'Interactive'; 3 = 'Network'; 4 = 'Batch'; 5 = 'Service'; 7 = 'Unlock'; 8 = 'NetworkCleartext'; 9 = 'NewCredentials'; 10 = 'RemoteInteractive (RDP)'; 11 = 'CachedInteractive'; 12 = 'CachedRemoteInteractive'; 13 = 'CachedUnlock' }
$Script:LogonStatus = @{
    '0xc000006a' = 'wrong password'; '0xc0000064' = 'unknown user name'; '0xc0000234' = 'account locked out'; '0xc0000072' = 'account disabled'
    '0xc000006f' = 'outside allowed hours'; '0xc0000070' = 'workstation restriction'; '0xc0000071' = 'password expired'; '0xc0000193' = 'account expired'
    '0xc0000133' = 'clock skew'; '0xc0000224' = 'password must change'; '0xc000015b' = 'logon type not granted'; '0xc000006d' = 'bad user name or password'
    '0xc000005e' = 'no logon servers'; '0xc0000413' = 'authentication firewall'; '0x18' = 'Kerberos: wrong password'; '0x6' = 'Kerberos: unknown user'; '0x12' = 'Kerberos: account disabled/locked'
}

#endregion

#region ===== Analysis: findings, timeline and per-item detection =====

function Test-IRRealUser([string]$U) {
    if (-not $U) { return $false }
    $n = ($U -split '\\')[-1].Trim().ToLowerInvariant()
    if (-not $n -or $n -eq '-' -or $n.EndsWith('$')) { return $false }
    if ($n -in @('system', 'local service', 'network service', 'localservice', 'networkservice', 'anonymous logon', 'anonymous', 'window manager', 'font driver host', 'iusr', 'defaultaccount', 'wdagutilityaccount')) { return $false }
    return $n -notmatch '^(dwm|umfd)-\d+$'
}

function Test-IRRealIp([string]$Ip) {
    if (-not $Ip -or $Ip -in @('-', '::1', '127.0.0.1', '0.0.0.0', '::', 'LOCAL', 'localhost')) { return $false }
    return $Ip -notmatch '^(127\.|::ffff:127\.|fe80:)'
}

function Get-IRLeaf([string]$Path) {
    if (-not $Path) { return '' }
    return (($Path.Trim().Trim('"') -split '[\\/]')[-1]).ToLowerInvariant()
}

function Add-IRUnique($List, $Value, [int]$Max = 25) {
    if ($null -eq $Value -or '' -eq $Value) { return }
    $v = [string]$Value
    if ($List.Count -lt $Max -and -not $List.Contains($v)) { $List.Add($v) }
}

function Start-IRItem {
    if ($null -eq $Script:Hits) { $Script:Hits = [System.Collections.Generic.List[string]]::new() } else { $Script:Hits.Clear() }
}

# One finding per rule + key; repeated observations raise the hit count and widen first/last seen.
function Add-IRFinding {
    param(
        [Parameter(Mandatory)][string]$Rule, [Parameter(Mandatory)][string]$Title, [string]$Severity = 'medium', [string]$Technique,
        $Time, [string]$Source, [string]$Description, [string]$Evidence, [string]$Key = '',
        [string[]]$User, [string[]]$Ip, [string[]]$Process, [string[]]$File, [string[]]$Hash, [string[]]$Domain
    )
    $k = "$Rule|$($Key.ToLowerInvariant())"
    $f = $Script:Findings[$k]
    if (-not $f) {
        $n = 0
        if ($Script:RuleCounts.ContainsKey($Rule)) { $n = $Script:RuleCounts[$Rule] }
        if ($n -ge 40) {
            $k = "$Rule|__more__"; $f = $Script:Findings[$k]
            $Title = "$Title (further occurrences grouped)"
        } else { $Script:RuleCounts[$Rule] = $n + 1 }
    }
    if (-not $f) {
        $m = $null
        if ($Technique) { $m = $Script:Mitre[$Technique] }
        $f = [ordered]@{
            id = $null; key = $k; rule = $Rule; title = $Title; severity = $Severity; technique = $Technique
            technique_name = $(if ($m) { $m.name } else { $null }); tactic = $(if ($m) { $m.tactic } else { $null })
            first_seen = $null; last_seen = $null; hits = 0; description = $Description
            sources = [System.Collections.Generic.List[string]]::new(); evidence = [System.Collections.Generic.List[string]]::new()
            users = [System.Collections.Generic.List[string]]::new(); ips = [System.Collections.Generic.List[string]]::new()
            processes = [System.Collections.Generic.List[string]]::new(); files = [System.Collections.Generic.List[string]]::new()
            hashes = [System.Collections.Generic.List[string]]::new(); domains = [System.Collections.Generic.List[string]]::new()
            recommendation = (Get-IRAdvice $Technique); incident = $null
        }
        $Script:Findings[$k] = $f
    }
    $f.hits = $f.hits + 1
    if ($Script:SevRank[$Severity] -gt $Script:SevRank[$f.severity]) { $f.severity = $Severity }
    $iso = Get-IRIso $Time
    if ($iso) {
        if (-not $f.first_seen -or [string]::CompareOrdinal($iso, $f.first_seen) -lt 0) { $f.first_seen = $iso }
        if (-not $f.last_seen -or [string]::CompareOrdinal($iso, $f.last_seen) -gt 0) { $f.last_seen = $iso }
    }
    Add-IRUnique $f.sources $Source 10
    if ($Evidence) { Add-IRUnique $f.evidence (Limit-IRText $Evidence 700) 8 }
    foreach ($x in $User) { if (Test-IRRealUser $x) { Add-IRUnique $f.users $x } }
    foreach ($x in $Ip) { if (Test-IRRealIp $x) { Add-IRUnique $f.ips $x } }
    foreach ($x in $Process) { Add-IRUnique $f.processes $x }
    foreach ($x in $File) { Add-IRUnique $f.files $x }
    foreach ($x in $Hash) { Add-IRUnique $f.hashes $x }
    foreach ($x in $Domain) { Add-IRUnique $f.domains $x }
    if ($null -ne $Script:Hits -and -not $Script:Hits.Contains($k)) { $Script:Hits.Add($k) }
}

# Timeline entries are kept when they are inherently interesting (-Keep) or when a rule fired on
# the item currently being processed (Start-IRItem ... Add-IRFinding ... Add-IRTimeline).
function Add-IRTimeline {
    param($Time, [string]$Source, [string]$Event, [string]$Category, [string]$Summary, [string]$User, [switch]$Keep)
    $flagged = ($null -ne $Script:Hits -and $Script:Hits.Count -gt 0)
    if (-not $Keep -and -not $flagged -and -not $Script:InEventPass) { return }
    $iso = Get-IRIso $Time
    if (-not $iso) { return }
    if (-not $flagged -and [string]::CompareOrdinal($iso, $Script:SinceIso) -lt 0) { return }
    $Script:Timeline.Add(@{
            t = $iso; src = $Source; ev = $Event; cat = $Category; sum = (Limit-IRText $Summary 450); u = $User
            fk = $(if ($flagged) { $Script:Hits.ToArray() } else { $null })
        })
}

function Get-IRPathRisk([string]$Path) {
    if (-not $Path) { return $false }
    return $Script:SuspDirRx.IsMatch($Path.Trim('"'))
}

function ConvertFrom-IRBase64([string]$Value) {
    $s = $Value.Trim('"', "'")
    $pad = $s.Length % 4
    if ($pad -eq 1) { $s = $s.Substring(0, $s.Length - 1) } elseif ($pad) { $s += '=' * (4 - $pad) }
    try { $b = [Convert]::FromBase64String($s) } catch { return $null }
    $t = [Text.Encoding]::Unicode.GetString($b)
    if (($t -replace '[\x20-\x7e\r\n\t]', '').Length -gt ($t.Length / 4)) { $t = [Text.Encoding]::UTF8.GetString($b) }
    return $t
}

$Script:TextIpRx = New-Object Text.RegularExpressions.Regex('(?<![\d\.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d\.])')
$Script:TextHostRx = New-Object Text.RegularExpressions.Regex('(?i)\b(?:https?|ftp)://([a-z0-9][a-z0-9\.\-]*[a-z0-9])')
$Script:TextPathRx = New-Object Text.RegularExpressions.Regex('(?i)(?<![\w\\])[a-z]:\\[^\s"''|<>,;]*?\.(?:exe|dll|sys|ps1|psm1|bat|cmd|vbs|js|jse|hta|scr|msi|lnk|zip|7z|rar|iso)\b')

function Test-IRText {
    param([string]$Text, [string]$Scope = 'proc', $Time, [string]$Source, [string]$User, [string]$Process, [int]$Depth = 0)
    if (-not $Text) { return }
    if ($Text.Length -gt 60000) { $Text = $Text.Substring(0, 60000) }
    foreach ($r in $Script:CmdRules) {
        if ($r.scope -eq 'proc' -and $Scope -ne 'proc') { continue }
        $m = $r.rx.Match($Text)
        if (-not $m.Success) { continue }
        $start = [Math]::Max(0, $m.Index - 150)
        $len = [Math]::Min($Text.Length - $start, 450)
        $snip = $Text.Substring($start, $len)
        if ($start -gt 0) { $snip = '...' + $snip }
        if ($start + $len -lt $Text.Length) { $snip += '...' }
        $key = if ($Text.Length -le 1500) { Limit-IRText $Text 300 } else { $m.Value }
        $scope = if ($Text.Length -le 1500) { $Text } else { $snip }
        $ips = @($Script:TextIpRx.Matches($scope) | ForEach-Object { $_.Value } | Select-Object -Unique -First 5)
        $files = @($Script:TextPathRx.Matches($scope) | ForEach-Object { $_.Value } | Select-Object -Unique -First 5)
        $doms = @($Script:TextHostRx.Matches($scope) | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() } | Where-Object { $_ -notmatch '^[\d\.]+$' } | Select-Object -Unique -First 5)
        Add-IRFinding -Rule $r.id -Title $r.title -Severity $r.sev -Technique $r.tech -Time $Time -Source $Source `
            -Evidence "[$Source] $snip" -Key $key -User $User -Process $Process -Ip $ips -File $files -Domain $doms
        if ($r.id -eq 'PS-ENCODED' -and $Depth -eq 0) {
            $em = $Script:EncRx.Match($Text)
            if ($em.Success) {
                $dec = ConvertFrom-IRBase64 $em.Groups[2].Value
                if ($dec) {
                    $fk = "PS-ENCODED|$($key.ToLowerInvariant())"
                    if ($Script:Findings.Contains($fk)) { Add-IRUnique $Script:Findings[$fk].evidence ('Decoded: ' + (Limit-IRText $dec 600)) 8 }
                    Test-IRText -Text $dec -Scope 'any' -Time $Time -Source "$Source (decoded -EncodedCommand)" -User $User -Process $Process -Depth 1
                }
            }
        }
    }
}

function Test-IRTool([string]$Name, [string]$Path, $Time, [string]$Source, [string]$User, [string]$Hash) {
    if (-not $Name) { $Name = Get-IRLeaf $Path }
    if (-not $Name) { return }
    foreach ($r in $Script:ToolRules) {
        $m = $r.rx.Match($Name)
        if (-not $m.Success) { continue }
        $tool = $m.Value.ToLowerInvariant() -replace '\.(exe|dll|bin)$', ''
        Add-IRFinding -Rule $r.id -Title "$($r.title): $tool" -Severity $r.sev -Technique $r.tech -Time $Time -Source $Source `
            -Evidence "[$Source] $(if ($Path) { $Path } else { $Name })" -Key $tool -User $User -File $Path -Hash $Hash
        return
    }
}

# Same file seen as C:\x, \Device\HarddiskVolume3\x or "C:\x" must produce the same key.
function Get-IRPathKey([string]$Path) {
    if (-not $Path) { return '' }
    return ($Path.Trim().Trim('"') -replace '^([a-z]:|\\device\\harddiskvolume\d+|\\\\\?\\[a-z]:)\\', '').ToLowerInvariant()
}

function Test-IRDomain([string]$Domain, $Time, [string]$Source, [string]$Process, [string]$User) {
    if (-not $Domain) { return }
    $d = $Domain.Trim().TrimEnd('.').ToLowerInvariant()
    foreach ($r in $Script:DomainRules) {
        if (-not $r.rx.IsMatch($d)) { continue }
        Add-IRFinding -Rule $r.id -Title "$($r.title): $d" -Severity $r.sev -Technique $r.tech -Time $Time -Source $Source `
            -Evidence "[$Source] $d$(if ($Process) { " by $Process" })" -Key $d -Domain $d -Process $Process -User $User
        return
    }
}

function Get-IRUrlHost([string]$Url) {
    if ($Url -match '^[a-z][a-z0-9+.-]*://([^/:?#]+)') { return $Matches[1].ToLowerInvariant() }
    return $null
}

# Process creation from any source: 4688, Sysmon 1, live process list, PowerShell 400 host line.
function Invoke-IRProcessRules {
    param($Time, [string]$Source, [string]$Image, [string]$Cmd, [string]$Parent, [string]$User, [string]$Hash, [switch]$Timed)
    $name = Get-IRLeaf $Image
    $pname = Get-IRLeaf $Parent
    $text = if ($Cmd) { $Cmd } else { $Image }
    if ($text -and $text.IndexOf('IR-Investigator', [StringComparison]::OrdinalIgnoreCase) -ge 0) { return }
    Test-IRText -Text $text -Scope 'proc' -Time $Time -Source $Source -User $User -Process $Image
    if ($Timed -and $Cmd -and $Time -is [DateTime]) {
        foreach ($r in $Script:DiscoveryRules) {
            if ($r.rx.IsMatch($Cmd)) { $Script:DiscHits.Add(@{ t = $Time; u = $(if ($User) { $User } else { 'unknown' }); tech = $r.tech; cmd = (Limit-IRText $Cmd 200) }); break }
        }
    }
    $chain = "$pname -> $name"
    $ev = "[$Source] $chain : $(Limit-IRText $text 400)"
    if ($pname -and $name) {
        if ($Script:OfficeApps.ContainsKey($pname) -and $Script:Shells.ContainsKey($name)) {
            Add-IRFinding -Rule 'CHILD-OFFICE' -Title "Office / document reader spawned $name" -Severity high -Technique 'T1204.002' -Time $Time -Source $Source -Evidence $ev -Key $chain -User $User -Process $Image
        } elseif ($Script:WebServers.ContainsKey($pname) -and $Script:Shells.ContainsKey($name)) {
            Add-IRFinding -Rule 'CHILD-WEBSERVER' -Title "Web / database server process spawned $name (possible web shell)" -Severity critical -Technique 'T1505.003' -Time $Time -Source $Source -Evidence $ev -Key $chain -User $User -Process $Image
        } elseif ($pname -eq 'wmiprvse.exe' -and $name -in @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'wscript.exe', 'cscript.exe')) {
            Add-IRFinding -Rule 'CHILD-WMI' -Title "WMI provider host spawned $name (WMI execution)" -Severity medium -Technique 'T1047' -Time $Time -Source $Source -Evidence $ev -Key $(Limit-IRText $text 300) -User $User -Process $Image
        } elseif ($pname -eq 'wsmprovhost.exe' -and $Script:Shells.ContainsKey($name)) {
            Add-IRFinding -Rule 'CHILD-WINRM' -Title "PowerShell remoting host spawned $name" -Severity medium -Technique 'T1021.006' -Time $Time -Source $Source -Evidence $ev -Key $(Limit-IRText $text 300) -User $User -Process $Image
        } elseif ($pname -eq 'services.exe' -and $name -in @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'mshta.exe', 'rundll32.exe')) {
            Add-IRFinding -Rule 'CHILD-SERVICES' -Title "Service Control Manager started $name directly (service-based execution)" -Severity medium -Technique 'T1569.002' -Time $Time -Source $Source -Evidence $ev -Key $(Limit-IRText $text 300) -User $User -Process $Image
        } elseif ($pname -in @('mshta.exe', 'wscript.exe', 'cscript.exe') -and $name -in @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe', 'msiexec.exe')) {
            Add-IRFinding -Rule 'CHILD-SCRIPTHOST' -Title "Script host $pname spawned $name" -Severity high -Technique 'T1059.005' -Time $Time -Source $Source -Evidence $ev -Key $chain -User $User -Process $Image
        } elseif ($Script:UacBins.ContainsKey($pname) -and $name -notin @('mmc.exe', 'control.exe', 'systemsettings.exe', 'werfault.exe', 'consent.exe', 'conhost.exe')) {
            Add-IRFinding -Rule 'CHILD-UACBYPASS' -Title "Auto-elevating binary $pname spawned $name (UAC bypass)" -Severity high -Technique 'T1548.002' -Time $Time -Source $Source -Evidence $ev -Key $chain -User $User -Process $Image
        } elseif ($pname -eq 'spoolsv.exe' -and $name -in @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'rundll32.exe')) {
            Add-IRFinding -Rule 'CHILD-SPOOLER' -Title "Print spooler spawned $name (possible PrintNightmare)" -Severity high -Technique 'T1068' -Time $Time -Source $Source -Evidence $ev -Key $chain -User $User -Process $Image
        } elseif ($pname -eq 'lsass.exe' -and $name -notin @('werfault.exe', 'lsaiso.exe', 'efsui.exe')) {
            Add-IRFinding -Rule 'CHILD-LSASS' -Title "LSASS spawned $name" -Severity high -Technique 'T1003.001' -Time $Time -Source $Source -Evidence $ev -Key $chain -User $User -Process $Image
        }
    }
    if ($Image -and $Image -match '^([a-z]:|\\device\\)') {
        if ($Script:SystemNames.ContainsKey($name) -and -not $Script:TrustedDirRx.IsMatch($Image) -and -not ($name -eq 'explorer.exe' -and $Image -match '^[a-z]:\\windows\\explorer\.exe$')) {
            Add-IRFinding -Rule 'MASQUERADE' -Title "Windows binary name running from the wrong folder: $name" -Severity high -Technique 'T1036.005' -Time $Time -Source $Source -Evidence "[$Source] $Image" -Key $Image -User $User -Process $Image -File $Image -Hash $Hash
        }
        if (Get-IRPathRisk $Image) {
            Add-IRFinding -Rule 'EXEC-SUSP-DIR' -Title "Program executed from a staging / unusual folder: $name" -Severity medium -Technique 'T1204.002' -Time $Time -Source $Source -Evidence "[$Source] $(Limit-IRText $text 400)" -Key (Get-IRPathKey $Image) -User $User -Process $Image -File $Image -Hash $Hash
        }
    }
    if ($Script:TyposquatRx.IsMatch($name)) {
        Add-IRFinding -Rule 'TYPOSQUAT' -Title "Process name imitates a Windows binary: $name" -Severity high -Technique 'T1036.005' -Time $Time -Source $Source -Evidence "[$Source] $Image" -Key $name -User $User -Process $Image -File $Image -Hash $Hash
    }
    Test-IRTool -Name $name -Path $Image -Time $Time -Source $Source -User $User -Hash $Hash
}

function Test-IRConnection {
    param($Time, [string]$Source, [string]$Image, [string]$RemoteIp, $RemotePort, $LocalPort, [string]$HostName, [string]$User, [switch]$Inbound, [switch]$Listen)
    $name = Get-IRLeaf $Image
    $public = Test-IRPublicIp $RemoteIp
    $ev = "[$Source] $name $(if ($Inbound) { '<-' } else { '->' }) $RemoteIp`:$RemotePort$(if ($HostName) { " ($HostName)" }) local port $LocalPort"
    if ($Listen) {
        if (Get-IRPathRisk $Image) {
            Add-IRFinding -Rule 'LISTEN-SUSP-DIR' -Title "Program in a staging folder is listening on port $LocalPort" -Severity high -Technique 'T1571' -Time $Time -Source $Source -Evidence $ev -Key "$Image|$LocalPort" -Process $Image -File $Image
        }
        return
    }
    if ($Inbound) {
        $svc = switch ([int]$LocalPort) { 3389 { 'RDP' } 445 { 'SMB' } 5985 { 'WinRM' } 5986 { 'WinRM' } 22 { 'SSH' } default { $null } }
        if ($null -eq $svc -and $Script:RdpPort -and [int]$LocalPort -eq $Script:RdpPort) { $svc = 'RDP' }
        if ($svc -and $public) {
            Add-IRFinding -Rule 'INBOUND-PUBLIC' -Title "Inbound $svc connection from a public IP address" -Severity high -Technique 'T1133' -Time $Time -Source $Source -Evidence $ev -Key "$svc|$RemoteIp" -Ip $RemoteIp -User $User
        }
        return
    }
    if (-not $public) { return }
    if ($Script:LolNetHigh.ContainsKey($name)) {
        Add-IRFinding -Rule 'LOLBIN-NET' -Title "$name connected to the Internet" -Severity high -Technique 'T1071.001' -Time $Time -Source $Source -Evidence $ev -Key "$name|$RemoteIp" -Ip $RemoteIp -Process $Image -Domain $HostName -User $User
    } elseif ($Script:LolNetMed.ContainsKey($name)) {
        Add-IRFinding -Rule 'SHELL-NET' -Title "$name connected to the Internet" -Severity medium -Technique 'T1071.001' -Time $Time -Source $Source -Evidence $ev -Key "$name|$RemoteIp" -Ip $RemoteIp -Process $Image -Domain $HostName -User $User
    } elseif (Get-IRPathRisk $Image) {
        Add-IRFinding -Rule 'SUSPDIR-NET' -Title "Program in a staging folder connected to the Internet: $name" -Severity high -Technique 'T1071.001' -Time $Time -Source $Source -Evidence $ev -Key "$Image|$RemoteIp" -Ip $RemoteIp -Process $Image -File $Image -Domain $HostName -User $User
    }
    if ($null -ne $RemotePort -and '' -ne $RemotePort -and $Script:SusPorts.ContainsKey([int]$RemotePort)) {
        Add-IRFinding -Rule 'SUSP-PORT' -Title "Outbound connection to a port typical of C2 / backdoors ($RemotePort)" -Severity medium -Technique 'T1571' -Time $Time -Source $Source -Evidence $ev -Key "$RemoteIp|$RemotePort" -Ip $RemoteIp -Process $Image -User $User
    }
    if ($HostName) { Test-IRDomain $HostName $Time $Source $Image $User }
}

function Test-IRServiceInstall($Time, [string]$Source, [string]$Name, [string]$Command, [string]$Account, [string]$Type, [string]$User) {
    $img = Resolve-IRImagePath $Command
    $sev = 'medium'; $tech = 'T1543.003'
    if ($img -and $Script:TrustedDirRx.IsMatch($img) -and -not $Script:InterpRx.IsMatch([string]$Command)) { $sev = 'low' }
    if ($Command -match '(?i)(%comspec%|cmd(\.exe)?["'']?\s+/[ckr]|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|\\\\127\.0\.0\.1\\|\\\\localhost\\|admin\$|-enc|frombase64)' -or (Get-IRPathRisk $img)) { $sev = 'high' }
    if ($Command -match '(?i)\\\\[^\\]+\\admin\$|%comspec%|psexesvc|remcom|paexec|csexec') { $tech = 'T1569.002'; $sev = 'high' }
    $title = if ($Type -match 'kernel|file system') { "Kernel driver service installed: $Name" } else { "Service installed: $Name" }
    Add-IRFinding -Rule 'SERVICE-INSTALLED' -Title $title -Severity $sev -Technique $tech -Time $Time -Source $Source `
        -Evidence "[$Source] $Name : $Command (account: $Account)" -Key (("$Name|$img") -replace '\d+(\.\d+){1,3}', '*') -User $User -File $img
    Test-IRText -Text $Command -Scope 'proc' -Time $Time -Source $Source -User $User
    Test-IRTool -Name (Get-IRLeaf $img) -Path $img -Time $Time -Source $Source -User $User
    Test-IRTool -Name $Name -Path $img -Time $Time -Source $Source -User $User
    if ($img -and $Script:VulnDriverRx.IsMatch((Get-IRLeaf $img))) {
        Add-IRFinding -Rule 'BYOVD' -Title "Known vulnerable driver installed: $(Get-IRLeaf $img)" -Severity high -Technique 'T1068' -Time $Time -Source $Source -Evidence "[$Source] $img" -Key (Get-IRLeaf $img) -File $img
    }
}

function Get-IRTaskCommand([string]$Xml) {
    if (-not $Xml) { return '' }
    $c = foreach ($m in [regex]::Matches($Xml, '<Command>(.*?)</Command>(\s*<Arguments>(.*?)</Arguments>)?', 'Singleline')) {
        ([Net.WebUtility]::HtmlDecode($m.Groups[1].Value) + ' ' + [Net.WebUtility]::HtmlDecode($m.Groups[3].Value)).Trim()
    }
    return (@($c) -join ' | ')
}

function Test-IRTaskDefinition($Time, [string]$Source, [string]$Name, [string]$Command, [string]$User, [bool]$Hidden, [string]$Rule = 'TASK-CREATED') {
    $isMs = $Name -match '^\\Microsoft\\'
    if ($Command) { Test-IRText -Text $Command -Scope 'proc' -Time $Time -Source $Source -User $User }
    $img = Resolve-IRImagePath ($Command -split ' \| ')[0]
    if ($img) { Test-IRTool -Name (Get-IRLeaf $img) -Path $img -Time $Time -Source $Source -User $User }
    if ($isMs) { return }
    $risky = (Get-IRPathRisk $img) -or ($Command -and $Script:InterpRx.IsMatch($Command))
    if ($Rule -eq 'TASK-CREATED') {
        Add-IRFinding -Rule 'TASK-CREATED' -Title "Scheduled task created: $Name" -Severity $(if ($risky -or $Hidden) { 'high' } else { 'medium' }) -Technique 'T1053.005' `
            -Time $Time -Source $Source -Evidence "[$Source] $Name : $Command$(if ($Hidden) { ' (hidden)' })" -Key $Name -User $User -File $img
    } elseif ($risky -or $Hidden) {
        Add-IRFinding -Rule $Rule -Title "Suspicious scheduled task: $Name" -Severity $(if ((Get-IRPathRisk $img) -or $Hidden) { 'high' } else { 'medium' }) -Technique 'T1053.005' `
            -Time $Time -Source $Source -Evidence "[$Source] $Name : $Command$(if ($Hidden) { ' (hidden)' })" -Key $Name -User $User -File $img
    }
}

function Test-IRFilePath($Time, [string]$Source, [string]$Path, [string]$Process, [string]$User) {
    if (-not $Path) { return }
    $leaf = Get-IRLeaf $Path
    Test-IRTool -Name $leaf -Path $Path -Time $Time -Source $Source -User $User
    if ($leaf -match '^lsass.*\.(dmp|zip|bin)$|\\lsass[^\\]*\.dmp$') {
        Add-IRFinding -Rule 'LSASS-DUMP-FILE' -Title "LSASS dump file written: $leaf" -Severity critical -Technique 'T1003.001' -Time $Time -Source $Source -Evidence "[$Source] $Path by $Process" -Key $Path -File $Path -Process $Process -User $User
    }
    if ($leaf -eq 'ntds.dit' -and $Path -notmatch '(?i)\\windows\\ntds\\') {
        Add-IRFinding -Rule 'NTDS-COPY' -Title 'Copy of the AD database (ntds.dit) written' -Severity high -Technique 'T1003.003' -Time $Time -Source $Source -Evidence "[$Source] $Path by $Process" -Key $Path -File $Path -Process $Process -User $User
    }
    if ($Path -match '(?i)\\start menu\\programs\\startup\\[^\\]+$' -and $leaf -ne 'desktop.ini') {
        Add-IRFinding -Rule 'STARTUP-FILE' -Title "File written to a Startup folder: $leaf" -Severity high -Technique 'T1547.001' -Time $Time -Source $Source -Evidence "[$Source] $Path by $Process" -Key $Path -File $Path -Process $Process -User $User
    }
    if ($leaf -match '\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|rtf|csv|zip)\.(exe|scr|com|pif|js|jse|vbs|vbe|bat|cmd|hta|lnk|ps1|msi)$' -and -not $Script:RecentRx.IsMatch($Path)) {
        Add-IRFinding -Rule 'DOUBLE-EXT' -Title 'Double file extension' -Severity high -Technique 'T1036.007' -Time $Time -Source $Source -Evidence "[$Source] $Path" -Key $Path -File $Path -Process $Process -User $User
    }
    if ($Script:RansomRx.IsMatch($leaf)) {
        Add-IRFinding -Rule 'RANSOM-NOTE' -Title 'Ransom note or encrypted-file naming pattern' -Severity high -Technique 'T1486' -Time $Time -Source $Source -Evidence "[$Source] $Path by $Process" -Key $leaf -File $Path -Process $Process -User $User
    }
    if ($leaf -match '\.(exe|dll|scr|ps1|bat|cmd|vbs|js|hta)$' -and (Get-IRPathRisk $Path) -and $Process -notmatch '(?i)\\(msiexec|trustedinstaller|tiworker|svchost|setup\w*|.*installer\w*)\.exe$') {
        Add-IRFinding -Rule 'DROP-SUSP-DIR' -Title "Executable / script dropped into a staging folder: $leaf" -Severity medium -Technique 'T1105' -Time $Time -Source $Source -Evidence "[$Source] $Path by $Process" -Key $Path -File $Path -Process $Process -User $User
    }
}

function Test-IRRegistrySet($Time, [string]$Source, [string]$Key, [string]$Details, [string]$Process, [string]$User) {
    $line = "$Key = $Details"
    foreach ($r in $Script:RegRules) {
        if (-not $r.rx.IsMatch($line)) { continue }
        $sev = $r.sev
        if ($r.id -eq 'REGSET-RUNKEY') {
            if ($Process -and $Script:TrustedDirRx.IsMatch($Process) -and -not $Script:InterpRx.IsMatch([string]$Details) -and -not (Get-IRPathRisk $Details)) { $sev = 'low' }
            elseif ((Get-IRPathRisk $Details) -or $Script:InterpRx.IsMatch([string]$Details)) { $sev = 'high' }
        }
        if ($r.id -eq 'REGSET-IFEO' -and $Key -match '(?i)\\(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe\\') {
            Add-IRFinding -Rule 'ACCESSIBILITY-BACKDOOR' -Title 'Accessibility feature backdoor (sticky keys / utilman)' -Severity critical -Technique 'T1546.008' -Time $Time -Source $Source -Evidence "[$Source] $line by $Process" -Key $Key -Process $Process -User $User
        }
        Add-IRFinding -Rule $r.id -Title $r.title -Severity $sev -Technique $r.tech -Time $Time -Source $Source -Evidence "[$Source] $(Limit-IRText $line 400) by $Process" -Key $line -Process $Process -User $User
        break
    }
    if ($Details) { Test-IRText -Text $Details -Scope 'proc' -Time $Time -Source $Source -User $User -Process $Process }
}

#endregion

#region ===== Analysis: event logs =====

$Script:LogShort = @{
    'Security' = 'Security'; 'System' = 'System'; 'Application' = 'Application'
    'Microsoft-Windows-PowerShell/Operational' = 'PowerShell'; 'Windows PowerShell' = 'Windows PowerShell'
    'Microsoft-Windows-Sysmon/Operational' = 'Sysmon'
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' = 'RDP-LSM'
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' = 'RDP-RCM'
    'Microsoft-Windows-TerminalServices-RDPClient/Operational' = 'RDP-Client'
    'Microsoft-Windows-Windows Defender/Operational' = 'Defender'
    'Microsoft-Windows-TaskScheduler/Operational' = 'TaskScheduler'
    'Microsoft-Windows-WMI-Activity/Operational' = 'WMI'
    'Microsoft-Windows-Bits-Client/Operational' = 'BITS'
    'Microsoft-Windows-WinRM/Operational' = 'WinRM'
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' = 'Firewall'
    'Microsoft-Windows-SMBServer/Security' = 'SMBServer'
}

# Noisy event IDs get their own query so the newest-N cap cannot crowd out rare, high-value events.
$Script:EventSpecs = @(
    @{ log = 'Security'; ids = @(1102, 4719, 4720, 4722, 4724, 4725, 4726, 4728, 4732, 4756, 4740, 4697, 4698, 4699, 4702, 4778, 4779) }
    @{ log = 'Security'; ids = @(4624); extra = " and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='3' or Data[@Name='LogonType']='8' or Data[@Name='LogonType']='9' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11' or Data[@Name='LogonType']='12']" }
    @{ log = 'Security'; ids = @(4625, 4771) }
    @{ log = 'Security'; ids = @(4776); extra = " and EventData[Data[@Name='Status']!='0x0']" }
    @{ log = 'Security'; ids = @(4688) }
    @{ log = 'Security'; ids = @(4648) }
    @{ log = 'Security'; ids = @(4768); extra = " and EventData[Data[@Name='PreAuthType']='0']" }
    @{ log = 'Security'; ids = @(4769); extra = " and EventData[Data[@Name='TicketEncryptionType']='0x17']" }
    @{ log = 'Security'; ids = @(5140); extra = ' and EventData[Data[@Name=''ShareName'']=''\\*\ADMIN$'' or Data[@Name=''ShareName'']=''\\*\C$'']' }
    @{ log = 'System'; ids = @(7045, 7040, 104, 6005, 6006, 6008, 1074) }
    @{ log = 'Microsoft-Windows-PowerShell/Operational'; ids = @(4104) }
    @{ log = 'Windows PowerShell'; ids = @(400) }
    @{ log = 'Microsoft-Windows-Sysmon/Operational'; ids = @(1) }
    @{ log = 'Microsoft-Windows-Sysmon/Operational'; ids = @(3) }
    @{ log = 'Microsoft-Windows-Sysmon/Operational'; ids = @(6, 8, 25) }
    @{ log = 'Microsoft-Windows-Sysmon/Operational'; ids = @(10); extra = " and EventData[Data[@Name='TargetImage']='C:\Windows\system32\lsass.exe' or Data[@Name='TargetImage']='C:\Windows\System32\lsass.exe']" }
    @{ log = 'Microsoft-Windows-Sysmon/Operational'; ids = @(11) }
    @{ log = 'Microsoft-Windows-Sysmon/Operational'; ids = @(13) }
    @{ log = 'Microsoft-Windows-Sysmon/Operational'; ids = @(22) }
    @{ log = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; ids = @(21, 22, 24, 25) }
    @{ log = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; ids = @(1149) }
    @{ log = 'Microsoft-Windows-TerminalServices-RDPClient/Operational'; ids = @(1024, 1102) }
    @{ log = 'Microsoft-Windows-Windows Defender/Operational'; ids = @(1006, 1015, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012, 5013) }
    @{ log = 'Microsoft-Windows-TaskScheduler/Operational'; ids = @(106, 140, 141) }
    @{ log = 'Microsoft-Windows-WMI-Activity/Operational'; ids = @(5861) }
    @{ log = 'Microsoft-Windows-Bits-Client/Operational'; ids = @(59) }
    @{ log = 'Microsoft-Windows-WinRM/Operational'; ids = @(91) }
    @{ log = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; ids = @(2003, 2004, 2005, 2006, 2052, 2097, 2099) }
    @{ log = 'Microsoft-Windows-SMBServer/Security'; ids = @(551) }
    @{ log = 'Application'; ids = @(325, 326, 327, 1033, 11707) }
)

function Get-IREventFile([string]$Log) {
    foreach ($e in $Script:D['event_logs']) {
        if ($e.log -eq $Log -and $e.file) {
            $p = Join-Path $Script:In.Events $e.file
            if (Test-Path -LiteralPath $p) { return $p }
        }
    }
    $p = Join-Path $Script:In.Events ((($Log -replace '/', '%4') -replace '[\\:*?"<>|]', '_') + '.evtx')
    if (Test-Path -LiteralPath $p) { return $p }
    return $null
}

function ConvertFrom-IREvent($E, [string]$Log) {
    $d = @{}
    try {
        $x = [xml]$E.ToXml()
        $ed = $x.Event['EventData']
        if ($ed) {
            $i = 0
            foreach ($n in $ed.ChildNodes) {
                if ($n.LocalName -ne 'Data') { continue }
                $nm = $n.GetAttribute('Name')
                if (-not $nm) { $nm = "Data$i" }
                $d[$nm] = $n.InnerText; $i++
            }
        }
        $ud = $x.Event['UserData']
        if ($ud -and $ud.FirstChild) { foreach ($n in $ud.FirstChild.ChildNodes) { $d[$n.LocalName] = $n.InnerText } }
    } catch { }
    $t = $null
    if ($E.TimeCreated) { $t = $E.TimeCreated.ToUniversalTime() }
    return @{ t = $t; log = $Log; id = [int]$E.Id; rec = $E.RecordId; prov = $E.ProviderName; lvl = [int]$E.Level; sid = $(if ($E.UserId) { $E.UserId.Value } else { $null }); d = $d }
}

function Read-IREventSet([string]$Log, [int[]]$Ids, [string]$Extra) {
    $file = Get-IREventFile $Log
    if (-not $file) { return }
    $xp = "*[System[({0}) and TimeCreated[@SystemTime>='{1}']]{2}]" -f (($Ids | ForEach-Object { "EventID=$_" }) -join ' or '), $Script:SinceXml, $Extra
    # A disposed EventLogReader releases the .evtx file; Get-WinEvent -Path keeps it open until exit.
    $n = 0; $reader = $null
    try {
        $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($file, [System.Diagnostics.Eventing.Reader.PathType]::FilePath, $xp)
        $q.ReverseDirection = $true
        $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
        while ($n -lt $MaxEventsPerLog) {
            $e = $reader.ReadEvent()
            if ($null -eq $e) { break }
            try { ConvertFrom-IREvent $e $Log } finally { $e.Dispose() }
            $n++
        }
    } catch {
        Write-IRLog "  $Log [$($Ids -join ',')]: $($_.Exception.Message)" 'WARN'
    } finally {
        if ($reader) { $reader.Dispose() }
    }
    if ($n -ge $MaxEventsPerLog) {
        Write-IRLog "  $Log [$($Ids -join ',')]: capped at the newest $MaxEventsPerLog events (raise -MaxEventsPerLog for more)" 'WARN'
        $Script:CappedQueries.Add("$Log [$($Ids -join ',')]")
    }
}

function ConvertFrom-IRHex([string]$Value) {
    if (-not $Value) { return $null }
    try { if ($Value -match '^0x') { return [Convert]::ToInt64($Value.Substring(2), 16) }; return [int64]$Value } catch { return $null }
}

function Test-IRSelfProcess($Time, $ParentPid) {
    if (-not $Script:SelfPid -or $null -eq $ParentPid -or -not $Time) { return $false }
    return ([int64]$ParentPid -eq $Script:SelfPid -and $Time -ge $Script:SelfStart -and $Time -le $Script:SelfEnd)
}

# Antivirus engines flag this script's own detection patterns (AMSI scans every script it loads).
function Test-IRSelfResource([string]$Resource) {
    if (-not $Resource) { return $false }
    if ($Resource -match '(?i)IR-Investigator[^\\;]*\.ps1') { return $true }
    return [bool]($Script:SelfPath -and $Resource.IndexOf($Script:SelfPath, [StringComparison]::OrdinalIgnoreCase) -ge 0)
}

$Script:RecentRx = New-Object Text.RegularExpressions.Regex('\\microsoft\\(windows|office)\\recent\\', 'IgnoreCase')

# Drops every part of script blocks that belong to this tool, so its own detection strings
# never show up as findings.
function Select-IRScriptBlocks($Events) {
    $skip = @{}
    foreach ($e in $Events) {
        $txt = [string]$e.d['ScriptBlockText']; $path = [string]$e.d['Path']
        if ($txt.Contains($Script:SelfMarker) -or ($path -and ($path -match 'IR-Investigator[^\\]*\.ps1$' -or ($Script:SelfPath -and $path -eq $Script:SelfPath)))) {
            $skip[[string]$e.d['ScriptBlockId']] = 1
        } elseif ($txt.Length -lt 1500 -and $txt -match '(?i)IR-Investigator[^\\\s"'']*\.ps1') {
            # Short interactive blocks that only launch this script.
            $skip[[string]$e.d['ScriptBlockId']] = 1
        } elseif (-not $path -and $txt.Contains('$__cmdletization_objectModelWrapper')) {
            # Wrapper code PowerShell generates for CDXML modules (NetSecurity, Defender, ...) when they load.
            $skip[[string]$e.d['ScriptBlockId']] = 2
        }
    }
    $Script:SelfBlocks = @($skip.Values | Where-Object { $_ -eq 1 }).Count
    $Script:CdxmlBlocks = @($skip.Values | Where-Object { $_ -eq 2 }).Count
    foreach ($e in $Events) { if (-not $skip.ContainsKey([string]$e.d['ScriptBlockId'])) { $e } }
}

function Add-IRLogon($Time, [string]$User, $Type, [string]$Ip, [string]$Ws, [string]$Result, [string]$Auth, [string]$Reason) {
    $k = "$User|$Type|$Ip|$Ws|$Result"
    $r = $Script:LogonSum[$k]
    if (-not $r) {
        if ($Script:LogonSum.Count -ge 20000) { return }
        $tn = $Script:LogonTypes[[int]$Type]
        $r = [ordered]@{ user = $User; logon_type = $(if ($tn) { "$Type - $tn" } else { [string]$Type }); source_ip = $Ip; workstation = $Ws; result = $Result; events = 0; first = $null; last = $null; auth = $Auth; reasons = '' }
        $Script:LogonSum[$k] = $r
    }
    $r.events = $r.events + 1
    $iso = Get-IRIso $Time
    if ($iso) {
        if (-not $r.first -or [string]::CompareOrdinal($iso, $r.first) -lt 0) { $r.first = $iso }
        if (-not $r.last -or [string]::CompareOrdinal($iso, $r.last) -gt 0) { $r.last = $iso }
    }
    if ($Reason -and $r.reasons.Length -lt 200 -and $r.reasons.IndexOf($Reason) -lt 0) { $r.reasons = (($r.reasons, $Reason) | Where-Object { $_ }) -join '; ' }
}

function Add-IRFail($Time, [string]$User, [string]$Ip, [string]$Ws, [string]$Source) {
    if ($Script:Fails.Count -ge 400000 -or -not $Time) { return }
    $ip2 = ([string]$Ip) -replace '^::ffff:', ''
    $src = if (Test-IRRealIp $ip2) { $ip2 } elseif ($Ws -and $Ws -ne '-') { "host:$($Ws.ToUpperInvariant())" } else { 'local' }
    $Script:Fails.Add(@{ t = $Time; u = $User; ip = $ip2; src = $src; s = $Source })
}

function Invoke-IRSecurityEvent($E, $t, $d, [int]$id, [string]$src) {
    $subj = $null
    if ($d['SubjectUserName'] -and $d['SubjectUserName'] -ne '-') { $subj = "$($d['SubjectDomainName'])\$($d['SubjectUserName'])" }
    $tu = [string]$d['TargetUserName']
    $target = if ($tu) { "$($d['TargetDomainName'])\$tu" } else { $null }
    switch ($id) {
        4624 {
            if (-not (Test-IRRealUser $tu)) { return }
            $type = [int]$d['LogonType']; $ip = [string]$d['IpAddress']; $ws = [string]$d['WorkstationName']; $auth = [string]$d['AuthenticationPackageName']
            Add-IRLogon $t $target $type $ip $ws 'success' $auth $null
            if (($type -eq 3 -or $type -eq 10) -and (Test-IRRealIp $ip)) { $Script:LogonOk.Add(@{ t = $t; u = $target; ip = $ip; type = $type }) }
            $public = Test-IRPublicIp $ip
            $ev = "[$src] $target logon type $type from $ip ($ws) via $auth"
            if ($type -eq 10 -or $type -eq 12) {
                if ($public) { Add-IRFinding -Rule 'RDP-PUBLIC' -Title 'Remote Desktop logon from a public IP address' -Severity high -Technique 'T1133' -Time $t -Source $src -Evidence $ev -Key "$target|$ip" -User $target -Ip $ip }
                elseif (Test-IRRealIp $ip) { Add-IRFinding -Rule 'RDP-LOGON' -Title "Remote Desktop logon: $target" -Severity low -Technique 'T1021.001' -Time $t -Source $src -Evidence $ev -Key "$target|$ip" -User $target -Ip $ip }
            } elseif ($public -and ($type -eq 3 -or $type -eq 8)) {
                Add-IRFinding -Rule 'NET-LOGON-PUBLIC' -Title 'Network logon from a public IP address' -Severity high -Technique 'T1133' -Time $t -Source $src -Evidence $ev -Key "$target|$ip" -User $target -Ip $ip
            }
            if ($type -eq 9 -and $d['LogonProcessName'] -match 'seclogo') {
                Add-IRFinding -Rule 'LOGON-NEWCRED' -Title 'Logon with alternate credentials (runas /netonly or pass-the-hash)' -Severity medium -Technique 'T1550.002' -Time $t -Source $src -Evidence "$ev (process $($d['ProcessName']))" -Key $subj -User @($subj, $target)
            }
            $where = if ($ip -and $ip -ne '-') { $ip } else { 'local' }
            Add-IRTimeline $t $src '4624' 'logon' "Logon $($Script:LogonTypes[$type]) ($type): $target from $where$(if ($ws -and $ws -ne '-') { " [$ws]" }) via $auth" $target -Keep:($type -in @(2, 8, 9, 10, 11, 12))
        }
        4625 {
            $ip = [string]$d['IpAddress']; $ws = [string]$d['WorkstationName']
            $st = ([string]$d['SubStatus']).ToLowerInvariant()
            if (-not $st -or $st -eq '0x0' -or $st -eq '0x00000000') { $st = ([string]$d['Status']).ToLowerInvariant() }
            $reason = $Script:LogonStatus[$st]; if (-not $reason) { $reason = $st }
            Add-IRLogon $t $target ([int]$d['LogonType']) $ip $ws 'failure' ([string]$d['AuthenticationPackageName']) $reason
            Add-IRFail $t $target $ip $ws $src
        }
        4771 {
            $ip = ([string]$d['IpAddress']) -replace '^::ffff:', ''
            $st = ([string]$d['Status']).ToLowerInvariant()
            $reason = $Script:LogonStatus[$st]; if (-not $reason) { $reason = "Kerberos $st" }
            Add-IRLogon $t $tu 'Kerberos' $ip $null 'failure' 'Kerberos' $reason
            Add-IRFail $t $tu $ip $null $src
        }
        4776 {
            $ws = [string]$d['Workstation']
            $st = ([string]$d['Status']).ToLowerInvariant()
            $reason = $Script:LogonStatus[$st]; if (-not $reason) { $reason = $st }
            Add-IRLogon $t $tu 'NTLM' $null $ws 'failure' 'NTLM' $reason
            Add-IRFail $t $tu $null $ws $src
        }
        4648 {
            $srv = [string]$d['TargetServerName']
            if (-not $srv -or $srv -in @('localhost', '127.0.0.1', '-') -or $srv -ieq $Script:HostName -or $srv -like "$($Script:HostName).*") { return }
            if (-not (Test-IRRealUser $tu)) { return }
            $proc = [string]$d['ProcessName']
            Add-IRFinding -Rule 'EXPLICIT-CRED' -Title 'Explicit credentials used to access another host' -Severity low -Technique 'T1078' -Time $t -Source $src `
                -Evidence "[$src] $subj used $target for $srv via $proc" -Key "$subj|$target|$srv" -User @($subj, $target) -Ip $d['IpAddress'] -Process $proc
            $Script:ExplicitCred.Add(@{ t = $t; u = $subj; target = $srv })
            Add-IRTimeline $t $src '4648' 'lateral-movement' "Explicit credentials: $subj used $target to reach $srv ($proc)" $subj -Keep
        }
        4688 {
            if (Test-IRSelfProcess $t (ConvertFrom-IRHex $d['ProcessId'])) { $Script:SelfEvents++; return }
            $img = [string]$d['NewProcessName']; $cmd = [string]$d['CommandLine']; $par = [string]$d['ParentProcessName']
            $user = $subj
            if ($d['TargetUserName'] -and $d['TargetUserName'] -ne '-') { $user = "$($d['TargetDomainName'])\$($d['TargetUserName'])" }
            Invoke-IRProcessRules -Time $t -Source $src -Image $img -Cmd $cmd -Parent $par -User $user -Timed
            Add-IRTimeline $t $src '4688' 'process' "$(Get-IRLeaf $par) -> $(if ($cmd) { $cmd } else { $img })" $user -Keep:($img -and -not $Script:TrustedDirRx.IsMatch($img))
        }
        1102 {
            Add-IRFinding -Rule 'LOG-CLEARED' -Title 'Event log cleared: Security' -Severity high -Technique 'T1070.001' -Time $t -Source $src -Evidence "[$src] Security log cleared by $subj" -Key 'Security' -User $subj
            Add-IRTimeline $t $src '1102' 'defense-evasion' "Security event log cleared by $subj" $subj -Keep
        }
        4719 {
            if ($d['SubjectUserName'] -match '\$$') { return }
            Add-IRFinding -Rule 'AUDIT-POLICY-CHANGED' -Title 'Audit policy changed' -Severity medium -Technique 'T1562.002' -Time $t -Source $src `
                -Evidence "[$src] $subj changed subcategory $($d['SubcategoryGuid']): $($d['AuditPolicyChanges'])" -Key "$subj|$($d['SubcategoryGuid'])" -User $subj
            Add-IRTimeline $t $src '4719' 'defense-evasion' "Audit policy changed by $subj ($($d['SubcategoryGuid']): $($d['AuditPolicyChanges']))" $subj -Keep
        }
        4720 {
            Add-IRFinding -Rule 'ACCOUNT-CREATED' -Title "Account created: $tu" -Severity medium -Technique 'T1136.001' -Time $t -Source $src -Evidence "[$src] $target created by $subj" -Key $tu -User @($target, $subj)
            $Script:Created[$tu.ToLowerInvariant()] = $t
            if ($d['TargetSid']) { $Script:Created[[string]$d['TargetSid']] = $t }
            Add-IRTimeline $t $src '4720' 'account' "Account created: $target by $subj" $subj -Keep
        }
        { $_ -in @(4722, 4724, 4725, 4726) } {
            $what = switch ($id) { 4722 { 'enabled' } 4724 { 'password reset' } 4725 { 'disabled' } 4726 { 'deleted' } }
            if ($id -eq 4724 -and $d['SubjectUserName'] -eq $tu) { return }
            $rule = switch ($id) { 4722 { 'ACCOUNT-ENABLED' } 4724 { 'PASSWORD-RESET' } default { 'ACCOUNT-REMOVED' } }
            $sev = if ($id -in @(4725, 4726)) { 'medium' } else { 'low' }
            $tech = if ($id -in @(4725, 4726)) { 'T1531' } else { 'T1098' }
            Add-IRFinding -Rule $rule -Title "Account $what`: $tu" -Severity $sev -Technique $tech -Time $t -Source $src -Evidence "[$src] $target $what by $subj" -Key $tu -User @($target, $subj)
            Add-IRTimeline $t $src ([string]$id) 'account' "Account $what`: $target by $subj" $subj -Keep
        }
        { $_ -in @(4728, 4732, 4756) } {
            $group = $tu
            $member = [string]$d['MemberName']
            if (-not $member -or $member -eq '-') { $member = Resolve-IRSid $d['MemberSid'] }
            elseif ($member -match '^CN=([^,]+)') { $member = $Matches[1] }
            $priv = $Script:PrivGroupRx.IsMatch($group)
            $Script:GroupAdds.Add(@{ t = $t; member = $member; sid = [string]$d['MemberSid']; group = $group; priv = $priv })
            if ($priv) {
                Add-IRFinding -Rule 'PRIV-GROUP-ADD' -Title "Account added to privileged group $group" -Severity high -Technique 'T1098' -Time $t -Source $src -Evidence "[$src] $member added to $group by $subj" -Key "$group|$member" -User @($member, $subj)
            } else {
                Add-IRFinding -Rule 'GROUP-ADD-EVENT' -Title "Account added to group $group" -Severity low -Technique 'T1098' -Time $t -Source $src -Evidence "[$src] $member added to $group by $subj" -Key "$group|$member" -User @($member, $subj)
            }
            Add-IRTimeline $t $src ([string]$id) 'account' "$member added to group $group by $subj" $subj -Keep
        }
        4740 {
            Add-IRFinding -Rule 'ACCOUNT-LOCKOUT' -Title "Account locked out: $tu" -Severity medium -Technique 'T1110' -Time $t -Source $src -Evidence "[$src] $tu locked out (caller computer: $($d['TargetDomainName']))" -Key $tu -User $tu
            Add-IRTimeline $t $src '4740' 'credential-access' "Account locked out: $tu (caller $($d['TargetDomainName']))" $tu -Keep
        }
        4697 {
            Test-IRServiceInstall $t $src ([string]$d['ServiceName']) ([string]$d['ServiceFileName']) ([string]$d['ServiceAccount']) ([string]$d['ServiceType']) $subj
            Add-IRTimeline $t $src '4697' 'persistence' "Service installed: $($d['ServiceName']) -> $($d['ServiceFileName'])" $subj -Keep
        }
        { $_ -in @(4698, 4702) } {
            $name = [string]$d['TaskName']; $xml = [string]$d['TaskContent']
            $cmd = Get-IRTaskCommand $xml
            $hidden = $xml -match '<Hidden>true</Hidden>'
            if ($id -eq 4698) {
                Test-IRTaskDefinition $t $src $name $cmd $subj $hidden 'TASK-CREATED'
                $Script:TaskEvents.Add(@{ t = $t; name = $name; op = 'create' })
            } else { Test-IRTaskDefinition $t $src $name $cmd $subj $hidden 'TASK-UPDATED-SUSP' }
            Add-IRTimeline $t $src ([string]$id) 'persistence' "Scheduled task $(if ($id -eq 4698) { 'created' } else { 'updated' }): $name -> $cmd" $subj -Keep:($name -notmatch '^\\Microsoft\\')
        }
        4699 {
            $name = [string]$d['TaskName']
            $Script:TaskEvents.Add(@{ t = $t; name = $name; op = 'delete' })
            Add-IRTimeline $t $src '4699' 'persistence' "Scheduled task deleted: $name by $subj" $subj -Keep:($name -notmatch '^\\Microsoft\\')
        }
        { $_ -in @(4778, 4779) } {
            $user = "$($d['AccountDomain'])\$($d['AccountName'])"; $ip = [string]$d['ClientAddress']
            if ($id -eq 4778 -and (Test-IRPublicIp $ip)) {
                Add-IRFinding -Rule 'RDP-PUBLIC' -Title 'Remote Desktop logon from a public IP address' -Severity high -Technique 'T1133' -Time $t -Source $src -Evidence "[$src] $user reconnected from $ip ($($d['ClientName']))" -Key "$user|$ip" -User $user -Ip $ip
            }
            $Script:RdpSessions.Add([pscustomobject]@{ time = (Get-IRIso $t); event = $(if ($id -eq 4778) { 'Session reconnected' } else { 'Session disconnected' }); user = $user; source_ip = $ip; client = $d['ClientName']; session = $d['SessionName']; source = $src })
            Add-IRTimeline $t $src ([string]$id) 'remote-access' "RDP session $(if ($id -eq 4778) { 'reconnected' } else { 'disconnected' }): $user from $ip ($($d['ClientName']))" $user -Keep
        }
        4768 {
            $ip = ([string]$d['IpAddress']) -replace '^::ffff:', ''
            Add-IRFinding -Rule 'ASREP-ROAST' -Title "Kerberos TGT issued without pre-authentication: $tu" -Severity medium -Technique 'T1558.004' -Time $t -Source $src -Evidence "[$src] $tu from $ip" -Key "$tu|$ip" -User $tu -Ip $ip
            Add-IRTimeline $t $src '4768' 'credential-access' "TGT without pre-authentication for $tu requested from $ip" $tu
        }
        4769 {
            $svc = [string]$d['ServiceName']
            if ($svc -match '\$$|^krbtgt') { return }
            $Script:Tgs.Add(@{ t = $t; ip = (([string]$d['IpAddress']) -replace '^::ffff:', ''); svc = $svc; u = $tu })
        }
        5140 {
            $ip = [string]$d['IpAddress']
            if (-not (Test-IRRealIp $ip)) { return }
            Add-IRFinding -Rule 'ADMIN-SHARE-ACCESS' -Title "Administrative share $($d['ShareName']) accessed remotely" -Severity medium -Technique 'T1021.002' -Time $t -Source $src `
                -Evidence "[$src] $subj from $ip accessed $($d['ShareName'])" -Key "$subj|$ip|$($d['ShareName'])" -User $subj -Ip $ip
            Add-IRTimeline $t $src '5140' 'lateral-movement' "$subj from $ip accessed $($d['ShareName'])" $subj -Keep
        }
    }
}

function Invoke-IREventRule($E) {
    $t = $E.t; $d = $E.d; $id = $E.id
    $src = "$($Script:LogShort[$E.log]) $id"
    $evUser = $null
    if ($E.sid) { $evUser = Resolve-IRSid $E.sid }
    switch ($E.log) {
        'Security' { Invoke-IRSecurityEvent $E $t $d $id $src }
        'System' {
            switch ($id) {
                7045 {
                    Test-IRServiceInstall $t $src ([string]$d['ServiceName']) ([string]$d['ImagePath']) ([string]$d['AccountName']) ([string]$d['ServiceType']) $evUser
                    Add-IRTimeline $t $src '7045' 'persistence' "Service installed: $($d['ServiceName']) -> $($d['ImagePath']) ($($d['StartType']), $($d['AccountName']))" $evUser -Keep
                }
                7040 {
                    $svc = "$($d['param1']) ($($d['param4']))"
                    if ($Script:SecSvcRx.IsMatch($svc) -and "$($d['param3'])" -match '(?i)disabled|deaktiviert|d.sactiv|deshabilitado|disabilitato') {
                        Add-IRFinding -Rule 'SECSVC-DISABLED' -Title "Security service disabled: $($d['param1'])" -Severity high -Technique 'T1562.001' -Time $t -Source $src -Evidence "[$src] $svc start type $($d['param2']) -> $($d['param3'])" -Key $svc -User $evUser
                    }
                    Add-IRTimeline $t $src '7040' 'defense-evasion' "Service start type changed: $svc $($d['param2']) -> $($d['param3'])" $evUser
                }
                104 {
                    $ch = [string]$d['Channel']
                    $who = "$($d['SubjectDomainName'])\$($d['SubjectUserName'])"
                    Add-IRFinding -Rule 'LOG-CLEARED' -Title "Event log cleared: $ch" -Severity high -Technique 'T1070.001' -Time $t -Source $src -Evidence "[$src] $ch cleared by $who" -Key $ch -User $who
                    Add-IRTimeline $t $src '104' 'defense-evasion' "Event log '$ch' cleared by $who" $who -Keep
                }
                6005 { Add-IRTimeline $t $src '6005' 'system' 'Event Log service started (system boot)' $null -Keep }
                6006 { Add-IRTimeline $t $src '6006' 'system' 'Event Log service stopped (clean shutdown)' $null -Keep }
                6008 { Add-IRTimeline $t $src '6008' 'system' "Unexpected shutdown (previous shutdown at $($d['Data1']) $($d['Data0']))" $null -Keep }
                1074 { Add-IRTimeline $t $src '1074' 'system' "$($d['param5']) initiated by $($d['param7']) via $($d['param1']): $($d['param3']) $($d['param6'])" $d['param7'] -Keep }
            }
        }
        'Microsoft-Windows-PowerShell/Operational' {
            $txt = [string]$d['ScriptBlockText']; $path = [string]$d['Path']
            Test-IRText -Text $txt -Scope 'any' -Time $t -Source $src -User $evUser -Process $path
            if ($E.lvl -eq 3) {
                Add-IRFinding -Rule 'PS-SUSPICIOUS-BLOCK' -Title 'Script block flagged as suspicious by PowerShell itself' -Severity low -Technique 'T1059.001' -Time $t -Source $src `
                    -Evidence "[$src] $(if ($path) { "$path : " })$(Limit-IRText $txt 400)" -Key $(if ($path) { $path -replace '(?i)[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', '*' } else { 'interactive' }) -User $evUser
            }
            Add-IRTimeline $t $src '4104' 'powershell' "Script block $($d['MessageNumber'])/$($d['MessageTotal'])$(if ($path) { " from $path" }): $(Limit-IRText $txt 300)" $evUser
        }
        'Windows PowerShell' {
            $info = [string]$d['Data2']
            $hostApp = $null; $ver = $null
            if ($info -match 'HostApplication=([^\r\n]*)') { $hostApp = $Matches[1].Trim() }
            if ($info -match 'EngineVersion=([^\r\n]*)') { $ver = $Matches[1].Trim() }
            if (-not $hostApp -or $hostApp -match 'IR-Investigator') { return }
            if ($ver -like '2.*') {
                Add-IRFinding -Rule 'PS-V2-ENGINE' -Title 'PowerShell 2.0 engine started (bypasses script-block logging)' -Severity medium -Technique 'T1562.010' -Time $t -Source $src -Evidence "[$src] $hostApp (engine $ver)" -Key $hostApp
            }
            Test-IRText -Text $hostApp -Scope 'proc' -Time $t -Source $src
            Add-IRTimeline $t $src '400' 'powershell' "PowerShell engine $ver started: $hostApp" $null
        }
        'Microsoft-Windows-Sysmon/Operational' {
            $user = [string]$d['User']
            switch ($id) {
                1 {
                    if (Test-IRSelfProcess $t (ConvertFrom-IRHex $d['ParentProcessId'])) { $Script:SelfEvents++; return }
                    $img = [string]$d['Image']; $cmd = [string]$d['CommandLine']
                    $h = $null
                    if ($d['Hashes'] -match 'SHA256=([0-9A-Fa-f]{64})') { $h = $Matches[1].ToLowerInvariant() }
                    Invoke-IRProcessRules -Time $t -Source $src -Image $img -Cmd $cmd -Parent ([string]$d['ParentImage']) -User $user -Hash $h -Timed
                    Add-IRTimeline $t $src '1' 'process' "$(Get-IRLeaf $d['ParentImage']) -> $(if ($cmd) { $cmd } else { $img })" $user -Keep:($img -and -not $Script:TrustedDirRx.IsMatch($img))
                }
                3 {
                    $img = [string]$d['Image']
                    if ($d['Initiated'] -eq 'true') {
                        Test-IRConnection -Time $t -Source $src -Image $img -RemoteIp $d['DestinationIp'] -RemotePort $d['DestinationPort'] -LocalPort $d['SourcePort'] -HostName $d['DestinationHostname'] -User $user
                        Add-IRTimeline $t $src '3' 'network' "$(Get-IRLeaf $img) -> $($d['DestinationIp']):$($d['DestinationPort']) $($d['DestinationHostname'])" $user
                    } else {
                        Test-IRConnection -Time $t -Source $src -Image $img -RemoteIp $d['SourceIp'] -RemotePort $d['SourcePort'] -LocalPort $d['DestinationPort'] -User $user -Inbound
                        Add-IRTimeline $t $src '3' 'network' "$(Get-IRLeaf $img) <- $($d['SourceIp']) on port $($d['DestinationPort'])" $user
                    }
                }
                6 {
                    $img = [string]$d['ImageLoaded']
                    if ($d['Signed'] -eq 'false' -or ($d['SignatureStatus'] -and $d['SignatureStatus'] -ne 'Valid')) {
                        Add-IRFinding -Rule 'DRIVER-UNSIGNED-LOAD' -Title "Unsigned or invalid kernel driver loaded: $(Get-IRLeaf $img)" -Severity high -Technique 'T1014' -Time $t -Source $src -Evidence "[$src] $img signed=$($d['Signed']) status=$($d['SignatureStatus'])" -Key $img -File $img
                    }
                    if ($Script:VulnDriverRx.IsMatch((Get-IRLeaf $img))) {
                        Add-IRFinding -Rule 'BYOVD' -Title "Known vulnerable driver loaded: $(Get-IRLeaf $img)" -Severity high -Technique 'T1068' -Time $t -Source $src -Evidence "[$src] $img ($($d['Signature']))" -Key (Get-IRLeaf $img) -File $img
                    }
                    Add-IRTimeline $t $src '6' 'defense-evasion' "Driver loaded: $img ($($d['Signature']))" $null
                }
                8 {
                    $s = [string]$d['SourceImage']; $tg = [string]$d['TargetImage']
                    if ($Script:BenignInjectRx.IsMatch($s)) { return }
                    Add-IRFinding -Rule 'REMOTE-THREAD' -Title "Remote thread created in another process by $(Get-IRLeaf $s)" -Severity high -Technique 'T1055' -Time $t -Source $src -Evidence "[$src] $s -> $tg (start $($d['StartFunction']) $($d['StartModule']))" -Key "$s|$tg" -Process $s -User $user
                    Add-IRTimeline $t $src '8' 'defense-evasion' "Remote thread: $s -> $tg" $user
                }
                10 {
                    $s = [string]$d['SourceImage']
                    if ($Script:BenignInjectRx.IsMatch($s)) { return }
                    $acc = ConvertFrom-IRHex $d['GrantedAccess']
                    if ($null -ne $acc -and ($acc -band 0x10)) {
                        Add-IRFinding -Rule 'LSASS-ACCESS' -Title "Process opened LSASS with memory-read access: $(Get-IRLeaf $s)" -Severity critical -Technique 'T1003.001' -Time $t -Source $src -Evidence "[$src] $s access $($d['GrantedAccess'])" -Key $s -Process $s -File $s -User $user
                    }
                    if ([string]$d['CallTrace'] -match 'UNKNOWN') {
                        Add-IRFinding -Rule 'LSASS-UNKNOWN-CALLTRACE' -Title "LSASS accessed from unbacked memory by $(Get-IRLeaf $s)" -Severity high -Technique 'T1055' -Time $t -Source $src -Evidence "[$src] $s call trace $(Limit-IRText $d['CallTrace'] 300)" -Key $s -Process $s -User $user
                    }
                    Add-IRTimeline $t $src '10' 'credential-access' "$s opened lsass.exe (access $($d['GrantedAccess']))" $user
                }
                11 {
                    Test-IRFilePath $t $src ([string]$d['TargetFilename']) ([string]$d['Image']) $user
                    Add-IRTimeline $t $src '11' 'file' "File created: $($d['TargetFilename']) by $(Get-IRLeaf $d['Image'])" $user
                }
                13 {
                    Test-IRRegistrySet $t $src ([string]$d['TargetObject']) ([string]$d['Details']) ([string]$d['Image']) $user
                    Add-IRTimeline $t $src '13' 'registry' "Registry set: $($d['TargetObject']) = $($d['Details']) by $(Get-IRLeaf $d['Image'])" $user
                }
                22 {
                    $q = [string]$d['QueryName']; $img = [string]$d['Image']
                    Test-IRDomain $q $t $src $img $user
                    if ($Script:LolNetHigh.ContainsKey((Get-IRLeaf $img)) -and $q -notmatch '(?i)(\.|^)(microsoft|windows|windowsupdate|msftncsi|msedge|office|live|bing)\.(com|net)$') {
                        Add-IRFinding -Rule 'LOLBIN-DNS' -Title "$(Get-IRLeaf $img) resolved an external domain" -Severity medium -Technique 'T1071.001' -Time $t -Source $src -Evidence "[$src] $img -> $q" -Key "$(Get-IRLeaf $img)|$q" -Process $img -Domain $q -User $user
                    }
                    Add-IRTimeline $t $src '22' 'network' "DNS query $q by $(Get-IRLeaf $img)" $user
                }
                25 {
                    Add-IRFinding -Rule 'PROCESS-TAMPER' -Title "Process image tampering: $(Get-IRLeaf $d['Image'])" -Severity medium -Technique 'T1055.012' -Time $t -Source $src -Evidence "[$src] $($d['Image']) ($($d['Type']))" -Key ([string]$d['Image']) -Process $d['Image'] -User $user
                    Add-IRTimeline $t $src '25' 'defense-evasion' "Process tampering: $($d['Image']) ($($d['Type']))" $user
                }
            }
        }
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' {
            $user = [string]$d['User']; $addr = [string]$d['Address']
            $label = switch ($id) { 21 { 'RDP session logon' } 22 { 'RDP shell started' } 24 { 'RDP session disconnected' } 25 { 'RDP session reconnected' } }
            if ($id -in @(21, 25) -and (Test-IRRealIp $addr)) {
                if (Test-IRPublicIp $addr) { Add-IRFinding -Rule 'RDP-PUBLIC' -Title 'Remote Desktop logon from a public IP address' -Severity high -Technique 'T1133' -Time $t -Source $src -Evidence "[$src] $user from $addr" -Key "$user|$addr" -User $user -Ip $addr }
                else { Add-IRFinding -Rule 'RDP-LOGON' -Title "Remote Desktop logon: $user" -Severity low -Technique 'T1021.001' -Time $t -Source $src -Evidence "[$src] $user from $addr" -Key "$user|$addr" -User $user -Ip $addr }
            }
            $Script:RdpSessions.Add([pscustomobject]@{ time = (Get-IRIso $t); event = $label; user = $user; source_ip = $addr; client = $null; session = $d['SessionID']; source = $src })
            Add-IRTimeline $t $src ([string]$id) 'remote-access' "$label`: $user from $addr (session $($d['SessionID']))" $user -Keep:($id -ne 22)
        }
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' {
            $user = "$($d['Param2'])\$($d['Param1'])"; $ip = [string]$d['Param3']
            if (Test-IRPublicIp $ip) { Add-IRFinding -Rule 'RDP-PUBLIC' -Title 'Remote Desktop logon from a public IP address' -Severity high -Technique 'T1133' -Time $t -Source $src -Evidence "[$src] $user authenticated from $ip" -Key "$user|$ip" -User $user -Ip $ip }
            $Script:RdpSessions.Add([pscustomobject]@{ time = (Get-IRIso $t); event = 'RDP network authentication succeeded'; user = $user; source_ip = $ip; client = $null; session = $null; source = $src })
            Add-IRTimeline $t $src '1149' 'remote-access' "RDP authentication succeeded: $user from $ip" $user -Keep
        }
        'Microsoft-Windows-TerminalServices-RDPClient/Operational' {
            $v = [string]$d['Value']
            if (-not $v) { return }
            Add-IRFinding -Rule 'RDP-OUTBOUND' -Title "Outbound Remote Desktop connection to $v" -Severity low -Technique 'T1021.001' -Time $t -Source $src -Evidence "[$src] $evUser connected to $v" -Key $v -User $evUser
            Add-IRTimeline $t $src ([string]$id) 'lateral-movement' "Outbound RDP to $v by $evUser" $evUser -Keep
        }
        'Microsoft-Windows-Windows Defender/Operational' {
            switch ($id) {
                { $_ -in @(1006, 1015, 1116, 1117, 1118, 1119) } {
                    $threat = [string]$d['Threat Name']; $path = [string]$d['Path']; $proc = [string]$d['Process Name']; $duser = [string]$d['Detection User']
                    if (Test-IRSelfResource $path) { $Script:SelfEvents++; return }
                    $file = $path
                    if ($path -match 'file:_([^;]+)') { $file = $Matches[1] }
                    $tech = Get-IRThreatTechnique $threat
                    $failed = $id -in @(1118, 1119)
                    $sev = if ($failed -or $threat -match '(?i)ransom|backdoor|cobalts(?:)trike|meterp(?:)reter|mimik(?:)atz|hacktool|brute(?:)ratel|sli(?:)ver' -or $d['Severity Name'] -match '(?i)severe') { 'critical' } else { 'high' }
                    $rule = if ($failed) { 'DEFENDER-ACTION-FAILED' } else { 'DEFENDER-DETECTION' }
                    $title = if ($failed) { "Defender failed to remediate: $threat" } else { "Microsoft Defender detection: $threat" }
                    Add-IRFinding -Rule $rule -Title $title -Severity $sev -Technique $tech -Time $t -Source $src `
                        -Evidence "[$src] $threat in $path (process $proc, user $duser, action $($d['Action Name']))" -Key "$threat|$file" -File $file -Process $proc -User $duser
                    Test-IRTool -Name (Get-IRLeaf $file) -Path $file -Time $t -Source $src -User $duser
                    Add-IRTimeline $t $src ([string]$id) 'malware' "Defender $(if ($failed) { 'failed to act on' } else { 'detected' }) $threat in $path ($($d['Action Name']))" $duser -Keep
                }
                5001 {
                    Add-IRFinding -Rule 'DEFENDER-RTP-OFF' -Title 'Defender real-time protection disabled' -Severity high -Technique 'T1562.001' -Time $t -Source $src -Evidence "[$src] real-time protection disabled" -Key 'rtp'
                    Add-IRTimeline $t $src '5001' 'defense-evasion' 'Defender real-time protection disabled' $null -Keep
                }
                5004 { Add-IRTimeline $t $src '5004' 'defense-evasion' "Defender real-time protection setting changed: $($d['Feature Name']) = $($d['Configuration'])" $null -Keep }
                5007 {
                    $new = [string]$d['New Value']; $old = [string]$d['Old Value']
                    if ($new -match '(?i)\\exclusions\\') {
                        Add-IRFinding -Rule 'DEFENDER-EXCLUSION-ADDED' -Title 'Defender exclusion added' -Severity high -Technique 'T1562.001' -Time $t -Source $src -Evidence "[$src] $new" -Key $new
                    } elseif ($new -match '(?i)\\(disable\w+|disableantispyware)\s*=\s*0x1') {
                        $dsev = 'medium'
                        if ($new -match '(?i)\\policies\\|\\real-time protection\\|\\spynet\\|disableantispyware|disableantivirus|tamperprotection') { $dsev = 'high' }
                        Add-IRFinding -Rule 'DEFENDER-SETTING-DISABLED' -Title 'Defender protection setting disabled' -Severity $dsev -Technique 'T1562.001' -Time $t -Source $src -Evidence "[$src] $old -> $new" -Key $new
                    }
                    $cfg = "Defender configuration changed: $new"
                    if (-not $new.Trim()) { $cfg = "Defender configuration value removed: $old" }
                    Add-IRTimeline $t $src '5007' 'security-config' $cfg $null
                }
                { $_ -in @(5010, 5012) } {
                    Add-IRFinding -Rule 'DEFENDER-SCAN-DISABLED' -Title 'Defender scanning disabled' -Severity high -Technique 'T1562.001' -Time $t -Source $src -Evidence "[$src] scanning for $(if ($id -eq 5010) { 'malware and unwanted software' } else { 'viruses' }) disabled" -Key ([string]$id)
                    Add-IRTimeline $t $src ([string]$id) 'defense-evasion' 'Defender scanning disabled' $null -Keep
                }
                5013 {
                    Add-IRFinding -Rule 'DEFENDER-TAMPER-BLOCKED' -Title 'Tamper protection blocked a change to Defender (attempted tampering)' -Severity high -Technique 'T1562.001' -Time $t -Source $src -Evidence "[$src] $($d['Value']) $($d['Changed Value'])" -Key ([string]$d['Value'])
                    Add-IRTimeline $t $src '5013' 'defense-evasion' "Tamper protection blocked: $($d['Value'])" $null -Keep
                }
            }
        }
        'Microsoft-Windows-TaskScheduler/Operational' {
            $name = [string]$d['TaskName']; $isMs = $name -match '^\\Microsoft\\'
            $who = if ($d['UserContext']) { [string]$d['UserContext'] } else { [string]$d['UserName'] }
            switch ($id) {
                106 {
                    $Script:TaskEvents.Add(@{ t = $t; name = $name; op = 'create' })
                    if (-not $isMs) { Add-IRFinding -Rule 'TASK-CREATED' -Title "Scheduled task created: $name" -Severity medium -Technique 'T1053.005' -Time $t -Source $src -Evidence "[$src] $name registered by $who" -Key $name -User $who }
                    Add-IRTimeline $t $src '106' 'persistence' "Scheduled task registered: $name by $who" $who -Keep:(-not $isMs)
                }
                140 { Add-IRTimeline $t $src '140' 'persistence' "Scheduled task updated: $name by $who" $who -Keep:(-not $isMs) }
                141 {
                    $Script:TaskEvents.Add(@{ t = $t; name = $name; op = 'delete' })
                    Add-IRTimeline $t $src '141' 'persistence' "Scheduled task deleted: $name by $who" $who -Keep:(-not $isMs)
                }
            }
        }
        'Microsoft-Windows-WMI-Activity/Operational' {
            $c = [string]$d['CONSUMER']; $cause = [string]$d['PossibleCause']
            $benign = $c -match 'BVTConsumer|SCM Event Log Consumer'
            Add-IRFinding -Rule 'WMI-SUBSCRIPTION' -Title 'Permanent WMI event subscription created' -Severity $(if ($benign) { 'low' } else { 'high' }) -Technique 'T1546.003' -Time $t -Source $src `
                -Evidence "[$src] namespace $($d['Namespace']) consumer $c filter $($d['ESS']) $(Limit-IRText $cause 300)" -Key $c
            Test-IRText -Text $cause -Scope 'any' -Time $t -Source $src
            Add-IRTimeline $t $src '5861' 'persistence' "WMI subscription: $c ($($d['ESS']))" $null -Keep
        }
        'Microsoft-Windows-Bits-Client/Operational' {
            $url = [string]$d['url']
            if (-not $url -or $Script:TrustedUrlRx.IsMatch($url)) { return }
            $h = Get-IRUrlHost $url
            Add-IRFinding -Rule 'BITS-JOB' -Title 'BITS job transferring from a non-Microsoft URL' -Severity medium -Technique 'T1197' -Time $t -Source $src -Evidence "[$src] job '$($d['name'])' $url" -Key $url -Domain $h -User $evUser
            Test-IRDomain $h $t $src $null $evUser
            Add-IRTimeline $t $src '59' 'command-and-control' "BITS job '$($d['name'])' started: $url" $evUser -Keep
        }
        'Microsoft-Windows-WinRM/Operational' {
            Add-IRFinding -Rule 'WINRM-INBOUND' -Title 'Inbound WinRM / PowerShell remoting session' -Severity low -Technique 'T1021.006' -Time $t -Source $src -Evidence "[$src] shell created for $evUser $($d['resourceUri'])" -Key ([string]$evUser) -User $evUser
            Add-IRTimeline $t $src '91' 'lateral-movement' "WinRM shell created for $evUser" $evUser -Keep
        }
        'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' {
            $mod = [string]$d['ModifyingApplication']; $app = [string]$d['ApplicationPath']; $rn = [string]$d['RuleName']
            if ($id -in @(2004, 2097)) {
                if ((Get-IRPathRisk $app) -or $mod -match '(?i)\\(netsh|powershell|pwsh|cmd|wmic)\.exe$') {
                    Add-IRFinding -Rule 'FW-RULE-ADDED' -Title "Firewall rule added: $rn" -Severity $(if (Get-IRPathRisk $app) { 'medium' } else { 'low' }) -Technique 'T1562.004' -Time $t -Source $src `
                        -Evidence "[$src] '$rn' for $app (direction $($d['Direction']), action $($d['Action']), ports $($d['LocalPorts'])) by $mod" -Key $rn -File $app
                }
                Add-IRTimeline $t $src ([string]$id) 'defense-evasion' "Firewall rule added: '$rn' for $app by $(Get-IRLeaf $mod)" $null
            } elseif ($id -eq 2003) {
                $val = [string]$d['SettingValueString']; if (-not $val) { $val = [string]$d['SettingValue'] }
                if ($d['SettingType'] -eq '1' -and $val -match '^(no|false|off|0|0x0|0+)$') {
                    Add-IRFinding -Rule 'FIREWALL-DISABLED-EVENT' -Title 'Windows Firewall turned off' -Severity high -Technique 'T1562.004' -Time $t -Source $src -Evidence "[$src] profile $($d['ProfileChanged']) disabled by $mod" -Key ([string]$d['ProfileChanged'])
                }
                Add-IRTimeline $t $src '2003' 'defense-evasion' "Firewall setting changed in profile $($d['ProfileChanged']) by $(Get-IRLeaf $mod)" $null
            }
        }
        'Microsoft-Windows-SMBServer/Security' {
            Add-IRFail $t ([string]$d['UserName']) (([string]$d['ClientName']).TrimStart('\')) $null $src
        }
        'Application' {
            if ($E.prov -match 'ESENT' -and $id -in @(325, 326, 327)) {
                $txt = ($d.Values | ForEach-Object { [string]$_ }) -join ' '
                if ($txt -match '(?i)ntds\.dit' -and $txt -notmatch '(?i)\\windows\\ntds\\') {
                    Add-IRFinding -Rule 'NTDS-COPY' -Title 'Copy of the AD database (ntds.dit) opened' -Severity high -Technique 'T1003.003' -Time $t -Source $src -Evidence "[$src] $(Limit-IRText $txt 400)" -Key $txt
                }
                Add-IRTimeline $t $src ([string]$id) 'credential-access' "ESENT database event: $(Limit-IRText $txt 250)" $null
            } elseif ($E.prov -match 'MsiInstaller' -and $id -in @(1033, 11707)) {
                $prod = [string]$d['Data0']
                Test-IRTool -Name $prod -Path $null -Time $t -Source $src -User $evUser
                Add-IRTimeline $t $src ([string]$id) 'system' "Software installed: $prod" $evUser -Keep
            }
        }
    }
}

function Invoke-IREventAnalysis {
    $Script:InEventPass = $true
    foreach ($s in $Script:EventSpecs) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $file = Get-IREventFile $s.log
        $evs = @()
        if ($file) {
            $evs = @(Read-IREventSet $s.log $s.ids ([string]$s.extra))
            if ($s.log -eq 'Microsoft-Windows-PowerShell/Operational') { $evs = @(Select-IRScriptBlocks $evs) }
            foreach ($ev in $evs) {
                if (-not $ev.t) { continue }
                Start-IRItem
                $before = $Script:Timeline.Count
                try { Invoke-IREventRule $ev } catch {
                    $Script:RuleErrors++
                    if ($Script:RuleErrors -le 10) { Write-IRLog "  rule error on $($ev.log) $($ev.id): $($_.Exception.Message)" 'WARN' }
                }
                if ($Script:Timeline.Count -eq $before) {
                    $parts = @($ev.d.GetEnumerator() | Where-Object { $_.Value -and ([string]$_.Value).Trim() -and [string]$_.Value -ne '-' } | Select-Object -First 8 | ForEach-Object { "$($_.Key)=$(Limit-IRText ([string]$_.Value) 80)" })
                    $who = $null
                    if ($ev.sid) { $who = Resolve-IRSid $ev.sid }
                    Add-IRTimeline $ev.t "$($Script:LogShort[$ev.log]) $($ev.id)" ([string]$ev.id) 'event' ($parts -join '; ') $who -Keep
                }
            }
        }
        $sw.Stop()
        $Script:EventCount += $evs.Count
        $Script:ParseStats.Add([pscustomobject]@{ log = $s.log; event_ids = ($s.ids -join ', '); events = $evs.Count; seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); available = [bool]$file })
        if ($evs.Count) { Write-IRLog ("  {0} [{1}]: {2} events" -f $Script:LogShort[$s.log], ($s.ids -join ','), $evs.Count) }
    }
    $Script:Hits = $null
    $Script:InEventPass = $false
}

#endregion

#region ===== Analysis: correlation across events =====

function Set-IRFindingLast([string]$Key, $Time) {
    $f = $Script:Findings[$Key]
    $iso = Get-IRIso $Time
    if ($f -and $iso -and (-not $f.last_seen -or [string]::CompareOrdinal($iso, $f.last_seen) -gt 0)) { $f.last_seen = $iso }
}

function Invoke-IRCorrelation {
    # Brute force and password spraying, per source address / workstation.
    $groups = @{}
    foreach ($f in $Script:Fails) {
        if (-not $groups.ContainsKey($f.src)) { $groups[$f.src] = [System.Collections.Generic.List[object]]::new() }
        $groups[$f.src].Add($f)
    }
    foreach ($src in @($groups.Keys)) {
        $list = @($groups[$src] | Sort-Object { $_.t })
        $n = $list.Count
        if ($n -lt 10) { continue }
        $max = 0; $j = 0
        for ($i = 0; $i -lt $n; $i++) {
            while (($list[$i].t - $list[$j].t).TotalMinutes -gt 30) { $j++ }
            if ($i - $j + 1 -gt $max) { $max = $i - $j + 1 }
        }
        if ($max -lt 10 -and $n -lt 30) { continue }
        $users = @{}; foreach ($x in $list) { if ($x.u) { $users[[string]$x.u] = 1 } }
        $first = $list[0].t; $last = $list[$n - 1].t
        $ip = $list[0].ip
        $isIp = Test-IRRealIp $ip
        $spray = $users.Count -ge 5
        $rule = if ($spray) { 'PASSWORD-SPRAY' } else { 'BRUTE-FORCE' }
        $title = if ($spray) { "Password spraying from $src ($($users.Count) accounts)" } else { "Brute force from $src" }
        $sample = @($users.Keys | Select-Object -First 12)
        $srcs = (@($list | ForEach-Object { $_.s } | Select-Object -Unique) -join ', ')
        Start-IRItem
        Add-IRFinding -Rule $rule -Title $title -Severity high -Technique $(if ($spray) { 'T1110.003' } else { 'T1110.001' }) -Time $first -Source $srcs `
            -Evidence "$n failed logons from $src between $(Get-IRIso $first) and $(Get-IRIso $last), up to $max within 30 minutes, $($users.Count) account(s): $($sample -join ', ')" `
            -Key $src -Ip $(if ($isIp) { $ip } else { $null }) -User $sample
        Set-IRFindingLast "$rule|$($src.ToLowerInvariant())" $last
        Add-IRTimeline $first 'Security' 'correlation' 'credential-access' "$title`: $n failed logons until $(Get-IRIso $last)" $null -Keep
        if ($isIp) {
            $ok = @($Script:LogonOk | Where-Object { $_.ip -eq $ip -and $_.t -ge $first -and $_.t -le $last.AddHours(6) } | Sort-Object { $_.t })
            if ($ok.Count) {
                $okUsers = @($ok | ForEach-Object { $_.u } | Select-Object -Unique)
                Start-IRItem
                Add-IRFinding -Rule 'BRUTE-SUCCESS' -Title "Successful logon after brute force from $ip" -Severity critical -Technique 'T1078' -Time $ok[0].t -Source 'Security 4624/4625' `
                    -Evidence "$($ok.Count) successful logon(s) as $($okUsers -join ', ') from $ip after $n failures (first success $(Get-IRIso $ok[0].t))" -Key $ip -Ip $ip -User $okUsers
                Add-IRTimeline $ok[0].t 'Security' 'correlation' 'logon' "Successful logon as $($ok[0].u) from $ip after $n failed attempts" $ok[0].u -Keep
            }
        }
    }

    # Kerberoasting: many RC4 service tickets for different SPNs from one client in a short window.
    $byIp = @{}
    foreach ($x in $Script:Tgs) {
        if (-not $byIp.ContainsKey($x.ip)) { $byIp[$x.ip] = [System.Collections.Generic.List[object]]::new() }
        $byIp[$x.ip].Add($x)
    }
    foreach ($ip in @($byIp.Keys)) {
        $list = @($byIp[$ip] | Sort-Object { $_.t })
        $best = 0; $bi = 0; $j = 0
        for ($i = 0; $i -lt $list.Count; $i++) {
            while (($list[$i].t - $list[$j].t).TotalMinutes -gt 10) { $j++ }
            $svcs = @{}; for ($k = $j; $k -le $i; $k++) { $svcs[$list[$k].svc] = 1 }
            if ($svcs.Count -gt $best) { $best = $svcs.Count; $bi = $j }
        }
        if ($best -ge 5) {
            $names = @($list | ForEach-Object { $_.svc } | Select-Object -Unique | Select-Object -First 15)
            Start-IRItem
            Add-IRFinding -Rule 'KERBEROAST' -Title "Kerberoasting: RC4 service tickets for $best services from $ip" -Severity high -Technique 'T1558.003' -Time $list[$bi].t -Source 'Security 4769' `
                -Evidence "RC4 (0x17) tickets requested from $ip by $(@($list | ForEach-Object { $_.u } | Select-Object -Unique) -join ', '): $($names -join ', ')" -Key $ip -Ip $ip -User @($list | ForEach-Object { $_.u } | Select-Object -Unique)
            Add-IRTimeline $list[$bi].t 'Security' 'correlation' 'credential-access' "Kerberoasting from $ip ($best services in 10 minutes)" $null -Keep
        }
    }

    # Discovery bursts: >= 5 different discovery commands covering >= 3 techniques within 10 minutes.
    $byUser = @{}
    foreach ($x in $Script:DiscHits) {
        if (-not $byUser.ContainsKey($x.u)) { $byUser[$x.u] = [System.Collections.Generic.List[object]]::new() }
        $byUser[$x.u].Add($x)
    }
    foreach ($u in @($byUser.Keys)) {
        $list = @($byUser[$u] | Sort-Object { $_.t })
        $i = 0
        while ($i -lt $list.Count) {
            $j = $i; $cmds = @{}; $techs = @{}
            while ($j -lt $list.Count -and ($list[$j].t - $list[$i].t).TotalMinutes -le 10) { $cmds[$list[$j].cmd] = 1; $techs[$list[$j].tech] = 1 + [int]$techs[$list[$j].tech]; $j++ }
            if ($cmds.Count -ge 5 -and $techs.Count -ge 3) {
                $top = @($techs.GetEnumerator() | Sort-Object Value -Descending)[0].Key
                Start-IRItem
                Add-IRFinding -Rule 'DISCOVERY-BURST' -Title "Burst of $($cmds.Count) discovery commands by $u" -Severity $(if ($cmds.Count -ge 10) { 'high' } else { 'medium' }) -Technique $top `
                    -Time $list[$i].t -Source 'Process creation' -Evidence ("Within 10 minutes: " + ((@($cmds.Keys) | Select-Object -First 12) -join ' ; ')) -Key "$u|$(Get-IRIso $list[$i].t)" -User $u
                Set-IRFindingLast "DISCOVERY-BURST|$("$u|$(Get-IRIso $list[$i].t)".ToLowerInvariant())" $list[$j - 1].t
                Add-IRTimeline $list[$i].t 'Process creation' 'correlation' 'discovery' "Discovery burst by $u`: $($cmds.Count) commands ($((@($techs.Keys)) -join ', '))" $u -Keep
                $i = $j
            } else { $i++ }
        }
    }

    # Task created and deleted shortly after: typical of remote execution (ate(?:)xec, schtasks /s).
    $tasks = @{}
    foreach ($x in $Script:TaskEvents) {
        if (-not $tasks.ContainsKey($x.name)) { $tasks[$x.name] = [System.Collections.Generic.List[object]]::new() }
        $tasks[$x.name].Add($x)
    }
    foreach ($name in @($tasks.Keys)) {
        $c = @($tasks[$name] | Where-Object { $_.op -eq 'create' } | Sort-Object { $_.t })
        $del = @($tasks[$name] | Where-Object { $_.op -eq 'delete' } | Sort-Object { $_.t })
        foreach ($cr in $c) {
            $dl = $del | Where-Object { $_.t -ge $cr.t -and ($_.t - $cr.t).TotalMinutes -le 60 } | Select-Object -First 1
            if ($dl) {
                Start-IRItem
                Add-IRFinding -Rule 'TASK-CREATE-DELETE' -Title "Scheduled task created and deleted within an hour: $name" -Severity high -Technique 'T1053.005' -Time $cr.t -Source 'Security 4698/4699, TaskScheduler 106/141' `
                    -Evidence "$name created $(Get-IRIso $cr.t), deleted $(Get-IRIso $dl.t) - typical of remote execution tools (ate(?:)xec, schtasks /s)" -Key $name
                Add-IRTimeline $cr.t 'TaskScheduler' 'correlation' 'execution' "Task $name created and deleted after $([math]::Round(($dl.t - $cr.t).TotalMinutes, 1)) minutes" $null -Keep
                break
            }
        }
    }

    # New account placed in a privileged group.
    foreach ($g in $Script:GroupAdds) {
        if (-not $g.priv) { continue }
        $ct = $null
        if ($g.sid -and $Script:Created.ContainsKey($g.sid)) { $ct = $Script:Created[$g.sid] }
        else { $leaf = ([string]$g.member -split '\\')[-1].ToLowerInvariant(); if ($Script:Created.ContainsKey($leaf)) { $ct = $Script:Created[$leaf] } }
        if ($ct -and [math]::Abs(($g.t - $ct).TotalHours) -le 24) {
            Start-IRItem
            Add-IRFinding -Rule 'NEW-ADMIN-ACCOUNT' -Title "New account $($g.member) added to $($g.group)" -Severity high -Technique 'T1136.001' -Time $g.t -Source 'Security 4720 + 4732/4728/4756' `
                -Evidence "Account created $(Get-IRIso $ct) and added to $($g.group) $(Get-IRIso $g.t)" -Key "$($g.member)|$($g.group)" -User $g.member
            Add-IRTimeline $g.t 'Security' 'correlation' 'persistence' "New account $($g.member) added to privileged group $($g.group)" $g.member -Keep
        }
    }

    # One account using explicit credentials against several hosts.
    $bySubj = @{}
    foreach ($x in $Script:ExplicitCred) {
        if (-not $bySubj.ContainsKey([string]$x.u)) { $bySubj[[string]$x.u] = [System.Collections.Generic.List[object]]::new() }
        $bySubj[[string]$x.u].Add($x)
    }
    foreach ($u in @($bySubj.Keys)) {
        $targets = @($bySubj[$u] | ForEach-Object { $_.target } | Select-Object -Unique)
        if ($targets.Count -ge 3) {
            $first = ($bySubj[$u] | Sort-Object { $_.t } | Select-Object -First 1).t
            Start-IRItem
            Add-IRFinding -Rule 'EXPLICIT-CRED-SPREAD' -Title "$u used explicit credentials against $($targets.Count) hosts" -Severity medium -Technique 'T1078' -Time $first -Source 'Security 4648' `
                -Evidence "Targets: $((@($targets) | Select-Object -First 15) -join ', ')" -Key $u -User $u
            Add-IRTimeline $first 'Security' 'correlation' 'lateral-movement' "$u used explicit credentials against $($targets.Count) hosts" $u -Keep
        }
    }
    $Script:Hits = $null
}

#endregion

#region ===== Analysis: live state and artifacts =====

$Script:DoubleExtRx = New-Object Text.RegularExpressions.Regex('\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|rtf|csv|zip)\.(exe|scr|com|pif|js|jse|vbs|vbe|bat|cmd|hta|lnk|ps1|msi)$', $Script:RxOpt)
$Script:LsaDefault = @('msv1_0', 'kerberos', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp', 'scecli', 'rassfm', '""', 'credssp', 'negotiate', 'msoidssp', 'ntlm')

function Get-IRThreatTechnique([string]$Threat) {
    if ($Threat -match '(?i)stealer|lumma|redline|vidar|raccoon|stealc|rhadamanthys|metastealer|risepro') { return 'T1555.003' }
    if ($Threat -match '(?i)mimik(?:)atz|lsass|credential|pws|laza(?:)gne') { return 'T1003' }
    if ($Threat -match '(?i)ransom') { return 'T1486' }
    if ($Threat -match '(?i)coinminer|miner|xmrig') { return 'T1496' }
    if ($Threat -match '(?i)cobalts(?:)trike|meterp(?:)reter|sli(?:)ver|backdoor|brute(?:)ratel|hav(?:)oc|asyncrat|remcos|njrat|quasar|dcrat|xworm') { return 'T1071.001' }
    if ($Threat -match '(?i)autokms|kmsactivator|keygen|crack') { return 'T1204.002' }
    return $null
}

function Invoke-IRLiveAnalysis {
    $ds = $Script:D
    $cfg = @($ds['security_config'])[0]
    if ($cfg -and $cfg.rdp_port) { $Script:RdpPort = [int]$cfg.rdp_port }

    foreach ($p in $ds['processes']) {
        if ($Script:SelfPid -and ([int64]$p.pid -eq $Script:SelfPid -or [int64]$p.ppid -eq $Script:SelfPid)) { continue }
        Start-IRItem
        $src = 'Live: running process'
        $img = if ($p.path) { [string]$p.path } else { [string]$p.name }
        $t = Get-IRIso $p.started
        Invoke-IRProcessRules -Time $t -Source $src -Image $img -Cmd ([string]$p.command_line) -Parent ([string]$p.parent_name) -User ([string]$p.user) -Hash ([string]$p.sha256)
        if ($p.signature -eq 'HashMismatch') {
            Add-IRFinding -Rule 'SIG-MISMATCH' -Title "Running binary with an invalid signature: $(Get-IRLeaf $img)" -Severity high -Technique 'T1036.005' -Time $t -Source $src -Evidence "[$src] $img (pid $($p.pid))" -Key (Get-IRPathKey $img) -File $img -Hash $p.sha256 -Process $img
        } elseif ($p.signature -eq 'NotSigned' -and $p.path -and $Script:UserWritableRx.IsMatch([string]$p.path)) {
            Add-IRFinding -Rule 'UNSIGNED-USERDIR-PROC' -Title "Unsigned program running from a user-writable folder: $(Get-IRLeaf $img)" -Severity medium -Technique 'T1204.002' -Time $t -Source $src `
                -Evidence "[$src] $img (pid $($p.pid), parent $($p.parent_name), user $($p.user)) $(Limit-IRText $p.command_line 300)" -Key (Get-IRPathKey $img) -File $img -Hash $p.sha256 -Process $img -User $p.user
        }
        Add-IRTimeline $t $src 'process' 'process' "Running: $(Get-IRLeaf $p.parent_name) -> $(if ($p.command_line) { $p.command_line } else { $img }) (pid $($p.pid), $($p.user))" $p.user -Keep:($p.path -and -not $Script:TrustedDirRx.IsMatch([string]$p.path))
    }

    foreach ($c in $ds['network_connections']) {
        if ($Script:SelfPid -and [int64]$c.pid -eq $Script:SelfPid) { continue }
        Start-IRItem
        $src = 'Live: network connection'
        $img = if ($c.path) { [string]$c.path } else { [string]$c.process }
        if ([string]$c.state -match '^Listen') { Test-IRConnection -Source $src -Image $img -LocalPort $c.local_port -Listen; continue }
        if (-not $c.remote_address) { continue }
        $lp = [int]$c.local_port
        $inbound = $c.protocol -eq 'TCP' -and ($lp -in @(3389, 445, 5985, 5986, 22) -or ($Script:RdpPort -and $lp -eq $Script:RdpPort))
        Test-IRConnection -Time (Get-IRIso $c.created) -Source $src -Image $img -RemoteIp ([string]$c.remote_address) -RemotePort $c.remote_port -LocalPort $lp -Inbound:$inbound
        Add-IRTimeline $c.created $src 'network' 'network' "$(Get-IRLeaf $img) $($c.local_address):$($c.local_port) <-> $($c.remote_address):$($c.remote_port) $($c.state)" $null
    }

    foreach ($r in $ds['dns_cache']) { Start-IRItem; Test-IRDomain ([string]$r.name) $null 'Live: DNS cache' $null $null }

    foreach ($h in $ds['hosts_file']) {
        $names = [string]$h.names
        if ($names -match '^\s*(localhost|localhost\.localdomain|ip6-\w+)?\s*$') { continue }
        Start-IRItem
        $sec = $names -match '(?i)(microsoft|windowsupdate|defender|smartscreen|virustotal|kaspersky|eset|symantec|norton|mcafee|sophos|crowdstrike|sentinelone|malwarebytes|bitdefender|avast|trendmicro|carbonblack|cylance|paloaltonetworks|fortinet)'
        Add-IRFinding -Rule $(if ($sec) { 'HOSTS-SECURITY' } else { 'HOSTS-ENTRY' }) -Title $(if ($sec) { 'Hosts file redirects security / update domains' } else { "Custom hosts file entry: $names" }) `
            -Severity $(if ($sec) { 'high' } else { 'low' }) -Technique 'T1565.001' -Source 'Live: hosts file' -Evidence "$($h.address) $names" -Key "$($h.address) $names" -Domain @($names -split '\s+')
    }

    foreach ($p in $ds['port_proxy']) {
        Start-IRItem
        Add-IRFinding -Rule 'PORTPROXY-CONFIG' -Title "Port forwarding configured: $($p.listen) -> $($p.connect)" -Severity high -Technique 'T1090' -Source 'Live: netsh portproxy' -Evidence "$($p.type) listen $($p.listen) -> connect $($p.connect)" -Key ([string]$p.listen)
    }
    foreach ($p in $ds['proxy_settings']) {
        if ([string]$p.enabled -eq '1' -and [string]$p.server -match '(?i)^(https?://)?(127\.|localhost|\[?::1)') {
            Start-IRItem
            Add-IRFinding -Rule 'LOCAL-PROXY' -Title "Internet traffic of $($p.scope) routed through a local proxy" -Severity medium -Technique 'T1090' -Source 'Live: proxy settings' -Evidence "$($p.scope): $($p.server)" -Key "$($p.scope)|$($p.server)" -User $p.scope
        }
    }
    foreach ($s in $ds['smb_sessions']) {
        if (Test-IRPublicIp ([string]$s.client)) {
            Start-IRItem
            Add-IRFinding -Rule 'INBOUND-PUBLIC' -Title 'Inbound SMB connection from a public IP address' -Severity high -Technique 'T1133' -Source 'Live: SMB sessions' -Evidence "$($s.client) as $($s.user), $($s.opens) open files" -Key "SMB|$($s.client)" -Ip $s.client -User $s.user
        }
        Start-IRItem
        Add-IRTimeline $s.connected_since 'Live: SMB sessions' 'smb' 'lateral-movement' "SMB session from $($s.client) as $($s.user) ($($s.opens) open files)" $s.user -Keep
    }

    foreach ($u in $ds['local_users']) {
        Start-IRItem
        if ($u.enabled -eq $true -and [string]$u.sid -match '-501$') {
            Add-IRFinding -Rule 'GUEST-ENABLED' -Title 'Built-in Guest account is enabled' -Severity medium -Technique 'T1078.001' -Source 'Live: local users' -Evidence "$($u.name) enabled" -Key $u.name -User $u.name
        }
        if ($u.enabled -eq $true -and $u.password_required -eq $false) {
            Add-IRFinding -Rule 'NO-PASSWORD-REQUIRED' -Title "Enabled local account does not require a password: $($u.name)" -Severity low -Technique 'T1078.003' -Source 'Live: local users' -Evidence "$($u.name) PasswordRequired=False" -Key $u.name -User $u.name
        }
        Add-IRTimeline $u.last_logon 'Live: local users' 'account' 'account' "Local account $($u.name) last logon" $u.name -Keep
        Start-IRItem
        Add-IRTimeline $u.password_last_set 'Live: local users' 'account' 'account' "Password set for local account $($u.name)" $u.name -Keep
    }

    foreach ($s in $ds['services']) {
        Start-IRItem
        $src = 'Live: service'
        $cmd = [string]$s.command; $img = [string]$s.image
        $target = if ($s.service_dll) { [string]$s.service_dll } else { $img }
        Test-IRText -Text $cmd -Scope 'proc' -Source "$src $($s.name)"
        Test-IRTool -Name (Get-IRLeaf $target) -Path $target -Source $src -Hash $s.sha256
        Test-IRTool -Name ([string]$s.name) -Path $target -Source $src
        $risk = Get-IRPathRisk $target
        $unsigned = $s.signature -in @('NotSigned', 'HashMismatch')
        $interp = $Script:InterpRx.IsMatch($cmd) -and $cmd -notmatch '(?i)^"?[a-z]:\\windows\\(system32|syswow64)\\svchost\.exe'
        if ($risk -or ($unsigned -and $s.start_mode -eq 'Auto') -or $interp -or $s.signature -eq 'HashMismatch') {
            $sev = if ($risk -or ($unsigned -and $interp) -or $s.signature -eq 'HashMismatch') { 'high' } else { 'medium' }
            Add-IRFinding -Rule 'SERVICE-SUSPICIOUS' -Title "Suspicious service: $($s.name)" -Severity $sev -Technique 'T1543.003' -Source $src `
                -Evidence "[$src] $($s.name) ($($s.display_name)) $($s.state)/$($s.start_mode) as $($s.account): $cmd$(if ($s.service_dll) { " ServiceDll=$($s.service_dll)" }) [signature $($s.signature) $($s.signer)]" `
                -Key ([string]$s.name) -File $target -Hash $s.sha256
        }
    }

    foreach ($drv in $ds['drivers']) {
        Start-IRItem
        $leaf = Get-IRLeaf $drv.path
        if ($leaf -and $Script:VulnDriverRx.IsMatch($leaf)) {
            Add-IRFinding -Rule 'BYOVD' -Title "Known vulnerable driver present: $leaf" -Severity $(if ($drv.state -eq 'Running') { 'high' } else { 'medium' }) -Technique 'T1068' -Source 'Live: drivers' -Evidence "$($drv.name) $($drv.path) $($drv.state) [$($drv.signature) $($drv.signer)]" -Key $leaf -File $drv.path
        }
        if ($drv.state -eq 'Running' -and $drv.signature -in @('NotSigned', 'HashMismatch')) {
            Add-IRFinding -Rule 'DRIVER-UNSIGNED' -Title "Unsigned / tampered kernel driver running: $($drv.name)" -Severity high -Technique 'T1014' -Source 'Live: drivers' -Evidence "$($drv.name) $($drv.path) [$($drv.signature)]" -Key ([string]$drv.path) -File $drv.path
        }
    }

    foreach ($a in $ds['autoruns']) {
        Start-IRItem
        $cat = [string]$a.category; $cmd = [string]$a.command; $img = [string]$a.image; $sig = [string]$a.signature; $user = [string]$a.user
        $src = "Live: autorun ($cat)"
        $ev = "[$src] $($a.location) | $($a.name) = $cmd [signature $sig $($a.signer)]"
        $msSigned = $sig -eq 'Valid' -and [string]$a.signer -match '^Microsoft'
        $unsigned = $sig -in @('NotSigned', 'HashMismatch')
        $risk = Get-IRPathRisk $img
        Test-IRText -Text $cmd -Scope 'proc' -Source $src -User $user -Time $a.modified
        Test-IRTool -Name (Get-IRLeaf $img) -Path $img -Source $src -User $user -Hash $a.sha256
        $hit = $null
        switch ($cat) {
            'Winlogon' {
                $v = $cmd.Trim().TrimEnd(',').Trim().ToLowerInvariant()
                $ok = $false
                if ($a.name -eq 'Shell') { $ok = $v -match '^(explorer\.exe|[a-z]:\\windows\\explorer\.exe)$' }
                elseif ($a.name -eq 'Userinit') { $ok = $v -match '^([a-z]:\\windows\\system32\\)?userinit\.exe$' }
                if (-not $ok) { $hit = @('AUTORUN-WINLOGON', 'high', 'T1547.004', "Winlogon $($a.name) value is not the Windows default") }
            }
            'IFEO debugger' {
                if ([string]$a.name -match '(?i)^(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe$') { $hit = @('ACCESSIBILITY-BACKDOOR', 'critical', 'T1546.008', 'Accessibility feature backdoor (sticky keys / utilman)') }
                elseif ($sig -eq 'Valid') { $hit = @('AUTORUN-IFEO', 'low', 'T1546.012', "IFEO debugger set for $($a.name)") }
                else { $hit = @('AUTORUN-IFEO', 'high', 'T1546.012', "IFEO debugger set for $($a.name)") }
            }
            'SilentProcessExit monitor' { $hit = @('AUTORUN-SPE', 'high', 'T1546.012', "SilentProcessExit monitor process for $($a.name)") }
            'AppInit DLL' { $hit = @('AUTORUN-APPINIT', 'high', 'T1546.010', 'AppInit_DLLs configured') }
            'LSA package' { if (([string]$a.name).Trim().ToLowerInvariant() -notin $Script:LsaDefault) { $hit = @('AUTORUN-LSA', 'high', 'T1547.005', "Non-default LSA package: $($a.name)") } }
            'BootExecute' { if ($cmd -notmatch '^\s*autocheck autochk \*\s*$') { $hit = @('AUTORUN-BOOTEXECUTE', 'high', 'T1547', 'BootExecute contains a non-default entry') } }
            'Netsh helper' { if (-not $msSigned) { $hit = @('AUTORUN-NETSH', 'high', 'T1546.007', "Non-Microsoft netsh helper DLL: $($a.name)") } }
            'Print monitor' { if ($sig -ne 'Valid') { $hit = @('AUTORUN-PRINTMON', $(if ($risk -or $unsigned) { 'high' } else { 'medium' }), 'T1547.010', "Print monitor DLL is unsigned or missing: $($a.name)") } }
            'Screensaver' { if ($img -notmatch '(?i)\\windows\\(system32|syswow64)\\[^\\]+\.scr$') { $hit = @('AUTORUN-SCREENSAVER', 'high', 'T1546.002', 'Screensaver set to a non-system program') } }
            'COM object (user)' { if ($risk -or ($unsigned -and $img -notmatch '(?i)\\program files\\windowsapps\\')) { $hit = @('AUTORUN-COM-HIJACK', $(if ($risk) { 'high' } else { 'medium' }), 'T1546.015', "Per-user COM server (possible COM hijack): $($a.name)") } }
            'Office test' { $hit = @('AUTORUN-OFFICETEST', 'high', 'T1137.002', 'Office Test persistence key set') }
            default {
                $interp = $Script:InterpRx.IsMatch($cmd)
                if ($risk -or ($unsigned -and $interp) -or $sig -eq 'HashMismatch') { $hit = @('AUTORUN-SUSPICIOUS', 'high', 'T1547.001', "Suspicious autostart entry: $($a.name)") }
                elseif ($unsigned -or ($interp -and -not $msSigned)) { $hit = @('AUTORUN-SUSPICIOUS', 'medium', 'T1547.001', "Autostart entry to review: $($a.name)") }
            }
        }
        if ($hit) {
            Add-IRFinding -Rule $hit[0] -Title $hit[3] -Severity $hit[1] -Technique $hit[2] -Time $a.modified -Source $src -Evidence $ev -Key "$($a.location)|$($a.name)" -User $user -File $img -Hash $a.sha256
        }
        Add-IRTimeline $a.modified $src 'autorun' 'persistence' "Startup item created: $($a.name) -> $cmd" $user -Keep:($cat -eq 'Startup folder')
    }

    foreach ($tk in $ds['scheduled_tasks']) {
        Start-IRItem
        $src = 'Live: scheduled task'
        $name = [string]$tk.path; $cmd = [string]$tk.command
        $t = if ($tk.registered) { Get-IRIso $tk.registered } else { Get-IRIso $tk.file_created }
        $hid = [bool]$tk.hidden -and -not ($tk.signature -eq 'Valid' -and $tk.image -and $Script:TrustedDirRx.IsMatch([string]$tk.image))
        Test-IRTaskDefinition $null $src $name $cmd ([string]$tk.run_as) $hid 'TASK-SUSPICIOUS'
        if ($name -notmatch '^\\Microsoft\\' -and $tk.image -and $tk.signature -in @('NotSigned', 'HashMismatch')) {
            Add-IRFinding -Rule 'TASK-UNSIGNED' -Title "Scheduled task runs an unsigned program: $name" -Severity medium -Technique 'T1053.005' -Source $src -Evidence "[$src] $name -> $cmd (author $($tk.author), run as $($tk.run_as))" -Key $name -File $tk.image
        }
        Add-IRTimeline $t $src 'task' 'persistence' "Scheduled task present: $name -> $cmd (author $($tk.author), run as $($tk.run_as))" $tk.run_as -Keep:($name -notmatch '^\\Microsoft\\')
    }

    foreach ($w in $ds['wmi_persistence']) {
        if ($w.type -notin @('CommandLineEventConsumer', 'ActiveScriptEventConsumer')) { continue }
        Start-IRItem
        $benign = [string]$w.name -match 'BVTConsumer|SCM Event Log Consumer'
        Add-IRFinding -Rule 'WMI-CONSUMER' -Title "WMI $($w.type): $($w.name)" -Severity $(if ($benign) { 'low' } else { 'high' }) -Technique 'T1546.003' -Source 'Live: WMI subscription' `
            -Evidence "$($w.namespace) $($w.type) '$($w.name)': $(Limit-IRText $w.detail 400)" -Key ([string]$w.name)
        Test-IRText -Text ([string]$w.detail) -Scope 'any' -Source 'Live: WMI subscription'
    }

    $st = @($ds['defender_status'])[0]
    if ($st) {
        Start-IRItem
        if ($st.realtime_protection -eq $false) { Add-IRFinding -Rule 'DEFENDER-RTP-OFF' -Title 'Defender real-time protection disabled' -Severity high -Technique 'T1562.001' -Source 'Live: Defender status' -Evidence 'RealTimeProtectionEnabled = False' -Key 'rtp' }
        if ($st.antivirus_enabled -eq $false) { Add-IRFinding -Rule 'DEFENDER-AV-OFF' -Title 'Microsoft Defender antivirus disabled' -Severity high -Technique 'T1562.001' -Source 'Live: Defender status' -Evidence "AntivirusEnabled = False (mode $($st.running_mode))" -Key 'av' }
    }
    $pref = @($ds['defender_preferences'])[0]
    if ($pref) {
        foreach ($n in 'disable_realtime_monitoring', 'disable_behavior_monitoring', 'disable_ioav_protection', 'disable_script_scanning', 'disable_block_at_first_seen') {
            if ($pref.$n -eq $true) { Add-IRFinding -Rule 'DEFENDER-SETTING-DISABLED' -Title 'Defender protection setting disabled' -Severity high -Technique 'T1562.001' -Source 'Live: Defender preferences' -Evidence "$n = True" -Key $n }
        }
    }
    foreach ($e in $ds['defender_exclusions']) {
        Start-IRItem
        $v = [string]$e.value
        $broad = ($e.type -eq 'Process') -or ($e.type -eq 'Extension' -and $v -match '(?i)^\.?(exe|dll|ps1|bat|cmd|vbs|js|hta|scr)$') -or
        ($v -match '(?i)^[a-z]:\\?$|\\(users|temp|programdata|windows\\temp|appdata|downloads|public)(\\|$)|^%(temp|appdata|userprofile|programdata)%')
        Add-IRFinding -Rule 'DEFENDER-EXCLUSION' -Title "Defender exclusion ($($e.type)): $v" -Severity $(if ($broad) { 'high' } else { 'medium' }) -Technique 'T1562.001' -Source "Live: $($e.source)" -Evidence "$($e.type) exclusion '$v' ($($e.source))" -Key "$($e.type)|$v"
    }
    foreach ($th in $ds['defender_threats']) {
        Start-IRItem
        $res = [string]$th.resources
        if (Test-IRSelfResource $res) { $Script:SelfEvents++; continue }
        $file = $res
        if ($res -match 'file:_([^;]+)') { $file = $Matches[1] }
        $threat = [string]$th.threat
        $sev = if ($th.action_success -eq $false -or $threat -match '(?i)ransom|backdoor|cobalts(?:)trike|meterp(?:)reter|mimik(?:)atz|hacktool|brute(?:)ratel|sli(?:)ver' -or [int]$th.severity_id -ge 5) { 'critical' } else { 'high' }
        Add-IRFinding -Rule 'DEFENDER-DETECTION' -Title "Microsoft Defender detection: $threat" -Severity $sev -Technique (Get-IRThreatTechnique $threat) -Time $th.detected -Source 'Live: Defender history' `
            -Evidence "$threat in $res (process $($th.process), user $($th.user), remediated $($th.remediated), success $($th.action_success))" -Key "$threat|$file" -File $file -Process $th.process -User $th.user
        Add-IRTimeline $th.detected 'Live: Defender history' 'threat' 'malware' "Defender detected $threat ($res), process $($th.process)" $th.user -Keep
    }

    foreach ($fp in $ds['firewall_profiles']) {
        if ([string]$fp.enabled -match '^(False|0)$') {
            Start-IRItem
            Add-IRFinding -Rule 'FIREWALL-PROFILE-OFF' -Title "Windows Firewall disabled for the $($fp.profile) profile" -Severity high -Technique 'T1562.004' -Source 'Live: firewall' -Evidence "$($fp.profile): Enabled=$($fp.enabled)" -Key ([string]$fp.profile)
        }
    }
    foreach ($r in $ds['firewall_rules']) {
        if ($r.direction -eq 'Inbound' -and $r.action -eq 'Allow' -and $r.enabled -eq 'True' -and $r.program -and (Get-IRPathRisk ([string]$r.program))) {
            Start-IRItem
            Add-IRFinding -Rule 'FW-RULE-SUSP' -Title "Inbound firewall rule allows a program in a staging folder: $(Get-IRLeaf $r.program)" -Severity medium -Technique 'T1562.004' -Source 'Live: firewall rules' `
                -Evidence "'$($r.name)' allows $($r.program) ports $($r.local_port) from $($r.remote_address)" -Key ([string]$r.name) -File $r.program
        }
    }

    if ($cfg) {
        Start-IRItem
        if ([string]$cfg.wdigest_use_logon_credential -eq '1') { Add-IRFinding -Rule 'CFG-WDIGEST' -Title 'WDigest cleartext credential caching is enabled' -Severity high -Technique 'T1112' -Source 'Live: security configuration' -Evidence 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest UseLogonCredential = 1' -Key 'wdigest' }
        if ([string]$cfg.uac_enable_lua -eq '0') { Add-IRFinding -Rule 'CFG-UAC-OFF' -Title 'User Account Control is disabled (EnableLUA = 0)' -Severity medium -Technique 'T1548.002' -Source 'Live: security configuration' -Evidence 'EnableLUA = 0' -Key 'uac' }
        if ([string]$cfg.local_account_token_filter_policy -eq '1') { Add-IRFinding -Rule 'CFG-LATFP' -Title 'Remote admin with local accounts enabled (LocalAccountTokenFilterPolicy = 1)' -Severity medium -Technique 'T1112' -Source 'Live: security configuration' -Evidence 'LocalAccountTokenFilterPolicy = 1 enables pass-the-hash with local accounts' -Key 'latfp' }
    }

    foreach ($b in $ds['bam']) {
        Start-IRItem
        $path = [string]$b.path; $src = "Live: $($b.source)"
        Test-IRTool -Name (Get-IRLeaf $path) -Path $path -Time $b.last_run -Source $src -User $b.user
        if (Get-IRPathRisk $path) {
            Add-IRFinding -Rule 'EXEC-SUSP-DIR' -Title "Program executed from a staging / unusual folder: $(Get-IRLeaf $path)" -Severity medium -Technique 'T1204.002' -Time $b.last_run -Source $src -Evidence "[$src] $path (user $($b.user))" -Key (Get-IRPathKey $path) -User $b.user -File $path
        }
        Add-IRTimeline $b.last_run $src 'bam' 'execution' "$($b.source): $path last executed by $($b.user)" $b.user -Keep
    }
    foreach ($u in $ds['userassist']) {
        Start-IRItem
        $prog = [string]$u.program; $src = if ($u.source) { 'Offline hive: UserAssist' } else { 'Live: UserAssist' }
        Test-IRTool -Name (Get-IRLeaf $prog) -Path $prog -Time $u.last_run -Source $src -User $u.user
        if ($prog -notmatch '(?i)\.lnk$' -and (Get-IRPathRisk $prog)) {
            Add-IRFinding -Rule 'EXEC-SUSP-DIR' -Title "Program executed from a staging / unusual folder: $(Get-IRLeaf $prog)" -Severity medium -Technique 'T1204.002' -Time $u.last_run -Source $src -Evidence "[$src] $prog (user $($u.user), $($u.run_count) runs)" -Key (Get-IRPathKey $prog) -User $u.user -File $prog
        }
        Add-IRTimeline $u.last_run $src 'userassist' 'execution' "UserAssist: $prog run $($u.run_count) time(s) by $($u.user)" $u.user -Keep
    }
    foreach ($p in $ds['prefetch']) {
        Start-IRItem
        $exe = ([string]$p.executable).ToLowerInvariant(); $src = 'Live: Prefetch'
        Test-IRTool -Name $exe -Path $null -Time $p.last_run_approx -Source $src
        if ($Script:TyposquatRx.IsMatch($exe)) {
            Add-IRFinding -Rule 'TYPOSQUAT' -Title "Process name imitates a Windows binary: $exe" -Severity high -Technique 'T1036.005' -Time $p.last_run_approx -Source $src -Evidence "[$src] $($p.file)" -Key $exe
        }
        Add-IRTimeline $p.last_run_approx $src 'prefetch' 'execution' "Prefetch: $exe last run (approx.)" $null -Keep
        if ($p.first_run_approx -and (Get-IRIso $p.first_run_approx) -ne (Get-IRIso $p.last_run_approx)) {
            Add-IRTimeline $p.first_run_approx $src 'prefetch' 'execution' "Prefetch: $exe first run (approx.)" $null -Keep
        }
    }
    foreach ($s in $ds['shimcache']) {
        Start-IRItem
        $path = [string]$s.path
        Test-IRTool -Name (Get-IRLeaf $path) -Path $path -Source 'Live: ShimCache'
        if (Get-IRPathRisk $path) {
            Add-IRFinding -Rule 'SHIMCACHE-SUSP-DIR' -Title "Program in a staging folder recorded in ShimCache: $(Get-IRLeaf $path)" -Severity low -Technique 'T1204.002' -Source 'Live: ShimCache' -Evidence "[ShimCache #$($s.order)] $path (modified $($s.file_modified))" -Key (Get-IRPathKey $path) -File $path
        }
    }

    foreach ($h in $ds['powershell_history']) {
        Start-IRItem
        Test-IRText -Text ([string]$h.command) -Scope 'proc' -Source "PSReadLine history ($($h.user), line $($h.line))" -User $h.user
    }
    foreach ($r in $ds['recent_files']) {
        Start-IRItem
        $target = [string]$r.target; $src = 'Live: Recent (LNK)'
        $leaf = if ($target) { Get-IRLeaf $target } else { ([string]$r.name).ToLowerInvariant() }
        Test-IRTool -Name $leaf -Path $target -Time $r.last_opened -Source $src -User $r.user
        if ($Script:DoubleExtRx.IsMatch($leaf)) {
            Add-IRFinding -Rule 'DOUBLE-EXT' -Title 'Double file extension' -Severity high -Technique 'T1036.007' -Time $r.last_opened -Source $src -Evidence "[$src] $($r.user) opened $target" -Key $target -File $target -User $r.user
        }
        if ($target -match '^\\\\[^\\]+\\(admin|[a-z])\$') {
            Add-IRFinding -Rule 'ADMIN-SHARE' -Title 'Admin share opened by a user' -Severity medium -Technique 'T1021.002' -Time $r.last_opened -Source $src -Evidence "[$src] $($r.user) opened $target" -Key $target -User $r.user
        }
        Add-IRTimeline $r.last_opened $src 'lnk' 'user-activity' "$($r.user) opened $(if ($target) { $target } else { $r.name })" $r.user -Keep
    }
    foreach ($r in $ds['recycle_bin']) {
        Start-IRItem
        $p = [string]$r.original_path
        Test-IRTool -Name (Get-IRLeaf $p) -Path $p -Time $r.deleted -Source 'Live: Recycle Bin' -User $r.user
        Add-IRTimeline $r.deleted 'Live: Recycle Bin' 'recycle' 'user-activity' "$($r.user) deleted $p ($([math]::Round([double]$r.size / 1KB)) KB)" $r.user -Keep
    }
    foreach ($m in $ds['user_mru']) {
        Start-IRItem
        $v = [string]$m.value
        switch ([string]$m.type) {
            'RunMRU' { Test-IRText -Text ($v -replace '\\1$', '') -Scope 'proc' -Source "RunMRU ($($m.user))" -User $m.user }
            'RDP MRU' { if ($v) { Add-IRFinding -Rule 'RDP-OUTBOUND' -Title "Outbound Remote Desktop connection to $v" -Severity low -Technique 'T1021.001' -Source "RDP client history ($($m.user))" -Evidence "$($m.user) -> $v" -Key $v -User $m.user } }
            'RDP server' { Add-IRFinding -Rule 'RDP-OUTBOUND' -Title "Outbound Remote Desktop connection to $($m.name)" -Severity low -Technique 'T1021.001' -Source "RDP client history ($($m.user))" -Evidence "$($m.user) -> $($m.name) as $v" -Key ([string]$m.name) -User $m.user }
            default {
                if ($v -match '\\\\[^\\]+\\(admin|[a-z])\$') {
                    Add-IRFinding -Rule 'ADMIN-SHARE' -Title 'Admin share opened by a user' -Severity medium -Technique 'T1021.002' -Source "$($m.type) ($($m.user))" -Evidence "$($m.user): $v" -Key $v -User $m.user
                }
            }
        }
    }

    foreach ($s in $ds['installed_software']) {
        Start-IRItem
        Test-IRTool -Name ([string]$s.name) -Path ([string]$s.location) -Time $s.installed -Source 'Live: installed software'
        Add-IRTimeline $s.installed 'Live: installed software' 'software' 'system' "Software installed: $($s.name) $($s.version) ($($s.publisher), $($s.scope))" $null -Keep
    }
    foreach ($h in $ds['hotfixes']) { Start-IRItem; Add-IRTimeline $h.installed 'Live: updates' 'hotfix' 'system' "Update installed: $($h.id) $($h.description)" $h.by -Keep }
    foreach ($n in $ds['network_history']) {
        Start-IRItem
        Add-IRTimeline $n.first_connected 'Live: network history' 'network' 'network' "First connection to network '$($n.name)'" $null -Keep
        Add-IRTimeline $n.last_connected 'Live: network history' 'network' 'network' "Last connection to network '$($n.name)'" $null -Keep
    }

    foreach ($f in $ds['file_scan']) {
        Start-IRItem
        $path = [string]$f.path; $leaf = Get-IRLeaf $path; $src = 'Live: file scan'
        $ext = ''
        if ($leaf -match '(\.[^.]+)$') { $ext = $Matches[1] }
        $isPe = $Script:PeExt.Contains($ext)
        $zone = $f.zone_id
        $unsigned = $isPe -and $f.signature -in @('NotSigned', 'HashMismatch')
        $common = @{ Time = $f.created; Source = $src; File = $path; Hash = $f.sha256 }
        Test-IRTool -Name $leaf -Path $path -Time $f.created -Source $src -Hash $f.sha256
        if ($Script:DoubleExtRx.IsMatch($leaf) -and -not $Script:RecentRx.IsMatch($path)) { Add-IRFinding -Rule 'DOUBLE-EXT' -Title 'Double file extension' -Severity high -Technique 'T1036.007' -Evidence "[$src] $path" -Key $path @common }
        if ($Script:RansomRx.IsMatch($leaf)) { Add-IRFinding -Rule 'RANSOM-NOTE' -Title 'Ransom note or encrypted-file naming pattern' -Severity high -Technique 'T1486' -Evidence "[$src] $path" -Key $leaf @common }
        if ($f.signature -eq 'HashMismatch') {
            Add-IRFinding -Rule 'FILE-SIG-MISMATCH' -Title "Executable with an invalid signature: $leaf" -Severity high -Technique 'T1036.005' -Evidence "[$src] $path signer $($f.signer)" -Key (Get-IRPathKey $path) @common
        } elseif ($unsigned -and (Get-IRPathRisk $path)) {
            Add-IRFinding -Rule 'FILE-SUSP-DIR' -Title "Unsigned executable in a staging folder: $leaf" -Severity medium -Technique 'T1204.002' -Evidence "[$src] $path ($($f.size) bytes, created $($f.created))" -Key (Get-IRPathKey $path) @common
        } elseif ($unsigned -and $path -match '(?i)^[a-z]:\\windows\\(system32|syswow64)\\(drivers\\)?[^\\]+$') {
            Add-IRFinding -Rule 'SYSDIR-UNSIGNED' -Title "Unsigned executable recently created in a system folder: $leaf" -Severity high -Technique 'T1036.005' -Evidence "[$src] $path (created $($f.created))" -Key (Get-IRPathKey $path) @common
        }
        if ($zone -ge 3) {
            $from = if ($f.host_url) { " from $($f.host_url)" } else { '' }
            if ($ext -in @('.iso', '.img', '.vhd', '.vhdx')) {
                Add-IRFinding -Rule 'DISK-IMAGE-DOWNLOAD' -Title "Disk image downloaded from the internet: $leaf" -Severity medium -Technique 'T1553.005' -Evidence "[$src] $path$from" -Key (Get-IRPathKey $path) -Domain (Get-IRUrlHost $f.host_url) @common
            } elseif ($ext -in @('.js', '.jse', '.vbs', '.vbe', '.wsf', '.hta', '.lnk', '.one', '.xll', '.library-ms', '.scr', '.pif', '.cpl', '.msc', '.bat', '.cmd', '.ps1')) {
                Add-IRFinding -Rule 'RISKY-DOWNLOAD' -Title "Script / shortcut / container downloaded from the internet: $leaf" -Severity medium -Technique 'T1204.002' -Evidence "[$src] $path$from" -Key (Get-IRPathKey $path) -Domain (Get-IRUrlHost $f.host_url) @common
            } elseif ($unsigned) {
                Add-IRFinding -Rule 'UNSIGNED-DOWNLOAD' -Title "Unsigned executable downloaded from the internet: $leaf" -Severity low -Technique 'T1204.002' -Evidence "[$src] $path$from" -Key (Get-IRPathKey $path) -Domain (Get-IRUrlHost $f.host_url) @common
            }
            if ($f.host_url) { Test-IRDomain (Get-IRUrlHost $f.host_url) $f.created $src $null $null }
        }
        if ($f.hidden -eq $true -and $isPe -and $Script:UserWritableRx.IsMatch($path)) {
            Add-IRFinding -Rule 'HIDDEN-EXE' -Title "Hidden executable in a user-writable folder: $leaf" -Severity medium -Technique 'T1564.001' -Evidence "[$src] $path" -Key (Get-IRPathKey $path) @common
        }
        $info = ''
        if ($zone -ge 3) { $info += " (downloaded$(if ($f.host_url) { " from $($f.host_url)" }))" }
        if ($isPe) { $info += " [$($f.signature) $($f.signer)]" }
        Add-IRTimeline $f.created $src 'file' 'file' "File created: $path$info" $null -Keep
    }

    foreach ($a in $ds['alternate_data_streams']) {
        if ([int64]$a.size -le 0) { continue }
        Start-IRItem
        Add-IRFinding -Rule 'ADS-HIDDEN' -Title "Alternate data stream: $($a.stream) on $(Get-IRLeaf $a.path)" -Severity $(if ([int64]$a.size -gt 102400) { 'medium' } else { 'low' }) -Technique 'T1564.004' -Source 'Live: alternate data streams' `
            -Evidence "$($a.path):$($a.stream) ($($a.size) bytes)" -Key "$($a.path):$($a.stream)" -File $a.path
    }
    $Script:Hits = $null
}

function Get-IRGaps {
    $gaps = [System.Collections.Generic.List[object]]::new()
    $add = { param($Area, $Issue, $Fix, $Sev) $gaps.Add([pscustomobject]@{ area = $Area; issue = $Issue; recommendation = $Fix; severity = $Sev }) }
    $sys = $Script:Sys
    if ($sys -and $sys.elevated -eq $false) { & $add 'Collection' 'The collection did not run elevated: the Security log, registry hives, other users and locked files are missing.' 'Re-run as Administrator or SYSTEM.' 'high' }
    $logs = @{}
    foreach ($l in $Script:D['event_logs']) { $logs[[string]$l.log] = $l }
    foreach ($k in 'Security', 'System', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-Sysmon/Operational') {
        $l = $logs[$k]
        if (-not $l -or $l.missing -eq $true -or -not $l.file) {
            if ($k -eq 'Microsoft-Windows-Sysmon/Operational') { continue }
            if ($k -eq 'Security' -and $Script:Sys.elevated -eq $false) { & $add 'Event logs' 'The Security log could not be read (it needs elevation), so logons, account changes and 4688 were not analyzed.' 'Re-run the collection as Administrator.' 'high'; continue }
            if ($l -and $l.enabled -eq $false) { & $add 'Logging' "$k is disabled." "Enable it: wevtutil sl `"$k`" /e:true" 'medium'; continue }
            & $add 'Event logs' "$k was not collected or is empty." 'Check that the log exists and that the collection ran elevated.' 'medium'
            continue
        }
        $oldest = Get-IRIso $l.oldest_event
        if ($oldest -and [string]::CompareOrdinal($oldest, $Script:SinceIso) -gt 0) {
            & $add 'Log retention' "$k only reaches back to $oldest - older activity inside the $($Script:Days)-day window is not visible." "Increase the maximum log size (currently $($l.max_size_mb) MB) and forward logs to a SIEM." $(if ($k -eq 'Security') { 'high' } else { 'medium' })
        }
    }
    $cfg = @($Script:D['security_config'])[0]
    if ($cfg) {
        if (-not $cfg.sysmon_installed) { & $add 'Telemetry' 'Sysmon is not installed: no network, file, registry, DNS or LSASS-access telemetry.' 'Deploy Sysmon with a maintained configuration (sysmon-modular or SwiftOnSecurity).' 'medium' }
        if ([string]$cfg.process_cmdline_auditing -ne '1') { & $add 'Audit policy' 'Command lines are not recorded in process creation events (4688).' 'Enable "Include command line in process creation events" (ProcessCreationIncludeCmdLine_Enabled = 1).' 'high' }
        if ([string]$cfg.ps_script_block_logging -ne '1') { & $add 'PowerShell logging' 'Script block logging is not enforced: only blocks PowerShell itself considers suspicious are logged.' 'Enable PowerShell Script Block Logging by GPO.' 'medium' }
        if ([string]$cfg.ps_module_logging -ne '1') { & $add 'PowerShell logging' 'Module logging (4103) is not enabled.' 'Enable PowerShell Module Logging for all modules (*).' 'low' }
        if ([string]$cfg.ps_transcription -ne '1') { & $add 'PowerShell logging' 'PowerShell transcription is not enabled.' 'Enable transcription to a protected central share.' 'low' }
        if ([string]$cfg.lsa_run_as_ppl -notin @('1', '2')) { & $add 'Hardening' 'LSA protection (RunAsPPL) is off: admin-level malware can read LSASS memory.' 'Enable RunAsPPL and Credential Guard where supported.' 'medium' }
        if ([string]$cfg.rdp_deny_connections -eq '0' -and [string]$cfg.rdp_nla_required -eq '0') { & $add 'Hardening' 'Remote Desktop is enabled without Network Level Authentication.' 'Require NLA and restrict RDP to VPN / jump hosts.' 'medium' }
        if ([string]$cfg.smb1_server -eq '1') { & $add 'Hardening' 'The SMBv1 server is enabled.' 'Disable SMBv1.' 'low' }
    }
    $ap = @{}
    foreach ($a in $Script:D['audit_policy']) { $ap[([string]$a.guid).Trim('{', '}').ToUpperInvariant()] = [string]$a.setting }
    $need = [ordered]@{
        '0CCE922B-69AE-11D9-BED3-505054503030' = @('Process Creation (4688)', 'high')
        '0CCE9215-69AE-11D9-BED3-505054503030' = @('Logon (4624 / 4625)', 'high')
        '0CCE9235-69AE-11D9-BED3-505054503030' = @('User Account Management (4720 ...)', 'medium')
        '0CCE9237-69AE-11D9-BED3-505054503030' = @('Security Group Management (4728 / 4732)', 'medium')
        '0CCE9227-69AE-11D9-BED3-505054503030' = @('Other Object Access Events (4698 scheduled tasks)', 'medium')
        '0CCE9211-69AE-11D9-BED3-505054503030' = @('Security System Extension (4697 service installs)', 'medium')
        '0CCE922F-69AE-11D9-BED3-505054503030' = @('Audit Policy Change (4719)', 'low')
    }
    foreach ($k in $need.Keys) {
        if ($ap.ContainsKey($k) -and $ap[$k] -match '(?i)^\s*(no auditing)?\s*$') { & $add 'Audit policy' "$($need[$k][0]) is not audited." 'Enable success and failure auditing for this subcategory (Advanced Audit Policy).' $need[$k][1] }
    }
    $st = @($Script:D['defender_status'])[0]
    if ($st -and $st.tamper_protected -eq $false) { & $add 'Hardening' 'Defender tamper protection is off.' 'Enable tamper protection.' 'low' }
    foreach ($q in $Script:CappedQueries) { & $add 'Analysis' "Event query $q hit the -MaxEventsPerLog cap; older events in the window were not analyzed." 'Re-run Analyze with a higher -MaxEventsPerLog, or analyze the .evtx with Hayabusa / Chainsaw.' 'low' }
    foreach ($a in @($Script:ArtifactNotes)) {
        if ($a) { & $add "Artifacts: $($a.artifact)" $a.note 'Parse that artifact with a dedicated tool (AmcacheParser, SrumECmd, JLECmd, RECmd, Hindsight), or re-collect elevated.' 'low' }
    }
    return $gaps
}

#endregion

#region ===== Analysis: raw artifacts (browsers, Amcache, hives, Jump Lists, SRUM) =====

# Read-only parsers for the raw files in artifacts\. Nothing in the case is modified: SQLite and
# ESE databases are opened from temporary copies because opening them replays their journals.
$Script:ArtifactCode = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace IRInv
{
    public static class Bin
    {
        public static int I32(byte[] b, int p) { return (p >= 0 && p + 4 <= b.Length) ? BitConverter.ToInt32(b, p) : 0; }
        public static uint U32(byte[] b, int p) { return (uint)I32(b, p); }
        public static int U16(byte[] b, int p) { return (p >= 0 && p + 2 <= b.Length) ? BitConverter.ToUInt16(b, p) : 0; }
        public static long I64(byte[] b, int p) { return (p >= 0 && p + 8 <= b.Length) ? BitConverter.ToInt64(b, p) : 0; }
        public static DateTime? FileTime(long v)
        {
            if (v <= 0 || v >= 2650467743999999999L) return null;
            try { return DateTime.FromFileTimeUtc(v); } catch { return null; }
        }
        // MS-DOS date then time, local time of the machine that wrote it.
        public static string Fat(byte[] b, int p)
        {
            int d = U16(b, p), t = U16(b, p + 2);
            if (d == 0) return null;
            try { return new DateTime(1980 + (d >> 9), (d >> 5) & 15, d & 31, t >> 11, (t >> 5) & 63, (t & 31) * 2).ToString("yyyy-MM-dd HH:mm:ss"); }
            catch { return null; }
        }
        public static string Ascii(byte[] b, int p, int max)
        {
            if (p < 0 || p >= b.Length) return "";
            int lim = Math.Min(b.Length, p + max), e = p;
            while (e < lim && b[e] != 0) e++;
            return Encoding.Default.GetString(b, p, e - p);
        }
        public static string Uni(byte[] b, int p, int maxChars)
        {
            if (p < 0 || p + 1 >= b.Length) return "";
            int lim = Math.Min(b.Length - 1, p + maxChars * 2), e = p;
            while (e < lim && (b[e] != 0 || b[e + 1] != 0)) e += 2;
            return Encoding.Unicode.GetString(b, p, e - p);
        }
        public static int Find(byte[] b, byte[] pat, int from)
        {
            for (int i = Math.Max(0, from); i + pat.Length <= b.Length; i++)
            {
                int j = 0;
                while (j < pat.Length && b[i + j] == pat[j]) j++;
                if (j == pat.Length) return i;
            }
            return -1;
        }
        public static byte[] Sub(byte[] b, int p, int n)
        {
            byte[] r = new byte[n];
            Buffer.BlockCopy(b, p, r, 0, n);
            return r;
        }
    }

    public static class Sqlite
    {
        const string L = "winsqlite3.dll";
        [DllImport(L, CallingConvention = CallingConvention.StdCall)] static extern int sqlite3_open_v2(byte[] file, out IntPtr db, int flags, IntPtr vfs);
        [DllImport(L, CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)] static extern int sqlite3_prepare16_v2(IntPtr db, string sql, int nBytes, out IntPtr stmt, IntPtr tail);
        [DllImport(L, CallingConvention = CallingConvention.StdCall)] static extern int sqlite3_step(IntPtr stmt);
        [DllImport(L, CallingConvention = CallingConvention.StdCall)] static extern int sqlite3_column_count(IntPtr stmt);
        [DllImport(L, CallingConvention = CallingConvention.StdCall)] static extern IntPtr sqlite3_column_name16(IntPtr stmt, int i);
        [DllImport(L, CallingConvention = CallingConvention.StdCall)] static extern int sqlite3_column_type(IntPtr stmt, int i);
        [DllImport(L, CallingConvention = CallingConvention.StdCall)] static extern long sqlite3_column_int64(IntPtr stmt, int i);
        [DllImport(L, CallingConvention = CallingConvention.StdCall)] static extern double sqlite3_column_double(IntPtr stmt, int i);
        [DllImport(L, CallingConvention = CallingConvention.StdCall)] static extern IntPtr sqlite3_column_text16(IntPtr stmt, int i);
        [DllImport(L, CallingConvention = CallingConvention.StdCall)] static extern int sqlite3_column_bytes16(IntPtr stmt, int i);
        [DllImport(L, CallingConvention = CallingConvention.StdCall)] static extern int sqlite3_finalize(IntPtr stmt);
        [DllImport(L, CallingConvention = CallingConvention.StdCall)] static extern int sqlite3_close(IntPtr db);
        [DllImport(L, CallingConvention = CallingConvention.StdCall)] static extern IntPtr sqlite3_errmsg16(IntPtr db);

        static string Err(IntPtr db) { return db == IntPtr.Zero ? "" : Marshal.PtrToStringUni(sqlite3_errmsg16(db)); }

        public static List<Dictionary<string, object>> Query(string path, string sql, int max)
        {
            List<Dictionary<string, object>> rows = new List<Dictionary<string, object>>();
            IntPtr db;
            // Read-write on the temporary copy so a leftover journal / WAL is applied.
            int rc = sqlite3_open_v2(Encoding.UTF8.GetBytes(path + "\0"), out db, 2, IntPtr.Zero);
            if (rc != 0) { string m = Err(db); sqlite3_close(db); throw new IOException("sqlite open failed (" + rc + "): " + m); }
            try
            {
                IntPtr st;
                rc = sqlite3_prepare16_v2(db, sql, -1, out st, IntPtr.Zero);
                if (rc != 0) throw new InvalidOperationException("sqlite prepare failed (" + rc + "): " + Err(db));
                try
                {
                    int n = sqlite3_column_count(st);
                    string[] names = new string[n];
                    for (int i = 0; i < n; i++) names[i] = Marshal.PtrToStringUni(sqlite3_column_name16(st, i));
                    while (rows.Count < max)
                    {
                        rc = sqlite3_step(st);
                        if (rc == 101) break;
                        if (rc != 100) throw new InvalidOperationException("sqlite step failed (" + rc + "): " + Err(db));
                        Dictionary<string, object> row = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                        for (int i = 0; i < n; i++)
                        {
                            switch (sqlite3_column_type(st, i))
                            {
                                case 1: row[names[i]] = sqlite3_column_int64(st, i); break;
                                case 2: row[names[i]] = sqlite3_column_double(st, i); break;
                                case 3:
                                    {
                                        IntPtr p = sqlite3_column_text16(st, i);
                                        int len = sqlite3_column_bytes16(st, i);
                                        row[names[i]] = p == IntPtr.Zero ? "" : Marshal.PtrToStringUni(p, len / 2);
                                        break;
                                    }
                                default: row[names[i]] = null; break;
                            }
                        }
                        rows.Add(row);
                    }
                }
                finally { sqlite3_finalize(st); }
            }
            finally { sqlite3_close(db); }
            return rows;
        }
    }

    // Offline registry hive (regf). Dirty hives get their .LOG1/.LOG2 (HvLE format) replayed in memory.
    public class RegHive
    {
        internal byte[] D;
        public RegKey Root;
        public int LogPagesApplied;
        public bool Dirty;
        public RegHive(string path)
        {
            D = File.ReadAllBytes(path);
            if (D.Length < 4096 + 32 || D[0] != 0x72 || D[1] != 0x65 || D[2] != 0x67 || D[3] != 0x66) throw new InvalidDataException("not a registry hive: " + path);
            uint prim = Bin.U32(D, 4), sec = Bin.U32(D, 8);
            Dirty = prim != sec;
            if (Dirty) ReplayLogs(path, sec);
            Root = new RegKey(this, Bin.I32(D, 0x24));
        }
        void ReplayLogs(string path, uint sec)
        {
            List<KeyValuePair<uint, byte[]>> entries = new List<KeyValuePair<uint, byte[]>>();
            foreach (string lp in new string[] { path + ".LOG1", path + ".LOG2" })
            {
                if (!File.Exists(lp)) continue;
                byte[] L;
                try { L = File.ReadAllBytes(lp); } catch { continue; }
                int p = 512;
                while (p + 40 <= L.Length && L[p] == 0x48 && L[p + 1] == 0x76 && L[p + 2] == 0x4C && L[p + 3] == 0x45)
                {
                    int size = Bin.I32(L, p + 4);
                    if (size < 40 || (size % 512) != 0 || p + size > L.Length) break;
                    entries.Add(new KeyValuePair<uint, byte[]>(Bin.U32(L, p + 12), Bin.Sub(L, p, size)));
                    p += size;
                }
            }
            entries.Sort(delegate (KeyValuePair<uint, byte[]> a, KeyValuePair<uint, byte[]> b) { return a.Key.CompareTo(b.Key); });
            uint want = 0;
            bool started = false;
            foreach (KeyValuePair<uint, byte[]> kv in entries)
            {
                if (kv.Key < sec) continue;
                if (started && kv.Key < want) continue;
                if (started && kv.Key != want) break;
                started = true;
                want = kv.Key + 1;
                byte[] e = kv.Value;
                int binsSize = Bin.I32(e, 16), pages = Bin.I32(e, 20);
                if (pages < 0 || 40 + pages * 8 > e.Length) break;
                if (binsSize > 0 && 4096 + binsSize > D.Length) Array.Resize(ref D, 4096 + binsSize);
                int data = 40 + pages * 8;
                for (int i = 0; i < pages; i++)
                {
                    int off = Bin.I32(e, 40 + i * 8), sz = Bin.I32(e, 44 + i * 8);
                    if (off < 0 || sz <= 0 || data + sz > e.Length || 4096L + off + sz > D.Length) break;
                    Buffer.BlockCopy(e, data, D, 4096 + off, sz);
                    data += sz;
                    LogPagesApplied++;
                }
            }
        }
    }

    public class RegKey
    {
        readonly RegHive h;
        readonly int p;
        public string Name;
        public DateTime? LastWrite;
        internal RegKey(RegHive hive, int off)
        {
            h = hive;
            p = 4096 + off + 4;
            byte[] D = h.D;
            if (off < 0 || p + 0x4C > D.Length || D[p] != 0x6E || D[p + 1] != 0x6B) throw new InvalidDataException("bad key cell");
            int flags = Bin.U16(D, p + 2), nl = Math.Min(Bin.U16(D, p + 0x48), D.Length - p - 0x4C);
            LastWrite = Bin.FileTime(Bin.I64(D, p + 4));
            Name = (flags & 0x20) != 0 ? Encoding.GetEncoding(28591).GetString(D, p + 0x4C, nl) : Encoding.Unicode.GetString(D, p + 0x4C, nl & ~1);
        }
        public List<RegKey> SubKeys()
        {
            List<RegKey> list = new List<RegKey>();
            if (Bin.I32(h.D, p + 0x14) > 0) Collect(Bin.I32(h.D, p + 0x1C), list, 0);
            return list;
        }
        void Collect(int off, List<RegKey> list, int depth)
        {
            byte[] D = h.D;
            int q = 4096 + off + 4;
            if (depth > 3 || off <= 0 || q + 4 > D.Length) return;
            int n = Bin.U16(D, q + 2);
            if (D[q] == 0x6C && (D[q + 1] == 0x66 || D[q + 1] == 0x68)) { for (int i = 0; i < n; i++) Add(Bin.I32(D, q + 4 + i * 8), list); }
            else if (D[q] == 0x6C && D[q + 1] == 0x69) { for (int i = 0; i < n; i++) Add(Bin.I32(D, q + 4 + i * 4), list); }
            else if (D[q] == 0x72 && D[q + 1] == 0x69) { for (int i = 0; i < n; i++) Collect(Bin.I32(D, q + 4 + i * 4), list, depth + 1); }
        }
        void Add(int off, List<RegKey> list) { try { list.Add(new RegKey(h, off)); } catch { } }
        public RegKey Open(string path)
        {
            RegKey k = this;
            foreach (string part in path.Split(new char[] { '\\' }, StringSplitOptions.RemoveEmptyEntries))
            {
                RegKey next = null;
                foreach (RegKey s in k.SubKeys()) { if (string.Equals(s.Name, part, StringComparison.OrdinalIgnoreCase)) { next = s; break; } }
                if (next == null) return null;
                k = next;
            }
            return k;
        }
        public List<RegValue> Values()
        {
            List<RegValue> list = new List<RegValue>();
            byte[] D = h.D;
            int n = Bin.I32(D, p + 0x24), lo = Bin.I32(D, p + 0x28);
            if (n <= 0 || n > 100000 || lo <= 0) return list;
            int q = 4096 + lo + 4;
            for (int i = 0; i < n && q + i * 4 + 4 <= D.Length; i++)
            {
                try { RegValue v = RegValue.Read(D, Bin.I32(D, q + i * 4)); if (v != null) list.Add(v); } catch { }
            }
            return list;
        }
        public object GetValue(string name)
        {
            foreach (RegValue v in Values()) { if (string.Equals(v.Name, name, StringComparison.OrdinalIgnoreCase)) return v.Value; }
            return null;
        }
    }

    public class RegValue
    {
        public string Name;
        public int Type;
        public byte[] Data;
        public object Value;
        internal static RegValue Read(byte[] D, int off)
        {
            int p = 4096 + off + 4;
            if (off <= 0 || p + 0x14 > D.Length || D[p] != 0x76 || D[p + 1] != 0x6B) return null;
            RegValue v = new RegValue();
            int nl = Bin.U16(D, p + 2), doff = Bin.I32(D, p + 8), flags = Bin.U16(D, p + 0x10);
            uint size = Bin.U32(D, p + 4);
            v.Type = Bin.I32(D, p + 0x0C);
            if (p + 0x14 + nl > D.Length) return null;
            v.Name = (flags & 1) != 0 ? Encoding.GetEncoding(28591).GetString(D, p + 0x14, nl) : Encoding.Unicode.GetString(D, p + 0x14, nl & ~1);
            int len = (int)(size & 0x7FFFFFFF);
            if ((size & 0x80000000) != 0) { v.Data = Bin.Sub(D, p + 8, Math.Min(len, 4)); }
            else
            {
                int c = 4096 + doff + 4;
                if (doff <= 0 || c + 8 > D.Length) v.Data = new byte[0];
                else if (len > 16344 && D[c] == 0x64 && D[c + 1] == 0x62)
                {
                    int segs = Bin.U16(D, c + 2), lst = 4096 + Bin.I32(D, c + 4) + 4;
                    MemoryStream ms = new MemoryStream();
                    for (int i = 0; i < segs && ms.Length < len; i++)
                    {
                        int s = 4096 + Bin.I32(D, lst + i * 4) + 4;
                        int take = (int)Math.Min(16344, len - ms.Length);
                        if (s < 4096 || s + take > D.Length) break;
                        ms.Write(D, s, take);
                    }
                    v.Data = ms.ToArray();
                }
                else v.Data = Bin.Sub(D, c, Math.Max(0, Math.Min(len, D.Length - c)));
            }
            v.Value = ToObject(v.Type, v.Data);
            return v;
        }
        static object ToObject(int type, byte[] d)
        {
            switch (type)
            {
                case 1:
                case 2:
                    {
                        string s = Encoding.Unicode.GetString(d, 0, d.Length & ~1);
                        int z = s.IndexOf('\0');
                        return z >= 0 ? s.Substring(0, z) : s;
                    }
                case 7: return Encoding.Unicode.GetString(d, 0, d.Length & ~1).Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
                case 4: return d.Length >= 4 ? (object)BitConverter.ToUInt32(d, 0) : null;
                case 11: return d.Length >= 8 ? (object)BitConverter.ToInt64(d, 0) : null;
                default: return d;
            }
        }
    }

    public class ShellBag
    {
        public string Path;
        public DateTime? KeyLastWrite;
        public string Modified;
        public string Created;
        public string Accessed;
        public int ItemType;
    }

    public static class Shell
    {
        static readonly byte[] Beef0004 = new byte[] { 0x04, 0x00, 0xEF, 0xBE };
        static readonly Dictionary<string, string> Guids = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "{20D04FE0-3AEA-1069-A2D8-08002B30309D}", "My Computer" }, { "{59031A47-3F72-44A7-89C5-5595FE6B30EE}", "User profile" },
            { "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}", "Network" }, { "{208D2C60-3AEA-1069-A2D7-08002B30309D}", "Network" },
            { "{679F85CB-0220-4080-B29B-5540CC05AAB6}", "Quick access" }, { "{031E4825-7B94-4DC3-B131-E946B44C8DD5}", "Libraries" },
            { "{645FF040-5081-101B-9F08-00AA002F954E}", "Recycle Bin" }, { "{21EC2020-3AEA-1069-A2DD-08002B30309D}", "Control Panel" },
            { "{26EE0668-A00A-44D7-9371-BEB064C98683}", "Control Panel" }, { "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "Desktop" },
            { "{374DE290-123F-4565-9164-39C4925E467B}", "Downloads" }, { "{088E3905-0323-4B02-9826-5D99428E115F}", "Downloads" },
            { "{D3162B92-9365-467A-956B-92703ACA08AF}", "Documents" }, { "{A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0}", "Documents" },
            { "{3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA}", "Pictures" }, { "{24AD3AD4-A569-4530-98E1-AB02F9417AA8}", "Pictures" },
            { "{1CF1260C-4DD0-4EBB-811F-33C572699FDE}", "Music" }, { "{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}", "Music" },
            { "{A0953C92-50DC-43BF-BE83-3742FED03C9C}", "Videos" }, { "{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}", "Videos" },
            { "{018D5C66-4533-4307-9B53-224DE2ED1FE6}", "OneDrive" }, { "{9E52AB10-F80D-49DF-ACB8-4330F5687855}", "CD burning" }
        };

        public static string ItemName(byte[] d, int s, int size, out string mod, out string cre, out string acc)
        {
            mod = null; cre = null; acc = null;
            if (size < 3 || s + size > d.Length) return "?";
            byte[] b = Bin.Sub(d, s, size);
            int type = b[2];
            if (type == 0x1F)
            {
                if (size >= 20)
                {
                    string g = new Guid(Bin.Sub(b, 4, 16)).ToString("B").ToUpperInvariant();
                    string n;
                    return Guids.TryGetValue(g, out n) ? n : g;
                }
                return "{root}";
            }
            if ((type & 0x70) == 0x20) return Bin.Ascii(b, 3, 20).TrimEnd('\\');
            if ((type & 0x70) == 0x40) return Bin.Ascii(b, 5, 260);
            string shortName = null;
            if ((type & 0x70) == 0x30)
            {
                mod = Bin.Fat(b, 8);
                shortName = Bin.Ascii(b, 14, 260);
            }
            int sig = Bin.Find(b, Beef0004, 4);
            if (sig >= 4)
            {
                int e = sig - 4, ver = Bin.U16(b, e + 2);
                cre = Bin.Fat(b, e + 8);
                acc = Bin.Fat(b, e + 12);
                int no = ver >= 9 ? 0x2E : ver >= 8 ? 0x2A : ver >= 7 ? 0x26 : ver >= 3 ? 0x12 : -1;
                if (no > 0)
                {
                    string ln = Bin.Uni(b, e + no, 260);
                    if (ln.Length > 0) return ln;
                }
            }
            if (!string.IsNullOrEmpty(shortName)) return shortName;
            return "[item 0x" + type.ToString("X2") + "]";
        }

        public static string Join(string prefix, string name)
        {
            if (name.Length == 2 && name[1] == ':') return name;
            if (name.StartsWith("\\\\")) return name;
            if (string.IsNullOrEmpty(prefix)) return name;
            return prefix.TrimEnd('\\') + "\\" + name;
        }

        public static string IdListPath(byte[] b, int p, int len)
        {
            string path = "";
            int end = Math.Min(b.Length, p + len), guard = 0;
            while (p + 2 <= end && guard++ < 64)
            {
                int sz = Bin.U16(b, p);
                if (sz < 3 || p + sz > end) break;
                string m, c, a;
                path = Join(path, ItemName(b, p, sz, out m, out c, out a));
                p += sz;
            }
            return path;
        }

        public static List<ShellBag> BagMru(RegKey root)
        {
            List<ShellBag> list = new List<ShellBag>();
            Walk(root, "", list, 0);
            return list;
        }

        static void Walk(RegKey k, string prefix, List<ShellBag> list, int depth)
        {
            if (depth > 40 || list.Count > 50000) return;
            Dictionary<string, RegKey> subs = new Dictionary<string, RegKey>(StringComparer.OrdinalIgnoreCase);
            foreach (RegKey s in k.SubKeys()) subs[s.Name] = s;
            foreach (RegValue v in k.Values())
            {
                int slot;
                if (!int.TryParse(v.Name, out slot) || v.Data == null || v.Data.Length < 3) continue;
                string mod, cre, acc;
                string name = ItemName(v.Data, 0, Math.Min(v.Data.Length, Math.Max(3, Bin.U16(v.Data, 0))), out mod, out cre, out acc);
                string path = Join(prefix, name);
                RegKey child;
                subs.TryGetValue(v.Name, out child);
                ShellBag sb = new ShellBag();
                sb.Path = path; sb.Modified = mod; sb.Created = cre; sb.Accessed = acc; sb.ItemType = v.Data[2];
                sb.KeyLastWrite = child != null ? child.LastWrite : null;
                list.Add(sb);
                if (child != null) Walk(child, path, list, depth + 1);
            }
        }
    }

    // OLE compound file (automaticDestinations-ms): every stream by name.
    public class Cfb
    {
        public Dictionary<string, byte[]> Streams = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        const uint Last = 0xFFFFFFFA;
        public Cfb(byte[] b)
        {
            if (b.Length < 512 || Bin.U32(b, 0) != 0xE011CFD0 || Bin.U32(b, 4) != 0xE11AB1A1) throw new InvalidDataException("not a compound file");
            int ss = 1 << Bin.U16(b, 0x1E), mss = 1 << Bin.U16(b, 0x20);
            if (ss != 512 && ss != 4096) throw new InvalidDataException("unsupported sector size " + ss);
            uint cutoff = Bin.U32(b, 0x38);
            List<uint> fatSecs = new List<uint>();
            for (int i = 0; i < 109; i++) { uint s = Bin.U32(b, 0x4C + i * 4); if (s < Last) fatSecs.Add(s); }
            uint dif = Bin.U32(b, 0x44);
            int guard = 0, per = ss / 4 - 1;
            while (dif < Last && guard++ < 10000)
            {
                long o = ((long)dif + 1) * ss;
                if (o + ss > b.Length) break;
                for (int i = 0; i < per; i++) { uint s = Bin.U32(b, (int)o + i * 4); if (s < Last) fatSecs.Add(s); }
                dif = Bin.U32(b, (int)o + per * 4);
            }
            List<uint> fat = new List<uint>();
            foreach (uint s in fatSecs)
            {
                long o = ((long)s + 1) * ss;
                for (int i = 0; i < ss / 4; i++) fat.Add(o + i * 4 + 4 <= b.Length ? Bin.U32(b, (int)o + i * 4) : 0xFFFFFFFE);
            }
            byte[] dir = Chain(b, fat, Bin.U32(b, 0x30), ss, -1);
            if (dir.Length < 128) throw new InvalidDataException("no directory");
            byte[] mini = Chain(b, fat, Bin.U32(dir, 0x74), ss, Bin.U32(dir, 0x78));
            byte[] mf = Chain(b, fat, Bin.U32(b, 0x3C), ss, -1);
            List<uint> miniFat = new List<uint>();
            for (int i = 0; i + 4 <= mf.Length; i += 4) miniFat.Add(Bin.U32(mf, i));
            for (int o = 128; o + 128 <= dir.Length; o += 128)
            {
                if (dir[o + 0x42] != 2) continue;
                int nl = Bin.U16(dir, o + 0x40);
                string name = nl >= 2 ? Encoding.Unicode.GetString(dir, o, Math.Min(64, nl) - 2) : "";
                uint start = Bin.U32(dir, o + 0x74);
                long size = Bin.U32(dir, o + 0x78);
                if (size > b.Length) continue;
                byte[] data = size < cutoff ? MiniChain(mini, miniFat, start, mss, size) : Chain(b, fat, start, ss, size);
                if (!Streams.ContainsKey(name)) Streams[name] = data;
            }
        }
        static byte[] Chain(byte[] b, List<uint> fat, uint start, int ss, long size)
        {
            MemoryStream ms = new MemoryStream();
            uint s = start;
            int guard = 0;
            while (s < Last && guard++ <= fat.Count)
            {
                long o = ((long)s + 1) * ss;
                if (o >= b.Length) break;
                ms.Write(b, (int)o, (int)Math.Min(ss, b.Length - o));
                if (size >= 0 && ms.Length >= size) break;
                if (s >= fat.Count) break;
                s = fat[(int)s];
            }
            byte[] r = ms.ToArray();
            if (size >= 0 && r.Length > size) Array.Resize(ref r, (int)size);
            return r;
        }
        static byte[] MiniChain(byte[] mini, List<uint> mfat, uint start, int mss, long size)
        {
            MemoryStream ms = new MemoryStream();
            uint s = start;
            int guard = 0;
            while (s < Last && guard++ <= mfat.Count && ms.Length < size)
            {
                long o = (long)s * mss;
                if (o >= mini.Length) break;
                ms.Write(mini, (int)o, (int)Math.Min(mss, mini.Length - o));
                if (s >= mfat.Count) break;
                s = mfat[(int)s];
            }
            byte[] r = ms.ToArray();
            if (r.Length > size) Array.Resize(ref r, (int)size);
            return r;
        }
    }

    public class LnkInfo
    {
        public string Target, Arguments, WorkingDir, Name, RelativePath, MachineId, VolumeSerial, DriveType, VolumeLabel;
        public DateTime? Created, Accessed, Modified;
        public long FileSize;
        public int Length;
    }

    public class DestEntry
    {
        public int EntryId, AccessCount;
        public string Host, Path;
        public DateTime? LastAccess;
        public bool Pinned;
    }

    public static class Lnk
    {
        static readonly byte[] Header = new byte[] { 0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46 };
        static readonly string[] Drives = new string[] { "unknown", "no root", "removable", "fixed", "network", "cd-rom", "ram disk" };

        public static LnkInfo Parse(byte[] b, int s)
        {
            if (b == null || s < 0 || s + 0x4C > b.Length || Bin.I32(b, s) != 0x4C || Bin.U32(b, s + 4) != 0x00021401) return null;
            LnkInfo r = new LnkInfo();
            uint flags = Bin.U32(b, s + 0x14);
            r.Created = Bin.FileTime(Bin.I64(b, s + 0x1C));
            r.Accessed = Bin.FileTime(Bin.I64(b, s + 0x24));
            r.Modified = Bin.FileTime(Bin.I64(b, s + 0x2C));
            r.FileSize = Bin.U32(b, s + 0x34);
            int p = s + 0x4C;
            string idPath = null;
            if ((flags & 1) != 0)
            {
                int n = Bin.U16(b, p);
                try { idPath = Shell.IdListPath(b, p + 2, n); } catch { }
                p += 2 + n;
            }
            if ((flags & 2) != 0 && p + 0x1C <= b.Length)
            {
                int li = p, size = Bin.I32(b, li), hs = Bin.I32(b, li + 4), lf = Bin.I32(b, li + 8);
                if (size >= 0x1C && li + size <= b.Length)
                {
                    if ((lf & 1) != 0)
                    {
                        int vo = li + Bin.I32(b, li + 0x0C);
                        int dt = Bin.I32(b, vo + 4);
                        r.DriveType = dt >= 0 && dt < Drives.Length ? Drives[dt] : dt.ToString();
                        r.VolumeSerial = Bin.U32(b, vo + 8).ToString("X8");
                        int lo = Bin.I32(b, vo + 0x0C);
                        r.VolumeLabel = lo == 0x14 ? Bin.Uni(b, vo + Bin.I32(b, vo + 0x10), 64) : Bin.Ascii(b, vo + lo, 64);
                        int ub = hs >= 0x24 ? Bin.I32(b, li + 0x1C) : 0, us = hs >= 0x24 ? Bin.I32(b, li + 0x20) : 0;
                        string basePath = ub > 0 ? Bin.Uni(b, li + ub, 520) : Bin.Ascii(b, li + Bin.I32(b, li + 0x10), 520);
                        string suffix = us > 0 ? Bin.Uni(b, li + us, 520) : Bin.Ascii(b, li + Bin.I32(b, li + 0x18), 520);
                        r.Target = basePath + suffix;
                    }
                    if ((lf & 2) != 0 && string.IsNullOrEmpty(r.Target))
                    {
                        int cn = li + Bin.I32(b, li + 0x14);
                        string net = Bin.Ascii(b, cn + Bin.I32(b, cn + 8), 260);
                        string suffix = Bin.Ascii(b, li + Bin.I32(b, li + 0x18), 520);
                        r.Target = string.IsNullOrEmpty(suffix) ? net : net.TrimEnd('\\') + "\\" + suffix;
                        r.DriveType = "network";
                    }
                }
                p = li + Math.Max(size, 4);
            }
            bool uni = (flags & 0x80) != 0;
            string[] sd = new string[5];
            uint[] bits = new uint[] { 0x4, 0x8, 0x10, 0x20, 0x40 };
            for (int i = 0; i < 5; i++)
            {
                if ((flags & bits[i]) == 0) continue;
                int n = Bin.U16(b, p);
                p += 2;
                int bytes = uni ? n * 2 : n;
                if (p + bytes > b.Length) { p = b.Length; break; }
                sd[i] = uni ? Encoding.Unicode.GetString(b, p, bytes) : Encoding.Default.GetString(b, p, bytes);
                p += bytes;
            }
            r.Name = sd[0]; r.RelativePath = sd[1]; r.WorkingDir = sd[2]; r.Arguments = sd[3];
            int guard = 0;
            while (p + 4 <= b.Length && guard++ < 64)
            {
                int bs = Bin.I32(b, p);
                if (bs < 8 || p + bs > b.Length) { p += 4; break; }
                uint sig = Bin.U32(b, p + 4);
                if (sig == 0xA0000003 && bs >= 0x60) r.MachineId = Bin.Ascii(b, p + 16, 16);
                else if (sig == 0xA0000001 && bs >= 0x314 && string.IsNullOrEmpty(r.Target))
                {
                    string t = Bin.Uni(b, p + 268, 260);
                    r.Target = t.Length > 0 ? t : Bin.Ascii(b, p + 8, 260);
                }
                p += bs;
            }
            if (string.IsNullOrEmpty(r.Target)) r.Target = !string.IsNullOrEmpty(idPath) ? idPath : r.RelativePath;
            r.Length = p - s;
            return r;
        }

        public static List<LnkInfo> Scan(byte[] b)
        {
            List<LnkInfo> list = new List<LnkInfo>();
            int p = 0;
            while (p + 0x4C <= b.Length && list.Count < 5000)
            {
                int i = Bin.Find(b, Header, p);
                if (i < 0) break;
                LnkInfo l = null;
                try { l = Parse(b, i); } catch { }
                if (l != null) { list.Add(l); p = i + Math.Max(0x4C, l.Length); } else p = i + 4;
            }
            return list;
        }

        public static List<DestEntry> ParseDestList(byte[] d)
        {
            List<DestEntry> list = new List<DestEntry>();
            if (d == null || d.Length < 32) return list;
            int ver = Bin.I32(d, 0), count = Bin.I32(d, 4), p = 32;
            for (int i = 0; i < count && p + 0x72 <= d.Length; i++)
            {
                DestEntry e = new DestEntry();
                e.Host = Bin.Ascii(d, p + 0x48, 16);
                e.EntryId = Bin.I32(d, p + 0x58);
                e.LastAccess = Bin.FileTime(Bin.I64(d, p + 0x64));
                e.Pinned = Bin.I32(d, p + 0x6C) != -1;
                int nameLen, nameAt;
                if (ver >= 3) { e.AccessCount = Bin.I32(d, p + 0x74); nameLen = Bin.U16(d, p + 0x80); nameAt = p + 0x82; }
                else { nameLen = Bin.U16(d, p + 0x70); nameAt = p + 0x72; }
                if (nameAt + nameLen * 2 > d.Length) break;
                e.Path = Encoding.Unicode.GetString(d, nameAt, nameLen * 2);
                p = nameAt + nameLen * 2 + (ver >= 3 ? 4 : 0);
                list.Add(e);
            }
            return list;
        }
    }

    // ESE (Extensible Storage Engine) reader for SRUDB.dat, read-only, recovery off.
    public sealed class Ese : IDisposable
    {
        const string E = "esent.dll";
        [DllImport(E, CharSet = CharSet.Unicode)] static extern int JetCreateInstanceW(out IntPtr inst, string name);
        [DllImport(E, CharSet = CharSet.Unicode, EntryPoint = "JetSetSystemParameterW")] static extern int SetParam(ref IntPtr inst, IntPtr ses, uint id, IntPtr lp, string sz);
        [DllImport(E, CharSet = CharSet.Unicode, EntryPoint = "JetSetSystemParameterW")] static extern int SetGlobal(IntPtr noInstance, IntPtr ses, uint id, IntPtr lp, string sz);
        [DllImport(E)] static extern int JetInit(ref IntPtr inst);
        [DllImport(E, CharSet = CharSet.Unicode)] static extern int JetBeginSessionW(IntPtr inst, out IntPtr ses, string user, string pass);
        [DllImport(E, CharSet = CharSet.Unicode)] static extern int JetAttachDatabaseW(IntPtr ses, string file, uint grbit);
        [DllImport(E, CharSet = CharSet.Unicode)] static extern int JetOpenDatabaseW(IntPtr ses, string file, string connect, out uint db, uint grbit);
        [DllImport(E, CharSet = CharSet.Unicode)] static extern int JetOpenTableW(IntPtr ses, uint db, string table, IntPtr parms, uint cb, uint grbit, out IntPtr tbl);
        [DllImport(E, CharSet = CharSet.Unicode)] static extern int JetGetTableColumnInfoW(IntPtr ses, IntPtr tbl, string col, ref ColDef def, uint cb, uint level);
        [DllImport(E)] static extern int JetMove(IntPtr ses, IntPtr tbl, int rows, uint grbit);
        [DllImport(E)] static extern int JetRetrieveColumn(IntPtr ses, IntPtr tbl, uint col, byte[] data, uint cb, out uint actual, uint grbit, IntPtr info);
        [DllImport(E)] static extern int JetCloseTable(IntPtr ses, IntPtr tbl);
        [DllImport(E)] static extern int JetCloseDatabase(IntPtr ses, uint db, uint grbit);
        [DllImport(E, CharSet = CharSet.Unicode)] static extern int JetDetachDatabaseW(IntPtr ses, string file);
        [DllImport(E)] static extern int JetEndSession(IntPtr ses, uint grbit);
        [DllImport(E)] static extern int JetTerm(IntPtr inst);

        [StructLayout(LayoutKind.Sequential)]
        struct ColDef { public uint cbStruct, columnid, coltyp; public ushort wCountry, langid, cp, wCollate; public uint cbMax, grbit; }

        IntPtr inst, ses;
        uint db;
        string file;
        bool attached, opened;
        public int PageSize;

        static void Check(int rc, string what) { if (rc < 0) throw new InvalidOperationException("ESE " + what + " failed with error " + rc); }

        public Ese(string path, string workDir)
        {
            file = path;
            try
            {
                byte[] hdr = new byte[0x100];
                using (FileStream fs = File.OpenRead(path)) fs.Read(hdr, 0, hdr.Length);
                PageSize = Bin.I32(hdr, 0xEC);
                if (PageSize != 2048 && PageSize != 4096 && PageSize != 8192 && PageSize != 16384 && PageSize != 32768) PageSize = 4096;
                SetGlobal(IntPtr.Zero, IntPtr.Zero, 64, new IntPtr(PageSize), null);
                Check(JetCreateInstanceW(out inst, "IRInv" + Guid.NewGuid().ToString("N")), "create instance");
                string wd = workDir.EndsWith("\\") ? workDir : workDir + "\\";
                SetParam(ref inst, IntPtr.Zero, 34, IntPtr.Zero, "off");
                SetParam(ref inst, IntPtr.Zero, 0, IntPtr.Zero, wd);
                SetParam(ref inst, IntPtr.Zero, 1, IntPtr.Zero, wd);
                SetParam(ref inst, IntPtr.Zero, 2, IntPtr.Zero, wd);
                SetParam(ref inst, IntPtr.Zero, 45, IntPtr.Zero, null);
                Check(JetInit(ref inst), "init");
                Check(JetBeginSessionW(inst, out ses, null, null), "begin session");
                Check(JetAttachDatabaseW(ses, path, 1), "attach database");
                attached = true;
                Check(JetOpenDatabaseW(ses, path, null, out db, 1), "open database");
                opened = true;
            }
            catch { Dispose(); throw; }
        }

        public List<Dictionary<string, object>> Read(string table, string[] cols, string timeCol, DateTime since, int max)
        {
            IntPtr t;
            int rc = JetOpenTableW(ses, db, table, IntPtr.Zero, 0, 4, out t);
            if (rc == -1305) return null;
            Check(rc, "open table " + table);
            List<Dictionary<string, object>> rows = new List<Dictionary<string, object>>();
            try
            {
                List<uint> ids = new List<uint>(), types = new List<uint>(), cps = new List<uint>();
                List<string> names = new List<string>();
                foreach (string c in cols)
                {
                    ColDef d = new ColDef();
                    d.cbStruct = (uint)Marshal.SizeOf(typeof(ColDef));
                    if (JetGetTableColumnInfoW(ses, t, c, ref d, d.cbStruct, 0) < 0) continue;
                    ids.Add(d.columnid); types.Add(d.coltyp); cps.Add(d.cp); names.Add(c);
                }
                byte[] buf = new byte[65536];
                rc = JetMove(ses, t, int.MinValue, 0);
                while (rc >= 0 && rows.Count < max)
                {
                    Dictionary<string, object> row = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                    bool keep = true;
                    for (int i = 0; i < ids.Count; i++)
                    {
                        uint got;
                        int r2 = JetRetrieveColumn(ses, t, ids[i], buf, (uint)buf.Length, out got, 0, IntPtr.Zero);
                        object v = (r2 < 0 || r2 == 1004) ? null : Decode(types[i], cps[i], buf, (int)Math.Min(got, (uint)buf.Length));
                        row[names[i]] = v;
                        if (!string.IsNullOrEmpty(timeCol) && names[i] == timeCol && v is DateTime && (DateTime)v < since) { keep = false; break; }
                    }
                    if (keep) rows.Add(row);
                    rc = JetMove(ses, t, 1, 0);
                }
            }
            finally { JetCloseTable(ses, t); }
            return rows;
        }

        static object Decode(uint type, uint cp, byte[] b, int n)
        {
            switch (type)
            {
                case 1: case 2: return n >= 1 ? (object)(int)b[0] : null;
                case 3: return n >= 2 ? (object)(int)BitConverter.ToInt16(b, 0) : null;
                case 4: return n >= 4 ? (object)BitConverter.ToInt32(b, 0) : null;
                case 5: case 15: return n >= 8 ? (object)BitConverter.ToInt64(b, 0) : null;
                case 6: return n >= 4 ? (object)(double)BitConverter.ToSingle(b, 0) : null;
                case 7: return n >= 8 ? (object)BitConverter.ToDouble(b, 0) : null;
                case 8:
                    if (n < 8) return null;
                    try { return DateTime.SpecifyKind(DateTime.FromOADate(BitConverter.ToDouble(b, 0)), DateTimeKind.Utc); } catch { return null; }
                case 14: return n >= 4 ? (object)(long)BitConverter.ToUInt32(b, 0) : null;
                case 16: return n >= 16 ? (object)new Guid(Bin.Sub(b, 0, 16)).ToString() : null;
                case 17: return n >= 2 ? (object)(int)BitConverter.ToUInt16(b, 0) : null;
                case 10:
                case 12:
                    return cp == 1200 ? Encoding.Unicode.GetString(b, 0, n & ~1).TrimEnd('\0') : Encoding.Default.GetString(b, 0, n).TrimEnd('\0');
                default: return Bin.Sub(b, 0, n);
            }
        }

        public void Dispose()
        {
            if (opened) JetCloseDatabase(ses, db, 0);
            if (attached) JetDetachDatabaseW(ses, file);
            if (ses != IntPtr.Zero) JetEndSession(ses, 0);
            if (inst != IntPtr.Zero) JetTerm(inst);
            opened = false; attached = false; ses = IntPtr.Zero; inst = IntPtr.Zero;
        }
    }
}
'@

$Script:WebkitEpoch = [DateTime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
$Script:UnixEpoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
$Script:ChromeTransition = @('link', 'typed', 'auto_bookmark', 'auto_subframe', 'manual_subframe', 'generated', 'auto_toplevel', 'form_submit', 'reload', 'keyword', 'keyword_generated')
$Script:FirefoxTransition = @{ 1 = 'link'; 2 = 'typed'; 3 = 'bookmark'; 4 = 'embed'; 5 = 'redirect_permanent'; 6 = 'redirect_temporary'; 7 = 'download'; 8 = 'framed_link'; 9 = 'reload' }
$Script:ChromeDlState = @('in_progress', 'complete', 'cancelled', 'interrupted')
$Script:ChromeDanger = @('safe', 'dangerous_file', 'dangerous_url', 'dangerous_content', 'maybe_dangerous', 'uncommon', 'user_validated', 'dangerous_host', 'potentially_unwanted')
$Script:ExecExtRx = New-Object Text.RegularExpressions.Regex('\.(exe|dll|scr|com|pif|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|msi|msix|appx|lnk|iso|img|vhdx?|jar)$', $Script:RxOpt)
$Script:SyncClientRx = New-Object Text.RegularExpressions.Regex('\\(onedrive|filecoauth|dropbox|googledrivefs|googledrivesync|box|boxsync|icloud\w*|backblaze\w*|bztransmit\w*|carbonite\w*|veeam\w*|msmpeng|mssense|teams|ms-teams|zoom|steam\w*|epicgameslauncher)\.exe$|^(dosvc|wuauserv|bits)$', $Script:RxOpt)
$Script:JumpListApps = @{
    '1b4dd67f29cb1962' = 'Explorer'; 'f01b4d95cf55d32a' = 'Explorer'; '5f7b5f1e01b83767' = 'Quick Access'; '1bc392b8e104a00e' = 'Remote Desktop (mstsc)'
    '9b9cdc69c1c24e2b' = 'Notepad'; '918e0ecb43d17e23' = 'Notepad'; '7e4dca80246863e3' = 'Control Panel'; '12dc1ea8e34b5a6' = 'Paint'
    '5d696d521de238c3' = 'Chrome'; '6824f4a902c78fbd' = 'Firefox'; '28c8b86deab549a1' = 'Internet Explorer'
}

function Initialize-IRArtifactParsers {
    if ('IRInv.RegHive' -as [type]) { return $true }
    try { Add-Type -TypeDefinition $Script:ArtifactCode -Language CSharp -ErrorAction Stop; return $true }
    catch { Write-IRLog "  artifact parsers could not be compiled: $($_.Exception.Message)" 'WARN'; return $false }
}

function Add-IRArtifactNote([string]$Area, [string]$Text) {
    $Script:ArtifactNotes.Add([pscustomobject]@{ artifact = $Area; note = $Text })
    Write-IRLog "  $Area`: $Text" 'WARN'
}

function Add-IRDataRows([string]$Name, $Rows) {
    $cur = if ($Script:D.ContainsKey($Name)) { @($Script:D[$Name]) } else { @() }
    $Script:D[$Name] = @($cur) + @($Rows)
}

# Profile folder name -> profile row from the live collection (user name, loaded or not).
function Get-IRProfileRow([string]$Folder) {
    return @($Script:D['user_profiles'] | Where-Object { $_ -and [string]$_.name -eq $Folder }) | Select-Object -First 1
}

function Copy-IRWorkFile([string]$Path, [string]$Work, [string[]]$Companions) {
    $dir = Join-Path $Work ([Guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $dst = Join-Path $dir (Split-Path -Leaf $Path)
    Copy-Item -LiteralPath $Path -Destination $dst -Force
    foreach ($c in $Companions) {
        if (Test-Path -LiteralPath ($Path + $c)) { Copy-Item -LiteralPath ($Path + $c) -Destination ($dst + $c) -Force }
    }
    return $dst
}

function ConvertFrom-IRWebkit($Value) {
    if ($null -eq $Value -or [long]$Value -le 0) { return $null }
    return ConvertFrom-IRFileTime ([long]$Value * 10)
}

function ConvertFrom-IRUnixMicro($Value) {
    if ($null -eq $Value -or [long]$Value -le 0) { return $null }
    try { return ConvertTo-IRTime ($Script:UnixEpoch.AddTicks([long]$Value * 10)) } catch { return $null }
}

function Test-IRBrowserVisit($Time, [string]$Url, [string]$Browser, [string]$User) {
    Start-IRItem
    $src = "Browser history: $Browser ($User)"
    $h = Get-IRUrlHost $Url
    if ($h) {
        Test-IRDomain $h $Time $src $Browser $User
        if ($h -match '^\d{1,3}(\.\d{1,3}){3}$' -and (Test-IRPublicIp $h)) {
            if ($Url -match '(?i)\.(exe|dll|scr|ps1|bat|cmd|vbs|js|hta|msi|zip|rar|7z|iso|img)([?#]|$)') {
                Add-IRFinding -Rule 'BROWSER-IP-FILE' -Title "Browser fetched a file straight from an IP address: $h" -Severity medium -Technique 'T1105' -Time $Time -Source $src -Evidence "[$src] $(Limit-IRText $Url 300)" -Key $h -Ip $h -User $User
            } else {
                Add-IRFinding -Rule 'BROWSER-IP-URL' -Title "Browser opened a public IP address directly: $h" -Severity low -Technique 'T1071.001' -Time $Time -Source $src -Evidence "[$src] $(Limit-IRText $Url 300)" -Key $h -Ip $h -User $User
            }
        }
    }
    Add-IRTimeline $Time $src 'visit' 'browser' "$User visited $(Limit-IRText $Url 300)" $User
}

function Test-IRBrowserDownload($Row) {
    Start-IRItem
    $src = "Browser download: $($Row.browser) ($($Row.user))"
    $path = [string]$Row.target_path; $url = [string]$Row.url; $leaf = Get-IRLeaf $path
    $h = Get-IRUrlHost $url
    if ($path) { Test-IRFilePath -Time $Row.time -Source $src -Path $path -Process $Row.browser -User $Row.user }
    if ($h) { Test-IRDomain $h $Row.time $src $Row.browser $Row.user }
    if ($Row.danger -and $Row.danger -ne 'safe' -and $Script:ChromeDanger -contains $Row.danger) {
        Add-IRFinding -Rule 'BROWSER-DL-DANGER' -Title "Download the browser flagged as dangerous: $leaf" -Severity medium -Technique 'T1204.002' -Time $Row.time -Source $src `
            -Evidence "[$src] $url -> $path (verdict $($Row.danger), state $($Row.state))" -Key (Get-IRPathKey $path) -File $path -Domain $h -User $Row.user
    } elseif ($Script:ExecExtRx.IsMatch($leaf) -and $url -and -not $Script:TrustedUrlRx.IsMatch($url)) {
        Add-IRFinding -Rule 'BROWSER-DL-EXEC' -Title "Executable / script downloaded from the Internet: $leaf" -Severity low -Technique 'T1105' -Time $Row.time -Source $src `
            -Evidence "[$src] $url -> $path" -Key (Get-IRPathKey $path) -File $path -User $Row.user
    }
    $size = if ($Row.size) { " ($($Row.size) bytes)" } else { '' }
    Add-IRTimeline $Row.time $src 'download' 'browser' "$($Row.user) downloaded $(Limit-IRText $url 200) -> $path$size [$($Row.state)]" $Row.user -Keep
}

function Invoke-IRBrowserAnalysis([string]$UsersDir, [string]$Work) {
    $hist = [System.Collections.Generic.List[object]]::new()
    $dls = [System.Collections.Generic.List[object]]::new()
    $wk = [long](($Script:Since - $Script:WebkitEpoch).Ticks / 10)
    $ux = [long](($Script:Since - $Script:UnixEpoch).Ticks / 10)
    $dbs = @(Get-ChildItem -LiteralPath $UsersDir -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { ($_.Name -eq 'History' -or $_.Name -eq 'places.sqlite') -and $_.FullName -match '\\Browsers\\' })
    foreach ($f in $dbs) {
        $browser = $f.Directory.Parent.Name; $prof = $f.Directory.Name
        $folder = $f.Directory.Parent.Parent.Parent.Name
        $pr = Get-IRProfileRow $folder
        $user = if ($pr -and $pr.user) { [string]$pr.user } else { $folder }
        try {
            $db = Copy-IRWorkFile $f.FullName $Work @('-journal', '-wal')
            $nv = 0; $nd = 0
            if ($f.Name -eq 'History') {
                $visits = [IRInv.Sqlite]::Query($db, "SELECT v.visit_time AS t, u.url AS url, u.title AS title, v.transition AS tr, u.visit_count AS vc FROM visits v JOIN urls u ON u.id = v.url WHERE v.visit_time >= $wk ORDER BY v.visit_time DESC", 20000)
                foreach ($r in $visits) {
                    $t = ConvertFrom-IRWebkit $r['t']
                    $core = [int]([long]$r['tr'] -band 0xFF)
                    $tr = if ($core -lt $Script:ChromeTransition.Count) { $Script:ChromeTransition[$core] } else { [string]$core }
                    $hist.Add([pscustomobject]@{ time = $t; user = $user; browser = $browser; profile = $prof; url = [string]$r['url']; title = [string]$r['title']; transition = $tr; visit_count = $r['vc'] })
                    Test-IRBrowserVisit $t ([string]$r['url']) $browser $user
                    $nv++
                }
                try {
                    $downloads = [IRInv.Sqlite]::Query($db, "SELECT d.start_time AS t, d.end_time AS te, d.target_path AS path, d.total_bytes AS size, d.state AS state, d.danger_type AS danger, d.referrer AS referrer, d.mime_type AS mime, (SELECT c.url FROM downloads_url_chains c WHERE c.id = d.id ORDER BY c.chain_index DESC LIMIT 1) AS url FROM downloads d WHERE d.start_time >= $wk ORDER BY d.start_time DESC", 5000)
                } catch {
                    $downloads = [IRInv.Sqlite]::Query($db, "SELECT start_time AS t, target_path AS path, total_bytes AS size, state AS state FROM downloads WHERE start_time >= $wk ORDER BY start_time DESC", 5000)
                }
                foreach ($r in $downloads) {
                    $st = if ($null -ne $r['state'] -and [int]$r['state'] -lt $Script:ChromeDlState.Count) { $Script:ChromeDlState[[int]$r['state']] } else { [string]$r['state'] }
                    $dg = if ($null -eq $r['danger']) { $null } elseif ([int]$r['danger'] -lt $Script:ChromeDanger.Count) { $Script:ChromeDanger[[int]$r['danger']] } else { [string]$r['danger'] }
                    $row = [pscustomobject]@{
                        time = (ConvertFrom-IRWebkit $r['t']); finished = (ConvertFrom-IRWebkit $r['te']); user = $user; browser = $browser; profile = $prof
                        url = [string]$r['url']; referrer = [string]$r['referrer']; target_path = [string]$r['path']; size = $r['size']; mime = [string]$r['mime']; state = $st; danger = $dg
                    }
                    $dls.Add($row); Test-IRBrowserDownload $row; $nd++
                }
            } else {
                $visits = [IRInv.Sqlite]::Query($db, "SELECT v.visit_date AS t, p.url AS url, p.title AS title, v.visit_type AS tr, p.visit_count AS vc FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id WHERE v.visit_date >= $ux ORDER BY v.visit_date DESC", 20000)
                foreach ($r in $visits) {
                    $t = ConvertFrom-IRUnixMicro $r['t']
                    $tr = $Script:FirefoxTransition[[int]$r['tr']]
                    if (-not $tr) { $tr = [string]$r['tr'] }
                    $hist.Add([pscustomobject]@{ time = $t; user = $user; browser = $browser; profile = $prof; url = [string]$r['url']; title = [string]$r['title']; transition = $tr; visit_count = $r['vc'] })
                    Test-IRBrowserVisit $t ([string]$r['url']) $browser $user
                    $nv++
                }
                $downloads = @()
                try { $downloads = [IRInv.Sqlite]::Query($db, "SELECT a.dateAdded AS t, p.url AS url, a.content AS dest FROM moz_annos a JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id JOIN moz_places p ON p.id = a.place_id WHERE n.name = 'downloads/destinationFileURI' AND a.dateAdded >= $ux ORDER BY a.dateAdded DESC", 5000) } catch { }
                foreach ($r in $downloads) {
                    $dest = [string]$r['dest']
                    try { if ($dest -match '^file:') { $dest = ([Uri]$dest).LocalPath } } catch { }
                    $row = [pscustomobject]@{
                        time = (ConvertFrom-IRUnixMicro $r['t']); finished = $null; user = $user; browser = $browser; profile = $prof
                        url = [string]$r['url']; referrer = $null; target_path = $dest; size = $null; mime = $null; state = $null; danger = $null
                    }
                    $dls.Add($row); Test-IRBrowserDownload $row; $nd++
                }
            }
            Write-IRLog "  $browser/$prof ($user): $nv visits, $nd downloads in the window"
        } catch { Add-IRArtifactNote 'Browsers' "$browser/$prof ($user) could not be read: $($_.Exception.Message)" }
    }
    $Script:D['browser_history'] = @($hist | Sort-Object { $_.time } -Descending | Select-Object -First 15000)
    $Script:D['browser_downloads'] = @($dls)
}

function Invoke-IRAmcacheAnalysis([string]$Art) {
    $hv = Join-Path $Art 'Amcache\Amcache.hve'
    if (-not (Test-Path -LiteralPath $hv)) { Add-IRArtifactNote 'Amcache' 'Amcache.hve is not in the case (it is locked by Windows: collect elevated so the shadow-copy fallback can read it).'; return }
    $h = New-Object IRInv.RegHive $hv
    if ($h.Dirty) { Write-IRLog "  Amcache: dirty hive, $($h.LogPagesApplied) page(s) replayed from the transaction logs" }
    $files = [System.Collections.Generic.List[object]]::new()
    $k = $h.Root.Open('Root\InventoryApplicationFile')
    if (-not $k) { Add-IRArtifactNote 'Amcache' 'Root\InventoryApplicationFile not found (pre-Windows 10 Amcache format is not decoded).' }
    else {
        foreach ($e in $k.SubKeys()) {
            $v = @{}
            foreach ($x in $e.Values()) { $v[$x.Name] = $x.Value }
            $path = [string]$v['LowerCaseLongPath']
            $sha1 = [string]$v['FileId']
            if ($sha1.Length -eq 44 -and $sha1.StartsWith('0000')) { $sha1 = $sha1.Substring(4) }
            $t = ConvertTo-IRTime $e.LastWrite
            $os = [string]$v['IsOsComponent'] -eq '1'
            $files.Add([pscustomobject]@{
                    recorded = $t; path = $path; name = [string]$v['Name']; sha1 = $sha1; publisher = [string]$v['Publisher']; product = [string]$v['ProductName']
                    version = [string]$v['Version']; link_date = [string]$v['LinkDate']; size = $v['Size']; os_component = $os; program_id = [string]$v['ProgramId']
                })
            if (-not $path) { continue }
            Start-IRItem
            $leaf = Get-IRLeaf $path
            Test-IRTool -Name $leaf -Path $path -Time $t -Source 'Amcache' -Hash $sha1
            if ($Script:TyposquatRx.IsMatch($leaf)) {
                Add-IRFinding -Rule 'TYPOSQUAT' -Title "Process name imitates a Windows binary: $leaf" -Severity high -Technique 'T1036.005' -Time $t -Source 'Amcache' -Evidence "[Amcache] $path (sha1 $sha1)" -Key $leaf -File $path -Hash $sha1
            }
            if (-not $os -and (Get-IRPathRisk $path)) {
                Add-IRFinding -Rule 'AMCACHE-SUSP-DIR' -Title "Program in a staging folder recorded in Amcache: $leaf" -Severity low -Technique 'T1204.002' -Time $t -Source 'Amcache' `
                    -Evidence "[Amcache] $path (sha1 $sha1, publisher '$($v['Publisher'])', recorded $t)" -Key (Get-IRPathKey $path) -File $path -Hash $sha1
            }
            $keep = -not $os -and -not $Script:TrustedDirRx.IsMatch($path)
            Add-IRTimeline $t 'Amcache' 'amcache' 'execution' "Amcache: $path recorded (sha1 $sha1)" $null -Keep:$keep
        }
    }
    $progs = [System.Collections.Generic.List[object]]::new()
    $k = $h.Root.Open('Root\InventoryApplication')
    if ($k) {
        foreach ($e in $k.SubKeys()) {
            $v = @{}
            foreach ($x in $e.Values()) { $v[$x.Name] = $x.Value }
            $name = [string]$v['Name']
            $progs.Add([pscustomobject]@{
                    recorded = (ConvertTo-IRTime $e.LastWrite); name = $name; publisher = [string]$v['Publisher']; version = [string]$v['Version']
                    install_date = [string]$v['InstallDate']; source = [string]$v['Source']; root_dir = [string]$v['RootDirPath']; uninstall = [string]$v['UninstallString']
                })
            if ($name) { Start-IRItem; Test-IRTool -Name $name -Path ([string]$v['RootDirPath']) -Time (ConvertTo-IRTime $e.LastWrite) -Source 'Amcache: installed program' }
        }
    }
    $Script:D['amcache_files'] = @($files)
    $Script:D['amcache_programs'] = @($progs)
    Write-IRLog "  Amcache: $($files.Count) files, $($progs.Count) programs"
}

function Read-IROfflineUserActivity($Hive, [string]$User) {
    $ua = [System.Collections.Generic.List[object]]::new()
    $k = $Hive.Root.Open('Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist')
    if ($k) {
        foreach ($g in $k.SubKeys()) {
            $c = $g.Open('Count')
            if (-not $c) { continue }
            foreach ($v in $c.Values()) {
                $name = ConvertFrom-IRRot13 $v.Name
                if ($name -match '^UEME_') { continue }
                foreach ($guid in $Script:KnownFolders.Keys) { if ($name.StartsWith($guid, [StringComparison]::OrdinalIgnoreCase)) { $name = $Script:KnownFolders[$guid] + $name.Substring($guid.Length) } }
                $d = $v.Data
                $count = $null; $focus = $null; $last = $null
                if ($d -is [byte[]] -and $d.Length -ge 68) {
                    $count = [BitConverter]::ToInt32($d, 4)
                    $focus = [math]::Round([BitConverter]::ToInt32($d, 12) / 1000)
                    $last = ConvertFrom-IRFileTime ([BitConverter]::ToInt64($d, 60))
                }
                $ua.Add([pscustomobject]@{ user = $User; program = $name; run_count = $count; focus_seconds = $focus; last_run = $last; source = 'offline NTUSER.DAT' })
            }
        }
    }
    $mru = [System.Collections.Generic.List[object]]::new()
    foreach ($pair in @(@('RunMRU', 'Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'), @('TypedPaths', 'Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'), @('RDP MRU', 'Software\Microsoft\Terminal Server Client\Default'))) {
        $k = $Hive.Root.Open($pair[1])
        if (-not $k) { continue }
        foreach ($v in $k.Values()) {
            if ($v.Name -eq 'MRUList') { continue }
            $mru.Add([pscustomobject]@{ user = $User; type = $pair[0]; name = $v.Name; value = [string]$v.Value; source = 'offline NTUSER.DAT' })
        }
    }
    $k = $Hive.Root.Open('Software\Microsoft\Terminal Server Client\Servers')
    if ($k) { foreach ($s in $k.SubKeys()) { $mru.Add([pscustomobject]@{ user = $User; type = 'RDP server'; name = $s.Name; value = [string]$s.GetValue('UsernameHint'); source = 'offline NTUSER.DAT' }) } }
    $k = $Hive.Root.Open('Network')
    if ($k) { foreach ($s in $k.SubKeys()) { $mru.Add([pscustomobject]@{ user = $User; type = 'Mapped drive'; name = $s.Name; value = ('{0} as {1}' -f $s.GetValue('RemotePath'), $s.GetValue('UserName')); source = 'offline NTUSER.DAT' }) } }
    if ($ua.Count) { Add-IRDataRows 'userassist' $ua }
    if ($mru.Count) { Add-IRDataRows 'user_mru' $mru }
    Write-IRLog "  $User (profile not loaded at collection): $($ua.Count) UserAssist and $($mru.Count) MRU entries from the offline NTUSER.DAT"
}

function Invoke-IRUserHiveAnalysis([string]$UsersDir) {
    $bags = [System.Collections.Generic.List[object]]::new()
    foreach ($u in @(Get-ChildItem -LiteralPath $UsersDir -Directory -ErrorAction SilentlyContinue)) {
        $pr = Get-IRProfileRow $u.Name
        $user = if ($pr -and $pr.user) { [string]$pr.user } else { $u.Name }
        $hives = @{}
        foreach ($fn in 'UsrClass.dat', 'NTUSER.DAT') {
            $p = Join-Path $u.FullName $fn
            if (-not (Test-Path -LiteralPath $p)) { continue }
            try { $hives[$fn] = New-Object IRInv.RegHive $p } catch { Add-IRArtifactNote 'Hives' "$($u.Name)\$fn could not be parsed: $($_.Exception.GetBaseException().Message)" }
        }
        $n0 = $bags.Count
        foreach ($pair in @(@('UsrClass.dat', 'Local Settings\Software\Microsoft\Windows\Shell\BagMRU'), @('UsrClass.dat', 'Local Settings\Software\Microsoft\Windows\ShellNoRoam\BagMRU'),
                @('NTUSER.DAT', 'Software\Microsoft\Windows\Shell\BagMRU'), @('NTUSER.DAT', 'Software\Microsoft\Windows\ShellNoRoam\BagMRU'))) {
            $hv = $hives[$pair[0]]
            if (-not $hv) { continue }
            $k = $hv.Root.Open($pair[1])
            if (-not $k) { continue }
            foreach ($b in [IRInv.Shell]::BagMru($k)) {
                $t = ConvertTo-IRTime $b.KeyLastWrite
                $bags.Add([pscustomobject]@{ user = $user; path = $b.Path; bag_key_written = $t; folder_modified = $b.Modified; folder_created = $b.Created; folder_accessed = $b.Accessed; hive = $pair[0] })
                Start-IRItem
                $src = "ShellBags ($user)"
                if ($b.Path -match '^\\\\[^\\]+\\(admin|[a-z])\$') {
                    Add-IRFinding -Rule 'ADMIN-SHARE' -Title 'Admin share opened by a user' -Severity medium -Technique 'T1021.002' -Time $t -Source $src -Evidence "[$src] $user browsed $($b.Path)" -Key $b.Path -User $user
                }
                Test-IRTool -Name (Get-IRLeaf $b.Path) -Path $b.Path -Time $t -Source $src -User $user
                if ($t) { Add-IRTimeline $t $src 'shellbag' 'user-activity' "$user browsed folder $($b.Path)" $user -Keep }
            }
        }
        if ($bags.Count -gt $n0) { Write-IRLog "  $user`: $($bags.Count - $n0) ShellBags folders" }
        if ($hives['NTUSER.DAT'] -and -not ($pr -and $pr.loaded)) { Read-IROfflineUserActivity $hives['NTUSER.DAT'] $user }
    }
    $Script:D['shellbags'] = @($bags)
}

function Test-IRJumpEntry($Row) {
    Start-IRItem
    $src = "Jump List: $($Row.app) ($($Row.user))"
    $target = [string]$Row.target; $t = $Row.last_used; $leaf = Get-IRLeaf $target
    Test-IRTool -Name $leaf -Path $target -Time $t -Source $src -User $Row.user
    if ($Script:DoubleExtRx.IsMatch($leaf)) {
        Add-IRFinding -Rule 'DOUBLE-EXT' -Title 'Double file extension' -Severity high -Technique 'T1036.007' -Time $t -Source $src -Evidence "[$src] $($Row.user) opened $target" -Key $target -File $target -User $Row.user
    }
    if ($target -match '^\\\\[^\\]+\\(admin|[a-z])\$') {
        Add-IRFinding -Rule 'ADMIN-SHARE' -Title 'Admin share opened by a user' -Severity medium -Technique 'T1021.002' -Time $t -Source $src -Evidence "[$src] $($Row.user) opened $target" -Key $target -User $Row.user
    }
    if ($Script:ExecExtRx.IsMatch($leaf) -and $leaf -notmatch '\.lnk$' -and (Get-IRPathRisk $target)) {
        Add-IRFinding -Rule 'EXEC-SUSP-DIR' -Title "Program executed from a staging / unusual folder: $leaf" -Severity medium -Technique 'T1204.002' -Time $t -Source $src -Evidence "[$src] $target (user $($Row.user))" -Key (Get-IRPathKey $target) -User $Row.user -File $target
    }
    if ($Row.app_id -eq '1bc392b8e104a00e') {
        $dst = if ([string]$Row.arguments -match '/v:\s*"?([^\s"]+)') { $Matches[1] } elseif ($target) { [IO.Path]::GetFileNameWithoutExtension($target) } else { $null }
        if ($dst) { Add-IRFinding -Rule 'RDP-OUTBOUND' -Title "Outbound Remote Desktop connection to $dst" -Severity low -Technique 'T1021.001' -Time $t -Source $src -Evidence "[$src] $($Row.user) -> $dst $($Row.arguments)" -Key $dst -User $Row.user }
    }
    if ($t) { Add-IRTimeline $t $src 'jumplist' 'user-activity' "$($Row.user) opened $target$(if ($Row.arguments) { " $($Row.arguments)" }) via $($Row.app)" $Row.user -Keep }
}

function New-IRJumpRow([string]$User, [string]$AppId, [string]$Kind, $Lnk, $Dest) {
    $app = $Script:JumpListApps[$AppId]
    if (-not $app) { $app = "AppID $AppId" }
    $target = if ($Lnk -and $Lnk.Target) { $Lnk.Target } elseif ($Dest) { $Dest.Path } else { $null }
    [pscustomobject]@{
        user = $User; app = $app; app_id = $AppId; kind = $Kind
        last_used = $(if ($Dest) { ConvertTo-IRTime $Dest.LastAccess } else { $null })
        access_count = $(if ($Dest) { $Dest.AccessCount } else { $null }); pinned = $(if ($Dest) { $Dest.Pinned } else { $null })
        target = $target; arguments = $(if ($Lnk) { $Lnk.Arguments } else { $null }); working_dir = $(if ($Lnk) { $Lnk.WorkingDir } else { $null })
        target_created = $(if ($Lnk) { ConvertTo-IRTime $Lnk.Created } else { $null }); target_modified = $(if ($Lnk) { ConvertTo-IRTime $Lnk.Modified } else { $null })
        target_accessed = $(if ($Lnk) { ConvertTo-IRTime $Lnk.Accessed } else { $null }); size = $(if ($Lnk) { $Lnk.FileSize } else { $null })
        drive_type = $(if ($Lnk) { $Lnk.DriveType } else { $null }); volume_serial = $(if ($Lnk) { $Lnk.VolumeSerial } else { $null })
        machine_id = $(if ($Lnk) { $Lnk.MachineId } else { $null }); host = $(if ($Dest) { $Dest.Host } else { $null })
    }
}

function Invoke-IRJumpListAnalysis([string]$UsersDir) {
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($u in @(Get-ChildItem -LiteralPath $UsersDir -Directory -ErrorAction SilentlyContinue)) {
        $pr = Get-IRProfileRow $u.Name
        $user = if ($pr -and $pr.user) { [string]$pr.user } else { $u.Name }
        $n0 = $rows.Count
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $u.FullName 'JumpLists\AutomaticDestinations') -File -Force -ErrorAction SilentlyContinue)) {
            $appId = $f.Name.Split('.')[0].ToLowerInvariant()
            try {
                $cfb = [IRInv.Cfb]::new([IO.File]::ReadAllBytes($f.FullName))
                $dest = @{}
                if ($cfb.Streams.ContainsKey('DestList')) { foreach ($e in [IRInv.Lnk]::ParseDestList($cfb.Streams['DestList'])) { $dest['{0:x}' -f $e.EntryId] = $e } }
                foreach ($sn in @($cfb.Streams.Keys)) {
                    if ($sn -eq 'DestList') { continue }
                    $l = [IRInv.Lnk]::Parse($cfb.Streams[$sn], 0)
                    $e = $dest[$sn.ToLowerInvariant()]
                    if (-not $l -and -not $e) { continue }
                    $rows.Add((New-IRJumpRow $user $appId 'automatic' $l $e))
                }
            } catch { Add-IRArtifactNote 'Jump Lists' "$($u.Name)\$($f.Name) could not be parsed: $($_.Exception.GetBaseException().Message)" }
        }
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $u.FullName 'JumpLists\CustomDestinations') -File -Force -ErrorAction SilentlyContinue)) {
            $appId = $f.Name.Split('.')[0].ToLowerInvariant()
            try { foreach ($l in [IRInv.Lnk]::Scan([IO.File]::ReadAllBytes($f.FullName))) { $rows.Add((New-IRJumpRow $user $appId 'custom' $l $null)) } }
            catch { Add-IRArtifactNote 'Jump Lists' "$($u.Name)\$($f.Name) could not be parsed: $($_.Exception.Message)" }
        }
        if ($rows.Count -gt $n0) { Write-IRLog "  $user`: $($rows.Count - $n0) Jump List entries" }
    }
    foreach ($r in $rows) { Test-IRJumpEntry $r }
    $Script:D['jump_lists'] = @($rows)
}

function Invoke-IRSrumAnalysis([string]$Art, [string]$Work) {
    $srcDb = Join-Path $Art 'SRUM\SRUDB.dat'
    if (-not (Test-Path -LiteralPath $srcDb)) { Add-IRArtifactNote 'SRUM' 'SRUDB.dat is not in the case (it is locked by Windows: collect elevated so the shadow-copy fallback can read it).'; return }
    $dir = Join-Path $Work 'srum'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $Art 'SRUM') -File -Force)) { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $dir $f.Name) -Force }
    # Replays SRU*.log into the copy so the database is in a clean-shutdown state.
    $null = & (Join-Path $env:SystemRoot 'System32\esentutl.exe') /r sru "/l$dir" "/s$dir" "/d$dir" /i /o 2>&1
    $rec = $LASTEXITCODE
    $db = Join-Path $dir 'SRUDB.dat'
    $map = @{}; $net = $null; $apps = $null
    $ese = $null
    try {
        try { $ese = [IRInv.Ese]::new($db, $dir) }
        catch { throw "$($_.Exception.GetBaseException().Message) (esentutl recovery exit code $rec)" }
        foreach ($r in @($ese.Read('SruDbIdMapTable', [string[]]@('IdType', 'IdIndex', 'IdBlob'), $null, [DateTime]::MinValue, 2000000))) {
            if ($null -eq $r['IdIndex']) { continue }
            $blob = $r['IdBlob']
            $val = $null
            if ($blob -is [byte[]]) {
                if ([int]$r['IdType'] -eq 3) { try { $val = Resolve-IRSid ((New-Object Security.Principal.SecurityIdentifier($blob, 0)).Value) } catch { } }
                else { $val = [Text.Encoding]::Unicode.GetString($blob).TrimEnd([char]0) }
            }
            if (-not $val) { $val = "(id $($r['IdIndex']))" }
            $map[[int]$r['IdIndex']] = $val
        }
        $net = $ese.Read('{973F5D5C-1D90-4944-BE8E-24B94231A174}', [string[]]@('TimeStamp', 'AppId', 'UserId', 'BytesSent', 'BytesRecvd', 'InterfaceLuid'), 'TimeStamp', $Script:Since, 500000)
        $apps = $ese.Read('{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}', [string[]]@('TimeStamp', 'AppId', 'UserId', 'ForegroundCycleTime', 'BackgroundCycleTime', 'ForegroundBytesRead', 'ForegroundBytesWritten', 'BackgroundBytesRead', 'BackgroundBytesWritten'), 'TimeStamp', $Script:Since, 500000)
    } finally { if ($ese) { $ese.Dispose() } }

    $netRows = [System.Collections.Generic.List[object]]::new()
    $agg = @{}
    foreach ($r in @($net)) {
        if (-not $r) { continue }
        $app = $map[[int]$r['AppId']]; $user = $map[[int]$r['UserId']]
        $t = ConvertTo-IRTime $r['TimeStamp']
        $sent = [long]$r['BytesSent']; $recv = [long]$r['BytesRecvd']
        $netRows.Add([pscustomobject]@{ time = $t; app = $app; user = $user; bytes_sent = $sent; bytes_received = $recv })
        $key = "$app|$user"
        $a = $agg[$key]
        if (-not $a) { $a = [pscustomobject]@{ app = $app; user = $user; bytes_sent = [long]0; bytes_received = [long]0; first = $t; last = $t; records = 0 }; $agg[$key] = $a }
        $a.bytes_sent += $sent; $a.bytes_received += $recv; $a.records++
        if ($t -and (-not $a.first -or [string]::CompareOrdinal($t, $a.first) -lt 0)) { $a.first = $t }
        if ($t -and (-not $a.last -or [string]::CompareOrdinal($t, $a.last) -gt 0)) { $a.last = $t }
        if ($sent -ge 200MB) {
            Start-IRItem
            Add-IRTimeline $t 'SRUM' 'network-usage' 'network' ("{0} sent {1:n0} MB in one hour ({2})" -f $app, ($sent / 1MB), $user) $user -Keep
        }
    }
    foreach ($a in $agg.Values) {
        Start-IRItem
        $src = "SRUM network usage ($($a.user))"
        $leaf = Get-IRLeaf $a.app
        $vol = "{0:n1} MB sent, {1:n1} MB received between {2} and {3}" -f ($a.bytes_sent / 1MB), ($a.bytes_received / 1MB), $a.first, $a.last
        Test-IRTool -Name $leaf -Path $a.app -Time $a.last -Source $src -User $a.user
        if (Get-IRPathRisk $a.app) {
            Add-IRFinding -Rule 'SRUM-NET-SUSP-DIR' -Title "Program in a staging folder used the network: $leaf" -Severity medium -Technique 'T1071.001' -Time $a.last -Source $src -Evidence "[$src] $($a.app): $vol" -Key (Get-IRPathKey $a.app) -File $a.app -User $a.user
        }
        if ($a.bytes_sent -ge 1GB -and $a.bytes_sent -gt $a.bytes_received) {
            $sev = if ($Script:SyncClientRx.IsMatch([string]$a.app)) { 'low' } else { 'medium' }
            Add-IRFinding -Rule 'SRUM-LARGE-UPLOAD' -Title ("Large upload by {0}: {1:n1} GB sent" -f $leaf, ($a.bytes_sent / 1GB)) -Severity $sev -Technique 'T1048' -Time $a.last -Source $src -Evidence "[$src] $($a.app): $vol" -Key ([string]$a.app) -File $a.app -User $a.user
        }
    }

    $appRows = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    foreach ($r in @($apps)) {
        if (-not $r) { continue }
        $app = $map[[int]$r['AppId']]; $user = $map[[int]$r['UserId']]
        $t = ConvertTo-IRTime $r['TimeStamp']
        $appRows.Add([pscustomobject]@{
                time = $t; app = $app; user = $user; foreground_cycles = $r['ForegroundCycleTime']; background_cycles = $r['BackgroundCycleTime']
                fg_bytes_read = $r['ForegroundBytesRead']; fg_bytes_written = $r['ForegroundBytesWritten']; bg_bytes_read = $r['BackgroundBytesRead']; bg_bytes_written = $r['BackgroundBytesWritten']
            })
        if (-not $app -or $seen.ContainsKey("$app|$user")) { continue }
        $seen["$app|$user"] = 1
        Start-IRItem
        $src = "SRUM application usage ($user)"
        $leaf = Get-IRLeaf $app
        Test-IRTool -Name $leaf -Path $app -Time $t -Source $src -User $user
        if ($app -match '\\' -and (Get-IRPathRisk $app)) {
            Add-IRFinding -Rule 'EXEC-SUSP-DIR' -Title "Program executed from a staging / unusual folder: $leaf" -Severity medium -Technique 'T1204.002' -Time $t -Source $src -Evidence "[$src] $app (user $user)" -Key (Get-IRPathKey $app) -User $user -File $app
        }
    }
    foreach ($r in @($appRows | Sort-Object { $_.time } | Group-Object { "$($_.app)|$($_.user)" } | ForEach-Object { $_.Group[0] })) {
        if (-not $r.app -or $r.app -notmatch '\\' -or $Script:TrustedDirRx.IsMatch([string]$r.app)) { continue }
        Start-IRItem
        Add-IRTimeline $r.time "SRUM application usage ($($r.user))" 'app-usage' 'execution' "SRUM: $($r.app) first active in the window ($($r.user))" $r.user -Keep
    }
    $Script:D['srum_network'] = @($netRows | Sort-Object { $_.time } -Descending | Select-Object -First 10000)
    $Script:D['srum_network_summary'] = @($agg.Values | Sort-Object { $_.bytes_sent } -Descending)
    $Script:D['srum_app_usage'] = @($appRows | Sort-Object { $_.time } -Descending | Select-Object -First 10000)
    Write-IRLog "  SRUM: $($netRows.Count) network and $($appRows.Count) app usage records in the window, $($map.Count) ids"
}

function Invoke-IRArtifactAnalysis {
    $Script:ArtifactNotes = [System.Collections.Generic.List[object]]::new()
    $art = Join-Path $Script:In.Root 'artifacts'
    if (-not (Test-Path -LiteralPath $art)) { Write-IRLog '  no artifacts folder in the case (Quick collection) - skipped'; return }
    if (-not (Initialize-IRArtifactParsers)) { Add-IRArtifactNote 'Artifacts' 'The parsers could not be compiled (Add-Type blocked?): browsers, Amcache, ShellBags, Jump Lists and SRUM were not analysed.'; return }
    $work = Join-Path ([IO.Path]::GetTempPath()) ('IRArt_' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $work -Force | Out-Null
    $users = Join-Path $art 'Users'
    try {
        foreach ($step in @(
                @('Browsers', { Invoke-IRBrowserAnalysis $users $work }),
                @('Amcache', { Invoke-IRAmcacheAnalysis $art }),
                @('Hives', { Invoke-IRUserHiveAnalysis $users }),
                @('Jump Lists', { Invoke-IRJumpListAnalysis $users }),
                @('SRUM', { Invoke-IRSrumAnalysis $art $work }))) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            try { & $step[1] } catch { Add-IRArtifactNote $step[0] "analysis failed: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" }
            Write-IRLog ('  {0} done in {1:n1}s' -f $step[0], $sw.Elapsed.TotalSeconds)
        }
    } finally {
        $Script:Hits = $null
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
        Remove-IRFolder $work | Out-Null
    }
    if ($Script:ArtifactNotes.Count) { $Script:D['artifact_notes'] = @($Script:ArtifactNotes) }
}

#endregion

#region ===== Analysis: incidents, verdict, recommendations, report data =====

function Get-IRMaxSeverity($Items) {
    $best = 'info'
    foreach ($i in $Items) { if ($Script:SevRank[$i.severity] -gt $Script:SevRank[$best]) { $best = $i.severity } }
    return $best
}

function Get-IRSortedFindings {
    $sorted = @($Script:Findings.Values | Sort-Object @{ Expression = { $Script:SevRank[$_.severity] }; Descending = $true }, @{ Expression = { if ($_.first_seen) { $_.first_seen } else { 'z' } } })
    $i = 0
    foreach ($f in $sorted) { $i++; $f.id = 'F{0:d3}' -f $i }
    return $sorted
}

function Get-IREntityKeys($F) {
    $keys = [System.Collections.Generic.List[string]]::new()
    foreach ($u in $F.users) { $keys.Add('u:' + ([string]$u -split '\\')[-1].ToLowerInvariant()) }
    foreach ($i in $F.ips) { $keys.Add('i:' + $i.ToLowerInvariant()) }
    foreach ($p in (@($F.files) + @($F.processes))) {
        if ($p -and $p -match '[\\/]' -and -not $Script:TrustedDirRx.IsMatch([string]$p)) { $keys.Add('f:' + (Get-IRPathKey $p)) }
    }
    foreach ($h in $F.hashes) { $keys.Add('h:' + $h.ToLowerInvariant()) }
    foreach ($d in $F.domains) { $keys.Add('d:' + $d.ToLowerInvariant()) }
    # PSReadLine history has no timestamps; one user's history is a single command stream.
    if (-not $F.first_seen -and $Script:SevRank[$F.severity] -ge 3) {
        foreach ($s in $F.sources) { if ([string]$s -match '^PSReadLine history \(([^,]+),') { $keys.Add('s:psh:' + $Matches[1].ToLowerInvariant()) } }
    }
    return $keys
}

function New-IRGraph($Members, [string]$HostName) {
    $nodes = [ordered]@{}
    $links = [System.Collections.Generic.List[object]]::new()
    $nodes['host'] = [ordered]@{ id = 'host'; type = 'host'; label = $HostName; full = $HostName }
    foreach ($m in $Members) {
        $fid = "F:$($m.id)"
        $nodes[$fid] = [ordered]@{ id = $fid; type = 'finding'; label = $m.title; full = "$($m.id) $($m.title)"; sev = $m.severity; ref = $m.id; tactic = $m.tactic }
        $ents = [System.Collections.Generic.List[object]]::new()
        foreach ($u in @($m.users | Select-Object -First 3)) { $ents.Add(@('user', [string]$u, ([string]$u -split '\\')[-1])) }
        foreach ($i in @($m.ips | Select-Object -First 3)) { $ents.Add(@('ip', [string]$i, [string]$i)) }
        foreach ($d in @($m.domains | Select-Object -First 2)) { $ents.Add(@('domain', [string]$d, [string]$d)) }
        foreach ($p in @((@($m.files) + @($m.processes)) | Where-Object { $_ -and $_ -match '[\\/]' } | Select-Object -Unique -First 2)) { $ents.Add(@('file', [string]$p, (Get-IRLeaf $p))) }
        if (-not $ents.Count) { $links.Add([ordered]@{ s = 'host'; t = $fid }); continue }
        foreach ($e in $ents) {
            $nid = $e[0] + ':' + $(if ($e[0] -eq 'file') { Get-IRPathKey $e[1] } else { $e[1].ToLowerInvariant() })
            if (-not $nodes.Contains($nid)) {
                $nodes[$nid] = [ordered]@{ id = $nid; type = $e[0]; label = $e[2]; full = $e[1] }
                if ($e[0] -in @('user', 'ip')) { $links.Add([ordered]@{ s = 'host'; t = $nid }) }
            }
            $links.Add([ordered]@{ s = $fid; t = $nid })
        }
    }
    return [ordered]@{ nodes = @($nodes.Values | ForEach-Object { $_ }); links = $links }
}

function Get-IRIncidentTitle($Tactics, $Top, $Techniques) {
    $t = @($Tactics)
    # Impact also covers resource hijacking (T1496) and data manipulation (T1565): not ransomware.
    $destructive = @($Techniques | Where-Object { [string]$_ -match '^T(1485|1486|1488|1489|1490|1491|1495|1529|1561)(\.|$)' }).Count -gt 0
    $mining = @($Techniques | Where-Object { [string]$_ -eq 'T1496' }).Count -gt 0
    if ($destructive) { return 'Possible ransomware / destructive activity' }
    $title = $null
    if ('credential-access' -in $t -and 'lateral-movement' -in $t) { $title = 'Credential theft and lateral movement' }
    elseif ('command-and-control' -in $t -or 'exfiltration' -in $t) { $title = 'Command-and-control / data exfiltration' }
    elseif ('credential-access' -in $t -and 'initial-access' -in $t) { $title = 'Credential attack against remote access' }
    elseif ('credential-access' -in $t) { $title = 'Credential access' }
    elseif ('lateral-movement' -in $t) { $title = 'Lateral movement' }
    elseif ('persistence' -in $t -and 'execution' -in $t) { $title = 'Malicious execution with persistence' }
    elseif ('defense-evasion' -in $t -and $t.Count -gt 1 -and -not ($mining -and $t.Count -eq 2 -and 'impact' -in $t)) { $title = 'Defense evasion with follow-on activity' }
    elseif ('persistence' -in $t) { $title = 'Persistence' }
    elseif ('initial-access' -in $t) { $title = 'Suspicious remote access' }
    elseif ($mining) { return 'Cryptocurrency mining (resource hijacking)' }
    elseif ('defense-evasion' -in $t) { $title = 'Defense evasion' }
    elseif ('discovery' -in $t) { $title = 'Reconnaissance' }
    elseif ('impact' -in $t) { $title = 'Data manipulation' }
    if (-not $title) { return $Top.title }
    if ($mining) { $title += ' + cryptomining' }
    return $title
}

function Format-IRDuration([TimeSpan]$Span) {
    if ($Span.TotalMinutes -lt 1) { return 'under a minute' }
    if ($Span.TotalHours -lt 1) { return '{0:n0} minutes' -f $Span.TotalMinutes }
    if ($Span.TotalDays -lt 2) { return '{0:n1} hours' -f $Span.TotalHours }
    return '{0:n1} days' -f $Span.TotalDays
}

# Findings sharing a strong entity (file, hash, IP, domain) are always related; findings sharing
# only an account are related when they happened within 24 hours of each other.
function Build-IRIncidents($Findings) {
    $parent = @{}
    foreach ($f in $Findings) { $parent[$f.id] = $f.id }
    $find = { param($x) while ($parent[$x] -ne $x) { $parent[$x] = $parent[$parent[$x]]; $x = $parent[$x] }; $x }
    $union = { param($a, $b) $ra = & $find $a; $rb = & $find $b; if ($ra -ne $rb) { $parent[$ra] = $rb } }
    $ents = @{}
    foreach ($f in $Findings) {
        if ($f.severity -eq 'info') { continue }
        foreach ($k in (Get-IREntityKeys $f)) {
            if (-not $ents.ContainsKey($k)) { $ents[$k] = [System.Collections.Generic.List[object]]::new() }
            if (-not $ents[$k].Contains($f)) { $ents[$k].Add($f) }
        }
    }
    foreach ($k in @($ents.Keys)) {
        $list = $ents[$k]
        if ($list.Count -lt 2 -or $list.Count -gt 60) { continue }
        if ($k.StartsWith('u:')) {
            $timed = @($list | Where-Object { $_.first_seen } | Sort-Object { $_.first_seen })
            for ($i = 1; $i -lt $timed.Count; $i++) {
                $a = Get-IRDate $timed[$i - 1].last_seen; $b = Get-IRDate $timed[$i].first_seen
                if ($a -and $b -and ($b - $a).TotalHours -le 24) { & $union $timed[$i - 1].id $timed[$i].id }
            }
        } else {
            for ($i = 1; $i -lt $list.Count; $i++) { & $union $list[0].id $list[$i].id }
        }
    }
    # Host-wide settings (Defender off, firewall off, WDigest...) carry no user / file / IP to link
    # on; one incident per tactic instead of one per setting.
    $loose = @{}
    foreach ($f in $Findings) {
        if ($f.severity -eq 'info' -or -not $f.tactic -or @(Get-IREntityKeys $f).Count) { continue }
        if ($loose.ContainsKey($f.tactic)) { & $union $loose[$f.tactic] $f.id } else { $loose[$f.tactic] = $f.id }
    }
    $comps = [ordered]@{}
    foreach ($f in $Findings) {
        $r = & $find $f.id
        if (-not $comps.Contains($r)) { $comps[$r] = [System.Collections.Generic.List[object]]::new() }
        $comps[$r].Add($f)
    }
    $incs = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $comps.Values) {
        $sev = Get-IRMaxSeverity $c
        # An incident needs one high/critical finding, or at least two related findings reaching medium.
        if ($Script:SevRank[$sev] -lt 2 -or ($Script:SevRank[$sev] -eq 2 -and $c.Count -lt 2)) { continue }
        $members = @($c | Sort-Object @{ Expression = { if ($_.first_seen) { $_.first_seen } else { 'z' } } }, @{ Expression = { $Script:SevRank[$_.severity] }; Descending = $true })
        $top = @($c | Sort-Object @{ Expression = { $Script:SevRank[$_.severity] }; Descending = $true }, @{ Expression = { $_.hits }; Descending = $true })[0]
        $score = 0; foreach ($m in $members) { $score += $Script:SevWeight[$m.severity] }
        $times = @($members | ForEach-Object { $_.first_seen; $_.last_seen } | Where-Object { $_ } | Sort-Object)
        $first = $null; $last = $null
        if ($times.Count) { $first = $times[0]; $last = $times[-1] }
        $tk = @{}; foreach ($m in $members) { if ($m.tactic) { $tk[$m.tactic] = 1 } }
        $tactics = @($Script:Tactics | Where-Object { $tk.ContainsKey($_.key) } | ForEach-Object { $_.key })
        $tacticNames = @($Script:Tactics | Where-Object { $tk.ContainsKey($_.key) } | ForEach-Object { $_.name })
        $users = @($members | ForEach-Object { $_.users } | Where-Object { $_ } | Select-Object -Unique -First 15)
        $ips = @($members | ForEach-Object { $_.ips } | Where-Object { $_ } | Select-Object -Unique -First 15)
        $files = @($members | ForEach-Object { $_.files } | Where-Object { $_ -and -not $Script:TrustedDirRx.IsMatch([string]$_) } | Select-Object -Unique -First 15)
        $domains = @($members | ForEach-Object { $_.domains } | Where-Object { $_ } | Select-Object -Unique -First 15)
        $story = [System.Collections.Generic.List[string]]::new()
        foreach ($m in $members) {
            $tn = 'Other'
            if ($m.tactic) { $tn = ($Script:Tactics | Where-Object { $_.key -eq $m.tactic }).name }
            $when = if ($m.first_seen) { ($m.first_seen -replace 'T', ' ' -replace 'Z$', ' UTC') } else { 'time unknown (live state)' }
            $story.Add("$when | $tn | $($m.title)$(if ($m.technique) { " ($($m.technique))" })$(if ($m.hits -gt 1) { " - $($m.hits) occurrences" })")
        }
        $span = ''
        if ($first -and $last) { $span = "between $($first -replace 'T', ' ' -replace 'Z$', ' UTC') and $($last -replace 'T', ' ' -replace 'Z$', ' UTC') ($(Format-IRDuration ((Get-IRDate $last) - (Get-IRDate $first))))" }
        $summary = "$($members.Count) related finding(s)$(if ($span) { " $span" }), covering $($tacticNames.Count) ATT&CK tactic(s): $($tacticNames -join ' -> ')."
        if ($users.Count) { $summary += " Accounts: $(($users | Select-Object -First 6) -join ', ')." }
        if ($ips.Count) { $summary += " Remote addresses: $(($ips | Select-Object -First 6) -join ', ')." }
        $incs.Add([ordered]@{
                id = $null; title = (Get-IRIncidentTitle $tactics $top @($members | ForEach-Object { $_.technique })); headline = $top.title; severity = $sev; score = [math]::Min(100, $score)
                first_seen = $first; last_seen = $last; summary = $summary; narrative = $story
                findings = @($members | ForEach-Object { $_.id }); tactics = $tactics; techniques = @($members | Where-Object { $_.technique } | ForEach-Object { $_.technique } | Select-Object -Unique)
                users = $users; ips = $ips; files = $files; domains = $domains
                graph = (New-IRGraph $members $Script:HostName); _members = $members
            })
    }
    $ordered = @($incs | Sort-Object @{ Expression = { $Script:SevRank[$_.severity] }; Descending = $true }, @{ Expression = { $_.score }; Descending = $true })
    $n = 0
    foreach ($inc in $ordered) {
        $n++; $inc.id = 'INC-{0:d2}' -f $n
        foreach ($m in $inc._members) { $m.incident = $inc.id }
    }
    return $ordered
}

function Get-IRVerdict($Findings, $Incidents) {
    $counts = [ordered]@{ critical = 0; high = 0; medium = 0; low = 0; info = 0 }
    $part = @{ critical = 0; high = 0; medium = 0; low = 0; info = 0 }
    foreach ($f in $Findings) { $counts[$f.severity] = $counts[$f.severity] + 1; $part[$f.severity] += $Script:SevWeight[$f.severity] }
    $score = $part['critical'] + $part['high'] + [math]::Min(30, $part['medium']) + [math]::Min(10, $part['low'])
    $score = [math]::Min(100, $score)
    $level = 'No significant findings'; $tone = 'ok'
    if ($counts['critical'] -gt 0 -or ($score -ge 60 -and $counts['high'] -gt 0)) { $level = 'Compromise likely'; $tone = 'critical' }
    elseif ($counts['high'] -gt 0 -or $score -ge 40) { $level = 'Suspicious activity'; $tone = 'high' }
    elseif ($counts['medium'] -gt 0) { $level = 'Needs review'; $tone = 'medium' }
    $top = @($Findings | Where-Object { $Script:SevRank[$_.severity] -ge 3 } | Select-Object -First 3 | ForEach-Object { $_.title })
    $text = "$(@($Findings).Count) finding(s) - $($counts['critical']) critical, $($counts['high']) high, $($counts['medium']) medium, $($counts['low']) low - grouped into $(@($Incidents).Count) incident(s)."
    if ($top.Count) { $text += ' Most severe: ' + ($top -join '; ') + '.' }
    return [ordered]@{ level = $level; tone = $tone; score = $score; counts = $counts; summary = $text }
}

function Get-IRRecommendations($Findings, $Incidents, $Gaps) {
    $tac = @{}
    $maxRank = 0
    foreach ($f in $Findings) {
        if ($Script:SevRank[$f.severity] -gt $maxRank) { $maxRank = $Script:SevRank[$f.severity] }
        if ($f.tactic -and $Script:SevRank[$f.severity] -ge 3) { $tac[$f.tactic] = 1 }
    }
    $sig = @($Findings | Where-Object { $Script:SevRank[$_.severity] -ge 2 })
    $users = @($sig | ForEach-Object { $_.users } | Where-Object { $_ } | Select-Object -Unique -First 20)
    $ips = @($sig | ForEach-Object { $_.ips } | Where-Object { $_ } | Select-Object -Unique -First 20)
    $c = [System.Collections.Generic.List[string]]::new()
    if ($maxRank -ge 3) {
        $c.Add('Isolate the host from the network (EDR network containment or switch port) but keep it powered on.')
        $c.Add('Capture memory before any reboot or clean-up (WinPMem, Magnet RAM Capture, DumpIt): injected code, network state and credentials only exist in RAM.')
    }
    if ($tac['credential-access']) {
        $c.Add("Treat credentials used on this host as compromised and reset them$(if ($users.Count) { ', starting with: ' + ($users -join ', ') }). If domain admins or a domain controller are involved, plan a double krbtgt reset.")
    }
    if ($tac['lateral-movement']) { $c.Add("Bring the other hosts involved into scope$(if ($ips.Count) { ': ' + ($ips -join ', ') }) and collect them with this script.") }
    if ($tac['command-and-control'] -or $tac['exfiltration']) { $c.Add('Block the IPs and domains in the IOC table at the firewall, proxy and DNS, and search proxy / firewall logs for other hosts contacting them.') }
    if ($tac['impact']) { $c.Add('Disconnect and protect backups now; assume encryption or destruction may follow on other hosts.') }
    if ($tac['persistence']) { $c.Add('Remove the persistence entries listed in the findings only after their files and registry keys are preserved (they are in this case package).') }
    if ($tac['defense-evasion']) { $c.Add('Re-enable impaired protections (Defender, firewall, auditing) and recover cleared or missing logs from the SIEM / forwarders.') }
    if ($tac['initial-access']) { $c.Add('Close the exposed remote access path (RDP / SMB / WinRM reachable from the Internet) and require VPN plus MFA.') }
    if (-not $c.Count) { $c.Add('Automated triage found nothing high or critical that requires containment. Review the medium / low findings to confirm.') }

    $n = [System.Collections.Generic.List[string]]::new()
    $n.Add('Validate every finding against its evidence and the raw artifact: these are heuristics and can be false positives (admin tools, installers, security software).')
    $n.Add('Run Hayabusa or Chainsaw (Sigma rules) over the eventlogs folder for wider event-log coverage than this triage.')
    if ($Script:Sys.profile -eq 'Quick') { $n.Add('This was a Quick collection: re-collect with -CollectionProfile Standard or Full to get registry hives, Amcache, SRUM, Jump Lists and browser history.') }
    else { $n.Add('Browser history, Amcache, ShellBags, Jump Lists and SRUM were parsed into the evidence tabs; for full depth (all hive keys, Prefetch volumes, deleted records) also run Eric Zimmerman''s tools: RECmd, PECmd, AmcacheParser, SrumECmd, JLECmd / LECmd, plus Hindsight.') }
    if (@($Findings | Where-Object { $_.hashes.Count }).Count) { $n.Add('Check the SHA-256 hashes in the IOC table against threat intelligence and hunt for them on other hosts.') }
    $n.Add('Hunt for the same accounts, IPs, hashes and service / task names on other hosts with the EDR or SIEM.')
    $n.Add('If the case may go to legal or HR, or deleted files matter, acquire a full disk image ($MFT, $UsnJrnl, unallocated space).')

    $byTech = [ordered]@{}
    foreach ($f in $Findings) {
        if (-not $f.technique -or $Script:SevRank[$f.severity] -lt 1) { continue }
        $base = $f.technique.Split('.')[0]
        if (-not $byTech.Contains($base)) {
            $m = $Script:Mitre[$base]; if (-not $m) { $m = $Script:Mitre[$f.technique] }
            $byTech[$base] = [ordered]@{ technique = $base; name = $(if ($m) { $m.name -replace ':.*$', '' } else { $f.technique_name }); advice = (Get-IRAdvice $base); severity = $f.severity; findings = [System.Collections.Generic.List[string]]::new() }
        }
        $e = $byTech[$base]
        if ($Script:SevRank[$f.severity] -gt $Script:SevRank[$e.severity]) { $e.severity = $f.severity }
        Add-IRUnique $e.findings $f.id 50
    }
    return [ordered]@{
        containment = $c; next_steps = $n
        techniques = @($byTech.Values | Sort-Object @{ Expression = { $Script:SevRank[$_.severity] }; Descending = $true })
        gaps = @($Gaps)
    }
}

function Get-IRIocs($Findings) {
    $map = [ordered]@{}
    $add = {
        param($Type, $Value, $F)
        if (-not $Value) { return }
        $k = "$Type|$(([string]$Value).ToLowerInvariant())"
        $e = $map[$k]
        if (-not $e) { $e = [ordered]@{ type = $Type; value = [string]$Value; severity = $F.severity; findings = [System.Collections.Generic.List[string]]::new() }; $map[$k] = $e }
        if ($Script:SevRank[$F.severity] -gt $Script:SevRank[$e.severity]) { $e.severity = $F.severity }
        Add-IRUnique $e.findings $F.id 20
    }
    foreach ($f in $Findings) {
        if ($Script:SevRank[$f.severity] -lt 2) { continue }
        foreach ($i in $f.ips) { & $add $(if (Test-IRPublicIp $i) { 'ip (public)' } else { 'ip (internal)' }) $i $f }
        foreach ($d in $f.domains) { & $add 'domain' $d $f }
        foreach ($h in $f.hashes) { & $add 'sha256' $h $f }
        foreach ($p in $f.files) { if (-not $Script:TrustedDirRx.IsMatch([string]$p)) { & $add 'file' $p $f } }
        foreach ($u in $f.users) { & $add 'account' $u $f }
    }
    return @($map.Values | Sort-Object @{ Expression = { $Script:SevRank[$_.severity] }; Descending = $true }, @{ Expression = { $_.type } })
}

$Script:DatasetInfo = [ordered]@{
    processes = @('Running processes', 'Live state'); network_connections = @('Network connections', 'Network'); dns_cache = @('DNS cache', 'Network')
    arp_cache = @('ARP cache', 'Network'); ip_configuration = @('IP configuration', 'Network'); smb_shares = @('SMB shares', 'Network')
    smb_sessions = @('SMB sessions', 'Network'); hosts_file = @('Hosts file', 'Network'); proxy_settings = @('Proxy settings', 'Network')
    port_proxy = @('Port proxy (netsh)', 'Network'); network_history = @('Network history', 'Network')
    logon_summary = @('Logon summary (4624 / 4625 / 4771 / 4776)', 'Accounts'); rdp_sessions = @('RDP sessions', 'Accounts')
    local_users = @('Local users', 'Accounts'); group_members = @('Privileged group members', 'Accounts'); sessions = @('Logged-on sessions', 'Accounts'); user_profiles = @('User profiles', 'Accounts')
    services = @('Services', 'Persistence'); drivers = @('Drivers', 'Persistence'); autoruns = @('Autostart locations', 'Persistence')
    scheduled_tasks = @('Scheduled tasks', 'Persistence'); wmi_persistence = @('WMI event subscriptions', 'Persistence')
    defender_status = @('Defender status', 'Security controls'); defender_preferences = @('Defender preferences', 'Security controls')
    defender_exclusions = @('Defender exclusions', 'Security controls'); defender_threats = @('Defender detection history', 'Security controls')
    firewall_profiles = @('Firewall profiles', 'Security controls'); firewall_rules = @('Firewall rules', 'Security controls')
    security_config = @('Security configuration', 'Security controls'); audit_policy = @('Audit policy', 'Security controls')
    prefetch = @('Prefetch', 'Execution'); bam = @('BAM / DAM', 'Execution'); userassist = @('UserAssist', 'Execution'); shimcache = @('ShimCache (AppCompatCache)', 'Execution')
    powershell_history = @('PowerShell history (PSReadLine)', 'User activity'); recent_files = @('Recent files (LNK)', 'User activity'); user_mru = @('Run / typed paths / RDP MRU', 'User activity')
    usb_devices = @('USB storage devices', 'User activity'); recycle_bin = @('Recycle Bin', 'User activity')
    file_scan = @('Recent executables, scripts and archives', 'Files'); alternate_data_streams = @('Alternate data streams', 'Files')
    browser_history = @('Browser history (visits in the window)', 'Artifacts'); browser_downloads = @('Browser downloads', 'Artifacts')
    amcache_files = @('Amcache: files (path, SHA-1, publisher)', 'Artifacts'); amcache_programs = @('Amcache: installed programs', 'Artifacts')
    shellbags = @('ShellBags (folders browsed)', 'Artifacts'); jump_lists = @('Jump Lists (files opened per application)', 'Artifacts')
    srum_network_summary = @('SRUM: network usage per program', 'Artifacts'); srum_network = @('SRUM: network usage (hourly)', 'Artifacts')
    srum_app_usage = @('SRUM: application resource usage', 'Artifacts'); artifact_notes = @('Raw artifact parsing notes', 'Artifacts')
    installed_software = @('Installed software', 'System'); hotfixes = @('Installed updates', 'System')
    event_logs = @('Event log inventory', 'Collection'); event_parse_stats = @('Event log analysis statistics', 'Collection'); collection_steps = @('Collection steps', 'Collection')
}

function ConvertTo-IRTable($Rows, [int]$Max = 25000) {
    $rows = @($Rows)
    $cols = [System.Collections.Generic.List[string]]::new()
    foreach ($r in ($rows | Select-Object -First 200)) {
        if ($null -eq $r) { continue }
        $names = if ($r -is [System.Collections.IDictionary]) { @($r.Keys) } else { @($r.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($nm in $names) { if (-not $cols.Contains([string]$nm)) { $cols.Add([string]$nm) } }
    }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $rows) {
        if ($out.Count -ge $Max) { break }
        if ($null -eq $r) { continue }
        $isDict = $r -is [System.Collections.IDictionary]
        $vals = New-Object object[] $cols.Count
        for ($i = 0; $i -lt $cols.Count; $i++) {
            $v = if ($isDict) { $r[$cols[$i]] } else { $r.($cols[$i]) }
            if ($v -is [DateTime]) { $v = ConvertTo-IRTime $v }
            elseif ($v -is [System.Collections.IDictionary] -or $v -is [System.Management.Automation.PSCustomObject]) { $v = ConvertTo-IRJson $v }
            elseif ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { $v = (@($v) | ForEach-Object { [string]$_ }) -join ', ' }
            $vals[$i] = $v
        }
        $out.Add($vals)
    }
    return [ordered]@{ title = $null; group = $null; columns = $cols.ToArray(); rows = $out; total = $rows.Count }
}

function Test-IRManifest([string]$Root) {
    $m = Join-Path $Root 'manifest.csv'
    $res = [ordered]@{ status = 'not available'; checked = 0; verified = 0; mismatched = [System.Collections.Generic.List[string]]::new(); missing = [System.Collections.Generic.List[string]]::new() }
    if (-not (Test-Path -LiteralPath $m)) {
        $res.status = if ($Mode -eq 'All') { 'manifest is written after the report (see manifest.csv in the package)' } else { 'no manifest.csv in the case' }
        return $res
    }
    foreach ($r in @(Import-Csv -LiteralPath $m)) {
        if ($r.path -like 'report\*') { continue }
        $res.checked++
        $p = Join-Path $Root $r.path
        if (-not (Test-Path -LiteralPath $p)) { Add-IRUnique $res.missing $r.path 200; continue }
        $h = $null
        try { $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch { }
        if ($h -eq $r.sha256) { $res.verified++ } else { Add-IRUnique $res.mismatched $r.path 200 }
    }
    $res.status = if ($res.mismatched.Count -or $res.missing.Count) { 'FAILED - files changed or missing since collection' } else { 'verified - every file matches its SHA-256 from collection time' }
    return $res
}

function Invoke-IRAnalysis {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$ReportPath)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $Script:In = @{ Root = $Root; Live = (Join-Path $Root 'live'); Events = (Join-Path $Root 'eventlogs') }
    Write-IRLog "===== Analysis: $Root ====="
    $Script:D = @{}
    $Script:Sys = $null
    foreach ($f in @(Get-ChildItem -LiteralPath $Script:In.Live -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
        try {
            if ($f.BaseName -eq 'system') { $Script:Sys = Read-IRData $f.FullName }
            else { $Script:D[$f.BaseName] = @(Read-IRData $f.FullName) }
        } catch { Write-IRLog "  could not read $($f.Name): $($_.Exception.Message)" 'WARN' }
    }
    if (-not $Script:Sys) { throw "Not an IR-Investigator case folder (live\system.json is missing): $Root" }

    $Script:Findings = [ordered]@{}; $Script:RuleCounts = @{}; $Script:Hits = $null
    $Script:Timeline = [System.Collections.Generic.List[object]]::new()
    foreach ($n in 'Fails', 'LogonOk', 'Tgs', 'DiscHits', 'TaskEvents', 'GroupAdds', 'ExplicitCred', 'RdpSessions', 'ParseStats', 'CappedQueries') {
        Set-Variable -Scope Script -Name $n -Value ([System.Collections.Generic.List[object]]::new())
    }
    $Script:CappedQueries = [System.Collections.Generic.List[string]]::new()
    $Script:Created = @{}; $Script:LogonSum = [ordered]@{}
    $Script:EventCount = 0; $Script:RuleErrors = 0; $Script:SelfEvents = 0; $Script:SelfBlocks = 0; $Script:CdxmlBlocks = 0
    $Script:HostName = [string]$Script:Sys.hostname
    $ref = Get-IRDate $Script:Sys.collection_start
    if (-not $ref) { $ref = [DateTime]::UtcNow }
    $end = Get-IRDate $Script:Sys.collection_end
    if (-not $end) { $end = $ref.AddHours(6) }
    $since = $ref.AddDays(-$Days)
    $Script:Since = $since
    $Script:SinceIso = $since.ToString('yyyy-MM-ddTHH:mm:ssZ', $Script:Inv)
    $Script:SinceXml = $since.ToString('yyyy-MM-ddTHH:mm:ss.000Z', $Script:Inv)
    $Script:SelfPid = $null
    if ($Script:Sys.collector_pid) { $Script:SelfPid = [int64]$Script:Sys.collector_pid }
    $Script:SelfPath = [string]$Script:Sys.script_path
    $Script:SelfStart = $ref.AddMinutes(-1); $Script:SelfEnd = $end.AddMinutes(10)
    $Script:RdpPort = $null
    Write-IRLog "Host $($Script:HostName) | window $($Script:SinceIso) -> $(ConvertTo-IRTime $end) ($Days days) | max $MaxEventsPerLog events per query"

    Write-IRLog '> Event logs'
    Invoke-IREventAnalysis
    Write-IRLog '> Raw artifacts (browsers, Amcache, hives, Jump Lists, SRUM)'
    Invoke-IRArtifactAnalysis
    Write-IRLog '> Live state and artifacts'
    Invoke-IRLiveAnalysis
    Write-IRLog '> Correlation'
    Invoke-IRCorrelation
    $gaps = @(Get-IRGaps)
    $findings = @(Get-IRSortedFindings)
    Write-IRLog '> Incidents and report'
    $incidents = @(Build-IRIncidents $findings)
    $verdict = Get-IRVerdict $findings $incidents
    $recs = Get-IRRecommendations $findings $incidents $gaps
    $iocs = @(Get-IRIocs $findings)

    $tl = $Script:Timeline
    $limit = 30000
    $truncated = $false
    $keep = @($tl | Where-Object { $_.fk })
    $rest = @($tl | Where-Object { -not $_.fk })
    if ($keep.Count + $rest.Count -gt $limit) {
        $truncated = $true
        $rest = @($rest | Sort-Object { $_.t } -Descending | Select-Object -First ([math]::Max(0, $limit - $keep.Count)))
    }
    $timeline = foreach ($e in (@($keep) + @($rest) | Sort-Object { $_.t })) {
        $ids = [System.Collections.Generic.List[string]]::new()
        $sev = $null
        foreach ($k in @($e.fk)) {
            if (-not $k) { continue }
            $fx = $Script:Findings[$k]
            if (-not $fx) { continue }
            Add-IRUnique $ids $fx.id 10
            if (-not $sev -or $Script:SevRank[$fx.severity] -gt $Script:SevRank[$sev]) { $sev = $fx.severity }
        }
        [ordered]@{ t = $e.t; src = $e.src; ev = $e.ev; cat = $e.cat; sum = $e.sum; u = $e.u; sev = $sev; f = $ids }
    }

    $matrix = [ordered]@{}
    foreach ($t in $Script:Tactics) { $matrix[$t.key] = [System.Collections.Generic.List[object]]::new() }
    $techIdx = @{}
    foreach ($f in $findings) {
        if (-not $f.technique -or -not $f.tactic -or -not $matrix.Contains($f.tactic)) { continue }
        $e = $techIdx[$f.technique]
        if (-not $e) {
            $e = [ordered]@{ id = $f.technique; name = $f.technique_name; severity = $f.severity; hits = 0; findings = [System.Collections.Generic.List[string]]::new() }
            $techIdx[$f.technique] = $e
            $matrix[$f.tactic].Add($e)
        }
        if ($Script:SevRank[$f.severity] -gt $Script:SevRank[$e.severity]) { $e.severity = $f.severity }
        $e.hits = $e.hits + $f.hits
        $e.findings.Add($f.id)
    }

    # @() over an [ordered] dictionary's .Values throws "Argument types do not match" on PowerShell 5.1.
    $derived = @{ logon_summary = @($Script:LogonSum.Values | ForEach-Object { $_ }); rdp_sessions = @($Script:RdpSessions); event_parse_stats = @($Script:ParseStats) }
    $evidence = [ordered]@{}
    foreach ($name in $Script:DatasetInfo.Keys) {
        if (-not $derived.ContainsKey($name) -and -not $Script:D.ContainsKey($name)) { continue }
        $rows = if ($derived.ContainsKey($name)) { $derived[$name] } else { $Script:D[$name] }
        if ($null -eq $rows) { $rows = @() }
        $tb = ConvertTo-IRTable $rows
        $tb.title = $Script:DatasetInfo[$name][0]; $tb.group = $Script:DatasetInfo[$name][1]
        $evidence[$name] = $tb
    }
    foreach ($name in @($Script:D.Keys | Sort-Object)) {
        if ($evidence.Contains($name)) { continue }
        $tb = ConvertTo-IRTable $Script:D[$name]
        $tb.title = $name; $tb.group = 'Other'
        $evidence[$name] = $tb
    }

    $graphMembers = @($findings | Where-Object { $_.incident } | Select-Object -First 160)
    $sw.Stop()
    $data = [ordered]@{
        meta = [ordered]@{
            tool = 'IR-Investigator'; version = $Script:Version; generated = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', $Script:Inv)
            window_from = $Script:SinceIso; window_to = (ConvertTo-IRTime $end); days = $Days; max_events = $MaxEventsPerLog
            case = $(if ($Script:Sys.case_name) { $Script:Sys.case_name } else { Split-Path -Leaf $Root })
            case_label = $(if ($CaseLabel) { $CaseLabel } else { $Script:Sys.case_label }); examiner = $(if ($Examiner) { $Examiner } else { $Script:Sys.examiner })
            events_parsed = $Script:EventCount; timeline_total = $tl.Count; timeline_truncated = $truncated; analysis_seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            self_filtered_events = $Script:SelfEvents; self_filtered_script_blocks = $Script:SelfBlocks; cdxml_script_blocks = $Script:CdxmlBlocks; rule_errors = $Script:RuleErrors
        }
        system = $Script:Sys
        verdict = $verdict
        tactics = @($Script:Tactics)
        findings = @($findings | ForEach-Object { $x = [ordered]@{}; foreach ($k in $_.Keys) { if ($k -ne 'key') { $x[$k] = $_[$k] } }; $x })
        incidents = @($incidents | ForEach-Object { $x = [ordered]@{}; foreach ($k in $_.Keys) { if ($k -ne '_members') { $x[$k] = $_[$k] } }; $x })
        timeline = @($timeline)
        matrix = $matrix
        catalog = @($Script:Mitre.Values | Sort-Object { $_.id })
        evidence = $evidence
        recommendations = $recs
        iocs = $iocs
        integrity = (Test-IRManifest $Root)
        steps = @($Script:D['collection_steps'])
        graph = (New-IRGraph $graphMembers $Script:HostName)
    }
    Write-IRReport $data $ReportPath
    Write-IRLog ("Analysis finished in {0:n0}s: {1} events, {2} findings, {3} incidents, {4} timeline entries - verdict: {5}" -f $sw.Elapsed.TotalSeconds, $Script:EventCount, $findings.Count, $incidents.Count, @($timeline).Count, $verdict.level) 'OK'
    return [pscustomobject]@{ Report = $ReportPath; Verdict = $verdict; Findings = $findings.Count; Incidents = $incidents.Count }
}

#endregion

#region ===== HTML report =====

function Write-IRReport($Data, [string]$Path) {
    New-IRDir (Split-Path -Parent $Path) | Out-Null
    $json = ConvertTo-IRJson $Data
    $html = (Get-IRReportTemplate).Replace('/*__IRDATA__*/', $json)
    [IO.File]::WriteAllText($Path, $html, (New-Object System.Text.UTF8Encoding($false)))
    Write-IRLog ("Report written: {0} ({1:n1} MB)" -f $Path, ((Get-Item -LiteralPath $Path).Length / 1MB)) 'OK'
}

# Every value from the evidence is rendered with textContent / setAttribute only, never as HTML.
function Get-IRReportTemplate {
    return @'
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IR-Investigator report</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--line:#2a3340;--text:#e6edf3;--muted:#8b98a8;--accent:#4c8dff;--critical:#ff4d5e;--high:#ff8c42;--medium:#f2c94c;--low:#5ab0ff;--info:#7d8590;--ok:#3fb950}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,-apple-system,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header{position:sticky;top:0;z-index:5;background:rgba(13,17,23,.94);backdrop-filter:blur(6px);border-bottom:1px solid var(--line);padding:10px 24px}
.hrow{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
header h1{font-size:16px;margin:0;font-weight:600}
nav{display:flex;gap:4px;flex-wrap:wrap;margin-top:8px}
nav button{background:none;border:1px solid transparent;color:var(--muted);padding:5px 12px;border-radius:6px;cursor:pointer;font:inherit}
nav button:hover{color:var(--text)}
nav button.on{color:var(--text);background:var(--panel2);border-color:var(--line)}
nav .n{margin-left:6px;font-size:11px;background:var(--line);border-radius:8px;padding:0 6px;color:var(--text)}
main{padding:20px 24px;max-width:1700px;margin:0 auto}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
.card h2{font-size:15px;margin:0 0 12px;font-weight:600}
h3{font-size:13px;margin:14px 0 6px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.grid{display:grid;gap:16px}.g2{grid-template-columns:repeat(auto-fit,minmax(460px,1fr))}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:16px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.stat.click{cursor:pointer}.stat.click:hover{border-color:var(--accent)}
.stat b{display:block;font-size:24px;line-height:1.2}.stat span{color:var(--muted);font-size:12px}
.sev{display:inline-block;padding:0 8px;border-radius:10px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.03em;border:1px solid;white-space:nowrap}
.sev.critical{color:var(--critical);background:rgba(255,77,94,.12)}.sev.high{color:var(--high);background:rgba(255,140,66,.12)}
.sev.medium{color:var(--medium);background:rgba(242,201,76,.12)}.sev.low{color:var(--low);background:rgba(90,176,255,.12)}.sev.info{color:var(--info);background:rgba(125,133,144,.12)}
.verdict{border-left:5px solid}.vrow{display:flex;gap:24px;align-items:center;justify-content:space-between}
.vlevel{font-size:26px;font-weight:700}.vtext p{margin:6px 0 0;color:var(--text)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;position:sticky;top:0;background:var(--panel);white-space:nowrap;z-index:1}
th.sort{cursor:pointer}th.sort:hover{color:var(--text)}
td{word-break:break-word;max-width:640px}
tr.click{cursor:pointer}tr.click:hover td{background:var(--panel2)}
.nowrap{white-space:nowrap}
input,select{background:var(--panel2);border:1px solid var(--line);color:var(--text);border-radius:6px;padding:5px 10px;font:inherit}
input[type=search]{min-width:260px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.btn{background:var(--panel2);border:1px solid var(--line);color:var(--text);border-radius:6px;padding:5px 12px;cursor:pointer;font:inherit;display:inline-block}
.btn:hover{border-color:var(--accent);text-decoration:none}.btn.small{padding:1px 8px;font-size:12px}
.mono{font-family:Consolas,"Cascadia Mono","IBM Plex Mono",monospace;font-size:12px}
.small{font-size:11.5px}.muted{color:var(--muted)}
pre{white-space:pre-wrap;word-break:break-all;background:#0a0e13;border:1px solid var(--line);border-radius:6px;padding:8px 10px;margin:6px 0;font:12px Consolas,"Cascadia Mono",monospace;max-height:280px;overflow:auto}
.chips{display:flex;flex-wrap:wrap;gap:4px}.chips span{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:0 8px;font-size:12px;word-break:break-all}
.tag{background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:0 6px;font-size:11.5px;font-family:Consolas,monospace;white-space:nowrap}
.tag.inc{border-color:var(--accent);color:var(--accent)}
.chain{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:6px}
.tac{border:1px solid var(--line);border-radius:8px;padding:8px 10px;background:var(--panel2);min-height:76px}
.tac.hit{cursor:pointer;border-width:2px}.tac .tn{font-weight:600;font-size:12.5px}.tac .tc{font-size:13px;margin-top:4px;font-weight:600}
.matrix{display:grid;grid-template-columns:repeat(12,minmax(150px,1fr));gap:8px;overflow-x:auto;padding-bottom:6px}
.mh{background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:6px 8px;margin-bottom:6px;min-height:58px}
.tech{border:1px solid var(--line);border-radius:6px;padding:6px 8px;font-size:12px;margin-bottom:6px;background:var(--panel);cursor:pointer}
.tech:hover{border-color:var(--accent)}.tech.dim{opacity:.38;cursor:default}.tech.dim:hover{border-color:var(--line)}
details.f{border:1px solid var(--line);border-radius:8px;margin-bottom:8px;background:var(--panel)}
details.f>summary{padding:9px 12px;cursor:pointer;display:flex;gap:10px;align-items:center;flex-wrap:wrap;list-style:none}
details.f>summary::-webkit-details-marker{display:none}
details.f[open]>summary{border-bottom:1px solid var(--line)}
details.f .body{padding:4px 14px 14px}.ft{font-weight:600}.right{margin-left:auto}
.rec{background:rgba(76,141,255,.08);border:1px solid rgba(76,141,255,.35);border-radius:6px;padding:8px 10px;margin:8px 0 12px}
.kv{display:grid;grid-template-columns:150px 1fr;gap:5px 14px;font-size:13px}.kv>div:nth-child(odd){color:var(--muted)}
.graph{width:100%;background:#0a0e13;border:1px solid var(--line);border-radius:8px;display:block;touch-action:none}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:8px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;vertical-align:-1px}
.pager{display:flex;gap:8px;align-items:center;margin-top:10px}
.story{margin:0;padding-left:20px}.story li{margin-bottom:4px;font-size:13px}
.ihead{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:16px}.iid{font-family:Consolas,monospace}
.ds-layout{display:grid;grid-template-columns:270px 1fr;gap:16px;align-items:start}
.dsl{display:flex;flex-direction:column;gap:2px;max-height:78vh;overflow:auto;position:sticky;top:110px}
.dsg{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin:10px 0 2px}
.dsb{display:flex;justify-content:space-between;gap:8px;text-align:left;background:none;border:1px solid transparent;color:var(--text);padding:4px 8px;border-radius:6px;cursor:pointer;font:inherit;font-size:13px}
.dsb:hover{background:var(--panel2)}.dsb.on{background:var(--panel2);border-color:var(--line)}
.tablewrap{overflow:auto;max-height:74vh;border:1px solid var(--line);border-radius:8px}
.trec{border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin-bottom:8px}.trec p{margin:6px 0}
.hist{width:100%;height:auto;display:block}
.flist>div{margin:2px 0;font-size:13px}
.note{color:var(--muted);font-size:12px;margin-top:20px;text-align:center}
ol li{margin-bottom:6px}
.gcanvas{width:100%;height:72vh;min-height:520px;display:block;background:#0a0e13;border-radius:8px;cursor:grab;touch-action:none}
.gwrap{position:relative;padding:8px}
.gstat{position:absolute;left:18px;top:14px;font-size:12px;color:var(--muted);pointer-events:none}
.ghelp{position:absolute;right:18px;bottom:14px;font-size:11px;color:var(--muted);pointer-events:none;text-align:right}
.gf{display:flex;gap:6px 12px;flex-wrap:wrap;font-size:12px;margin:0 0 10px}
.gf label{cursor:pointer;color:var(--muted);display:inline-flex;align-items:center;gap:4px}
.gf i{display:inline-block;width:10px;height:10px;border-radius:50%}
.gchip{display:inline-block;border:1px solid var(--line);border-radius:12px;padding:0 8px;margin:2px;font-size:12px;color:var(--text);background:var(--panel2);max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:middle;text-decoration:none}
.gchip.on{border-color:var(--accent);color:#cfe0ff}
.gres{margin:0 0 10px}
input[type=date]{color-scheme:dark}
.gmodal-bg{position:fixed;inset:0;background:rgba(1,4,9,.72);z-index:100;display:flex;align-items:center;justify-content:center}
.gmodal{background:var(--panel);border:1px solid var(--line);border-radius:12px;width:min(1280px,95vw);height:90vh;display:flex;flex-direction:column;box-shadow:0 20px 60px rgba(0,0,0,.6)}
.gmhead{padding:16px 20px 0;border-bottom:1px solid var(--line)}
.gmtabs{display:flex;gap:2px;margin-top:10px;flex-wrap:wrap}
.gmtabs button{background:none;border:0;border-bottom:2px solid transparent;color:var(--muted);padding:8px 14px;cursor:pointer;font:inherit}
.gmtabs button.on{color:var(--text);border-bottom-color:var(--accent)}
.gmbody{flex:1;overflow:auto;padding:14px 20px 20px}
.gtree,.gtree ul{list-style:none;margin:0;padding-left:0}
.gtree ul{border-left:1px dashed #33404f;margin-left:7px;padding-left:16px}
.gtree li{margin:1px 0}
.trow{padding:3px 6px;border-radius:5px}
.trow:hover{background:var(--panel2)}
.trow.hit{background:rgba(76,141,255,.14);outline:1px solid rgba(76,141,255,.45)}
.car{display:inline-block;width:16px;color:var(--muted);cursor:pointer;user-select:none}
.gdot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:middle}
@media(max-width:900px){.ds-layout{grid-template-columns:1fr}.dsl{position:static;max-height:240px}.g2{grid-template-columns:1fr}}
</style></head>
<body>
<header><div class="hrow"><h1 id="h-title">IR-Investigator report</h1><span class="muted small" id="h-sub"></span>
<label class="muted small" style="margin-left:auto">Times <select id="tz"><option value="utc">UTC</option><option value="local">Host local time</option></select></label></div>
<nav id="nav"></nav></header>
<main id="main"></main>
<script type="application/json" id="irdata">/*__IRDATA__*/</script>
<script>
(function(){
'use strict';
var D;
try{D=JSON.parse(document.getElementById('irdata').textContent);}catch(err){document.getElementById('main').textContent='The report data could not be parsed: '+err;return;}
const SEV=['info','low','medium','high','critical'];
const rank=s=>Math.max(0,SEV.indexOf(s||'info'));
const COL={critical:'#ff4d5e',high:'#ff8c42',medium:'#f2c94c',low:'#5ab0ff',info:'#7d8590',ok:'#3fb950'};
const TC={host:'#e6edf3',user:'#c297ff',ip:'#2dd4bf',file:'#f778ba',domain:'#7ee787'};
const NS='http://www.w3.org/2000/svg';
function add(e,kids){for(const c of kids){if(c==null||c===false)continue;if(Array.isArray(c))add(e,c);else e.appendChild(c instanceof Node?c:document.createTextNode(String(c)));}}
function mk(ns,tag,a,kids){const e=ns?document.createElementNS(ns,tag):document.createElement(tag);if(a)for(const k in a){const v=a[k];if(v==null||v===false)continue;if(k==='text')e.textContent=v;else if(typeof v==='function')e.addEventListener(k.replace(/^on/,''),v);else e.setAttribute(k,v===true?'':String(v));}add(e,kids);return e;}
const h=(t,a,...k)=>mk(null,t,a,k);
const s=(t,a,...k)=>mk(NS,t,a,k);
const F=D.findings||[],I=D.incidents||[],T=D.timeline||[],M=D.meta||{},Y=D.system||{};
const FI={};F.forEach(f=>FI[f.id]=f);
const TN={};(D.tactics||[]).forEach(t=>TN[t.key]=t.name);
let TZ='utc';const OFF=Number(Y.utc_offset_minutes)||0;
const ISO=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;
function ft(v){if(!v)return '';const d=new Date(v);if(isNaN(d))return String(v);const x=TZ==='utc'?d:new Date(d.getTime()+OFF*6e4);return x.toISOString().slice(0,19).replace('T',' ')+(TZ==='utc'?' Z':'');}
const offTxt=()=>'UTC'+(OFF>=0?'+':'-')+(Math.abs(OFF)/60);
const tzLabel=()=>TZ==='utc'?'UTC':'host local, '+offTxt();
const sev=x=>h('span',{class:'sev '+(x||'info'),text:x||'info'});
const st={tab:'overview',f:fReset(),t:tReset(),m:{full:false},e:{ds:null,q:'',sort:-1,dir:1,page:0}};
function fReset(){return{q:'',sev:'',tac:'',tech:'',inc:'',open:null};}
function tReset(){return{q:'',src:'',cat:'',flag:false,sev:'',fid:'',inc:'',day:'',page:0};}
function flink(id){return h('a',{href:'#',class:'mono',title:FI[id]?FI[id].title:'',text:id,onclick:e=>{e.preventDefault();openFinding(id);}});}
function ilink(id){return h('a',{href:'#',class:'mono',text:id,onclick:e=>{e.preventDefault();go('incidents');setTimeout(()=>{const el=document.getElementById('inc-'+id);if(el)el.scrollIntoView({block:'start'});},0);}});}
function openFinding(id){st.f=fReset();st.f.open=id;go('findings');}
function chips(a,mono){a=[].concat(a||[]);return h('div',{class:'chips'},a.map(x=>h('span',{class:mono?'mono':null,text:x})));}
function kv(p){return h('div',{class:'kv'},p.filter(x=>x[1]!=null&&x[1]!==''&&!(Array.isArray(x[1])&&!x[1].length)).map(x=>[h('div',{text:x[0]}),h('div',null,(x[1] instanceof Node)?x[1]:Array.isArray(x[1])?chips(x[1],x[2]):String(x[1]))]));}
function sel(opts,val,on){const e=h('select',{onchange:()=>on(e.value)},opts.map(o=>h('option',{value:o[0],text:o[1]})));e.value=val;return e;}
function search(val,ph,on){const e=h('input',{type:'search',placeholder:ph,value:val});let tm;e.addEventListener('input',()=>{clearTimeout(tm);tm=setTimeout(()=>on(e.value),220);});return e;}
function cell(v){if(v==null)return '';if(typeof v==='boolean')return v?'yes':'no';if(typeof v==='object')return JSON.stringify(v);const x=String(v);if(ISO.test(x))return ft(x);return x.length>420?h('span',{title:x.slice(0,4000),text:x.slice(0,420)+'\u2026'}):x;}
function csv(name,cols,rows){const q=v=>{v=v==null?'':Array.isArray(v)?v.join('; '):String(v);if(/^[=+\-@\t\r]/.test(v))v="'"+v;return /[",\n\r]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;};
 const txt=[cols.map(q).join(',')].concat(rows.map(r=>r.map(q).join(','))).join('\r\n');const a=h('a',{href:URL.createObjectURL(new Blob(['\ufeff'+txt],{type:'text/csv'})),download:name});document.body.appendChild(a);a.click();a.remove();}
function objTable(rows){rows=rows||[];if(!rows.length)return h('p',{class:'muted',text:'None.'});const cols=[];rows.slice(0,100).forEach(r=>Object.keys(r||{}).forEach(k=>{if(!cols.includes(k))cols.push(k);}));
 return h('div',{class:'tablewrap'},h('table',null,h('thead',null,h('tr',null,cols.map(c=>h('th',{text:c})))),h('tbody',null,rows.map(r=>h('tr',null,cols.map(c=>h('td',null,cell((r||{})[c]))))))));}
function stat(v,label,color,on){return h('div',{class:'stat'+(on?' click':''),onclick:on||null},h('b',{style:color?'color:'+color:null,text:String(v)}),h('span',{text:label}));}
function legend(){return h('div',{class:'legend'},[['host',TC.host],['finding (colour = severity)',COL.high],['account',TC.user],['IP address',TC.ip],['file / process',TC.file],['domain',TC.domain]].map(x=>h('span',null,h('i',{style:'background:'+x[1]}),x[0])),h('span',{text:'drag to rearrange, click a finding to open it'}));}

function gauge(score,tone){const r=42,c=2*Math.PI*r,p=Math.min(100,score)/100,col=COL[tone]||COL.ok;
 return s('svg',{width:120,height:120,viewBox:'0 0 110 110'},s('circle',{cx:55,cy:55,r:r,style:'fill:none;stroke:#2a3340;stroke-width:10'}),
 s('circle',{cx:55,cy:55,r:r,transform:'rotate(-90 55 55)',style:'fill:none;stroke:'+col+';stroke-width:10;stroke-linecap:round;stroke-dasharray:'+(c*p)+' '+c}),
 s('text',{x:55,y:60,'text-anchor':'middle',style:'font-size:24px;font-weight:700;fill:#e6edf3',text:String(score)}),
 s('text',{x:55,y:78,'text-anchor':'middle',style:'font-size:10px;fill:#8b98a8',text:'risk / 100'}));}

function forceGraph(g,H){
 const W=1000;H=H||480;
 const svg=s('svg',{viewBox:'0 0 '+W+' '+H,class:'graph',style:'height:'+H+'px'});
 if(!g||!g.nodes||g.nodes.length<2){svg.appendChild(s('text',{x:20,y:30,style:'fill:#8b98a8',text:'No related entities to draw.'}));return svg;}
 const N=g.nodes.map((n,i)=>Object.assign({},n,{x:W/2+Math.cos(i*2.4)*(40+14*Math.sqrt(i)*2),y:H/2+Math.sin(i*2.4)*(30+10*Math.sqrt(i)*2),vx:0,vy:0}));
 const ix={};N.forEach(n=>ix[n.id]=n);
 const L=[],seen=new Set();(g.links||[]).forEach(l=>{const a=ix[l.s],b=ix[l.t],k=l.s+'|'+l.t;if(a&&b&&a!==b&&!seen.has(k)){seen.add(k);L.push({a:a,b:b});}});
 const k=Math.max(45,Math.min(120,Math.sqrt(W*H/N.length)*0.6));
 for(let it=0;it<300;it++){const al=1-it/300;
  for(let i=0;i<N.length;i++){const a=N[i];for(let j=i+1;j<N.length;j++){const b=N[j];let dx=a.x-b.x,dy=a.y-b.y,d2=dx*dx+dy*dy;if(d2<0.01){dx=Math.random()-.5;dy=Math.random()-.5;d2=.5;}if(Math.abs(dy)<18&&Math.abs(dx)<170){const p=(18-Math.abs(dy))*0.3,sg=dy>=0?1:-1;a.vy+=sg*p;b.vy-=sg*p;}if(d2>k*k*16)continue;const d=Math.sqrt(d2),f=k*k/d*0.2*al;a.vx+=dx/d*f;a.vy+=dy/d*f;b.vx-=dx/d*f;b.vy-=dy/d*f;}}
  L.forEach(l=>{const dx=l.b.x-l.a.x,dy=l.b.y-l.a.y,d=Math.sqrt(dx*dx+dy*dy)||1,f=(d-k)*0.08*al;l.a.vx+=dx/d*f;l.a.vy+=dy/d*f;l.b.vx-=dx/d*f;l.b.vy-=dy/d*f;});
  N.forEach(n=>{n.vx+=(W/2-n.x)*0.008*al;n.vy+=(H/2-n.y)*0.014*al;if(n.type==='host'){n.vx=(W/2-n.x)*0.2;n.vy=(H/2-n.y)*0.2;}
   n.x+=Math.max(-25,Math.min(25,n.vx));n.y+=Math.max(-25,Math.min(25,n.vy));n.vx*=0.55;n.vy*=0.55;n.x=Math.max(25,Math.min(W-25,n.x));n.y=Math.max(18,Math.min(H-18,n.y));});}
 const lg=s('g'),ng=s('g');svg.appendChild(lg);svg.appendChild(ng);
 L.forEach(l=>{l.el=s('line',{style:'stroke:#36414f;stroke-width:1.2'});lg.appendChild(l.el);});
 const upd=()=>{L.forEach(l=>{l.el.setAttribute('x1',l.a.x);l.el.setAttribute('y1',l.a.y);l.el.setAttribute('x2',l.b.x);l.el.setAttribute('y2',l.b.y);});N.forEach(n=>n.el.setAttribute('transform','translate('+n.x+','+n.y+')'));};
 const hl=(n,on)=>{L.forEach(l=>{if(l.a===n||l.b===n)l.el.style.stroke=on?'#4c8dff':'#36414f';});};
 N.forEach(n=>{const fnd=n.type==='finding';const c=fnd?COL[n.sev||'info']:(TC[n.type]||'#888');const r=n.type==='host'?13:fnd?5+rank(n.sev)*2:7;
  const shape=fnd?s('circle',{r:r,style:'fill:'+c+';stroke:#0a0e13;stroke-width:2'}):n.type==='host'?s('rect',{x:-r,y:-r,width:2*r,height:2*r,rx:3,style:'fill:'+c}):s('rect',{x:-r*0.8,y:-r*0.8,width:1.6*r,height:1.6*r,transform:'rotate(45)',style:'fill:'+c});
  const lab=String(n.label||'');
  n.el=s('g',{style:'cursor:'+(fnd?'pointer':'grab')},shape,s('text',{x:r+5,y:4,style:'font-size:11px;fill:'+(fnd?'#e6edf3':'#aab6c3')+';pointer-events:none',text:lab.length>34?lab.slice(0,33)+'\u2026':lab}),s('title',{text:(n.full||lab)+(fnd?'':' ('+n.type+')')}));
  n.el.addEventListener('mouseenter',()=>hl(n,true));n.el.addEventListener('mouseleave',()=>hl(n,false));
  n.el.addEventListener('pointerdown',ev=>{ev.preventDefault();const pt=svg.createSVGPoint(),x0=ev.clientX,y0=ev.clientY;let moved=false;
   const mv=e=>{if(Math.abs(e.clientX-x0)+Math.abs(e.clientY-y0)>3)moved=true;pt.x=e.clientX;pt.y=e.clientY;const p=pt.matrixTransform(svg.getScreenCTM().inverse());n.x=p.x;n.y=p.y;upd();};
   const up=()=>{window.removeEventListener('pointermove',mv);window.removeEventListener('pointerup',up);if(!moved&&fnd&&n.ref)openFinding(n.ref);};
   window.addEventListener('pointermove',mv);window.addEventListener('pointerup',up);});
  ng.appendChild(n.el);});
 upd();return svg;}

function histogram(){
 const from=Date.parse(M.window_from),to=Date.parse(M.window_to);if(isNaN(from)||isNaN(to)||to<=from)return h('p',{class:'muted',text:'No analysis window.'});
 const day=864e5,n=Math.max(1,Math.ceil((to-from)/day)),all=new Array(n).fill(0),fl=new Array(n).fill(0);
 T.forEach(e=>{const i=Math.floor((Date.parse(e.t)-from)/day);if(i>=0&&i<n){all[i]++;if(rank(e.sev)>=2)fl[i]++;}});
 const W=1000,H=170,pb=22,mx=Math.max(1,...all),bw=W/n,g=s('svg',{viewBox:'0 0 '+W+' '+H,class:'hist'});
 for(let i=0;i<n;i++){const x=i*bw,ha=(H-pb-8)*all[i]/mx,hf=(H-pb-8)*fl[i]/mx,d=new Date(from+i*day).toISOString().slice(0,10);
  g.appendChild(s('g',{style:'cursor:pointer',onclick:()=>{st.t=tReset();st.t.day=d;go('timeline');}},s('title',{text:d+' (UTC): '+all[i]+' timeline entries, '+fl[i]+' linked to medium+ findings'}),
   s('rect',{x:x+1,y:H-pb-ha,width:Math.max(1,bw-2),height:ha,style:'fill:#2f4a6d'}),hf?s('rect',{x:x+1,y:H-pb-hf,width:Math.max(1,bw-2),height:hf,style:'fill:'+COL.high}):null,
   s('rect',{x:x,y:0,width:bw,height:H-pb,style:'fill:transparent'})));
  if(i%Math.ceil(n/12)===0)g.appendChild(s('text',{x:x+2,y:H-6,style:'font-size:11px;fill:#8b98a8',text:d.slice(5)}));}
 return h('div',null,g,h('div',{class:'legend'},h('span',null,h('i',{style:'background:#2f4a6d'}),'timeline entries per UTC day'),h('span',null,h('i',{style:'background:'+COL.high}),'linked to medium+ findings'),h('span',{text:'click a day to open it in the timeline'})));}

function vOverview(){
 const v=D.verdict||{},c=v.counts||{},tone=v.tone||'ok';
 const ban=h('div',{class:'card verdict',style:'border-left-color:'+(COL[tone]||COL.ok)},h('div',{class:'vrow'},h('div',{class:'vtext'},h('div',{class:'muted small',text:'VERDICT'}),h('div',{class:'vlevel',style:'color:'+(COL[tone]||COL.ok),text:v.level||''}),h('p',{text:v.summary||''}),h('p',{class:'muted small',text:'Automated heuristic triage: confirm every finding against its evidence before acting on it.'})),gauge(v.score||0,tone)));
 const stats=h('div',{class:'stats'},['critical','high','medium','low'].map(k=>stat(c[k]||0,k+' findings',COL[k],()=>{st.f=fReset();st.f.sev=k;go('findings');})),
  stat(I.length,'incidents',null,()=>go('incidents')),stat((M.events_parsed||0).toLocaleString(),'events analyzed',null,null),stat(T.length.toLocaleString(),'timeline entries',null,()=>go('timeline')),
  stat(((D.recommendations||{}).gaps||[]).length,'visibility gaps',null,()=>go('recs')));
 const ts={};F.forEach(f=>{if(!f.tactic)return;const t=ts[f.tactic]||(ts[f.tactic]={n:0,sev:'info'});t.n++;if(rank(f.severity)>rank(t.sev))t.sev=f.severity;});
 const chain=h('div',{class:'card'},h('h2',{text:'Attack chain - MITRE ATT&CK tactics observed'}),h('div',{class:'chain'},(D.tactics||[]).map(t=>{const x=ts[t.key];
  return h('div',{class:'tac'+(x?' hit':''),style:x?'border-color:'+COL[x.sev]:null,onclick:x?()=>{st.f=fReset();st.f.tac=t.key;go('findings');}:null},h('div',{class:'tn',text:t.name}),h('div',{class:'muted small',text:t.id}),h('div',{class:'tc',style:x?'color:'+COL[x.sev]:'color:#4b5563',text:x?x.n+' finding'+(x.n>1?'s':''):'none'}));})));
 const top=h('div',{class:'card'},h('h2',{text:'Most severe findings'}),F.length?h('table',null,h('tbody',null,F.slice(0,12).map(x=>h('tr',{class:'click',onclick:()=>openFinding(x.id)},h('td',null,sev(x.severity)),h('td',{class:'mono nowrap',text:x.id}),h('td',{text:x.title}),h('td',{class:'mono muted nowrap',text:x.technique||''}),h('td',{class:'muted nowrap small',text:x.first_seen?ft(x.first_seen):'live state'}))))):h('p',{class:'muted',text:'No findings.'}));
 const incs=h('div',{class:'card'},h('h2',{text:'Incidents'}),I.length?h('table',null,h('tbody',null,I.map(x=>h('tr',{class:'click',onclick:()=>{go('incidents');setTimeout(()=>{const el=document.getElementById('inc-'+x.id);if(el)el.scrollIntoView();},0);}},h('td',null,sev(x.severity)),h('td',{class:'mono nowrap',text:x.id}),h('td',null,h('div',{text:x.title}),h('div',{class:'muted small',text:x.headline})),h('td',{class:'muted small nowrap',text:x.findings.length+' findings'}),h('td',{class:'muted small nowrap',text:x.first_seen?ft(x.first_seen):''}))))):h('p',{class:'muted',text:'No incidents were formed.'}));
 const ips=[].concat(Y.ip_addresses||[]);
 const host=h('div',{class:'card'},h('h2',{text:'Host and case'}),kv([['Hostname',Y.hostname],['Domain',Y.domain],['Role',Y.role],['Operating system',(Y.os||'')+(Y.os_version?' ('+Y.os_version+')':'')],['IP addresses',ips],['Time zone',(Y.timezone||'')+' ('+offTxt()+')'],['Last boot',ft(Y.last_boot)],['OS installed',ft(Y.install_date)],['Hardware',[Y.manufacturer,Y.model,Y.serial].filter(Boolean).join(' / ')],
  ['Collected as',(Y.run_as||'')+(Y.elevated?' (elevated)':' (NOT elevated - partial evidence)')],['Profile',Y.profile],['Collection',ft(Y.collection_start)+'  ->  '+ft(Y.collection_end)],['Analysis window',ft(M.window_from)+'  ->  '+ft(M.window_to)+' ('+M.days+' days)'],['Case',M.case],['Case label',M.case_label],['Examiner',M.examiner]]));
 return h('div',null,ban,stats,chain,h('div',{class:'card'},h('h2',{text:'Activity over the analysis window'}),histogram()),h('div',{class:'grid g2'},top,incs),host);}

function vIncidents(){
 const w=h('div');
 if(!I.length)w.appendChild(h('div',{class:'card'},h('p',{text:'No incidents: no group of related findings reached medium severity. Review the Findings tab for isolated low-severity items.'})));
 else if(D.graph&&D.graph.nodes&&D.graph.nodes.length>2)w.appendChild(h('div',{class:'card'},h('h2',{text:'All incidents - entity graph'}),h('p',{class:'muted small',text:'Findings linked to the accounts, IP addresses, files and domains they involve. Findings that share an entity belong together.'}),forceGraph(D.graph,600),legend()));
 I.forEach(x=>{w.appendChild(h('div',{class:'card',id:'inc-'+x.id,style:'border-left:5px solid '+COL[x.severity]},
  h('div',{class:'ihead'},sev(x.severity),h('b',{class:'iid',text:x.id}),h('b',{text:x.title}),h('span',{class:'muted small',text:'score '+x.score+'/100'})),
  h('div',{class:'muted',text:'Key finding: '+x.headline}),h('p',{text:x.summary}),
  h('div',{class:'grid g2'},h('div',null,h('h3',{text:'What happened (chronological, UTC)'}),h('ol',{class:'story'},(x.narrative||[]).map(l=>h('li',{text:l}))),
    h('h3',{text:'Findings'}),h('div',{class:'flist'},(x.findings||[]).map(id=>h('div',null,flink(id),' ',FI[id]?sev(FI[id].severity):null,' ',FI[id]?FI[id].title:''))),
    h('h3',{text:'Entities'}),kv([['Tactics',(x.tactics||[]).map(t=>TN[t]||t)],['Techniques',x.techniques,1],['Accounts',x.users],['IP addresses',x.ips,1],['Files',x.files,1],['Domains',x.domains,1]]),
    h('div',{class:'toolbar',style:'margin-top:12px'},h('button',{class:'btn',text:'Show in timeline',onclick:()=>{st.t=tReset();st.t.inc=x.id;go('timeline');}}),h('button',{class:'btn',text:'Show findings',onclick:()=>{st.f=fReset();st.f.inc=x.id;go('findings');}}))),
   h('div',null,h('h3',{text:'Incident graph'}),forceGraph(x.graph,460),legend()))));});
 return w;}

function findingBody(x){
 const ev=[].concat(x.evidence||[]);
 return h('div',{class:'body'},h('p',{text:x.description||''}),h('div',{class:'rec'},h('b',{text:'Recommended action: '}),x.recommendation||''),
  kv([['Rule',x.rule],['MITRE ATT&CK',x.technique?x.technique+' - '+(x.technique_name||'')+' ('+(TN[x.tactic]||x.tactic||'')+')':''],['First seen',ft(x.first_seen)],['Last seen',ft(x.last_seen)],['Occurrences',x.hits],['Incident',x.incident?ilink(x.incident):''],
   ['Sources',x.sources],['Accounts',x.users],['IP addresses',x.ips,1],['Processes',x.processes,1],['Files',x.files,1],['SHA-256',x.hashes,1],['Domains',x.domains,1]]),
  ev.length?[h('h3',{text:'Evidence'}),ev.map(e=>h('pre',{text:e}))]:null,
  h('div',{class:'toolbar',style:'margin-top:10px'},x.first_seen?h('button',{class:'btn',text:'Show in timeline',onclick:()=>{st.t=tReset();st.t.fid=x.id;go('timeline');}}):null,
   x.technique?h('a',{class:'btn',href:'https://attack.mitre.org/techniques/'+x.technique.replace('.','/')+'/',target:'_blank',rel:'noopener noreferrer',text:'ATT&CK: '+x.technique}):null));}
function findingCard(x){
 const d=h('details',{class:'f',id:'fd-'+x.id,style:'border-left:4px solid '+COL[x.severity]});
 d.appendChild(h('summary',null,sev(x.severity),h('b',{class:'mono nowrap',text:x.id}),h('span',{class:'ft',text:x.title}),x.technique?h('span',{class:'tag',text:x.technique}):null,x.hits>1?h('span',{class:'tag',text:'x'+x.hits}):null,x.incident?h('span',{class:'tag inc',text:x.incident}):null,h('span',{class:'muted small right',text:x.first_seen?ft(x.first_seen):'live state'})));
 let done=false;d.addEventListener('toggle',()=>{if(d.open&&!done){done=true;d.appendChild(findingBody(x));}});return d;}
function vFindings(){
 const f=st.f,list=h('div'),cnt=h('span',{class:'muted small'});
 function draw(){list.textContent='';const q=f.q.toLowerCase();let n=0;
  F.forEach(x=>{if(f.sev&&x.severity!==f.sev)return;if(f.tac&&x.tactic!==f.tac)return;if(f.tech&&x.technique!==f.tech&&!(x.technique||'').startsWith(f.tech+'.'))return;if(f.inc&&x.incident!==f.inc)return;if(q&&JSON.stringify(x).toLowerCase().indexOf(q)<0)return;n++;list.appendChild(findingCard(x));});
  cnt.textContent=n+' of '+F.length+' findings';if(!n)list.appendChild(h('div',{class:'card muted',text:'No findings match the filters.'}));}
 const tb=h('div',{class:'toolbar'},search(f.q,'Search findings, evidence, users, IPs...',v=>{f.q=v;draw();}),
  sel([['','All severities']].concat(SEV.slice().reverse().map(x=>[x,x])),f.sev,v=>{f.sev=v;draw();}),
  sel([['','All tactics']].concat((D.tactics||[]).map(t=>[t.key,t.name])),f.tac,v=>{f.tac=v;draw();}),
  sel([['','All incidents']].concat(I.map(i=>[i.id,i.id+' '+i.title])),f.inc,v=>{f.inc=v;draw();}),
  f.tech?h('span',{class:'tag',text:'technique '+f.tech}):null,h('button',{class:'btn',text:'Clear filters',onclick:()=>{st.f=fReset();render();}}),
  h('button',{class:'btn',text:'Export CSV',onclick:()=>csv('findings.csv',['id','severity','title','technique','tactic','first_seen','last_seen','hits','incident','users','ips','files','hashes','domains','description','recommendation'],F.map(x=>[x.id,x.severity,x.title,x.technique,x.tactic,x.first_seen,x.last_seen,x.hits,x.incident,x.users,x.ips,x.files,x.hashes,x.domains,x.description,x.recommendation]))}),cnt);
 draw();
 if(f.open){const id=f.open;f.open=null;setTimeout(()=>{const e=document.getElementById('fd-'+id);if(e){e.open=true;e.scrollIntoView({block:'center'});}},0);}
 return h('div',null,tb,list);}

function vTimeline(){
 const t=st.t,PS=250,body=h('tbody'),info=h('span',{class:'muted small'}),pager=h('div',{class:'pager'});
 const srcs=[...new Set(T.map(e=>e.src))].sort(),cats=[...new Set(T.map(e=>e.cat).filter(Boolean))].sort();let rows=[];
 function filt(){const q=t.q.toLowerCase();const inc=t.inc?new Set(((I.find(i=>i.id===t.inc)||{}).findings)||[]):null;
  rows=T.filter(e=>{if(t.flag&&!e.sev)return false;if(t.sev&&(!e.sev||rank(e.sev)<rank(t.sev)))return false;if(t.src&&e.src!==t.src)return false;if(t.cat&&e.cat!==t.cat)return false;
   if(t.fid&&!(e.f||[]).includes(t.fid))return false;if(inc&&!(e.f||[]).some(id=>inc.has(id)))return false;if(t.day&&String(e.t||'').slice(0,10)!==t.day)return false;
   if(q&&((e.sum||'')+' '+(e.u||'')+' '+e.src+' '+e.ev+' '+(e.cat||'')+' '+(e.f||[]).join(' ')).toLowerCase().indexOf(q)<0)return false;return true;});
  t.page=Math.min(t.page,Math.max(0,Math.ceil(rows.length/PS)-1));draw();}
 function draw(){body.textContent='';const a=t.page*PS;
  rows.slice(a,a+PS).forEach(e=>body.appendChild(h('tr',{style:e.sev?'box-shadow:inset 3px 0 0 '+COL[e.sev]:null},h('td',{class:'mono nowrap',text:ft(e.t)}),h('td',null,e.sev?sev(e.sev):''),h('td',{class:'nowrap',text:e.src}),h('td',{class:'mono',text:e.ev}),h('td',{class:'muted',text:e.cat||''}),h('td',{text:e.sum||''}),h('td',{text:e.u||''}),h('td',{class:'nowrap'},(e.f||[]).map(id=>[flink(id),' '])))));
  info.textContent=rows.length.toLocaleString()+' of '+T.length.toLocaleString()+' entries'+(M.timeline_truncated?' (timeline capped at '+T.length.toLocaleString()+' of '+(M.timeline_total||0).toLocaleString()+'; every flagged entry kept)':'');
  const pages=Math.max(1,Math.ceil(rows.length/PS));pager.textContent='';
  pager.appendChild(h('button',{class:'btn',text:'Previous',disabled:t.page<=0?true:null,onclick:()=>{t.page--;draw();window.scrollTo(0,0);}}));pager.appendChild(h('span',{class:'muted small',text:'page '+(t.page+1)+' of '+pages}));
  pager.appendChild(h('button',{class:'btn',text:'Next',disabled:t.page>=pages-1?true:null,onclick:()=>{t.page++;draw();window.scrollTo(0,0);}}));}
 const active=[t.fid?'finding '+t.fid:null,t.inc?'incident '+t.inc:null,t.day?'day '+t.day+' (UTC)':null].filter(Boolean);
 const tb=h('div',{class:'toolbar'},search(t.q,'Search summary, user, event id...',v=>{t.q=v;t.page=0;filt();}),
  sel([['','All sources']].concat(srcs.map(x=>[x,x])),t.src,v=>{t.src=v;t.page=0;filt();}),sel([['','All categories']].concat(cats.map(x=>[x,x])),t.cat,v=>{t.cat=v;t.page=0;filt();}),
  sel([['','Any severity'],['low','low and above'],['medium','medium and above'],['high','high and above'],['critical','critical']],t.sev,v=>{t.sev=v;t.page=0;filt();}),
  h('label',{class:'small'},h('input',{type:'checkbox',checked:t.flag?true:null,onchange:e=>{t.flag=e.target.checked;t.page=0;filt();}}),' only entries linked to findings'),
  active.map(a=>h('span',{class:'tag inc',text:a})),h('button',{class:'btn',text:'Clear filters',onclick:()=>{st.t=tReset();render();}}),
  h('button',{class:'btn',text:'Export CSV',onclick:()=>csv('timeline.csv',['time_utc','severity','source','event','category','summary','user','findings'],rows.map(e=>[e.t,e.sev,e.src,e.ev,e.cat,e.sum,e.u,e.f]))}),info);
 filt();
 return h('div',null,tb,h('div',{class:'card',style:'padding:0'},h('div',{class:'tablewrap',style:'border:0;max-height:none'},h('table',null,h('thead',null,h('tr',null,['Time ('+tzLabel()+')','Severity','Source','Event','Category','Summary','Account','Findings'].map(c=>h('th',{text:c})))),body))),pager);}

function vAttack(){
 const mat=D.matrix||{};let obsN=0;Object.keys(mat).forEach(k=>obsN+=(mat[k]||[]).length);
 const tb=h('div',{class:'toolbar'},h('label',null,h('input',{type:'checkbox',checked:st.m.full?true:null,onchange:e=>{st.m.full=e.target.checked;render();}}),' Show every technique the analyzer can detect'),h('span',{class:'muted small',text:obsN+' techniques observed. Colour = highest severity; click a technique to see its findings.'}));
 const grid=h('div',{class:'matrix'});
 (D.tactics||[]).forEach(t=>{const obs=(mat[t.key]||[]).slice().sort((a,b)=>rank(b.severity)-rank(a.severity)||b.hits-a.hits),ids=new Set(obs.map(o=>o.id));
  const col=h('div',null,h('div',{class:'mh',style:obs.length?'border-color:'+COL[obs[0].severity]:null},h('b',{text:t.name}),h('div',{class:'muted small',text:t.id+' - '+obs.length+' observed'})));
  obs.forEach(o=>col.appendChild(h('div',{class:'tech',style:'border-left:4px solid '+COL[o.severity],title:o.findings.join(', '),onclick:()=>{st.f=fReset();st.f.tech=o.id;go('findings');}},h('div',{class:'mono small',text:o.id}),h('div',{text:o.name}),h('div',{class:'muted small',text:o.findings.length+' finding(s), '+o.hits+' hit(s)'}))));
  if(st.m.full)(D.catalog||[]).filter(c=>c.tactic===t.key&&!ids.has(c.id)).forEach(c=>col.appendChild(h('div',{class:'tech dim'},h('div',{class:'mono small',text:c.id}),h('div',{text:c.name}))));
  grid.appendChild(col);});
 return h('div',null,tb,h('div',{class:'card'},grid));}

function vEvidence(){
 const E=D.evidence||{},names=Object.keys(E);if(!names.length)return h('div',{class:'card muted',text:'No evidence datasets.'});
 if(!st.e.ds||!E[st.e.ds])st.e.ds=names.find(n=>E[n].rows&&E[n].rows.length)||names[0];
 const side=h('div',{class:'dsl'}),groups={};names.forEach(n=>{const g=E[n].group||'Other';(groups[g]=groups[g]||[]).push(n);});
 Object.keys(groups).forEach(g=>{side.appendChild(h('div',{class:'dsg',text:g}));groups[g].forEach(n=>side.appendChild(h('button',{class:'dsb'+(n===st.e.ds?' on':''),onclick:()=>{st.e={ds:n,q:'',sort:-1,dir:1,page:0};render();}},h('span',{text:E[n].title||n}),h('span',{class:'muted small',text:String(E[n].total||0)}))));});
 const e=st.e,ds=E[e.ds],cols=ds.columns||[],PS=500,tbody=h('tbody'),info=h('span',{class:'muted small'}),pager=h('div',{class:'pager'});let rows=[];
 const cmp=(a,b)=>{if(a==null||a==='')return(b==null||b==='')?0:1;if(b==null||b==='')return -1;if(typeof a==='number'&&typeof b==='number')return a-b;return String(a).localeCompare(String(b),undefined,{numeric:true});};
 function filt(){const q=e.q.toLowerCase();rows=(ds.rows||[]).filter(r=>!q||r.some(v=>v!=null&&String(v).toLowerCase().indexOf(q)>=0));if(e.sort>=0){const i=e.sort,d=e.dir;rows=rows.slice().sort((a,b)=>cmp(a[i],b[i])*d);}e.page=Math.min(e.page,Math.max(0,Math.ceil(rows.length/PS)-1));draw();}
 function draw(){tbody.textContent='';const a=e.page*PS;rows.slice(a,a+PS).forEach(r=>tbody.appendChild(h('tr',null,r.map(v=>/^[0-9a-f]{40,64}$/i.test(String(v))?h('td',{class:'nowrap mono',title:v,text:String(v).slice(0,12)+'\u2026'}):h('td',(v!=null&&String(v).length<=24)?{class:'nowrap'}:null,cell(v))))));
  info.textContent=rows.length.toLocaleString()+' of '+(ds.rows||[]).length.toLocaleString()+' rows'+((ds.total||0)>(ds.rows||[]).length?' (dataset has '+ds.total.toLocaleString()+' rows; the full data is in live\\'+e.ds+'.json)':'');
  const pages=Math.max(1,Math.ceil(rows.length/PS));pager.textContent='';
  if(pages>1){pager.appendChild(h('button',{class:'btn',text:'Previous',disabled:e.page<=0?true:null,onclick:()=>{e.page--;draw();}}));pager.appendChild(h('span',{class:'muted small',text:'page '+(e.page+1)+' of '+pages}));pager.appendChild(h('button',{class:'btn',text:'Next',disabled:e.page>=pages-1?true:null,onclick:()=>{e.page++;draw();}}));}}
 const head=h('tr',null,cols.map((c,i)=>h('th',{class:'sort',text:c+(e.sort===i?(e.dir>0?' \u25b2':' \u25bc'):''),onclick:()=>{if(e.sort===i)e.dir=-e.dir;else{e.sort=i;e.dir=1;}render();}})));
 const tb=h('div',{class:'toolbar'},h('b',{text:ds.title||e.ds}),search(e.q,'Filter rows...',v=>{e.q=v;e.page=0;filt();}),h('button',{class:'btn',text:'Export CSV',onclick:()=>csv(e.ds+'.csv',cols,rows)}),info);
 filt();
 return h('div',{class:'ds-layout'},side,h('div',null,tb,cols.length?h('div',{class:'tablewrap'},h('table',null,h('thead',null,head),tbody)):h('div',{class:'card muted',text:'This dataset is empty (collected, nothing found).'}),pager));}

function vRecs(){
 const r=D.recommendations||{},iocs=D.iocs||[],gaps=r.gaps||[];
 return h('div',null,h('div',{class:'grid g2'},h('div',{class:'card'},h('h2',{text:'Containment - do now'}),h('ol',null,(r.containment||[]).map(x=>h('li',{text:x})))),
   h('div',{class:'card'},h('h2',{text:'Investigation - next steps'}),h('ol',null,(r.next_steps||[]).map(x=>h('li',{text:x}))))),
  h('div',{class:'card'},h('h2',{text:'Eradication and hardening by ATT&CK technique'}),(r.techniques||[]).length?(r.techniques).map(t=>h('div',{class:'trec',style:'border-left:4px solid '+COL[t.severity]},h('div',null,sev(t.severity),' ',h('b',{class:'mono',text:t.technique}),' ',h('b',{text:t.name})),h('p',{text:t.advice}),h('div',{class:'small'},'Findings: ',(t.findings||[]).map(id=>[flink(id),' '])))):h('p',{class:'muted',text:'No technique-specific actions.'})),
  h('div',{class:'card'},h('h2',{text:'Visibility gaps - what this host could not tell us'}),gaps.length?h('table',null,h('thead',null,h('tr',null,['Severity','Area','Issue','Recommendation'].map(c=>h('th',{text:c})))),h('tbody',null,gaps.map(g=>h('tr',null,h('td',null,sev(g.severity)),h('td',{class:'nowrap',text:g.area}),h('td',{text:g.issue}),h('td',{text:g.recommendation}))))):h('p',{class:'muted',text:'No gaps detected.'})),
  h('div',{class:'card'},h('div',{class:'toolbar'},h('h2',{style:'margin:0',text:'Indicators of compromise ('+iocs.length+')'}),h('button',{class:'btn small',text:'Export CSV',onclick:()=>csv('iocs.csv',['type','value','severity','findings'],iocs.map(i=>[i.type,i.value,i.severity,i.findings]))})),
   iocs.length?h('div',{class:'tablewrap'},h('table',null,h('thead',null,h('tr',null,['Type','Value','Severity','Findings'].map(c=>h('th',{text:c})))),h('tbody',null,iocs.map(i=>h('tr',null,h('td',{class:'nowrap',text:i.type}),h('td',{class:'mono',text:i.value}),h('td',null,sev(i.severity)),h('td',null,(i.findings||[]).map(id=>[flink(id),' '])))))))
   :h('p',{class:'muted',text:'No indicators from medium or higher findings.'})));}

function vCollection(){
 const g=D.integrity||{};
 return h('div',null,h('div',{class:'grid g2'},
  h('div',{class:'card'},h('h2',{text:'Analysis'}),kv([['Tool',(M.tool||'')+' '+(M.version||'')],['Report generated',ft(M.generated)],['Analysis window',ft(M.window_from)+'  ->  '+ft(M.window_to)],['Events analyzed',(M.events_parsed||0).toLocaleString()],['Max events per query',M.max_events],['Timeline entries',(M.timeline_total||0).toLocaleString()+(M.timeline_truncated?' (capped in the report)':'')],['Own activity filtered',(M.self_filtered_events||0)+' events, '+(M.self_filtered_script_blocks||0)+' script blocks'],['Generated module code skipped',(M.cdxml_script_blocks||0)+' CDXML script blocks (Windows-generated wrappers)'],['Rule errors',M.rule_errors],['Analysis time',M.analysis_seconds+' s']])),
  h('div',{class:'card'},h('h2',{text:'Evidence integrity'}),kv([['Status',g.status],['Files checked',g.checked],['Verified',g.verified],['Changed',g.mismatched,1],['Missing',g.missing,1]]),h('p',{class:'muted small',text:'manifest.csv holds the SHA-256 of every collected file at collection time; the archive has its own .sha256 file.'}))),
  h('div',{class:'card'},h('h2',{text:'Collection steps'}),objTable(D.steps)),
  h('div',{class:'card'},h('h2',{text:'Event log analysis'}),h('p',{class:'muted small',text:'Per-query statistics are in Evidence > Collection.'}),h('button',{class:'btn',text:'Open event log inventory',onclick:()=>{st.e={ds:'event_logs',q:'',sort:-1,dir:1,page:0};go('evidence');}}),' ',h('button',{class:'btn',text:'Open analysis statistics',onclick:()=>{st.e={ds:'event_parse_stats',q:'',sort:-1,dir:1,page:0};go('evidence');}})));}

/* ---------- Entity graph ---------- */
const GT={host:['#e6edf3','H','Host'],incident:['#ff4d5e','INC','Incident'],finding:['#ff8c42','!','Finding'],technique:['#4c8dff','T','ATT&CK technique'],
 user:['#c297ff','U','Account'],group:['#bc8cff','G','Group'],ip:['#2dd4bf','IP','IP address'],domain:['#7ee787','D','Domain / remote host'],file:['#f778ba','F','File / process'],
 hash:['#ffa657','#','Hash'],service:['#79c0ff','S','Service / driver'],task:['#e3b341','TS','Scheduled task'],autorun:['#ff7b72','R','Autostart entry'],
 threat:['#ff4d5e','AV','Defender detection'],usb:['#a5d6ff','USB','USB device'],share:['#56d364','SH','Share']};
const GSKIP=new Set(['event_logs','event_parse_stats','collection_steps','audit_policy','security_config','firewall_profiles','defender_status','defender_preferences','defender_exclusions','ip_configuration','hotfixes','installed_software','amcache_programs','network_history','proxy_settings','artifact_notes','powershell_history','port_proxy']);
const GROLE={user:'user',account:'user',run_as:'user',by:'user',username:'user',owner:'user',member:'user',
 path:'file',image:'file',target:'file',target_path:'file',program:'file',app:'file',original_path:'file',service_dll:'file',executable:'name',process:'name',parent_name:'name',
 remote_address:'ip',address:'ip',source_ip:'ip',ip:'ip',client:'ipdom',url:'url',referrer:'url',host_url:'url',referrer_url:'url',sha256:'hash',sha1:'hash',md5:'hash',hash:'hash'};
const GENV=[[/^%system32%/i,'C:\\Windows\\System32'],[/^%syswow64%/i,'C:\\Windows\\SysWOW64'],[/^%(windows|systemroot|windir)%/i,'C:\\Windows'],[/^%programfiles\(x86\)%/i,'C:\\Program Files (x86)'],[/^%programfiles%/i,'C:\\Program Files'],[/^%programdata%/i,'C:\\ProgramData']];
const GRXP=/^(?:[a-z]:\\|\\\\[^\\?]+\\|\\device\\harddiskvolume\d+\\|\\\\\?\\[a-z]:\\|\\\?\?\\[a-z]:\\)/i;
function gLeaf(x){const p=String(x).replace(/[\\\/]+$/,'').split(/[\\\/]/);return p[p.length-1]||String(x);}
function nPath(v){if(v==null)return null;let x=String(v).trim();if(!x||x.length>700)return null;const q=/^"([^"]+)"/.exec(x);if(q)x=q[1];for(const e of GENV)x=x.replace(e[0],e[1]);if(!GRXP.test(x))return null;
 const m=/^(.+?\.(?:exe|dll|sys|scr|com|cpl|bat|cmd|ps1|vbs|js|hta|msi|lnk))(?=[\s,]|$)/i.exec(x);if(m)x=m[1];x=x.replace(/[\\\s]+$/,'');
 return {k:x.toLowerCase().replace(/^(?:\\\\\?\\|\\\?\?\\)?(?:[a-z]:|\\device\\harddiskvolume\d+)\\/,''),l:x};}
function nIp(v){let x=String(v==null?'':v).trim().replace(/^::ffff:/i,'');if(/^\d{1,3}(\.\d{1,3}){3}$/.test(x)){if(/^(127\.|0\.|255\.|169\.254\.)/.test(x))return null;return x;}
 x=x.toLowerCase();if(x.length>2&&x.indexOf(':')>=0&&/^[0-9a-f:]+$/.test(x)&&!/^(::1?|fe80:.*|ff0.*)$/.test(x))return x;return null;}
function nDom(v){const x=String(v==null?'':v).trim().toLowerCase().replace(/\.$/,'');if(!x||x.length>253||nIp(x))return null;return /^([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/.test(x)?x:null;}
function nUser(v){if(v==null)return null;const x=String(v).trim();if(!x||x.length>100||/^(-|n\/a|null|none|machine|all users|everyone|\(default\))$/i.test(x)||/[\/:]/.test(x))return null;const l=x.split('\\').pop().trim().toLowerCase();return l?{k:l,l:x}:null;}
function hexA(c,a){const n=parseInt(c.slice(1),16);return 'rgba('+(n>>16&255)+','+(n>>8&255)+','+(n&255)+','+a+')';}
let GM=null;
function gBuild(){
 const nodes=new Map(),edges=new Map(),low=x=>String(x==null?'':x).toLowerCase();
 const ek=(a,b)=>a.id<b.id?a.id+'\n'+b.id:b.id+'\n'+a.id;
 function node(k,type,label,full){let n=nodes.get(k);if(!n){const l=String(label==null||label===''?k:label);n={id:k,type:type,label:l,full:String(full==null||full===''?l:full),refs:[],nref:0,adj:new Map(),t0:null,t1:null,sev:null,ref:null,hot:0};nodes.set(k,n);}return n;}
 function link(a,b,rel,ref){if(!a||!b||a===b)return;const k=ek(a,b);let e=edges.get(k);if(!e){e={a:a,b:b,rels:new Set(),refs:[]};edges.set(k,e);a.adj.set(b.id,e);b.adj.set(a.id,e);}if(rel)e.rels.add(rel);if(ref&&e.refs.length<20)e.refs.push(ref);}
 function touch(n,ref,times){if(!n)return;if(ref){n.nref++;if(n.refs.length<300)n.refs.push(ref);}if(times)for(const t of times){if(!n.t0||t<n.t0)n.t0=t;if(!n.t1||t>n.t1)n.t1=t;}}
 const lk=(a,n,rel,ref,times)=>{if(!a||!n||a===n)return;touch(n,ref,times);link(a,n,rel,ref);};
 const EF=v=>{const p=nPath(v);return p?node('f:'+p.k,'file',gLeaf(p.l),p.l):null;};
 const EN=v=>{if(v==null)return null;const x=String(v).trim().replace(/^"|"$/g,'');if(!x||x.length>260)return null;if(/[\\\/]/.test(x))return EF(x);return /\.(exe|dll|sys|scr|com|bat|cmd|ps1)$/i.test(x)?node('p:'+low(x),'file',x,x):null;};
 const EU=v=>{const u=nUser(v);return u?node('u:'+u.k,'user',u.l,u.l):null;};
 const EI=v=>{const i=nIp(v);return i?node('i:'+i,'ip',i,i):null;};
 const ED=v=>{const d=nDom(v);return d?node('d:'+d,'domain',d,d):null;};
 const EH=v=>{const x=low(v).trim();return /^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/.test(x)?node('h:'+x,'hash',x.slice(0,12)+'\u2026',x):null;};
 const EURL=v=>{const m=/^[a-z][a-z0-9+.-]*:\/\/(?:[^@\/?#]*@)?(\[[^\]]+\]|[^\/:?#]+)/i.exec(String(v||''));if(!m)return null;const x=m[1].replace(/^\[|\]$/g,'');return EI(x)||ED(x);};
 const svc=v=>v?node('s:'+low(v),'service',v,v):null;
 const app=v=>{if(!v)return null;return EF(v)||EN(v)||(/^[A-Za-z][\w-]*$/.test(v)?svc(v):node('p:'+low(v),'file',v,v));};
 const ROLE={user:EU,file:EF,name:EN,ip:EI,url:EURL,hash:EH,domain:ED,ipdom:v=>EI(v)||ED(v)};
 const SPLIT={ip:1,hash:1,ipdom:1,domain:1};
 const host=node('host','host',Y.hostname||'host',(Y.hostname||'host')+(Y.domain?' ('+Y.domain+')':''));
 [].concat(Y.ip_addresses||[]).forEach(ip=>link(host,EI(ip),'own address'));
 const SPEC={
  processes:{pre:(rows,cols,c)=>{const ip=cols.indexOf('pid'),pp=cols.indexOf('path'),pn=cols.indexOf('name');c.pid={};rows.forEach(r=>{const n=EF(r[pp])||EN(r[pn]);if(n)c.pid[r[ip]]=n;});},
   p:r=>EF(r.path)||EN(r.name),x:(r,ref,p,c,t)=>{const par=c.pid[r.ppid];if(par&&par!==p)link(par,p,'started process (pid '+r.pid+')',ref);else if(r.parent_name)lk(EN(r.parent_name),p,'started process (pid '+r.pid+')',ref,t);}},
  network_connections:{p:r=>EF(r.path)||EN(r.process),roles:{address:null}},
  services:{p:r=>svc(r.name)},drivers:{p:r=>svc(r.name)},
  scheduled_tasks:{p:r=>r.path?node('t:'+low(r.path),'task',gLeaf(r.path),r.path):null,roles:{path:null}},
  autoruns:{p:r=>node('r:'+low(r.location)+'|'+low(r.name),'autorun',r.name||r.category,(r.category||'')+': '+(r.location||'')+' \\ '+(r.name||''))},
  wmi_persistence:{p:r=>r.name?node('r:wmi|'+low(r.type)+'|'+low(r.name),'autorun',r.name,'WMI '+(r.type||'')+': '+r.name):null},
  usb_devices:{p:r=>node('usb:'+low(r.serial||r.device),'usb',r.friendly_name||r.device||r.serial,(r.device||'')+' / '+(r.serial||'')),host:1},
  smb_shares:{p:r=>r.name?node('sh:'+low(r.name),'share',r.name,r.name+' -> '+(r.path||'')):null,host:1},
  group_members:{p:r=>r.group?node('g:'+low(r.group),'group',r.group,r.group):null,host:1},
  local_users:{p:r=>EU(r.name),host:1},
  user_profiles:{p:r=>EU(r.user)||EU(r.name),roles:{path:null},host:1},
  sessions:{p:r=>EU(r.user),host:1},
  dns_cache:{p:r=>ED(r.name)||ED(r.record),roles:{data:'ipdom'}},
  hosts_file:{p:r=>EI(r.address),x:(r,ref,p,c,t)=>String(r.names||'').split(/\s+/).forEach(n=>lk(p,ED(n),'hosts file entry',ref,t))},
  arp_cache:{p:r=>EI(r.address)},
  browser_history:{p:r=>EURL(r.url),roles:{url:null}},
  user_mru:{p:r=>{const ty=String(r.type||'');if(/^RDP/i.test(ty)){const v=String((/server/i.test(ty)?r.name:r.value)||'').replace(/:\d+$/,'').trim();return EI(v)||ED(v)||(v&&!/[\\\/\s]/.test(v)?node('d:'+low(v),'domain',v,v):null);}
   if(/mapped/i.test(ty))return EF(String(r.value||'').split(' as ')[0]);return EF(r.value);}},
  defender_threats:{p:r=>r.threat?node('av:'+low(r.threat),'threat',r.threat,r.threat):null,x:(r,ref,p,c,t)=>String(r.resources||'').split(/;\s*/).forEach(s=>{const m=/^[a-z]+:_?(.+)$/i.exec(s);if(m)lk(p,EF(m[1]),'detected',ref,t);})},
  srum_network_summary:{p:r=>app(r.app)},srum_network:{p:r=>app(r.app)},srum_app_usage:{p:r=>app(r.app)},
  jump_lists:{p:r=>EF(r.target),roles:{target:null}},
  recycle_bin:{p:r=>EF(r.original_path)}
 };
 const E=D.evidence||{};
 Object.keys(E).forEach(ds=>{if(GSKIP.has(ds))return;const tb=E[ds],cols=tb.columns||[],rows=tb.rows||[];if(!cols.length||!rows.length)return;const sp=SPEC[ds]||{},title=tb.title||ds;
  const roles=cols.map(c=>{const lc=c.toLowerCase();if(sp.roles&&lc in sp.roles)return sp.roles[lc];return GROLE[lc]||null;});
  const ctx={};if(sp.pre)sp.pre(rows,cols,ctx);
  rows.forEach((row,ri)=>{const r={};cols.forEach((c,i)=>r[c]=row[i]);const ref=[ds,ri],times=[];row.forEach(v=>{if(typeof v==='string'&&ISO.test(v))times.push(v);});
   const ents=[];cols.forEach((c,i)=>{const ro=roles[i],v=row[i];if(!ro||v==null||v==='')return;const fn=ROLE[ro];(SPLIT[ro]?String(v).split(/[,;\s]+/):[v]).forEach(pv=>{const n=fn(pv);if(n)ents.push([n,c]);});});
   let prim=sp.p?sp.p(r):null;if(!prim){const f=ents.find(x=>x[0].type==='file')||ents[0];if(f)prim=f[0];}
   if(!prim)return;touch(prim,ref,times);const seen=new Set([prim.id]);
   ents.forEach(x=>{if(seen.has(x[0].id))return;seen.add(x[0].id);lk(prim,x[0],title+': '+x[1],ref,times);});
   if(sp.host)link(host,prim,title,ref);if(sp.x)sp.x(r,ref,prim,ctx,times);});});
 const inc={};
 I.forEach(i=>{const n=node('I:'+i.id,'incident',i.id+' '+(i.title||''),i.title||i.id);n.sev=i.severity;n.ref=i.id;touch(n,null,[i.first_seen,i.last_seen].filter(Boolean));link(host,n,'incident');inc[i.id]=n;});
 F.forEach(f=>{const n=node('F:'+f.id,'finding',f.id+' '+(f.title||''),f.title||f.id);n.sev=f.severity;n.ref=f.id;const t=[f.first_seen,f.last_seen].filter(Boolean);touch(n,null,t);
  const att=(arr,fn,rel)=>[].concat(arr||[]).forEach(v=>{const m=fn(v);if(m){touch(m,null,t);link(n,m,rel);}});
  const txt=[f.title||''].concat(f.evidence||[]).map(String).join('\n');
  att(txt.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g),EI,'mentioned in finding');att(txt.match(/\b(?:https?|ftp):\/\/[^\s"'<>]+/gi),EURL,'mentioned in finding');
  att(txt.match(/[a-z]:\\[^"'<>|\r\n*?]+?\.(?:exe|dll|sys|scr|ps1|bat|cmd|vbs|js|hta|msi|lnk)\b/gi),EF,'mentioned in finding');
  att(f.users,EU,'account');att(f.ips,EI,'IP address');att(f.files,v=>EF(v)||EN(v),'file');att(f.processes,v=>EF(v)||EN(v),'process');att(f.hashes,EH,'hash');att(f.domains,v=>ED(v)||EI(v),'domain');
  if(f.technique)link(n,node('T:'+f.technique,'technique',f.technique,f.technique+' '+(f.technique_name||'')),'ATT&CK technique');
  if(f.incident&&inc[f.incident])link(inc[f.incident],n,'part of incident');else link(host,n,'finding');});
 const byLeaf={};nodes.forEach(n=>{if(n.id.startsWith('f:')){const l=low(gLeaf(n.full));(byLeaf[l]=byLeaf[l]||[]).push(n);}});
 [...nodes.values()].forEach(n=>{if(!n.id.startsWith('p:'))return;const c=byLeaf[n.id.slice(2)];if(!c||c.length!==1)return;const to=c[0];
  n.adj.forEach(e=>{const o=e.a===n?e.b:e.a;edges.delete(ek(n,o));o.adj.delete(n.id);if(o===to)return;link(to,o,null,null);const ne=to.adj.get(o.id);e.rels.forEach(x=>ne.rels.add(x));e.refs.forEach(x=>{if(ne.refs.length<20)ne.refs.push(x);});});
  to.refs=to.refs.concat(n.refs).slice(0,300);to.nref+=n.nref;if(n.t0&&(!to.t0||n.t0<to.t0))to.t0=n.t0;if(n.t1&&(!to.t1||n.t1>to.t1))to.t1=n.t1;nodes.delete(n.id);});
 nodes.forEach(n=>{if(n.type==='finding'||n.type==='incident'){n.hot=2;n.adj.forEach((e,id)=>{const o=nodes.get(id);if(o&&!o.hot)o.hot=1;});}});
 return {nodes:nodes,edges:edges};
}
const GV={vis:new Map(),sel:null,hov:null,drag:null,hide:new Set(),from:'',to:'',z:0.8,ox:0,oy:0,alpha:0,anim:0,layout:'lanes',root:'host',steps:1,seeded:false,autofit:false,dirty:true,need:true,VN:[],VE:[],NB:new Map(),heads:[],cv:null,stat:null,raf:0,q:'',mh:[]};
const GLANES=[['Host',['host']],['Incidents & findings',['incident','finding']],['Techniques & accounts',['technique','user','group']],['Processes & files',['file']],['Persistence & detections',['service','task','autorun','threat']],['Hashes, network & devices',['hash','ip','domain','usb','share']]];
const GTO={};Object.keys(GT).forEach((t,i)=>GTO[t]=i);
const gOrd=(a,b)=>(b.hot-a.hot)||(rank(b.sev)-rank(a.sev))||(b.nref-a.nref);
const gTyp=(a,b)=>GTO[a.n.type]-GTO[b.n.type];
function gTOk(n){if(!n.t0||(!GV.from&&!GV.to))return true;if(GV.from&&n.t1<GV.from+'T00:00:00Z')return false;if(GV.to&&n.t0>GV.to+'T23:59:59Z')return false;return true;}
const gShown=n=>!GV.hide.has(n.type)&&gTOk(n);
function gAll(n){return [...n.adj.keys()].map(id=>GM.nodes.get(id)).filter(Boolean).sort(gOrd);}
function gAdd(n,near){if(!n||GV.vis.has(n.id))return false;const b=(near&&GV.vis.get(near.id))||{x:0,y:0},a=Math.random()*6.2832,r=near?20:Math.random()*80;
 GV.vis.set(n.id,{n:n,x:b.x+Math.cos(a)*r,y:b.y+Math.sin(a)*r,tx:0,ty:0,vx:0,vy:0,pin:false,d:0,tp:null,k:0,bc:0});GV.dirty=true;return true;}
function gKick(){if(GV.layout==='force')GV.alpha=Math.max(GV.alpha,0.8);}
function gSeed(){GV.vis.clear();GV.sel=null;GV.root='host';const host=GM.nodes.get('host');gAdd(host,null);const fs=[];GM.nodes.forEach(n=>{if(n.type==='finding'||n.type==='incident')fs.push(n);});
 fs.forEach(n=>gAdd(n,host));fs.forEach(n=>n.adj.forEach((e,id)=>gAdd(GM.nodes.get(id),n)));
 if(!fs.length)gAll(host).slice(0,40).forEach(o=>gAdd(o,host));GV.alpha=1;GV.autofit=true;GV.dirty=true;}
function gExpand(n,steps,limit){limit=limit||40;let front=[n],added=0;for(let s=0;s<steps;s++){const next=[];front.forEach(m=>{let k=0;for(const o of gAll(m)){if(k>=limit||GV.vis.size>=3000)break;if(GV.vis.has(o.id)||!gShown(o))continue;gAdd(o,m);next.push(o);k++;}});added+=next.length;front=next;}
 gKick();if(added>25)GV.autofit=true;GV.dirty=true;}
function gFocus(n){const keep=new Set([n.id]);n.adj.forEach((e,id)=>{if(GV.vis.has(id))keep.add(id);});[...GV.vis.keys()].forEach(id=>{if(!keep.has(id))GV.vis.delete(id);});GV.root=n.id;gKick();GV.autofit=true;GV.dirty=true;}
function gRefresh(){const VN=[];GV.vis.forEach(v=>{v.d=0;if(gShown(v.n))VN.push(v);});const S=new Set(VN.map(v=>v.n.id)),VE=[];
 VN.forEach(v=>{const n=v.n;if(n.adj.size<=VN.length){n.adj.forEach((e,id)=>{if(n.id<id&&S.has(id))VE.push([v,GV.vis.get(id),e]);});}else VN.forEach(w=>{if(n.id<w.n.id){const e=n.adj.get(w.n.id);if(e)VE.push([v,w,e]);}});});
 const NB=new Map();VN.forEach(v=>NB.set(v,[]));VE.forEach(x=>{x[0].d++;x[1].d++;NB.get(x[0]).push(x[1]);NB.get(x[1]).push(x[0]);});
 GV.VN=VN;GV.VE=VE;GV.NB=NB;GV.dirty=false;GV.need=true;
 if(GV.layout!=='force'){if(GV.layout==='tree')gLayTree();else gLayLanes();GV.anim=1;if(GV.autofit){GV.autofit=false;gFit(true);}}
 if(GV.stat)GV.stat.textContent=VN.length+' entities, '+VE.length+' links on the graph  |  '+GM.nodes.size.toLocaleString()+' entities, '+GM.edges.size.toLocaleString()+' relations in the report';}
function gLayLanes(){const li={};GLANES.forEach((L,i)=>L[1].forEach(t=>li[t]=i));const lanes=GLANES.map(()=>[]);
 GV.VN.forEach(v=>lanes[li[v.n.type]!=null?li[v.n.type]:3].push(v));
 const idx=L=>L.forEach((v,i)=>v.k=L.length>1?i/(L.length-1):0.5);
 lanes.forEach(L=>{L.sort((a,b)=>gTyp(a,b)||gOrd(a.n,b.n));idx(L);});
 for(let p=0;p<4;p++)lanes.forEach(L=>{L.forEach(v=>{let s=0,c=0;(GV.NB.get(v)||[]).forEach(w=>{if(w.n.type!=='host'){s+=w.k;c++;}});v.bc=c?s/c:v.k;});L.sort((a,b)=>gTyp(a,b)||(a.bc-b.bc));idx(L);});
 const ROW=30,CW=270,GAP=130;let X=0;GV.heads=[];
 lanes.forEach((L,i)=>{if(!L.length)return;const n=L.length,rows=Math.max(1,Math.min(n,Math.max(24,Math.ceil(Math.sqrt(n*4))))),cols=Math.ceil(n/rows);
  L.forEach((v,j)=>{v.tx=X+Math.floor(j/rows)*CW;v.ty=(j%rows-(rows-1)/2)*ROW;});
  GV.heads.push({x:X,y:-(rows-1)/2*ROW-46,t:GLANES[i][0]+' ('+n+')'});X+=cols*CW+GAP;});
 const sh=Math.max(0,X-GAP-CW)/2;GV.VN.forEach(v=>{v.tx-=sh;v.tp=null;if(v.pin){v.tx=v.x;v.ty=v.y;}});GV.heads.forEach(hd=>hd.x-=sh);}
function gLayTree(){GV.heads=[];const N=GV.VN;if(!N.length)return;const inN=v=>v&&GV.NB.has(v);let r0=GV.vis.get(GV.root);if(!inN(r0))r0=GV.vis.get('host');if(!inN(r0))r0=N[0];
 const par=new Map([[r0,null]]),kids=new Map(),order=[r0];
 for(let i=0;i<order.length;i++){const v=order[i],k=[];(GV.NB.get(v)||[]).slice().sort((a,b)=>gTyp(a,b)||gOrd(a.n,b.n)).forEach(w=>{if(!par.has(w)){par.set(w,v);k.push(w);order.push(w);}});kids.set(v,k);}
 const DX=310,DY=28;let slot=0,maxd=0;
 const place=(v,d)=>{v.tp=par.get(v);v.tx=d*DX;if(d>maxd)maxd=d;const k=kids.get(v);if(!k.length)v.ty=(slot++)*DY;else{k.forEach(w=>place(w,d+1));v.ty=(k[0].ty+k[k.length-1].ty)/2;}};
 place(r0,0);const rest=N.filter(v=>!par.has(v));let ry=null;
 if(rest.length){slot+=2;ry=slot*DY-44;rest.sort((a,b)=>gTyp(a,b)||gOrd(a.n,b.n)).forEach(v=>{v.tp=null;v.tx=0;v.ty=(slot++)*DY;});}
 const sh=(slot-1)*DY/2;let y0=1e9;N.forEach(v=>{v.ty-=sh;if(v.ty<y0)y0=v.ty;if(v.pin){v.tx=v.x;v.ty=v.y;}});
 for(let d=0;d<=maxd;d++)GV.heads.push({x:d*DX,y:y0-46,t:d?'Step '+d:'Root: '+r0.n.label.slice(0,40)});
 if(ry!=null)GV.heads.push({x:0,y:ry-sh,t:'Not linked to the root ('+rest.length+')'});}
function gTick(){const N=GV.VN,al=GV.alpha,C=180,grid=new Map();
 N.forEach(v=>{const k=Math.floor(v.x/C)+','+Math.floor(v.y/C);let c=grid.get(k);if(!c)grid.set(k,c=[]);c.push(v);});
 N.forEach(v=>{const cx=Math.floor(v.x/C),cy=Math.floor(v.y/C);for(let i=-1;i<=1;i++)for(let j=-1;j<=1;j++){const c=grid.get((cx+i)+','+(cy+j));if(!c)continue;
  for(const w of c){if(w===v)continue;let dx=v.x-w.x,dy=v.y-w.y,d2=dx*dx+dy*dy;if(d2>C*C)continue;if(d2<1){dx=Math.random()-0.5;dy=Math.random()-0.5;d2=1;}const d=Math.sqrt(d2),f=Math.min(10,5000/d2)*al;v.vx+=dx/d*f;v.vy+=dy/d*f;}}});
 GV.VE.forEach(x=>{const a=x[0],b=x[1],dx=b.x-a.x,dy=b.y-a.y,d=Math.sqrt(dx*dx+dy*dy)||1,L=Math.min(320,70+14*Math.sqrt(Math.max(a.d,b.d))),f=(d-L)*0.04*al;a.vx+=dx/d*f;a.vy+=dy/d*f;b.vx-=dx/d*f;b.vy-=dy/d*f;});
 N.forEach(v=>{v.vx-=v.x*0.003*al;v.vy-=v.y*0.003*al;if(v.pin||v===GV.drag){v.vx=0;v.vy=0;return;}v.vx*=0.6;v.vy*=0.6;v.x+=Math.max(-30,Math.min(30,v.vx));v.y+=Math.max(-30,Math.min(30,v.vy));});
 GV.alpha*=0.98;if(GV.alpha<0.005)GV.alpha=0;}
function gR(v){const n=v.n,t=n.type;if(t==='host')return 14;if(t==='incident')return 12;if(t==='finding')return 7+rank(n.sev)*1.2;return GV.layout==='force'?6+Math.min(6,Math.log2(1+v.d)):7;}
function gColor(n){return (n.type==='finding'||n.type==='incident')?COL[n.sev||'info']:(GT[n.type]||GT.file)[0];}
function gDraw(){const cv=GV.cv;if(!cv)return;const W=cv.clientWidth,H=cv.clientHeight,dpr=window.devicePixelRatio||1;if(!W||!H)return;
 if(cv.width!==Math.round(W*dpr)||cv.height!==Math.round(H*dpr)){cv.width=Math.round(W*dpr);cv.height=Math.round(H*dpr);}
 const c=cv.getContext('2d'),z=GV.z,lay=GV.layout!=='force',tree=GV.layout==='tree';c.setTransform(dpr,0,0,dpr,0,0);c.fillStyle='#0a0e13';c.fillRect(0,0,W,H);c.translate(W/2+GV.ox,H/2+GV.oy);c.scale(z,z);
 const sel=GV.sel?GV.vis.get(GV.sel):null,nb=new Set();if(sel){nb.add(sel);(GV.NB.get(sel)||[]).forEach(w=>nb.add(w));}
 c.textBaseline='middle';c.textAlign='left';c.fillStyle='#6e7b8b';c.font='600 '+(12/Math.max(z,0.35))+'px Segoe UI,sans-serif';GV.heads.forEach(hd=>c.fillText(hd.t.toUpperCase(),hd.x-10,hd.y));
 GV.VE.forEach(x=>{const a=x[0],b=x[1],on=sel&&(a===sel||b===sel),te=tree&&(a.tp===b||b.tp===a),fx=a.n.type==='finding'?a:b.n.type==='finding'?b:null;
  let col=fx?hexA(gColor(fx.n),0.45):'#2f3b4a';if(tree&&!te)col='rgba(60,72,88,.22)';if(sel)col=on?'#4c8dff':'rgba(60,72,88,.18)';
  c.strokeStyle=col;c.lineWidth=(on?2:te?1.4:1)/z;c.beginPath();c.moveTo(a.x,a.y);
  if(lay){if(Math.abs(a.x-b.x)<2){const o=Math.min(120,30+Math.abs(a.y-b.y)*0.25);c.bezierCurveTo(a.x-o,a.y,b.x-o,b.y,b.x,b.y);}else{const mx=(a.x+b.x)/2;c.bezierCurveTo(mx,a.y,mx,b.y,b.x,b.y);}}else c.lineTo(b.x,b.y);c.stroke();});
 const fs=11.5/Math.max(z,0.35);
 GV.VN.forEach(v=>{const n=v.n,r=gR(v),col=gColor(n);c.globalAlpha=sel&&!nb.has(v)?0.22:1;c.beginPath();
  if(n.type==='host')c.rect(v.x-r,v.y-r,2*r,2*r);else if(n.type==='incident'){for(let i=0;i<6;i++){const a=Math.PI/3*i+Math.PI/6;c.lineTo(v.x+r*Math.cos(a),v.y+r*Math.sin(a));}c.closePath();}else c.arc(v.x,v.y,r,0,6.2832);
  c.fillStyle=n.type==='finding'?col:hexA(col,0.22);c.fill();c.strokeStyle=col;c.lineWidth=(v===sel?3:1.5)/z;c.stroke();
  if(v===sel){c.beginPath();c.arc(v.x,v.y,r+5,0,6.2832);c.strokeStyle='#fff';c.lineWidth=1.5/z;c.stroke();}
  if(r*z>=9){c.textAlign='center';c.fillStyle=n.type==='finding'?'#0a0e13':col;c.font='bold '+Math.max(6,r*0.75)+'px Segoe UI,sans-serif';c.fillText((GT[n.type]||GT.file)[1],v.x,v.y+0.5);}
  const showL=lay?(z>0.42||v===sel||v===GV.hov||n.hot===2||n.type==='host'||(sel&&nb.size<=60&&nb.has(v))):(z>1.05||(z>0.6&&v.d<=2)||v===sel||v===GV.hov||(sel&&nb.size<=60&&nb.has(v))||n.type==='host'||n.type==='incident'||(n.type==='finding'&&z>0.4));
  if(showL){const mx=lay?34:40,lab=n.label.length>mx?n.label.slice(0,mx-1)+'\u2026':n.label;c.font=(v===sel?'600 ':'')+fs+'px Segoe UI,sans-serif';c.fillStyle=v===sel||v===GV.hov?'#ffffff':'#b4c0cc';
   if(lay){c.textAlign='left';c.fillText(lab,v.x+r+6,v.y);}else{c.textAlign='center';c.fillText(lab,v.x,v.y+r+fs*0.9);}}});
 c.globalAlpha=1;}
function gHit(mx,my){const cv=GV.cv,x=(mx-cv.clientWidth/2-GV.ox)/GV.z,y=(my-cv.clientHeight/2-GV.oy)/GV.z;let best=null,bd=1e18;
 GV.VN.forEach(v=>{const r=gR(v)+5/GV.z,dx=v.x-x,dy=v.y-y,d=dx*dx+dy*dy;if(d<r*r&&d<bd){bd=d;best=v;}});
 if(!best&&GV.layout!=='force'&&GV.z>0.42){const fs=11.5/Math.max(GV.z,0.35);GV.VN.forEach(v=>{const r=gR(v);if(x>v.x+r&&x<v.x+r+6+Math.min(34,v.n.label.length)*fs*0.55&&Math.abs(y-v.y)<fs*0.7)best=v;});}
 return best;}
function gFit(useT){const N=GV.VN,cv=GV.cv;if(!N.length||!cv||!cv.clientWidth)return;let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
 N.forEach(v=>{const x=useT?v.tx:v.x,y=useT?v.ty:v.y;x0=Math.min(x0,x);y0=Math.min(y0,y);x1=Math.max(x1,x+(GV.layout!=='force'?190:0));y1=Math.max(y1,y);});GV.heads.forEach(hd=>{y0=Math.min(y0,hd.y);});
 const z=Math.max(0.06,Math.min(1.4,Math.min(cv.clientWidth/(x1-x0+120),cv.clientHeight/(y1-y0+100))));GV.z=z;GV.ox=-(x0+x1)/2*z;GV.oy=-(y0+y1)/2*z;GV.need=true;}
function gCenter(n){const v=GV.vis.get(n.id);if(v){const L=GV.layout!=='force';GV.ox=-(L?v.tx:v.x)*GV.z;GV.oy=-(L?v.ty:v.y)*GV.z;GV.need=true;}}
function gLoop(){if(!GV.cv||!GV.cv.isConnected){GV.raf=0;return;}if(GV.dirty)gRefresh();
 if(GV.layout==='force'){if(GV.alpha>0){gTick();GV.need=true;if(GV.autofit&&GV.alpha<0.12){GV.autofit=false;gFit();}}}
 else if(GV.anim){let mv=0;GV.VN.forEach(v=>{if(v===GV.drag)return;const dx=v.tx-v.x,dy=v.ty-v.y;if(Math.abs(dx)+Math.abs(dy)>0.6){v.x+=dx*0.2;v.y+=dy*0.2;mv=1;}else{v.x=v.tx;v.y=v.ty;}});GV.anim=mv;GV.need=true;}
 if(GV.need){GV.need=false;gDraw();}GV.raf=requestAnimationFrame(gLoop);}
function gWire(cv){let mode=null,sx=0,sy=0,moved=false,tgt=null,ct=0;const pos=e=>{const b=cv.getBoundingClientRect();return [e.clientX-b.left,e.clientY-b.top];};
 cv.addEventListener('pointerdown',e=>{const p=pos(e);tgt=gHit(p[0],p[1]);mode=tgt?'node':'pan';sx=e.clientX;sy=e.clientY;moved=false;cv.setPointerCapture(e.pointerId);if(tgt)GV.drag=tgt;});
 cv.addEventListener('pointermove',e=>{if(!mode){const p=pos(e),v=gHit(p[0],p[1]);if(v!==GV.hov){GV.hov=v;GV.need=true;cv.style.cursor=v?'pointer':'grab';cv.title=v?(GT[v.n.type]||GT.file)[2]+': '+v.n.full+'\nclick: details  |  double-click: expand':'';}return;}
  const dx=e.clientX-sx,dy=e.clientY-sy;if(!moved&&Math.abs(dx)+Math.abs(dy)<4)return;moved=true;sx=e.clientX;sy=e.clientY;
  if(mode==='pan'){GV.ox+=dx;GV.oy+=dy;}else{tgt.x+=dx/GV.z;tgt.y+=dy/GV.z;tgt.tx=tgt.x;tgt.ty=tgt.y;tgt.pin=true;gKick();}GV.need=true;});
 cv.addEventListener('pointerup',()=>{const m=mode;mode=null;GV.drag=null;if(moved)return;clearTimeout(ct);
  if(m==='node'&&tgt){const n=tgt.n;GV.sel=n.id;ct=setTimeout(()=>gOpen(n,true),260);}else GV.sel=null;GV.need=true;});
 cv.addEventListener('dblclick',e=>{clearTimeout(ct);const p=pos(e),v=gHit(p[0],p[1]);if(v){GV.sel=v.n.id;if(GV.layout==='tree'&&!GV.vis.get(GV.root))GV.root=v.n.id;gExpand(v.n,GV.steps);}});
 cv.addEventListener('wheel',e=>{e.preventDefault();const p=pos(e),mx=p[0]-cv.clientWidth/2,my=p[1]-cv.clientHeight/2,z=Math.max(0.06,Math.min(4,GV.z*Math.exp(-e.deltaY*0.0015)));
  GV.ox=mx-(mx-GV.ox)*z/GV.z;GV.oy=my-(my-GV.oy)*z/GV.z;GV.z=z;GV.need=true;},{passive:false});}
function gTerm(n){switch(n.type){case 'file':return gLeaf(n.full);case 'user':return n.full.split('\\').pop();case 'hash':return n.full;case 'finding':case 'incident':case 'technique':case 'host':return '';default:return n.label;}}
function gPick(n,near){if(GV.hide.has(n.type)){GV.hide.delete(n.type);GV.sel=n.id;gAdd(n,near);render();return;}gAdd(n,near);GV.sel=n.id;GV.dirty=true;gKick();}
function gSearch(q,box){box.textContent='';q=q.trim().toLowerCase();if(q.length<2)return;const out=[];
 for(const n of GM.nodes.values()){if(n.label.toLowerCase().indexOf(q)>=0||n.full.toLowerCase().indexOf(q)>=0){out.push(n);if(out.length>400)break;}}
 out.sort((x,y)=>((y.label.toLowerCase()===q)-(x.label.toLowerCase()===q))||gOrd(x,y));
 box.appendChild(h('div',{class:'muted small',text:out.length?(out.length>400?'400+':out.length)+' matching entities - click one to add it to the graph with its neighbours (click it on the graph for its details)':'No entity matches "'+q+'".'}));
 box.appendChild(h('div',null,out.slice(0,60).map(n=>h('a',{href:'#',class:'gchip'+(GV.vis.has(n.id)?' on':''),style:'border-left:3px solid '+gColor(n),title:(GT[n.type]||GT.file)[2]+': '+n.full,text:n.label.length>60?n.label.slice(0,59)+'\u2026':n.label,
  onclick:e=>{e.preventDefault();const added=!GV.vis.has(n.id);gPick(n,null);if(added)gExpand(n,1);gRefresh();gCenter(n);}}))));}
/* ---------- Entity details pop-up ---------- */
const GATTR={file:['signature','signer','sha256','sha1','publisher','product','version','size','created','modified','zone_id','host_url','referrer_url','first_run_approx','last_run_approx','last_run','run_count','focus_seconds','link_date','hidden','user'],
 service:['display_name','state','start_mode','account','command','image','service_dll','signature','signer','sha256'],task:['author','registered','enabled','hidden','run_as','run_level','triggers','command','image','signature','signer'],
 autorun:['category','location','command','image','user','signature','signer','modified'],user:['sid','enabled','last_logon','password_last_set','description','logon_type','source_ip','workstation','result','events'],
 ip:['mac','state','interface','names','remote_port','process','logon_type','client','source'],domain:['record','type','data','ttl','browser','title'],usb:['device','serial','friendly_name'],share:['path','description','special'],
 threat:['severity_id','detected','remediated','action_success','process','user','resources'],hash:['path','name','signer','publisher'],group:['group_sid','member','type']};
function gAttrs(n){const want=GATTR[n.type];if(!want)return [];const m=new Map();
 n.refs.forEach(r=>{const t=(D.evidence||{})[r[0]];if(!t)return;const row=t.rows[r[1]];if(!row)return;t.columns.forEach((c,i)=>{if(want.indexOf(c)<0)return;const v=row[i];if(v==null||v===''||typeof v==='object')return;const s=String(v);let e=m.get(c);if(!e)m.set(c,e=new Map());if(!e.has(s)&&e.size<4)e.set(s,t.title||r[0]);});});
 const out=[];want.forEach(c=>{const e=m.get(c);if(e)e.forEach((src,v)=>out.push([c,v,src]));});return out;}
function gTimeline(n,term){if(n.type==='finding')return T.filter(e=>(e.f||[]).indexOf(n.ref)>=0);
 if(n.type==='incident'){const ids=new Set(F.filter(f=>f.incident===n.ref).map(f=>f.id));return T.filter(e=>(e.f||[]).some(x=>ids.has(x)));}
 if(term&&term.length>2){const q=term.toLowerCase();return T.filter(e=>String(e.sum||'').toLowerCase().indexOf(q)>=0||String(e.u||'').toLowerCase().split('\\').pop()===q);}return [];}
function gLink(o,txt){return h('a',{href:'#',title:(GT[o.type]||GT.file)[2]+': '+o.full,text:txt||o.label,onclick:e=>{e.preventDefault();gOpen(o);}});}
function gRelFind(n){const direct=[],ind=new Map();
 n.adj.forEach((e,id)=>{const o=GM.nodes.get(id);if(!o)return;if(o.type==='finding')direct.push(o);
  else if(o.type!=='host'&&o.type!=='technique'&&o.type!=='incident'&&o.adj.size<600)o.adj.forEach((e2,id2)=>{const f=GM.nodes.get(id2);if(f&&f.type==='finding'&&f!==n){if(!ind.has(f))ind.set(f,[]);if(ind.get(f).length<3)ind.get(f).push(o);}});});
 direct.forEach(f=>ind.delete(f));
 if(!direct.length&&!ind.size)return h('p',{class:'muted small',text:'No finding involves this entity, directly or through one linked entity.'});
 const row=(f,via)=>h('div',{class:'trow'},sev(f.sev),' ',gLink(f),via?h('span',{class:'muted small'},'  via ',via.map((x,i)=>[i?', ':'',gLink(x)])):null);
 return h('div',null,direct.length?h('div',{class:'muted small',text:'Directly linked ('+direct.length+')'}):null,direct.sort(gOrd).map(f=>row(f)),
  ind.size?h('div',{class:'muted small',style:'margin-top:8px',text:'Through a linked entity ('+ind.size+')'}):null,[...ind.keys()].sort(gOrd).slice(0,30).map(f=>row(f,ind.get(f))));}
function gNbList(n,all){const grp={};all.forEach(o=>(grp[o.type]=grp[o.type]||[]).push(o));const box=h('div');
 Object.keys(GT).forEach(t=>{const L=grp[t];if(!L)return;box.appendChild(h('div',{style:'margin:4px 0'},h('span',{class:'muted small',style:'display:inline-block;min-width:170px',text:GT[t][2]+' ('+L.length+')'}),
  L.slice(0,60).map(o=>{const e=n.adj.get(o.id),rel=e&&e.rels.size?[...e.rels].slice(0,6).join('; '):'';return h('a',{href:'#',class:'gchip',style:'border-left:3px solid '+gColor(o),title:o.full+(rel?'\n'+rel:''),text:o.label.length>48?o.label.slice(0,47)+'\u2026':o.label,onclick:ev=>{ev.preventDefault();gOpen(o);}});}),
  L.length>60?h('span',{class:'muted small',text:' +'+(L.length-60)+' more (see Relationship tree)'}):null));});
 return all.length?box:h('p',{class:'muted small',text:'No linked entities.'});}
function gSum(n,B,all){const ds=[...new Set(n.refs.map(r=>r[0]))].map(d=>((D.evidence||{})[d]||{}).title||d);
 B.appendChild(h('div',{class:'grid g2'},h('div',null,h('h3',{text:'Overview'}),kv([['Type',(GT[n.type]||GT.file)[2]],['Value',h('span',{class:'mono',style:'word-break:break-all',text:n.full})],['First seen',ft(n.t0)],['Last seen',ft(n.t1)],['Linked entities',all.length.toLocaleString()],['Evidence rows',(n.nref||0).toLocaleString()],['Seen in',ds]])),
  h('div',null,h('h3',{text:'Findings'}),gRelFind(n))));
 if(n.type==='finding'&&FI[n.ref]){const f=FI[n.ref];B.appendChild(h('h3',{text:'Finding'}));B.appendChild(kv([['Rule',f.rule],['ATT&CK',(f.technique||'')+' '+(f.technique_name||'')],['Tactic',f.tactic],['Hits',f.hits],['First / last',ft(f.first_seen)+'  ->  '+ft(f.last_seen)],['Incident',f.incident],['Sources',f.sources]]));
  if(f.description)B.appendChild(h('p',{text:f.description}));[].concat(f.evidence||[]).slice(0,8).forEach(x=>B.appendChild(h('pre',{text:typeof x==='string'?x:JSON.stringify(x)})));
  if(f.recommendation)B.appendChild(h('p',{class:'muted small',text:'Recommendation: '+(typeof f.recommendation==='string'?f.recommendation:JSON.stringify(f.recommendation))}));}
 const at=gAttrs(n);if(at.length){B.appendChild(h('h3',{text:'Attributes from the evidence'}));
  B.appendChild(h('div',{class:'tablewrap',style:'max-height:none'},h('table',null,h('thead',null,h('tr',null,h('th',{text:'Attribute'}),h('th',{text:'Value'}),h('th',{text:'Source'}))),h('tbody',null,at.map(a=>h('tr',null,h('td',{class:'mono',text:a[0]}),h('td',null,cell(a[1])),h('td',{class:'muted small',text:a[2]})))))));}
 B.appendChild(h('h3',{text:'Linked entities'}));B.appendChild(gNbList(n,all));}
function gTreeNode(n,parent,path,open){const e=parent?parent.adj.get(n.id):null,rel=e&&e.rels.size?[...e.rels].slice(0,3).join('; '):'',cnt=n.adj.size-(parent?1:0);
 const li=h('li'),kb=h('ul',{style:'display:none'});let loaded=false;const car=h('span',{class:'car',text:cnt>0?'\u25b8':'\u00b7'});
 const load=()=>{loaded=true;const all=gAll(n).filter(o=>!path.has(o.id)),grp={};all.forEach(o=>(grp[o.type]=grp[o.type]||[]).push(o));const types=Object.keys(GT).filter(t=>grp[t]);
  types.forEach(t=>{const L=grp[t],g=h('li'),gk=h('ul',{style:'display:none'}),gc=h('span',{class:'car',text:'\u25b8'});let gl=false;
   const tog=()=>{if(!gl){gl=true;L.slice(0,150).forEach(o=>{const p2=new Set(path);p2.add(o.id);gk.appendChild(gTreeNode(o,n,p2,false));});if(L.length>150)gk.appendChild(h('li',{class:'muted small',text:'+'+(L.length-150)+' more - use Expand on graph or the Evidence tab'}));}
    const o=gk.style.display!=='none';gk.style.display=o?'none':'';gc.textContent=o?'\u25b8':'\u25be';};
   g.appendChild(h('div',{class:'trow',style:'cursor:pointer',onclick:tog},gc,h('i',{class:'gdot',style:'background:'+GT[t][0]}),h('b',{text:GT[t][2]}),h('span',{class:'muted small',text:' ('+L.length+')'})));g.appendChild(gk);kb.appendChild(g);
   if(L.length<=12||types.length===1)tog();});
  if(!types.length)kb.appendChild(h('li',{class:'muted small',text:'No further links.'}));};
 const toggle=()=>{if(cnt<=0)return;if(!loaded)load();const o=kb.style.display!=='none';kb.style.display=o?'none':'';car.textContent=o?'\u25b8':'\u25be';};
 car.addEventListener('click',toggle);
 li.appendChild(h('div',{class:'trow'},car,h('i',{class:'gdot',style:'background:'+gColor(n)}),n.type==='finding'?[sev(n.sev),' ']:null,parent?gLink(n):h('b',{text:n.label}),
  n.full!==n.label&&n.type!=='finding'?h('span',{class:'mono small muted',text:'  '+(n.full.length>110?n.full.slice(0,109)+'\u2026':n.full)}):null,
  rel?h('div',{class:'small',style:'margin-left:31px;color:#7d8fa3',text:rel}):null));
 li.appendChild(kb);if(open)toggle();return li;}
function gTreeTab(n,B){B.appendChild(h('p',{class:'muted small',text:'Everything linked to this entity, grouped by type. Open a branch to follow the links further (an entity already on the branch is not repeated). Click a name to open its details; the small line under it says where the link comes from (evidence table: column).'}));
 B.appendChild(h('ul',{class:'gtree'},gTreeNode(n,null,new Set([n.id]),true)));}
let GPT=null;
function gPT(){if(GPT)return GPT;GPT={rows:[],pid:new Map(),kids:new Map()};const t=(D.evidence||{}).processes;if(!t)return GPT;const C={};t.columns.forEach((c,i)=>C[c]=i);
 t.rows.forEach(r=>{const o={pid:r[C.pid],ppid:r[C.ppid],name:r[C.name],path:r[C.path],cmd:r[C.command_line],user:r[C.user],started:r[C.started],sig:r[C.signature],par:null};const p=nPath(o.path);o.key=p?p.k:null;GPT.rows.push(o);GPT.pid.set(o.pid,o);});
 GPT.rows.forEach(o=>{const p=GPT.pid.get(o.ppid);if(p&&p!==o&&(!p.started||!o.started||p.started<=o.started)){o.par=p;if(!GPT.kids.has(p))GPT.kids.set(p,[]);GPT.kids.get(p).push(o);}});return GPT;}
function gProcMatches(n){const P=gPT();if(!P.rows.length||n.type!=='file')return [];const k=n.id.startsWith('f:')?n.id.slice(2):null,nm=gLeaf(n.full).toLowerCase();return P.rows.filter(o=>k?o.key===k:String(o.name||'').toLowerCase()===nm);}
function gProcNode(o,mark,onPath,sub,d){const kids=gPT().kids.get(o)||[],inSub=sub||mark.has(o),li=h('li'),fn=o.key?GM.nodes.get('f:'+o.key):null;
 li.appendChild(h('div',{class:'trow'+(mark.has(o)?' hit':'')},h('i',{class:'gdot',style:'background:'+GT.file[0]}),fn?gLink(fn,o.name||fn.label):h('b',{text:o.name||'?'}),
  h('span',{class:'muted small',text:'  pid '+o.pid+(o.user?'  |  '+o.user:'')+(o.started?'  |  '+ft(o.started):'')+(o.sig?'  |  '+o.sig:'')}),
  o.cmd?h('div',{class:'mono small muted',style:'margin-left:16px;word-break:break-all',text:String(o.cmd).slice(0,700)}):null));
 const show=inSub?kids:kids.filter(k=>onPath.has(k)||mark.has(k));
 if(show.length&&d<14){const ul=h('ul');show.slice(0,80).forEach(k=>ul.appendChild(gProcNode(k,mark,onPath,inSub,d+1)));if(show.length>80)ul.appendChild(h('li',{class:'muted small',text:'+'+(show.length-80)+' more'}));li.appendChild(ul);}
 const hid=kids.length-show.length;if(hid>0)li.appendChild(h('div',{class:'muted small',style:'margin-left:22px',text:'('+hid+' other child process'+(hid>1?'es':'')+' of '+(o.name||'this process')+' not shown)'}));return li;}
function gProcTab(n,list,B){B.appendChild(h('p',{class:'muted small',text:'Process tree captured at collection time: the parent chain (PPID, checked against start times so a reused PID is not trusted) down to every running instance of this file, and everything those instances started. Highlighted lines are this entity.'}));
 const mark=new Set(list),onPath=new Set(),tops=[];list.forEach(o=>{let t=o,g=0;while(t.par&&g<20){onPath.add(t.par);t=t.par;g++;}if(tops.indexOf(t)<0)tops.push(t);});
 tops.slice(0,30).forEach(t=>B.appendChild(h('ul',{class:'gtree',style:'margin-bottom:12px'},gProcNode(t,mark,onPath,false,0))));}
function gEvTab(n,term,B){const byDs={};n.refs.forEach(r=>(byDs[r[0]]=byDs[r[0]]||[]).push(r[1]));const ks=Object.keys(byDs);
 if(!ks.length){B.appendChild(h('p',{class:'muted small',text:n.type==='finding'?'Findings carry their evidence in the Summary tab.':'No evidence row names this entity directly; it comes from a finding.'}));return;}
 if(n.nref>n.refs.length)B.appendChild(h('p',{class:'muted small',text:'Showing the first '+n.refs.length+' of '+n.nref.toLocaleString()+' rows. Open in Evidence shows them all.'}));
 ks.forEach(ds=>{const t=(D.evidence||{})[ds];if(!t)return;const idx=byDs[ds];
  B.appendChild(h('div',{style:'margin:6px 0 16px'},h('div',{class:'toolbar',style:'margin-bottom:4px'},h('b',{text:(t.title||ds)+' ('+idx.length+')'}),h('span',{class:'muted small',text:t.group||''}),
    h('button',{class:'btn small',text:'Open in Evidence',onclick:()=>{gClose();st.e={ds:ds,q:term||'',sort:-1,dir:1,page:0};go('evidence');}})),
   h('div',{class:'tablewrap',style:'max-height:340px'},h('table',null,h('thead',null,h('tr',null,t.columns.map(c=>h('th',{text:c})))),h('tbody',null,idx.slice(0,50).map(i=>h('tr',null,(t.rows[i]||[]).map(x=>h('td',null,cell(x))))))))));});}
function gTlTab(tl,term,B){if(!tl.length){B.appendChild(h('p',{class:'muted small',text:'No timeline entry mentions this entity.'}));return;}
 B.appendChild(h('div',{class:'toolbar'},h('span',{class:'muted small',text:tl.length+' entries'+(tl.length>200?' - first 200 shown':'')}),term?h('button',{class:'btn small',text:'Open in Timeline',onclick:()=>{gClose();st.t=tReset();st.t.q=term;go('timeline');}}):null));
 B.appendChild(h('div',{class:'tablewrap',style:'max-height:none'},h('table',null,h('thead',null,h('tr',null,['Time','Source','Event','User','Summary','Findings'].map(c=>h('th',{text:c})))),
  h('tbody',null,tl.slice(0,200).map(e=>h('tr',null,h('td',{class:'mono',style:'white-space:nowrap',text:ft(e.t)}),h('td',{text:e.src||''}),h('td',{text:e.ev||''}),h('td',{text:e.u||''}),h('td',null,cell(e.sum)),h('td',null,(e.f||[]).map(x=>[flink(x),' ']))))))));}
function gClose(){const m=document.getElementById('gmodal');if(m)m.remove();GV.mh=[];}
document.addEventListener('keydown',e=>{if(e.key==='Escape')gClose();});
function gOpen(n,fresh,tab){if(fresh)GV.mh=[];if(GV.mh[GV.mh.length-1]!==n)GV.mh.push(n);const old=document.getElementById('gmodal');if(old)old.remove();
 const col=gColor(n),ty=GT[n.type]||GT.file,term=gTerm(n),all=gAll(n),pl=gProcMatches(n),tl=gTimeline(n,term);
 const TB=[['sum','Summary'],['tree','Relationship tree ('+all.length+')'],pl.length?['proc','Process tree ('+pl.length+')']:null,['ev','Evidence ('+(n.nref||0).toLocaleString()+')'],['tl','Timeline ('+tl.length+')']].filter(Boolean);
 const body=h('div',{class:'gmbody'}),tabs=h('div',{class:'gmtabs'});
 const show=k=>{tabs.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.getAttribute('data-k')===k));body.textContent='';body.scrollTop=0;
  if(k==='tree')gTreeTab(n,body);else if(k==='proc')gProcTab(n,pl,body);else if(k==='ev')gEvTab(n,term,body);else if(k==='tl')gTlTab(tl,term,body);else gSum(n,body,all);};
 TB.forEach(t=>tabs.appendChild(h('button',{'data-k':t[0],text:t[1],onclick:()=>show(t[0])})));
 const acts=h('div',{class:'toolbar',style:'margin:10px 0 0'},
  GV.mh.length>1?h('button',{class:'btn',text:'\u2190 Back to '+GV.mh[GV.mh.length-2].label.slice(0,30),onclick:()=>{GV.mh.pop();gOpen(GV.mh.pop());}}):null,
  h('button',{class:'btn',text:'Show as tree on the graph',title:'Lay the graph out as a tree that starts from this entity',onclick:()=>{gClose();gPick(n,null);GV.root=n.id;GV.layout='tree';gExpand(n,Math.max(GV.steps,1));GV.autofit=true;GV.dirty=true;render();}}),
  h('button',{class:'btn',text:'Expand on the graph',onclick:()=>{gClose();gPick(n,null);gExpand(n,GV.steps);}}),
  h('button',{class:'btn',text:'Focus on the graph',title:'Keep only this entity and its linked entities on the graph',onclick:()=>{gClose();gPick(n,null);gExpand(n,1);gRefresh();gFocus(n);}}),
  n.type==='finding'?h('button',{class:'btn',text:'Open finding',onclick:()=>{gClose();openFinding(n.ref);}}):null,
  n.type==='incident'?h('button',{class:'btn',text:'Open incident',onclick:()=>{gClose();go('incidents');setTimeout(()=>{const el=document.getElementById('inc-'+n.ref);if(el)el.scrollIntoView({block:'start'});},0);}}):null,
  h('button',{class:'btn',text:'Copy value',onclick:ev=>{const b=ev.target;try{navigator.clipboard.writeText(n.full).then(()=>{b.textContent='Copied';});}catch(err){}}}));
 const m=h('div',{id:'gmodal',class:'gmodal-bg'},h('div',{class:'gmodal',role:'dialog'},
  h('div',{class:'gmhead'},h('div',{class:'toolbar',style:'margin:0;flex-wrap:nowrap'},h('span',{class:'tag',style:'border-color:'+col+';color:'+col,text:ty[2]}),n.sev?sev(n.sev):null,
    h('b',{style:'font-size:16px;word-break:break-all',text:n.label}),h('button',{class:'btn',style:'margin-left:auto',text:'Close (Esc)',onclick:gClose})),
   n.full!==n.label?h('div',{class:'mono small muted',style:'word-break:break-all;margin-top:6px',text:n.full}):null,acts,tabs),body));
 m.addEventListener('mousedown',e=>{if(e.target===m)gClose();});document.body.appendChild(m);show(tab&&TB.some(t=>t[0]===tab)?tab:'sum');}
function vGraph(){
 if(!GM){const w=h('div',{class:'card muted',text:'Building the entity graph from every evidence dataset\u2026'});setTimeout(()=>{try{GM=gBuild();}catch(err){w.textContent='The graph could not be built: '+err;return;}if(st.tab==='graph')render();},30);return w;}
 if(!GV.seeded){gSeed();GV.seeded=true;}
 const cnt={};GM.nodes.forEach(n=>cnt[n.type]=(cnt[n.type]||0)+1);
 const res=h('div',{class:'gres'});
 const qi=search(GV.q,'Search any entity: file, IP, domain, user, hash, service\u2026',v=>{GV.q=v;gSearch(v,res);});
 const d0=h('input',{type:'date',value:GV.from,title:'Show only entities seen on or after this day (undated entities stay visible)'}),d1=h('input',{type:'date',value:GV.to,title:'Show only entities seen on or before this day'});
 const setT=()=>{GV.from=d0.value;GV.to=d1.value;GV.dirty=true;};d0.addEventListener('change',setT);d1.addEventListener('change',setT);
 const png=()=>{const a=h('a',{href:GV.cv.toDataURL('image/png'),download:'ir-graph-'+(Y.hostname||'host')+'.png'});document.body.appendChild(a);a.click();a.remove();};
 const lay=sel([['lanes','Layout: columns by type'],['tree','Layout: tree from the selected entity'],['force','Layout: free (force)']],GV.layout,v=>{GV.layout=v;GV.heads=[];if(v==='tree')GV.root=GV.sel||GV.root||'host';if(v==='force')GV.alpha=1;GV.autofit=true;GV.dirty=true;});
 const tb=h('div',{class:'toolbar'},qi,lay,sel([['1','Expand: 1 step'],['2','Expand: 2 steps'],['3','Expand: 3 steps']],String(GV.steps),v=>{GV.steps=+v;}),
  h('span',{class:'muted small',text:'Seen'}),d0,h('span',{class:'muted small',text:'to'}),d1,
  h('button',{class:'btn',text:'Analysis window',onclick:()=>{d0.value=String(M.window_from||'').slice(0,10);d1.value=String(M.window_to||'').slice(0,10);setT();}}),
  h('button',{class:'btn',text:'All time',onclick:()=>{d0.value='';d1.value='';setT();}}));
 const tb2=h('div',{class:'toolbar'},
  h('button',{class:'btn',text:'Fit',onclick:()=>gFit(GV.layout!=='force')}),
  h('button',{class:'btn',text:'Tidy up',title:'Put dragged nodes back into the layout',onclick:()=>{GV.vis.forEach(v=>v.pin=false);GV.autofit=true;GV.dirty=true;gKick();}}),
  h('button',{class:'btn',text:'Reset',title:'Back to findings, incidents and their direct links',onclick:()=>gSeed()}),
  h('button',{class:'btn',text:'Clear',title:'Empty the graph, then add entities from the search',onclick:()=>{GV.vis.clear();GV.sel=null;GV.dirty=true;}}),
  h('button',{class:'btn',text:'Export PNG',onclick:png}));
 const filt=h('div',{class:'gf'},Object.keys(GT).filter(t=>cnt[t]).map(t=>{const cb=h('input',{type:'checkbox'});cb.checked=!GV.hide.has(t);
  cb.addEventListener('change',()=>{if(cb.checked)GV.hide.delete(t);else GV.hide.add(t);GV.dirty=true;});
  return h('label',{title:'Show or hide '+GT[t][2].toLowerCase()+' nodes'},cb,h('i',{style:'background:'+GT[t][0]}),GT[t][2]+' ('+cnt[t].toLocaleString()+')');}));
 const cv=h('canvas',{class:'gcanvas'});GV.cv=cv;GV.dirty=true;GV.need=true;gWire(cv);
 GV.stat=h('div',{class:'gstat'});
 if(GV.q)gSearch(GV.q,res);
 if(!GV.raf)GV.raf=requestAnimationFrame(gLoop);
 return h('div',null,h('div',{class:'card'},h('h2',{text:'Entity graph'}),h('p',{class:'muted small',text:'Every host, account, file, process, hash, IP, domain, service, task, autostart entry, USB device and share in the evidence tables, linked to the findings and incidents that mention them. Click an entity for its full details, relationship tree, process tree, evidence rows and timeline. Double-click to bring its neighbours onto the graph. A link means the two appear in the same evidence row or finding - context, not proof of causation.'}),tb,tb2,res,filt),
  h('div',{class:'card gwrap'},cv,GV.stat,h('div',{class:'ghelp',text:'click: details  |  double-click: expand  |  drag: move  |  wheel: zoom'})));}

const TABS=[['overview','Overview'],['incidents','Incidents',I.length],['findings','Findings',F.length],['timeline','Timeline',T.length],['graph','Graph'],['attack','MITRE ATT&CK'],['evidence','Evidence',Object.keys(D.evidence||{}).length],['recs','Recommendations'],['collection','Collection']];
const VIEWS={overview:vOverview,incidents:vIncidents,findings:vFindings,timeline:vTimeline,graph:vGraph,attack:vAttack,evidence:vEvidence,recs:vRecs,collection:vCollection};
const nav=document.getElementById('nav'),main=document.getElementById('main');
function go(tab){st.tab=tab;render();window.scrollTo(0,0);}
function render(){nav.textContent='';TABS.forEach(t=>nav.appendChild(h('button',{class:st.tab===t[0]?'on':null,onclick:()=>go(t[0])},t[1],t[2]!=null?h('span',{class:'n',text:String(t[2])}):null)));
 main.textContent='';let v;try{v=VIEWS[st.tab]();}catch(err){v=h('div',{class:'card',text:'This view failed to render: '+err});}main.appendChild(v);main.appendChild(h('div',{class:'note',text:'IR-Investigator '+(M.version||'')+' - heuristic triage. Every finding links to its evidence; confirm before acting. Raw artifacts in the case package are for validated forensic tools.'}));}
document.getElementById('h-title').textContent='IR report - '+(Y.hostname||'unknown host');
document.getElementById('h-sub').textContent=((D.verdict||{}).level||'')+'  |  collected '+ft(Y.collection_start)+'  |  '+(M.case||'');
document.title='IR report - '+(Y.hostname||'');
const tz=document.getElementById('tz');tz.addEventListener('change',()=>{TZ=tz.value;render();});
render();
})();
</script>
</body></html>
'@
}

#endregion

#region ===== Main =====

function Complete-IRPackage {
    $root = $Script:Case.Root
    $outside = Join-Path $Script:Case.OutputRoot "$($Script:Case.Name)_collection.log"
    Write-IRLog 'Packaging: collection.log is frozen here; later messages go to the log next to the archive.'
    try { Copy-Item -LiteralPath $Script:LogFile -Destination $outside -Force; $Script:LogFile = $outside } catch { }
    Repair-IRLongPaths $root
    $n = Write-IRManifest $root
    Write-IRLog "Manifest: $n files hashed (manifest.csv)" -NoConsole
    $arc = $null
    try { $arc = New-IRArchive $root } catch { Write-IRLog "Archive failed: $($_.Exception.Message)" 'ERROR' }
    if ($arc) {
        $hash = (Get-FileHash -LiteralPath $arc.path -Algorithm SHA256).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText("$($arc.path).sha256", "$hash  $(Split-Path -Leaf $arc.path)`r`n")
        Write-IRLog "Archive: $($arc.path) [$($arc.kind)] verified=$($arc.verified) sha256=$hash" 'OK' -Console "Archive: $($arc.path) [$($arc.kind)] verified=$($arc.verified)"
        if (-not $arc.verified) { Write-IRLog 'Archive verification failed - the case folder is kept.' 'WARN' }
        elseif (-not $KeepCaseFolder) {
            if (Remove-IRFolder $root) { Write-IRLog 'Case folder removed after verification (use -KeepCaseFolder to keep it).' }
            else { Write-IRLog "Could not remove the case folder $root" 'WARN' }
        }
    }
    if ($Archive -ne 'None' -and (-not $arc -or -not $arc.verified)) {
        Write-IRLog "The case folder is kept unarchived: $root" 'WARN'
        $Script:ExitCode = 3
    }
    return $arc
}

function Resolve-IRCaseInput([string]$Path) {
    if (-not $Path) { throw 'Analyze mode needs -CasePath <case folder or .zip>.' }
    if (-not (Test-Path -LiteralPath $Path)) { throw "CasePath not found: $Path" }
    $item = Get-Item -LiteralPath $Path
    $temp = $null
    if ($item.PSIsContainer) {
        $base = $item.FullName
    } elseif ($item.Extension -eq '.zip') {
        $temp = Join-Path ([IO.Path]::GetTempPath()) ('IRInv_' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        Write-IRLog "Extracting $($item.Name) to $temp"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($item.FullName, $temp)
        $base = $temp
    } elseif ($item.Extension -eq '.rar') {
        throw 'Extract the .rar first (WinRAR or 7-Zip with the case password), then pass the extracted folder as -CasePath.'
    } else { throw "Unsupported -CasePath: $Path (expected a case folder or .zip)" }
    $sys = Get-ChildItem -LiteralPath $base -Recurse -Filter 'system.json' -File -ErrorAction SilentlyContinue | Where-Object { $_.Directory.Name -eq 'live' } | Select-Object -First 1
    if (-not $sys) {
        if ($temp) { Remove-IRFolder $temp | Out-Null }
        throw "No IR-Investigator case found in $Path (live\system.json is missing)."
    }
    $root = $sys.Directory.Parent.FullName
    $report = if ($temp) { Join-Path $item.DirectoryName ($item.BaseName + '_IR-Report.html') } else { Join-Path $root 'report\IR-Report.html' }
    return @{ Root = $root; Temp = $temp; Report = $report }
}

function Show-IRSummary($Result, $Arc, [string]$CaseRoot) {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    if ($Result) {
        $v = $Result.Verdict
        $color = switch ($v.tone) { 'critical' { 'Red' } 'high' { 'Yellow' } 'medium' { 'Yellow' } default { 'Green' } }
        Write-Host ("  Verdict   : {0} (risk score {1}/100)" -f $v.level, $v.score) -ForegroundColor $color
        Write-Host ("  Findings  : {0}  (critical {1}, high {2}, medium {3}, low {4})  Incidents: {5}" -f $Result.Findings, $v.counts['critical'], $v.counts['high'], $v.counts['medium'], $v.counts['low'], $Result.Incidents)
        Write-Host "  Report    : $($Result.Report)" -ForegroundColor Cyan
    }
    if ($Arc) { Write-Host "  Archive   : $($Arc.path)" -ForegroundColor Cyan }
    elseif ($CaseRoot) { Write-Host "  Case      : $CaseRoot" -ForegroundColor Cyan }
    if ($Script:LogFile) { Write-Host "  Log       : $($Script:LogFile)" -ForegroundColor DarkGray }
    Write-Host ('=' * 78) -ForegroundColor DarkGray
}

function Get-IRResult($Output) {
    return @($Output | Where-Object { $_ -is [pscustomobject] -and $_.PSObject.Properties['Verdict'] }) | Select-Object -Last 1
}

$Script:ExitCode = 0
try {
    if ($Mode -eq 'Analyze') {
        $caseInput = Resolve-IRCaseInput $CasePath
        $res = $null
        try { $res = Get-IRResult (Invoke-IRAnalysis -Root $caseInput.Root -ReportPath $caseInput.Report) }
        finally { if ($caseInput.Temp) { Remove-IRFolder $caseInput.Temp | Out-Null } }
        Show-IRSummary $res $null $null
        if ($res -and -not $NoOpen) { Open-IRReport $res.Report }
    } else {
        Invoke-IRCollection
        $res = $null
        if ($Mode -eq 'All') {
            $rp = Join-Path $Script:Case.Report 'IR-Report.html'
            try {
                $res = Get-IRResult (Invoke-IRAnalysis -Root $Script:Case.Root -ReportPath $rp)
            } catch {
                Write-IRLog "Analysis failed: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber)) - the collected evidence is intact; run -Mode Analyze on the archive." 'ERROR'
                $Script:ExitCode = 2
            }
            if ($res) {
                $copy = Join-Path $Script:Case.OutputRoot "$($Script:Case.Name)_IR-Report.html"
                Copy-Item -LiteralPath $rp -Destination $copy -Force
                $res.Report = $copy
            }
        }
        $arc = Complete-IRPackage
        Show-IRSummary $res $arc $(if ($arc -and -not $KeepCaseFolder -and $arc.verified) { $null } else { $Script:Case.Root })
        if ($res -and -not $NoOpen) { Open-IRReport $res.Report }
    }
} catch {
    Write-Host "ERROR: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    if ($Script:LogFile) { Write-IRLog "Fatal: $($_.Exception.Message) $($_.ScriptStackTrace)" 'ERROR' }
    $Script:ExitCode = 1
} finally { Remove-IRShadow }
exit $Script:ExitCode

#endregion
