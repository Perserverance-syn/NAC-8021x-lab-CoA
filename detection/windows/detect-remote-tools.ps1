<#
.SYNOPSIS
    NAC posture check — detects unauthorized remote-access software on a Windows endpoint.

.DESCRIPTION
    Part of the posture-assessment pillar of the NAC lab. Scans the local machine for
    prohibited remote-access tools (AnyDesk, TeamViewer, RustDesk, etc.) across four
    independent surfaces so a tool can't hide by only renaming one of them:

        1. Running processes
        2. Installed services
        3. Installed programs (registry uninstall keys, 32- and 64-bit)
        4. Common install paths on disk

    On a violation it writes a structured JSON report and a human-readable log, and
    exits with code 1. A compliant machine exits 0. The exit code is what an
    enforcement layer (scheduled task -> CoA trigger) keys off of.

.NOTES
    Designed to run unprivileged where possible; some service/registry reads benefit
    from elevation. Detect-and-report by design — it never uninstalls anything.
    Remediation (forced uninstall) is a separate, deliberate Phase 3 step.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File detect-remote-tools.ps1
    powershell -ExecutionPolicy Bypass -File detect-remote-tools.ps1 -ReportPath C:\nac\report.json
#>

[CmdletBinding()]
param(
    [string]$ReportPath = "$env:ProgramData\nac-posture\report.json",
    [string]$LogPath    = "$env:ProgramData\nac-posture\posture.log"
)

# --- Blacklist -------------------------------------------------------------
# Keyed by friendly name. 'patterns' are matched (case-insensitive) against
# process names, service names/display names, installed-program names, and paths.
$Blacklist = @(
    @{ Name = "AnyDesk";        Patterns = @("anydesk") }
    @{ Name = "TeamViewer";     Patterns = @("teamviewer", "tv_w32", "tv_x64") }
    @{ Name = "RustDesk";       Patterns = @("rustdesk") }
    @{ Name = "Chrome Remote";  Patterns = @("remoting_host", "chrome remote desktop") }
    @{ Name = "UltraVNC";       Patterns = @("uvnc", "ultravnc", "winvnc") }
    @{ Name = "TightVNC";       Patterns = @("tvnserver", "tightvnc") }
    @{ Name = "RealVNC";        Patterns = @("vncserver", "realvnc") }
    @{ Name = "Splashtop";      Patterns = @("splashtop", "strwinclt") }
    @{ Name = "LogMeIn";        Patterns = @("logmein", "lmiguardiansvc") }
    @{ Name = "Supremo";        Patterns = @("supremo") }
    @{ Name = "Atera/AnyDesk";  Patterns = @("ateraagent") }
    @{ Name = "ConnectWise";    Patterns = @("connectwisecontrol", "screenconnect") }
)

# --- Helpers ---------------------------------------------------------------
function Write-PostureLog {
    param([string]$Message, [string]$Level = "INFO")
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $line
    try { Add-Content -Path $LogPath -Value $line -ErrorAction Stop } catch {}
}

function Test-Pattern {
    param([string]$Haystack, [string[]]$Patterns)
    if ([string]::IsNullOrWhiteSpace($Haystack)) { return $false }
    foreach ($p in $Patterns) {
        if ($Haystack.ToLower().Contains($p.ToLower())) { return $true }
    }
    return $false
}

# Ensure output directory exists
$reportDir = Split-Path -Parent $ReportPath
$logDir    = Split-Path -Parent $LogPath
foreach ($d in @($reportDir, $logDir)) {
    if ($d -and -not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

Write-PostureLog "Starting NAC posture scan on $env:COMPUTERNAME"

$findings = New-Object System.Collections.Generic.List[object]

# --- 1. Running processes --------------------------------------------------
try {
    $procs = Get-Process -ErrorAction SilentlyContinue
    foreach ($entry in $Blacklist) {
        foreach ($proc in $procs) {
            $path = $null
            try { $path = $proc.Path } catch {}
            if ((Test-Pattern $proc.ProcessName $entry.Patterns) -or (Test-Pattern $path $entry.Patterns)) {
                $findings.Add([pscustomobject]@{
                    Tool    = $entry.Name
                    Surface = "process"
                    Detail  = "PID $($proc.Id): $($proc.ProcessName)"
                    Path    = $path
                })
            }
        }
    }
} catch { Write-PostureLog "Process scan error: $_" "WARN" }

# --- 2. Services -----------------------------------------------------------
try {
    $services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
    foreach ($entry in $Blacklist) {
        foreach ($svc in $services) {
            if ((Test-Pattern $svc.Name $entry.Patterns) -or
                (Test-Pattern $svc.DisplayName $entry.Patterns) -or
                (Test-Pattern $svc.PathName $entry.Patterns)) {
                $findings.Add([pscustomobject]@{
                    Tool    = $entry.Name
                    Surface = "service"
                    Detail  = "$($svc.Name) ($($svc.State))"
                    Path    = $svc.PathName
                })
            }
        }
    }
} catch { Write-PostureLog "Service scan error: $_" "WARN" }

# --- 3. Installed programs (registry uninstall keys) -----------------------
$uninstallRoots = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
try {
    foreach ($root in $uninstallRoots) {
        $apps = Get-ItemProperty -Path $root -ErrorAction SilentlyContinue
        foreach ($entry in $Blacklist) {
            foreach ($app in $apps) {
                if (Test-Pattern $app.DisplayName $entry.Patterns) {
                    $findings.Add([pscustomobject]@{
                        Tool    = $entry.Name
                        Surface = "installed-program"
                        Detail  = "$($app.DisplayName) $($app.DisplayVersion)"
                        Path    = $app.InstallLocation
                    })
                }
            }
        }
    }
} catch { Write-PostureLog "Registry scan error: $_" "WARN" }

# --- 4. Common install paths on disk ---------------------------------------
$diskPaths = @(
    "$env:ProgramFiles", "${env:ProgramFiles(x86)}",
    "$env:LOCALAPPDATA", "$env:APPDATA"
)
try {
    foreach ($base in $diskPaths) {
        if (-not $base -or -not (Test-Path $base)) { continue }
        $dirs = Get-ChildItem -Path $base -Directory -ErrorAction SilentlyContinue
        foreach ($entry in $Blacklist) {
            foreach ($dir in $dirs) {
                if (Test-Pattern $dir.Name $entry.Patterns) {
                    $findings.Add([pscustomobject]@{
                        Tool    = $entry.Name
                        Surface = "disk-path"
                        Detail  = $dir.Name
                        Path    = $dir.FullName
                    })
                }
            }
        }
    }
} catch { Write-PostureLog "Disk scan error: $_" "WARN" }

# --- Report ----------------------------------------------------------------
$violations = $findings | Sort-Object Tool, Surface -Unique
$compliant  = ($violations.Count -eq 0)

$report = [pscustomobject]@{
    hostname   = $env:COMPUTERNAME
    user       = $env:USERNAME
    scanned_at = (Get-Date).ToString("o")
    compliant  = $compliant
    violations = $violations
}

try {
    $report | ConvertTo-Json -Depth 5 | Set-Content -Path $ReportPath -Encoding UTF8
    Write-PostureLog "Report written to $ReportPath"
} catch {
    Write-PostureLog "Failed to write report: $_" "ERROR"
}

if ($compliant) {
    Write-PostureLog "COMPLIANT — no prohibited remote-access tools found." "INFO"
    exit 0
} else {
    $names = ($violations | Select-Object -ExpandProperty Tool -Unique) -join ", "
    Write-PostureLog "NON-COMPLIANT — detected: $names" "ALERT"
    foreach ($v in $violations) {
        Write-PostureLog "  -> [$($v.Surface)] $($v.Tool): $($v.Detail)" "ALERT"
    }
    exit 1
}
