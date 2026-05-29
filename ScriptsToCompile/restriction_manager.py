"""
restriction_manager.py
Windows Restriction Manager  -  consolidated GUI for ACL, WDAC, firewall, and registry restrictions.
Requires Python 3.8+ and must be run as Administrator (the script will attempt to self-elevate).
Compiled with:
    pyinstaller --onefile --noconsole --uac-admin restriction_manager_gemini__vXX.py --add-data "FIREWALL_SUITE.dat;." --add-data "BROWSERGUARD_SYS.dat;." --add-data "ADAPTER_GUARD.dat;." --add-data "DNS_SUITE.dat;."
    (after running "python v2__encode_decode.py --encode" on the "BrowserGuard.sys" file, the "--onedir"-compiled
    "Firewall Suite" folder, the "--onedir"-compiled "adapter_guard_oneshot" folder, and the merged "--onedir"-compiled
    "dns_suite" folder to generate the .dat payload files)

v26 changes:
  • _task_toggle_row: dynamically grays out Start/Stop when NOT deployed.
  • Background monitor loop checks task toggle states every 2.5s and refreshes DNS Whitelist/Blacklist
    every 7.5s ONLY if the DNS suite is actively running.
  • Proxy Username field checks status live while typing (debounced 500ms).
  • Loading overlay applied to all extraction workers.
  • Canvas uses horizontal scrolling.
"""

import sys, os, subprocess, threading, tempfile, json, winreg, glob, re, shutil, hashlib, uuid, base64, time
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime
from pathlib import Path

# Suppress console/window pop-ups for all child processes on Windows
_CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0

# ─────────────────────────────────────────────────────────────────────────────
# SELF-ELEVATION
# ─────────────────────────────────────────────────────────────────────────────
def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def elevate():
    import ctypes
    params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit(0)

if not is_admin():
    elevate()

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS / DEFAULTS
# ─────────────────────────────────────────────────────────────────────────────
APP_DIR         = Path(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE      = APP_DIR / "restriction_state.json"
ACL_BACKUP_DIR  = Path(r"C:\NTFS_ACL_Backups")
ACL_BACKUP_GLOB = str(ACL_BACKUP_DIR / "acl_backup_multi_*.xml")

DEFAULT_BLOCKED_FILES = [
    "powershell.exe","powershell_ise.exe","bitsadmin.exe","certutil.exe",
    "cscript.exe","curl.exe","nslookup.exe","wsl.exe"
]

# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD DATA FILES — loaded from .dat files at runtime
# ─────────────────────────────────────────────────────────────────────────────
def _bundled_data_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return APP_DIR

def _has_dat(name: str) -> bool:
    return (_bundled_data_dir() / f"{name}.dat").is_file()

def _load_dat(name: str) -> bytes:
    path = _bundled_data_dir() / f"{name}.dat"
    if not path.is_file():
        raise FileNotFoundError(
            f"Payload file not found: {path}\n\n"
            f"Run  encode_decode.py --encode  to generate it, then either:\n"
            f"  • Place {name}.dat next to this script (for un-compiled use), or\n"
            f"  • Recompile with  --add-data \"{name}.dat;.\"  (for PyInstaller)."
        )
    return path.read_bytes()

BROWSERGUARD_DIR = Path(r"C:\BrowserGuard")

FIREWALL_SUITE_DIR  = Path(r"C:\Program Files\Restrictions\firewall_suite")
FIREWALL_TASK_NAME  = "Firewall Scheduler"
FIREWALL_SUITE_EXE  = FIREWALL_SUITE_DIR / "firewall_scheduler.exe"
FIREWALL_SHEET_EXE  = FIREWALL_SUITE_DIR / "timesheet_manager_firewall.exe"
FIREWALL_SHORTCUT   = Path(r"C:\Users\Public\Desktop\Timesheet Manager.lnk")

ADAPTER_GUARD_DIR           = Path(r"C:\Program Files\Restrictions\adapter_guard_oneshot")
ADAPTER_GUARD_TASK_NAME     = "AdapterGuard"
ADAPTER_GUARD_EXE           = ADAPTER_GUARD_DIR / "adapter_guard_oneshot.exe"
ADAPTER_GUARD_ALLOWED_FILE  = ADAPTER_GUARD_DIR / "ALLOWED_ADAPTERS.txt"
ADAPTER_GUARD_BACKUP_FILE   = ADAPTER_GUARD_DIR / "BACKUP_ALLOWED_ADAPTERS.txt"

DNS_SUITE_DIR               = Path(r"C:\Program Files\Restrictions\dns_suite")
DNS_TASK_NAME               = "DNS Server (Restrctions) (SYSTEM)"
DNS_SERVER_EXE              = DNS_SUITE_DIR / "dns_whitelist_blacklist_server.exe"
DNS_LOGGER_EXE              = DNS_SUITE_DIR / "dns_whitelist_logger.exe"
DNS_MERGE_EXE               = DNS_SUITE_DIR / "merge_whitelists.exe"
DNS_WHITELIST_FILE          = DNS_SUITE_DIR / "whitelisted_domains.json"
DNS_BLACKLIST_FILE          = DNS_SUITE_DIR / "blacklisted_domains.json"
DNS_CAPABLE_FILE            = DNS_SUITE_DIR / "DNS_CAPABLE_ADAPTERS.txt"
DNS_INCAPABLE_FILE          = DNS_SUITE_DIR / "DNS_INCAPABLE_ADAPTERS.txt"
DNS_UPSTREAM_FILE           = DNS_SUITE_DIR / "UPSTREAM_DNS.txt"
DNS_THRESHOLD_FILE          = DNS_SUITE_DIR / "THRESHOLD_DAYS.txt"
DNS_ACCESS_LOG_FILE         = DNS_SUITE_DIR / "domain_access_log.json"
DNS_DELETIONS_FILE          = DNS_SUITE_DIR / "domains_to_be_deleted.json"

DEFAULT_WDAC_POLICY   = "BlockRestrictedUser"
DEFAULT_WDAC_PUBLISHERS = ["Python Software Foundation"]
DEFAULT_WDAC_EXE_HASHES: list[str] = []

# ─────────────────────────────────────────────────────────────────────────────
# EMBEDDED POWERSHELL SCRIPTS
# ─────────────────────────────────────────────────────────────────────────────

PS_RESTRICT_ACL = r"""
param(
    [Parameter(Mandatory=$true)] [string]$FileNamesCSV,
    [Parameter(Mandatory=$true)] [string]$Username,
    [string]$Root = "C:\Windows"
)
[string[]]$FileNames = $FileNamesCSV -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Must be run as Administrator."; exit 1
}
$backupDir = "C:\NTFS_ACL_Backups"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
if ($Username -notmatch '\\') { $Username = "$env:COMPUTERNAME\$Username" }
Write-Output "Searching '$Root' for: $($FileNames -join ', ') ..."
try {
    $candidates = Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
                  Where-Object { $FileNames -contains $_.Name }
} catch { Write-Error "Search failed: $($_.Exception.Message)"; exit 1 }
if (-not $candidates -or $candidates.Count -eq 0) { Write-Output "No matching files found."; exit 0 }
$timestamp  = (Get-Date).ToString("yyyyMMdd_HHmmss")
$backupFile = Join-Path $backupDir "acl_backup_multi_$timestamp.xml"
$backupArray = @()
foreach ($f in $candidates) {
    try { $acl = Get-Acl -Path $f.FullName; $backupArray += [PSCustomObject]@{ Path=$f.FullName; Acl=$acl } }
    catch { Write-Error "Failed ACL read for $($f.FullName): $($_.Exception.Message). Aborting."; exit 1 }
}
try { $backupArray | Export-Clixml -Path $backupFile -Force; Write-Output "Backup: $backupFile" }
catch { Write-Error "Backup failed: $($_.Exception.Message). Aborting."; exit 1 }
$changed=@(); $denyRights=[System.Security.AccessControl.FileSystemRights]::FullControl
$inheritance=[System.Security.AccessControl.InheritanceFlags]::None
$propagation=[System.Security.AccessControl.PropagationFlags]::None
$accessType=[System.Security.AccessControl.AccessControlType]::Deny
foreach ($entry in $backupArray) {
    $path = $entry.Path
    try {
        Write-Output "Applying DENY to: $path"
        $acl = Get-Acl -Path $path
        $exists = $acl.Access | Where-Object {
            ($_.IdentityReference -eq $Username) -and ($_.AccessControlType -eq 'Deny') -and
            (($_.FileSystemRights -band $denyRights) -ne 0)
        }
        if ($exists) { Write-Output " - Already denied for $Username"; $changed += $path; continue }
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $Username,$denyRights,$inheritance,$propagation,$accessType)
        $acl.AddAccessRule($rule); Set-Acl -Path $path -AclObject $acl
        $verify = (Get-Acl -Path $path).Access | Where-Object { $_.IdentityReference -eq $Username -and $_.AccessControlType -eq 'Deny' }
        if (-not $verify) { throw "Verification failed." }
        Write-Output " - DENY applied."; $changed += $path
    } catch {
        Write-Warning "Failed on $path : $($_.Exception.Message)"
        Write-Warning "Rolling back..."
        foreach ($p in $changed) {
            try { $orig=$backupArray|Where-Object{$_.Path -eq $p}; if($orig){Set-Acl -Path $p -AclObject $orig.Acl; Write-Output " - Rolled back: $p"} }
            catch { Write-Warning " - Rollback failed: $p" }
        }
        Write-Error "Aborted. Backup at: $backupFile"; exit 1
    }
}
Write-Output "Done. Modified: $($changed.Count). Backup: $backupFile"
"""

PS_RESTORE_ACL = r"""
param([string]$BackupFile = "")
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Must be run as Administrator."; exit 1
}
$backupDir = "C:\NTFS_ACL_Backups"
if ([string]::IsNullOrWhiteSpace($BackupFile)) {
    $cand = Get-ChildItem -Path $backupDir -Filter "acl_backup_multi_*.xml" -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $cand) { Write-Error "No backup file found. Aborting."; exit 1 }
    $BackupFile = $cand.FullName; Write-Output "Using latest backup: $BackupFile"
} else {
    if (-not (Test-Path $BackupFile)) { Write-Error "Backup not found: $BackupFile"; exit 1 }
}
try {
    $items = Import-Clixml -Path $BackupFile
} catch {
    Write-Error "Import failed: $($_.Exception.Message)"
    exit 1
}
$restored = [System.Collections.Generic.List[string]]::new()
$errors   = [System.Collections.Generic.List[object]]::new()
foreach ($it in $items) {
    $path   = $it.Path
    $aclObj = $it.Acl
    try {
        if (Test-Path $path) {
            Set-Acl -Path $path -AclObject $aclObj
            Write-Output "Restored: $path"
            $restored.Add($path)
        } else {
            Write-Warning "Missing (skip): $path"
            $errors.Add([PSCustomObject]@{ Path=$path; Error="File not found" })
        }
    } catch {
        $msg = $_.Exception.Message
        Write-Warning "Failed: $path - $msg"
        $errors.Add([PSCustomObject]@{ Path=$path; Error=$msg })
    }
}
$rCount = $restored.Count
$eCount = $errors.Count
Write-Output ""
Write-Output "Restore complete. Restored: $rCount. Errors: $eCount."
if ($eCount -gt 0) { $errors | Format-Table -AutoSize }
Remove-Item $BackupFile -Force -ErrorAction SilentlyContinue
Write-Output "Backup removed: $(Split-Path $BackupFile -Leaf)"
"""

PS_WDAC_CREATE = r"""
#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory=$true)] [string]$PolicyName,
    [ValidateSet("Audit","Enforce")] [string]$Mode="Enforce",
    [string]$AllowExtraPathsCSV="",
    [string]$AllowExeHashesCSV="",
    [string]$AllowScriptHashesCSV="",
    [string]$AllowPublishersCSV="",
    [switch]$DisableScriptEnforcement,
    [switch]$Deploy,
    [string]$OutputDir="C:\WDACPolicy"
)
function Split-CSV([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return @() }
    return @($s -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
}
[string[]]$AllowExtraPaths   = Split-CSV $AllowExtraPathsCSV
[string[]]$AllowExeHashes    = Split-CSV $AllowExeHashesCSV
[string[]]$AllowScriptHashes = Split-CSV $AllowScriptHashesCSV
[string[]]$AllowPublishers   = Split-CSV $AllowPublishersCSV
Set-StrictMode -Off; $ErrorActionPreference="Stop"
$activeDir="C:\Windows\System32\CodeIntegrity\CiPolicies\Active"
$sidecarDir="C:\WDACPolicy"
$sidecarFile=Join-Path $sidecarDir ("policy_"+($PolicyName -replace '[^a-zA-Z0-9_\-]','_')+".txt")
function Get-SHA256([string]$Path) {
    if(-not(Test-Path $Path)){Write-Warning "Not found: $Path";return $null}
    return (Get-FileHash $Path -Algorithm SHA256).Hash
}
function Get-PolicyGuid([string]$name) {
    $md5=[System.Security.Cryptography.MD5]::Create()
    $b=[Text.Encoding]::UTF8.GetBytes($name.ToLower())
    return "{"+[guid]::new($md5.ComputeHash($b)).ToString().ToUpper()+"}"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$policyGuid=Get-PolicyGuid $PolicyName
$guidBare=$policyGuid.Trim("{").Trim("}")
$cipName="{$guidBare}.cip"
Write-Host "Policy: $PolicyName | Mode: $Mode | GUID: $policyGuid" -ForegroundColor Cyan

if(-not(Get-Command "ConvertFrom-CIPolicy" -ErrorAction SilentlyContinue)) {
    Write-Host "ConvertFrom-CIPolicy not found. Attempting to load/install ConfigCI..." -ForegroundColor Yellow
    $modPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\ConfigCI"
    if (Test-Path $modPath) {
        Import-Module $modPath -Force -ErrorAction SilentlyContinue
    }
    if (-not (Get-Command "ConvertFrom-CIPolicy" -ErrorAction SilentlyContinue)) {
        Write-Host "  Module not yet registered. Searching local servicing store..." -ForegroundColor Yellow
        $mums = @(Get-ChildItem "$env:SystemRoot\servicing\Packages" -Filter "*ConfigCI*.mum" -ErrorAction SilentlyContinue)
        if ($mums.Count -gt 0) {
            Write-Host "  Found $($mums.Count) ConfigCI package(s). Installing via DISM (local, offline)..." -ForegroundColor Yellow
            foreach ($mum in $mums) {
                Write-Host "    -> $($mum.Name)" -ForegroundColor Gray
                $dismOut = & "$env:SystemRoot\System32\dism.exe" /Online /NoRestart /Add-Package:"$($mum.FullName)" 2>&1
                if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 3010) {
                    Write-Host "    [OK] DISM exit $LASTEXITCODE" -ForegroundColor Green
                } else {
                    Write-Host "    DISM exit $LASTEXITCODE (may already be installed)" -ForegroundColor Yellow
                }
            }
            if (Test-Path $modPath) { Import-Module $modPath -Force -ErrorAction SilentlyContinue }
        } else {
            Write-Host "  No ConfigCI .mum packages found in $env:SystemRoot\servicing\Packages" -ForegroundColor Yellow
        }
    }
    if (-not (Get-Command "ConvertFrom-CIPolicy" -ErrorAction SilentlyContinue)) {
        Write-Error @"
ConfigCI module could not be loaded or installed automatically.
Tried:
  Module path : $modPath
  Servicing   : $env:SystemRoot\servicing\Packages\*ConfigCI*.mum
Most likely causes:
  - Windows 11 is older than 22H2 (update first, then retry).
  - The servicing package store is corrupt (run: sfc /scannow).
  - A reboot is pending from a previous DISM operation; reboot and retry.
"@
        exit 1
    }
    Write-Host "  [OK] ConfigCI module ready." -ForegroundColor Green
}

$fileRules=[Collections.Generic.List[string]]::new()
$fileRuleRefs=[Collections.Generic.List[string]]::new()
$extraSigners=[Collections.Generic.List[string]]::new()
$extraUMCI=[Collections.Generic.List[string]]::new()
$extraCi=[Collections.Generic.List[string]]::new()
$idx=1
$fileRules.Add('    <Allow ID="ID_ALLOW_PF86" FriendlyName="Allow PF86" FilePath="%OSDRIVE%\Program Files (x86)\*"/>')
$fileRules.Add('    <Allow ID="ID_ALLOW_PF"   FriendlyName="Allow PF"   FilePath="%OSDRIVE%\Program Files\*"/>')
$fileRuleRefs.Add('        <FileRuleRef RuleID="ID_ALLOW_PF86"/>')
$fileRuleRefs.Add('        <FileRuleRef RuleID="ID_ALLOW_PF"/>')
foreach($path in $AllowExtraPaths){
    $id="ID_ALLOW_P$idx";$e=$path -replace '"','&quot;'
    $fileRules.Add("    <Allow ID=`"$id`" FriendlyName=`"Allow $e`" FilePath=`"$e`"/>")
    $fileRuleRefs.Add("        <FileRuleRef RuleID=`"$id`"/>")
    Write-Host "  [+] Extra path: $path" -ForegroundColor Green;$idx++
}
foreach($fp in $AllowExeHashes){
    if(-not(Test-Path $fp)){Write-Warning "Not found, skipping: $fp";continue}
    $n=[IO.Path]::GetFileName($fp)
    Write-Host "  Extracting WDAC hashes for: $n ..." -ForegroundColor Yellow
    $tmpXml="$OutputDir\hash_tmp_$idx.xml"
    try {
        $rules=New-CIPolicyRule -Level Hash -DriverFilePath $fp -ErrorAction Stop
        New-CIPolicy -FilePath $tmpXml -Rules $rules -UserPEs -ErrorAction Stop
    } catch {Write-Warning "  Hash rule gen failed for: $fp - $_ -- skipping.";$idx++;continue}
    if(-not(Test-Path $tmpXml)){Write-Warning "  No XML for: $fp -- skipping.";$idx++;continue}
    [xml]$tmpDoc=Get-Content $tmpXml -Raw
    $allowNodes=$tmpDoc.SiPolicy.FileRules.ChildNodes|Where-Object{$_.LocalName -eq "Allow" -and $_.GetAttribute("Hash")}
    if(-not $allowNodes -or $allowNodes.Count -eq 0){Write-Warning "  No hash rules found for: $fp";Remove-Item $tmpXml -Force -ErrorAction SilentlyContinue;$idx++;continue}
    foreach($node in $allowNodes){
        $h=$node.GetAttribute("Hash");$fn=$node.GetAttribute("FriendlyName");$id="ID_ALLOW_HASH_P$idx"
        $fileRules.Add("    <Allow ID=`"$id`" FriendlyName=`"$fn`" Hash=`"$h`"/>")
        $fileRuleRefs.Add("        <FileRuleRef RuleID=`"$id`"/>")
        Write-Host "  [+] EXE hash: $fn" -ForegroundColor Green;$idx++
    }
    Remove-Item $tmpXml -Force -ErrorAction SilentlyContinue
}
foreach($fp in $AllowScriptHashes){
    $h=Get-SHA256 $fp;if(-not $h){$idx++;continue}
    $id="ID_ALLOW_SCPT_P$idx";$n=[IO.Path]::GetFileName($fp)
    $fileRules.Add("    <Allow ID=`"$id`" FriendlyName=`"Script: $n`" Hash=`"$h`"/>")
    $fileRuleRefs.Add("        <FileRuleRef RuleID=`"$id`"/>")
    Write-Host "  [+] Script hash: $n" -ForegroundColor Green;$idx++
}
foreach($cn in $AllowPublishers){
    Write-Host "  Searching for signed file from publisher: $cn ..." -ForegroundColor Yellow
    $searchPaths=@("$env:LOCALAPPDATA\Programs","$env:APPDATA","C:\Program Files","C:\Program Files (x86)","C:\Windows\System32")
    $matchedFile=$null
    :pubSearch foreach($sp in $searchPaths){
        if(-not(Test-Path $sp)){continue}
        $files=Get-ChildItem $sp -Recurse -Include "*.exe","*.dll" -ErrorAction SilentlyContinue
        foreach($f in $files){
            try{
                $sig=Get-AuthenticodeSignature $f.FullName -ErrorAction Stop
                if($sig.Status -eq "Valid" -and $sig.SignerCertificate -and $sig.SignerCertificate.Subject -match [regex]::Escape($cn)){
                    $matchedFile=$f.FullName;break pubSearch
                }
            }catch{}
        }
    }
    if(-not $matchedFile){Write-Warning "  No signed file found for '$cn' -- skipping.";continue}
    Write-Host "  Found: $matchedFile" -ForegroundColor Gray
    $tmpPubXml="$OutputDir\pub_tmp_$idx.xml"
    try{
        $rules=New-CIPolicyRule -Level Publisher -DriverFilePath $matchedFile -ErrorAction Stop
        New-CIPolicy -FilePath $tmpPubXml -Rules $rules -UserPEs -ErrorAction Stop
    }catch{Write-Warning "  Publisher rule gen failed for '$cn': $_ -- skipping.";$idx++;continue}
    if(-not(Test-Path $tmpPubXml)){Write-Warning "  No XML for publisher '$cn'";$idx++;continue}
    [xml]$tmpPubDoc=Get-Content $tmpPubXml -Raw
    $tmpSigners=$tmpPubDoc.SiPolicy.Signers.ChildNodes|Where-Object{$_.NodeType -eq "Element"}
    if(-not $tmpSigners -or @($tmpSigners).Count -eq 0){Write-Warning "  No signers for '$cn'";Remove-Item $tmpPubXml -Force -ErrorAction SilentlyContinue;$idx++;continue}
    foreach($sNode in $tmpSigners){
        $signerId="ID_SIGNER_PUB_P$idx";$signerName=$sNode.GetAttribute("Name");$innerXml=$sNode.InnerXml
        $extraSigners.Add("    <Signer ID=`"$signerId`" Name=`"$signerName`">$innerXml</Signer>")
        $extraUMCI.Add("          <AllowedSigner SignerId=`"$signerId`"/>")
        $extraCi.Add("    <CiSigner SignerId=`"$signerId`"/>")
        Write-Host "  [+] Publisher signer: $signerName" -ForegroundColor Green;$idx++
    }
    Remove-Item $tmpPubXml -Force -ErrorAction SilentlyContinue
}
Write-Host "Building XML..." -ForegroundColor Cyan
$auditLine   = if ($Mode -eq "Audit") { "    <Rule><Option>Enabled:Audit Mode</Option></Rule>" } else { "" }
$scriptLine  = if ($DisableScriptEnforcement) { "    <Rule><Option>Disabled:Script Enforcement</Option></Rule>" } else { "" }
$frB         = $fileRules    -join [System.Environment]::NewLine
$frrB        = $fileRuleRefs -join [System.Environment]::NewLine
$esB         = if ($extraSigners.Count) { $extraSigners -join [System.Environment]::NewLine } else { "" }
$euB         = if ($extraUMCI.Count)    { $extraUMCI    -join [System.Environment]::NewLine } else { "" }
$ecB         = if ($extraCi.Count)      { $extraCi      -join [System.Environment]::NewLine } else { "" }
$sb = [System.Text.StringBuilder]::new(65536)
[void]$sb.AppendLine('<?xml version="1.0" encoding="utf-8"?>')
[void]$sb.AppendLine('<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">')
[void]$sb.AppendLine('  <VersionEx>10.0.3.0</VersionEx>')
[void]$sb.AppendLine("  <PolicyID>$policyGuid</PolicyID>")
[void]$sb.AppendLine("  <BasePolicyID>$policyGuid</BasePolicyID>")
[void]$sb.AppendLine('  <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>')
[void]$sb.AppendLine('  <Rules>')
[void]$sb.AppendLine('    <Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule>')
[void]$sb.AppendLine('    <Rule><Option>Enabled:Advanced Boot Options Menu</Option></Rule>')
[void]$sb.AppendLine('    <Rule><Option>Enabled:UMCI</Option></Rule>')
[void]$sb.AppendLine('    <Rule><Option>Enabled:Inherit Default Policy</Option></Rule>')
[void]$sb.AppendLine('    <Rule><Option>Enabled:Update Policy No Reboot</Option></Rule>')
[void]$sb.AppendLine('    <Rule><Option>Enabled:Dynamic Code Security</Option></Rule>')
[void]$sb.AppendLine('    <Rule><Option>Enabled:Revoked Expired As Unsigned</Option></Rule>')
[void]$sb.AppendLine('    <Rule><Option>Enabled:Allow Supplemental Policies</Option></Rule>')
[void]$sb.AppendLine('    <Rule><Option>Disabled:Runtime FilePath Rule Protection</Option></Rule>')
if ($auditLine)  { [void]$sb.AppendLine($auditLine) }
if ($scriptLine) { [void]$sb.AppendLine($scriptLine) }
[void]$sb.AppendLine('  </Rules>')
[void]$sb.AppendLine('  <EKUs>')
[void]$sb.AppendLine('    <EKU ID="ID_EKU_WINDOWS"  Value="010A2B0601040182370A0306"/>')
[void]$sb.AppendLine('    <EKU ID="ID_EKU_WHQL"     Value="010A2B0601040182370A0305"/>')
[void]$sb.AppendLine('    <EKU ID="ID_EKU_ELAM"     Value="010A2B0601040182373D0401"/>')
[void]$sb.AppendLine('    <EKU ID="ID_EKU_HAL_EXT"  Value="010a2b0601040182373d0501"/>')
[void]$sb.AppendLine('    <EKU ID="ID_EKU_RT_EXT"   Value="010a2b0601040182370a0315"/>')
[void]$sb.AppendLine('    <EKU ID="ID_EKU_STORE"    Value="010a2b0601040182374c0301" FriendlyName="Windows Store EKU"/>')
[void]$sb.AppendLine('    <EKU ID="ID_EKU_DCODEGEN" Value="010A2B0601040182374C0501" FriendlyName="Dynamic Code Generation EKU"/>')
[void]$sb.AppendLine('    <EKU ID="ID_EKU_AM"       Value="010a2b0601040182374c0b01" FriendlyName="AntiMalware EKU"/>')
[void]$sb.AppendLine('  </EKUs>')
[void]$sb.AppendLine('  <FileRules>')
[void]$sb.AppendLine('    <FileAttrib ID="ID_FILEATTRIB_REFRESH_POLICY" FriendlyName="RefreshPolicy.exe FileAttribute" FileName="RefreshPolicy.exe" MinimumFileVersion="10.0.19042.0"/>')
if ($frB) { [void]$sb.AppendLine($frB) }
[void]$sb.AppendLine('  </FileRules>')
[void]$sb.AppendLine('  <Signers>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_WINDOWS_PRODUCTION"       Name="Microsoft Product Root 2010 Windows EKU"><CertRoot Type="Wellknown" Value="06"/><CertEKU ID="ID_EKU_WINDOWS"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_ELAM_PRODUCTION"          Name="Microsoft Product Root 2010 ELAM EKU"><CertRoot Type="Wellknown" Value="06"/><CertEKU ID="ID_EKU_ELAM"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_HAL_PRODUCTION"           Name="Microsoft Product Root 2010 HAL EKU"><CertRoot Type="Wellknown" Value="06"/><CertEKU ID="ID_EKU_HAL_EXT"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_WHQL_SHA2"                Name="Microsoft Product Root 2010 WHQL EKU"><CertRoot Type="Wellknown" Value="06"/><CertEKU ID="ID_EKU_WHQL"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_WHQL_SHA1"                Name="Microsoft Product Root WHQL EKU SHA1"><CertRoot Type="Wellknown" Value="05"/><CertEKU ID="ID_EKU_WHQL"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_WHQL_MD5"                 Name="Microsoft Product Root WHQL EKU MD5"><CertRoot Type="Wellknown" Value="04"/><CertEKU ID="ID_EKU_WHQL"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_WINDOWS_PRODUCTION_USER"  Name="Microsoft Product Root 2010 Windows EKU"><CertRoot Type="Wellknown" Value="06"/><CertEKU ID="ID_EKU_WINDOWS"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_ELAM_PRODUCTION_USER"     Name="Microsoft Product Root 2010 ELAM EKU"><CertRoot Type="Wellknown" Value="06"/><CertEKU ID="ID_EKU_ELAM"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_HAL_PRODUCTION_USER"      Name="Microsoft Product Root 2010 HAL EKU"><CertRoot Type="Wellknown" Value="06"/><CertEKU ID="ID_EKU_HAL_EXT"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_WHQL_SHA2_USER"           Name="Microsoft Product Root 2010 WHQL EKU"><CertRoot Type="Wellknown" Value="06"/><CertEKU ID="ID_EKU_WHQL"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_WHQL_SHA1_USER"           Name="Microsoft Product Root WHQL EKU SHA1"><CertRoot Type="Wellknown" Value="05"/><CertEKU ID="ID_EKU_WHQL"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_WINDOWS_FLIGHT_ROOT"      Name="Microsoft Flighting Root 2014 Windows EKU"><CertRoot Type="Wellknown" Value="0E"/><CertEKU ID="ID_EKU_WINDOWS"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_ELAM_FLIGHT"              Name="Microsoft Flighting Root 2014 ELAM EKU"><CertRoot Type="Wellknown" Value="0E"/><CertEKU ID="ID_EKU_ELAM"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_HAL_FLIGHT"               Name="Microsoft Flighting Root 2014 HAL EKU"><CertRoot Type="Wellknown" Value="0E"/><CertEKU ID="ID_EKU_HAL_EXT"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_WHQL_FLIGHT_SHA2"         Name="Microsoft Flighting Root 2014 WHQL EKU"><CertRoot Type="Wellknown" Value="0E"/><CertEKU ID="ID_EKU_WHQL"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_WINDOWS_FLIGHT_ROOT_USER" Name="Microsoft Flighting Root 2014 Windows EKU"><CertRoot Type="Wellknown" Value="0E"/><CertEKU ID="ID_EKU_WINDOWS"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_ELAM_FLIGHT_USER"         Name="Microsoft Flighting Root 2014 ELAM EKU"><CertRoot Type="Wellknown" Value="0E"/><CertEKU ID="ID_EKU_ELAM"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_HAL_FLIGHT_USER"          Name="Microsoft Flighting Root 2014 HAL EKU"><CertRoot Type="Wellknown" Value="0E"/><CertEKU ID="ID_EKU_HAL_EXT"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_WHQL_FLIGHT_SHA2_USER"    Name="Microsoft Flighting Root 2014 WHQL EKU"><CertRoot Type="Wellknown" Value="0E"/><CertEKU ID="ID_EKU_WHQL"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_WHQL_MD5_USER"            Name="Microsoft Product Root WHQL EKU MD5"><CertRoot Type="Wellknown" Value="04"/><CertEKU ID="ID_EKU_WHQL"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_STORE"                    Name="Microsoft MarketPlace PCA 2011"><CertRoot Type="TBS" Value="FC9EDE3DCCA09186B2D3BF9B738A2050CB1A554DA2DCADB55F3F72EE17721378"/><CertEKU ID="ID_EKU_STORE"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_STORE_FLIGHT_ROOT"        Name="Microsoft Flighting Root 2014 Store EKU"><CertRoot Type="Wellknown" Value="0E"/><CertEKU ID="ID_EKU_STORE"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_RT_PRODUCTION"            Name="Microsoft Product Root 2010 RT EKU"><CertRoot Type="Wellknown" Value="06"/><CertEKU ID="ID_EKU_RT_EXT"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_RT_FLIGHT"                Name="Microsoft Flighting Root 2014 RT EKU"><CertRoot Type="Wellknown" Value="0E"/><CertEKU ID="ID_EKU_RT_EXT"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_RT_STANDARD"              Name="Microsoft Standard Root 2011 RT EKU"><CertRoot Type="Wellknown" Value="07"/><CertEKU ID="ID_EKU_RT_EXT"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_TEST2010"                 Name="MincryptKnownRootMicrosoftTestRoot2010"><CertRoot Type="Wellknown" Value="0A"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_TEST2010_USER"            Name="MincryptKnownRootMicrosoftTestRoot2010"><CertRoot Type="Wellknown" Value="0A"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_DRM"                      Name="MincryptKnownRootMicrosoftDMDRoot2005"><CertRoot Type="Wellknown" Value="0C"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_DCODEGEN"                 Name="MincryptKnownRootMicrosoftProductRoot2010"><CertRoot Type="Wellknown" Value="06"/><CertEKU ID="ID_EKU_DCODEGEN"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_AM"                       Name="MincryptKnownRootMicrosoftStandardRoot2011"><CertRoot Type="Wellknown" Value="07"/><CertEKU ID="ID_EKU_AM"/></Signer>')
[void]$sb.AppendLine('    <Signer ID="ID_SIGNER_MICROSOFT_REFRESH_POLICY" Name="Microsoft Code Signing PCA 2011"><CertRoot Type="TBS" Value="F6F717A43AD9ABDDC8CEFDDE1C505462535E7D1307E630F9544A2D14FE8BF26E"/><CertPublisher Value="Microsoft Corporation"/><FileAttribRef RuleID="ID_FILEATTRIB_REFRESH_POLICY"/></Signer>')
if ($esB) { [void]$sb.AppendLine($esB) }
[void]$sb.AppendLine('  </Signers>')
[void]$sb.AppendLine('  <SigningScenarios>')
[void]$sb.AppendLine('    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_KMCI" FriendlyName="Kernel Mode">')
[void]$sb.AppendLine('      <ProductSigners><AllowedSigners>')
[void]$sb.AppendLine('        <AllowedSigner SignerId="ID_SIGNER_WINDOWS_PRODUCTION"/>')
[void]$sb.AppendLine('        <AllowedSigner SignerId="ID_SIGNER_ELAM_PRODUCTION"/>')
[void]$sb.AppendLine('        <AllowedSigner SignerId="ID_SIGNER_HAL_PRODUCTION"/>')
[void]$sb.AppendLine('        <AllowedSigner SignerId="ID_SIGNER_WHQL_SHA2"/>')
[void]$sb.AppendLine('        <AllowedSigner SignerId="ID_SIGNER_WHQL_SHA1"/>')
[void]$sb.AppendLine('        <AllowedSigner SignerId="ID_SIGNER_WHQL_MD5"/>')
[void]$sb.AppendLine('        <AllowedSigner SignerId="ID_SIGNER_WINDOWS_FLIGHT_ROOT"/>')
[void]$sb.AppendLine('        <AllowedSigner SignerId="ID_SIGNER_ELAM_FLIGHT"/>')
[void]$sb.AppendLine('        <AllowedSigner SignerId="ID_SIGNER_HAL_FLIGHT"/>')
[void]$sb.AppendLine('        <AllowedSigner SignerId="ID_SIGNER_WHQL_FLIGHT_SHA2"/>')
[void]$sb.AppendLine('        <AllowedSigner SignerId="ID_SIGNER_TEST2010"/>')
[void]$sb.AppendLine('      </AllowedSigners></ProductSigners>')
[void]$sb.AppendLine('    </SigningScenario>')
[void]$sb.AppendLine('    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_UMCI" FriendlyName="User Mode">')
[void]$sb.AppendLine('      <ProductSigners>')
[void]$sb.AppendLine('        <AllowedSigners>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_WINDOWS_PRODUCTION_USER"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_ELAM_PRODUCTION_USER"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_HAL_PRODUCTION_USER"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_WHQL_SHA2_USER"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_WHQL_SHA1_USER"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_WHQL_MD5_USER"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_WINDOWS_FLIGHT_ROOT_USER"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_ELAM_FLIGHT_USER"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_HAL_FLIGHT_USER"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_WHQL_FLIGHT_SHA2_USER"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_STORE"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_STORE_FLIGHT_ROOT"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_RT_PRODUCTION"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_DRM"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_DCODEGEN"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_AM"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_RT_FLIGHT"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_RT_STANDARD"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_MICROSOFT_REFRESH_POLICY"/>')
[void]$sb.AppendLine('          <AllowedSigner SignerId="ID_SIGNER_TEST2010_USER"/>')
if ($euB) { [void]$sb.AppendLine($euB) }
[void]$sb.AppendLine('        </AllowedSigners>')
[void]$sb.AppendLine('        <FileRulesRef>')
if ($frrB) { [void]$sb.AppendLine($frrB) }
[void]$sb.AppendLine('        </FileRulesRef>')
[void]$sb.AppendLine('      </ProductSigners>')
[void]$sb.AppendLine('    </SigningScenario>')
[void]$sb.AppendLine('  </SigningScenarios>')
[void]$sb.AppendLine('  <UpdatePolicySigners/>')
[void]$sb.AppendLine('  <CiSigners>')
[void]$sb.AppendLine('    <CiSigner SignerId="ID_SIGNER_STORE"/>')
[void]$sb.AppendLine('    <CiSigner SignerId="ID_SIGNER_MICROSOFT_REFRESH_POLICY"/>')
if ($ecB) { [void]$sb.AppendLine($ecB) }
[void]$sb.AppendLine('  </CiSigners>')
[void]$sb.AppendLine('  <HvciOptions>0</HvciOptions>')
[void]$sb.AppendLine('  <Settings>')
[void]$sb.AppendLine("    <Setting Provider=`"PolicyInfo`" Key=`"Information`" ValueName=`"Name`"><Value><String>$PolicyName</String></Value></Setting>")
[void]$sb.AppendLine("    <Setting Provider=`"PolicyInfo`" Key=`"Information`" ValueName=`"Id`"><Value><String>$guidBare</String></Value></Setting>")
[void]$sb.AppendLine('  </Settings>')
[void]$sb.AppendLine('</SiPolicy>')
$safe    = $PolicyName -replace '[^a-zA-Z0-9_\-]','_'
$xmlPath = "$OutputDir\${safe}_${Mode}.xml"
$cipPath = "$OutputDir\$cipName"
[System.IO.File]::WriteAllText($xmlPath, $sb.ToString(), [System.Text.Encoding]::UTF8)
Write-Host "  [OK] XML: $xmlPath" -ForegroundColor Green
Write-Host "  Compiling .cip ..." -ForegroundColor Yellow
try { ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cipPath -ErrorAction Stop }
catch { Write-Error "ConvertFrom-CIPolicy failed: $_"; exit 1 }
if(-not(Test-Path $cipPath)){ Write-Error "No .cip produced at: $cipPath"; exit 1 }
Write-Host "  [OK] CIP: $cipPath" -ForegroundColor Green
if($Deploy){
    if(-not(Test-Path $activeDir)){New-Item -ItemType Directory -Path $activeDir -Force|Out-Null}
    Get-ChildItem $activeDir -Filter "*.cip" -ErrorAction SilentlyContinue |
        Where-Object{$_.Name -like "*$guidBare*"} | Remove-Item -Force
    $dest=Join-Path $activeDir $cipName; Copy-Item $cipPath $dest -Force
    Write-Host "  [OK] Deployed: $dest" -ForegroundColor Green
    New-Item -ItemType Directory -Path $sidecarDir -Force | Out-Null
    $guidBare | Set-Content $sidecarFile -Encoding UTF8
    Write-Host "  [OK] GUID sidecar: $sidecarFile" -ForegroundColor Green
    Write-Host "REBOOT required to activate $Mode mode." -ForegroundColor $(if($Mode -eq 'Enforce'){'Red'}else{'Yellow'})
} else {
    Write-Host "Files in $OutputDir (use -Deploy to activate)." -ForegroundColor Green
}
"""

PS_WDAC_UNDO = r"""
param([Parameter(Mandatory=$true)] [string]$PolicyName)
$activeDir  = "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"
$sidecarDir = "C:\WDACPolicy"
$sidecarFile = Join-Path $sidecarDir ("policy_"+($PolicyName -replace '[^a-zA-Z0-9_\-]','_')+".txt")

$md5      = [System.Security.Cryptography.MD5]::Create()
$b        = [Text.Encoding]::UTF8.GetBytes($PolicyName.ToLower())
$guidBare = [guid]::new($md5.ComputeHash($b)).ToString().ToUpper()
$guidFull = "{$guidBare}"
$cipName  = "$guidFull.cip"
$cipPath  = Join-Path $activeDir $cipName

Write-Host "Target policy GUID: $guidFull" -ForegroundColor Cyan

function Remove-CipFile([string]$path, [string]$guid) {
    if (-not (Test-Path $path)) {
        Write-Host "  .cip not present in Active dir (already removed or never deployed)." -ForegroundColor Yellow
        return $true
    }
    $ciTool = "$env:SystemRoot\System32\CiTool.exe"
    if (Test-Path $ciTool) {
        Write-Host "  Trying CiTool.exe --remove-policy $guid ..." -ForegroundColor Yellow
        $out = & $ciTool --remove-policy $guid 2>&1
        Write-Host "  CiTool output: $out" -ForegroundColor Gray
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] CiTool removed the policy." -ForegroundColor Green
            return $true
        }
        Write-Host "  CiTool exit $LASTEXITCODE — falling back to takeown method." -ForegroundColor Yellow
    } else {
        Write-Host "  CiTool.exe not found — using takeown method." -ForegroundColor Yellow
    }
    Write-Host "  Taking ownership of: $(Split-Path $path -Leaf)" -ForegroundColor Yellow
    $null = & takeown.exe /f "$path" /A 2>&1
    $null = & icacls.exe "$path" /grant "Administrators:F" 2>&1
    try {
        Remove-Item $path -Force -ErrorAction Stop
        Write-Host "  [OK] Removed via takeown/icacls." -ForegroundColor Green
        return $true
    } catch {
        Write-Warning "  Remove-Item failed: $_"
        return $false
    }
}

$ok = Remove-CipFile $cipPath $guidBare
if ($ok) {
    Write-Host "Removed policy '$PolicyName'. Reboot to deactivate." -ForegroundColor Green
} else {
    Write-Warning "Could not remove '$cipName' from Active directory."
    Write-Warning "You may need to reboot into WinRE and delete it manually."
}

$outCip = Join-Path "C:\WDACPolicy" $cipName
if (Test-Path $outCip) {
    Remove-Item $outCip -Force -ErrorAction SilentlyContinue
    Write-Host "  Removed build CIP: $cipName" -ForegroundColor Gray
}
if (Test-Path $sidecarFile) {
    Remove-Item $sidecarFile -Force -ErrorAction SilentlyContinue
    Write-Host "  Removed sidecar: $(Split-Path $sidecarFile -Leaf)" -ForegroundColor Gray
}
"""

PS_BLOCK_STORE = r"""
Write-Host "Blocking Microsoft Store..." -ForegroundColor Yellow
$service=Get-Service -Name InstallService -ErrorAction SilentlyContinue
if($service){ Stop-Service InstallService -Force -ErrorAction SilentlyContinue; Set-Service InstallService -StartupType Disabled }
Get-NetFirewallRule -DisplayName "Block Microsoft Store" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "Block Microsoft Store" -Direction Outbound -Action Block -Profile Any -PackageFamilyName "Microsoft.WindowsStore_8wekyb3d8bbwe"
Write-Host "Microsoft Store is now blocked." -ForegroundColor Green
"""

PS_UNBLOCK_STORE = r"""
Write-Host "Unblocking Microsoft Store..." -ForegroundColor Yellow
Set-Service InstallService -StartupType Manual -ErrorAction SilentlyContinue
Start-Service InstallService -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayName "Block Microsoft Store" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host "Microsoft Store is now unblocked." -ForegroundColor Green
"""

PS_PROXY_LOCK = r"""
param([Parameter(Mandatory=$true)] [string]$Username)
#Requires -RunAsAdministrator

try {
    $sid = (New-Object System.Security.Principal.NTAccount($Username)).Translate(
               [System.Security.Principal.SecurityIdentifier]).Value
} catch {
    Write-Error "Could not resolve a SID for '$Username'. Check the username and try again. $_"
    exit 1
}
Write-Host "User : $Username" -ForegroundColor Cyan
Write-Host "SID  : $sid"      -ForegroundColor Cyan

$adminList = (& net localgroup Administrators 2>&1) -join "`n"
$inAdmins = $false
$pastLine = $false
foreach ($rawLine in ($adminList -split "`n")) {
    if ($rawLine -match '^-+') { $pastLine = $true; continue }
    if ($pastLine) {
        $trimmed = $rawLine.Trim()
        if ([string]::IsNullOrEmpty($trimmed) -or $trimmed -match '^The command') { break }
        $leafName = ($trimmed -split '\\')[-1]
        if ($leafName -ieq $Username) { $inAdmins = $true; break }
    }
}
if ($inAdmins) {
    Write-Error ("'$Username' is a member of the local Administrators group. " +
                 "Proxy lock must ONLY be applied to non-admin accounts.")
    exit 1
}
Write-Host "  [OK] '$Username' is not an administrator." -ForegroundColor Green

$regSubPath = "$sid\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$hivePath   = "HKU\$sid"
$hiveTest   = "Registry::HKEY_USERS\$sid"
$wasLoaded  = Test-Path $hiveTest -ErrorAction SilentlyContinue

if (-not $wasLoaded) {
    Write-Host "  Hive not currently loaded. Attempting to load from profile..." -ForegroundColor Yellow
    $profileEntry = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    if (-not (Test-Path $profileEntry)) {
        Write-Error ("No profile entry found for SID '$sid'. " +
                     "Has this user logged into this machine at least once?")
        exit 1
    }
    $profilePath = (Get-ItemProperty $profileEntry).ProfileImagePath
    $ntuserDat   = Join-Path $profilePath "NTUSER.DAT"
    if (-not (Test-Path $ntuserDat)) {
        Write-Error "NTUSER.DAT not found at: $ntuserDat"
        exit 1
    }
    Write-Host "  Loading hive: $ntuserDat" -ForegroundColor Yellow
    $loadOut = (& reg load $hivePath $ntuserDat 2>&1) -join " "
    Write-Host "  reg load result: $loadOut" -ForegroundColor Gray
    if ($LASTEXITCODE -ne 0) {
        Write-Error ("Failed to load the user hive (exit $LASTEXITCODE). " +
                     "If the account is currently logged in on this machine, log it out first " +
                     "so Windows releases the hive lock, then retry.")
        exit 1
    }
}

try {
    $inetRegPath = "Registry::HKEY_USERS\$regSubPath"
    if (-not (Test-Path $inetRegPath)) { New-Item -Path $inetRegPath -Force | Out-Null }

    $currentProxy = (Get-ItemProperty -Path $inetRegPath -Name "ProxyEnable" -ErrorAction SilentlyContinue).ProxyEnable
    Write-Host "  Current ProxyEnable value: $currentProxy" -ForegroundColor Yellow
    Set-ItemProperty -Path $inetRegPath -Name "ProxyEnable" -Value 0 -Type DWord -ErrorAction Stop
    Write-Host "  [OK] ProxyEnable set to 0." -ForegroundColor Green

    $connPath = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
    if (-not (Test-Path $connPath)) {
        New-Item -Path $connPath -Force | Out-Null
        Write-Host "  Created Connections subkey." -ForegroundColor Gray
    }
    foreach ($blobName in @("DefaultConnectionSettings", "SavedLegacySettings")) {
        $blob = (Get-ItemProperty -Path $connPath -Name $blobName -ErrorAction SilentlyContinue).$blobName
        if ($blob -and $blob.Length -ge 12) {
            $flags = [BitConverter]::ToInt32($blob, 8)
            Write-Host "  $blobName flags before: 0x$('{0:X}' -f $flags)" -ForegroundColor Yellow
            $flags = $flags -band (-bnot 0x02)
            $flagBytes = [BitConverter]::GetBytes([int32]$flags)
            [Array]::Copy($flagBytes, 0, $blob, 8, 4)
            $counter = [BitConverter]::ToUInt32($blob, 4) + 1
            $cntBytes = [BitConverter]::GetBytes([uint32]$counter)
            [Array]::Copy($cntBytes, 0, $blob, 4, 4)
            Set-ItemProperty -Path $connPath -Name $blobName -Value $blob -Type Binary -ErrorAction SilentlyContinue
            Write-Host "  [OK] $blobName flags after: 0x$('{0:X}' -f $flags) (FlagProxy cleared)." -ForegroundColor Green
        } elseif (-not $blob) {
            $newBlob = [byte[]](0x46,0x00,0x00,0x00, 0x01,0x00,0x00,0x00, 0x01,0x00,0x00,0x00) + ([byte[]](0x00)*28)
            Set-ItemProperty -Path $connPath -Name $blobName -Value $newBlob -Type Binary -ErrorAction SilentlyContinue
            Write-Host "  [OK] $blobName created with proxy disabled." -ForegroundColor Green
        }
    }

    $regRights  = [System.Security.AccessControl.RegistryRights]
    $permCheck  = [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
    $changePerms = $regRights::ChangePermissions

    $key = [Microsoft.Win32.Registry]::Users.OpenSubKey($regSubPath, $permCheck, $changePerms)
    if (-not $key) { Write-Error "Could not open the Internet Settings registry key with ChangePermissions access."; exit 1 }

    $acl      = $key.GetAccessControl()
    $identity = New-Object System.Security.Principal.NTAccount($Username)

    $denyMask = $regRights::SetValue      -bor
                $regRights::CreateSubKey  -bor
                $regRights::CreateLink    -bor
                $regRights::Delete        -bor
                $regRights::ChangePermissions -bor
                $regRights::TakeOwnership

    $existing = $acl.Access | Where-Object {
        $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and
        $_.IdentityReference.Value -ilike "*\$Username"
    }
    if ($existing) {
        Write-Host "  DENY rule already present for '$Username' — no change required." -ForegroundColor Yellow
    } else {
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $identity, $denyMask,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Deny
        )
        $acl.AddAccessRule($rule)
        $key.SetAccessControl($acl)
        Write-Host "  [OK] DENY ACE applied to Internet Settings + all subkeys for '$Username'." -ForegroundColor Green
    }
    $key.Close()

    Write-Host ""
    Write-Host "Proxy lock applied for '$Username'." -ForegroundColor Green
} catch {
    Write-Error "Failed to apply proxy lock: $_"
    exit 1
} finally {
    if (-not $wasLoaded) {
        [GC]::Collect()
        Start-Sleep -Milliseconds 800
        $unloadOut = (& reg unload $hivePath 2>&1) -join " "
        Write-Host "  reg unload: $unloadOut" -ForegroundColor Gray
    }
}
"""

PS_PROXY_UNLOCK = r"""
param([Parameter(Mandatory=$true)] [string]$Username)
#Requires -RunAsAdministrator

try {
    $sid = (New-Object System.Security.Principal.NTAccount($Username)).Translate(
               [System.Security.Principal.SecurityIdentifier]).Value
} catch {
    Write-Error "Could not resolve a SID for '$Username'. Check the username and try again. $_"
    exit 1
}
Write-Host "User : $Username" -ForegroundColor Cyan
Write-Host "SID  : $sid"      -ForegroundColor Cyan

$regSubPath = "$sid\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$hivePath   = "HKU\$sid"
$hiveTest   = "Registry::HKEY_USERS\$sid"
$wasLoaded  = Test-Path $hiveTest -ErrorAction SilentlyContinue

if (-not $wasLoaded) {
    Write-Host "  Hive not currently loaded. Attempting to load from profile..." -ForegroundColor Yellow
    $profileEntry = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    if (-not (Test-Path $profileEntry)) { Write-Error "No profile entry found for SID '$sid'."; exit 1 }
    $profilePath = (Get-ItemProperty $profileEntry).ProfileImagePath
    $ntuserDat   = Join-Path $profilePath "NTUSER.DAT"
    $loadOut = (& reg load $hivePath $ntuserDat 2>&1) -join " "
    Write-Host "  reg load result: $loadOut" -ForegroundColor Gray
    if ($LASTEXITCODE -ne 0) { Write-Error ("Failed to load user hive (exit $LASTEXITCODE). Log the account out fully and retry."); exit 1 }
}

try {
    $regRights   = [System.Security.AccessControl.RegistryRights]
    $permCheck   = [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree
    $changePerms = $regRights::ChangePermissions

    $key = [Microsoft.Win32.Registry]::Users.OpenSubKey($regSubPath, $permCheck, $changePerms)
    if (-not $key) { Write-Error "Could not open the Internet Settings key with ChangePermissions access."; exit 1 }

    $acl = $key.GetAccessControl()
    $denyRules = @($acl.Access | Where-Object {
        $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and
        $_.IdentityReference.Value -ilike "*\$Username"
    })

    if ($denyRules.Count -eq 0) {
        Write-Host "  No DENY rules found for '$Username' on this key — nothing to remove." -ForegroundColor Yellow
    } else {
        foreach ($rule in $denyRules) {
            $acl.RemoveAccessRule($rule) | Out-Null
            Write-Host "  Removed DENY rule: $($rule.RegistryRights)" -ForegroundColor Gray
        }
        $key.SetAccessControl($acl)
        Write-Host "  [OK] $($denyRules.Count) DENY ACE(s) removed from Internet Settings key." -ForegroundColor Green
    }
    $key.Close()

    Write-Host ""
    Write-Host "Proxy lock removed for '$Username'." -ForegroundColor Green
} catch {
    Write-Error "Failed to remove proxy lock: $_"
    exit 1
} finally {
    if (-not $wasLoaded) {
        [GC]::Collect()
        Start-Sleep -Milliseconds 800
        $unloadOut = (& reg unload $hivePath 2>&1) -join " "
        Write-Host "  reg unload: $unloadOut" -ForegroundColor Gray
    }
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# REGISTRY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _reg_set(hive, path, name, value, reg_type=winreg.REG_SZ):
    key = winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
    winreg.SetValueEx(key, name, 0, reg_type, value)
    winreg.CloseKey(key)

def _reg_delete_value(hive, path, name):
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        winreg.DeleteValue(key, name)
        winreg.CloseKey(key)
    except FileNotFoundError:
        pass

def _reg_delete_key_recursive(hive, path):
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY)
        while True:
            try:
                sub = winreg.EnumKey(key, 0)
                _reg_delete_key_recursive(hive, path + "\\" + sub)
            except OSError:
                break
        winreg.CloseKey(key)
        winreg.DeleteKey(winreg.OpenKey(hive, "\\".join(path.split("\\")[:-1]),
                                         0, winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY),
                         path.split("\\")[-1])
    except FileNotFoundError:
        pass

def _reg_read(hive, path, name):
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        val, _ = winreg.QueryValueEx(key, name)
        winreg.CloseKey(key)
        return val
    except FileNotFoundError:
        return None

def _reg_key_exists(hive, path):
    try:
        k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        winreg.CloseKey(k)
        return True
    except FileNotFoundError:
        return False

def apply_doh_chrome():
    base = r"SOFTWARE\Policies\Google\Chrome"
    _reg_set(winreg.HKEY_LOCAL_MACHINE, base, "DnsOverHttpsMode", "off")
    _reg_delete_value(winreg.HKEY_LOCAL_MACHINE, base, "DnsOverHttpsTemplates")
    _reg_set(winreg.HKEY_LOCAL_MACHINE, base, "CommandLineFlagSecurity", 1, winreg.REG_DWORD)

def remove_doh_chrome():
    base = r"SOFTWARE\Policies\Google\Chrome"
    for n in ("DnsOverHttpsMode", "DnsOverHttpsTemplates", "CommandLineFlagSecurity"):
        _reg_delete_value(winreg.HKEY_LOCAL_MACHINE, base, n)

def apply_doh_edge():
    base = r"SOFTWARE\Policies\Microsoft\Edge"
    _reg_set(winreg.HKEY_LOCAL_MACHINE, base, "BuiltInDnsClientEnabled", 0, winreg.REG_DWORD)
    _reg_set(winreg.HKEY_LOCAL_MACHINE, base, "DnsOverHttpsMode", "off")
    _reg_delete_value(winreg.HKEY_LOCAL_MACHINE, base, "DnsOverHttpsTemplates")
    _reg_set(winreg.HKEY_LOCAL_MACHINE, base, "CommandLineFlagSecurity", 1, winreg.REG_DWORD)

def remove_doh_edge():
    base = r"SOFTWARE\Policies\Microsoft\Edge"
    for n in ("BuiltInDnsClientEnabled", "DnsOverHttpsMode", "DnsOverHttpsTemplates", "CommandLineFlagSecurity"):
        _reg_delete_value(winreg.HKEY_LOCAL_MACHINE, base, n)

def _gpupdate():
    try:
        subprocess.run(["gpupdate", "/force", "/target:computer"],
                       capture_output=True, timeout=60,
                       creationflags=_CREATE_NO_WINDOW)
    except Exception:
        pass

def apply_ext_lockdown(chrome_allow_ids: list[str], edge_allow_ids: list[str]):
    cb = r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist"
    _reg_set(winreg.HKEY_LOCAL_MACHINE, cb, "1", "*")
    ca = r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist"
    _reg_delete_key_recursive(winreg.HKEY_LOCAL_MACHINE, ca)
    for i, eid in enumerate(chrome_allow_ids, 1):
        _reg_set(winreg.HKEY_LOCAL_MACHINE, ca, str(i), eid.strip())
    _reg_set(winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Google\Chrome",
             "BlockExternalExtensions", 1, winreg.REG_DWORD)
    eb = r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist"
    _reg_set(winreg.HKEY_LOCAL_MACHINE, eb, "1", "*")
    ea = r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist"
    _reg_delete_key_recursive(winreg.HKEY_LOCAL_MACHINE, ea)
    for i, eid in enumerate(edge_allow_ids, 1):
        _reg_set(winreg.HKEY_LOCAL_MACHINE, ea, str(i), eid.strip())
    _reg_set(winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\Edge",
             "BlockExternalExtensions", 1, winreg.REG_DWORD)
    _reg_set(winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Policies\Microsoft\Edge",
             "ExtensionInstallForcelist", 0, winreg.REG_DWORD)
    _gpupdate()

def remove_ext_lockdown():
    for p in [
        r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist",
        r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist",
        r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist",
        r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallAllowlist",
    ]:
        _reg_delete_key_recursive(winreg.HKEY_LOCAL_MACHINE, p)
    for hive, path, name in [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome",   "BlockExternalExtensions"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge",  "BlockExternalExtensions"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge",  "ExtensionInstallForcelist"),
    ]:
        _reg_delete_value(hive, path, name)
    _gpupdate()

# ─────────────────────────────────────────────────────────────────────────────
# EXTENSION AUTO-DETECT
# ─────────────────────────────────────────────────────────────────────────────

def _iter_browser_user_data_dirs(relative_path: str):
    import json as _json
    users_root = Path(os.environ.get("SystemDrive", "C:") + "\\Users")
    seen: set[Path] = set()

    candidate_bases: list[Path] = []
    if users_root.exists():
        try:
            for user_dir in users_root.iterdir():
                if not user_dir.is_dir(): continue
                candidate = user_dir / "AppData" / "Local" / relative_path
                candidate_bases.append(candidate)
        except PermissionError:
            pass

    local_app = os.environ.get("LOCALAPPDATA", "")
    if local_app:
        candidate_bases.append(Path(local_app) / relative_path)

    for base in candidate_bases:
        resolved = base.resolve()
        if resolved in seen: continue
        seen.add(resolved)
        if base.exists(): yield base

def _read_extensions_from_user_data(base: "Path") -> dict[str, str]:
    import json as _json
    results: dict[str, str] = {}
    for profile in base.glob("*/Extensions"):
        for ext_dir in profile.iterdir():
            if not ext_dir.is_dir() or len(ext_dir.name) < 20: continue
            if ext_dir.name in results: continue
            for ver_dir in ext_dir.iterdir():
                if not ver_dir.is_dir(): continue
                manifest = ver_dir / "manifest.json"
                if manifest.exists():
                    try:
                        data = _json.loads(manifest.read_text(encoding="utf-8", errors="ignore"))
                        name = data.get("name", ext_dir.name)
                        if name.startswith("__MSG_"): name = ext_dir.name
                        results[ext_dir.name] = name
                    except Exception:
                        results[ext_dir.name] = ext_dir.name
                    break
    return results

def detect_chrome_extensions() -> dict[str, str]:
    results: dict[str, str] = {}
    for base in _iter_browser_user_data_dirs(r"Google\Chrome\User Data"):
        results.update(_read_extensions_from_user_data(base))
    return results

def detect_edge_extensions() -> dict[str, str]:
    results: dict[str, str] = {}
    for base in _iter_browser_user_data_dirs(r"Microsoft\Edge\User Data"):
        results.update(_read_extensions_from_user_data(base))
    return results

# ─────────────────────────────────────────────────────────────────────────────
# STATUS CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def check_acl_applied(username: str) -> tuple[str, str]:
    backups = sorted(glob.glob(ACL_BACKUP_GLOB))
    if backups:
        ts = Path(backups[-1]).stem.replace("acl_backup_multi_", "")
        return (f"Backup exists ({ts})", "#4ade80")
    return ("Not applied", "#f87171")

def _policy_guid(policy_name: str) -> str:
    raw = bytearray(hashlib.md5(policy_name.lower().encode("utf-8")).digest())
    raw[0], raw[1], raw[2], raw[3] = raw[3], raw[2], raw[1], raw[0]
    raw[4], raw[5] = raw[5], raw[4]
    raw[6], raw[7] = raw[7], raw[6]
    return str(uuid.UUID(bytes=bytes(raw))).upper()

def check_wdac_deployed(policy_name: str) -> tuple[str, str]:
    guid      = _policy_guid(policy_name)
    cip_name  = "{" + guid + "}.cip"
    active    = Path(r"C:\Windows\System32\CodeIntegrity\CiPolicies\Active")
    out_cip   = Path(r"C:\WDACPolicy") / cip_name

    active_accessible = False
    if active.exists():
        try:
            active_files = os.listdir(str(active))
            active_accessible = True
            if any(f.upper() == cip_name.upper() for f in active_files):
                return (f"Active: {policy_name}", "#4ade80")
        except Exception:
            pass

    if out_cip.exists() and not active_accessible:
        return ("Built \u2014 reboot to activate", "#facc15")

    sidecar_name = "policy_" + re.sub(r'[^a-zA-Z0-9_\-]', '_', policy_name) + ".txt"
    sidecar = Path(r"C:\WDACPolicy") / sidecar_name
    for stale in (sidecar, out_cip):
        if stale.exists():
            try: stale.unlink()
            except Exception: pass

    return ("Not deployed", "#f87171")

def check_store_blocked() -> tuple[str, str]:
    svc_start = _reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\InstallService", "Start")
    if svc_start == 4:
        return ("Blocked", "#4ade80")
    try:
        fw_key = (r"SYSTEM\CurrentControlSet\Services\SharedAccess"
                  r"\Parameters\FirewallPolicy\FirewallRules")
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, fw_key,
                            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            idx = 0
            while True:
                try:
                    _, data, _ = winreg.EnumValue(k, idx)
                    idx += 1
                    if isinstance(data, str) and "Name=Block Microsoft Store" in data and "Active=TRUE" in data:
                        return ("Blocked", "#4ade80")
                except OSError:
                    break
    except Exception:
        pass
    return ("Not blocked", "#f87171")

def check_doh(browser: str) -> tuple[str, str]:
    if browser == "chrome": val = _reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode")
    else: val = _reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode")
    if val == "off": return ("DoH disabled via policy", "#4ade80")
    return ("Not configured", "#f87171")

def check_ext_lockdown(browser: str) -> tuple[str, str]:
    if browser == "chrome": val = _reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist", "1")
    else: val = _reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist", "1")
    if val == "*": return ("Blocklist active", "#4ade80")
    return ("Not configured", "#f87171")

def _is_user_local_admin(username: str) -> bool:
    if not username: return False
    try:
        r = subprocess.run(
            ["net", "localgroup", "Administrators"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace", creationflags=_CREATE_NO_WINDOW
        )
        in_list = False
        for line in r.stdout.splitlines():
            if "---" in line:
                in_list = True
                continue
            if in_list:
                entry = line.strip()
                if not entry or "The command completed" in entry: break
                leaf = entry.split("\\")[-1]
                if leaf.lower() == username.lower(): return True
        return False
    except Exception:
        return False

def check_proxy_locked(username: str) -> tuple[str, str]:
    if not username: return ("No user configured", "#64748b")
    ps_cmd = (
        "try {"
        f" $sid=(New-Object System.Security.Principal.NTAccount('{username}')).Translate("
        " [System.Security.Principal.SecurityIdentifier]).Value;"
        " $k=[Microsoft.Win32.Registry]::Users.OpenSubKey("
        " \"$sid\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\",$false);"
        " if(-not $k){Write-Output 'HIVE_NOT_LOADED';exit 0}"
        " $acl=$k.GetAccessControl();$k.Close();"
        " $d=$acl.Access|Where-Object{"
        " $_.AccessControlType -eq 'Deny' -and"
        f" $_.IdentityReference.Value -ilike '*\\{username}'"
        " };"
        " if($d){Write-Output 'LOCKED'}else{Write-Output 'UNLOCKED'}"
        "} catch { Write-Output \"ERR:$_\" }"
    )
    try:
        r = subprocess.run(
            [_get_powershell_exe(), "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace", creationflags=_CREATE_NO_WINDOW
        )
        out = r.stdout.strip()
        if out == "LOCKED":          return (f"Locked ({username})", "#4ade80")
        if out == "UNLOCKED":        return ("Not locked",           "#f87171")
        if out == "HIVE_NOT_LOADED": return ("Hive not loaded — user may be offline", "#facc15")
        return ("Cannot check", "#64748b")
    except Exception:
        return ("Cannot check", "#64748b")

# ─────────────────────────────────────────────────────────────────────────────
# FIREWALL SUITE POWERSHELL SCRIPTS
# ─────────────────────────────────────────────────────────────────────────────

PS_FIREWALL_SETUP = r"""
param()
#Requires -RunAsAdministrator

$taskName       = "Firewall Scheduler"
$suiteDir       = "C:\Program Files\Restrictions\firewall_suite"
$schedulerExe   = "$suiteDir\firewall_scheduler.exe"
$timesheetExe   = "$suiteDir\timesheet_manager_firewall.exe"
$allUsersDesktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
$shortcutPath   = Join-Path $allUsersDesktop "Timesheet Manager.lnk"

if (-not (Test-Path $schedulerExe)) {
    Write-Error "firewall_scheduler.exe not found at: $schedulerExe`nExtraction may have failed."
    exit 1
}
if (-not (Test-Path $timesheetExe)) {
    Write-Warning "timesheet_manager_firewall.exe not found at: $timesheetExe — shortcut will still be created but may not work."
}
Write-Host "  [OK] Suite files confirmed at: $suiteDir" -ForegroundColor Green

Write-Host "Registering scheduled task: $taskName" -ForegroundColor Cyan

$taskXml = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\Firewall Scheduler</URI>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='EventLog'] and EventID=6005]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT30S</Delay>
    </EventTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=107]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>PT30S</Delay>
    </EventTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>5</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"C:\Program Files\Restrictions\firewall_suite\firewall_scheduler.exe"</Command>
    </Exec>
  </Actions>
</Task>
'@

$tmpXml = [System.IO.Path]::GetTempFileName() + ".xml"
try {
    [System.IO.File]::WriteAllText($tmpXml, $taskXml, [System.Text.Encoding]::Unicode)
    $result = (& schtasks /Create /TN $taskName /XML $tmpXml /F 2>&1) -join " "
    if ($LASTEXITCODE -ne 0) {
        Write-Error "schtasks /Create failed (exit $LASTEXITCODE): $result"
        exit 1
    }
    Write-Host "  [OK] Task '$taskName' registered." -ForegroundColor Green
} finally {
    Remove-Item $tmpXml -Force -ErrorAction SilentlyContinue
}

Write-Host "Creating desktop shortcut at: $shortcutPath" -ForegroundColor Cyan
try {
    $shell   = New-Object -ComObject WScript.Shell
    $lnk     = $shell.CreateShortcut($shortcutPath)
    $lnk.TargetPath       = $timesheetExe
    $lnk.WorkingDirectory = $suiteDir
    $lnk.Description      = "Timesheet Manager — set daily internet access schedule"
    $lnk.Save()
    Write-Host "  [OK] Shortcut created." -ForegroundColor Green
} catch {
    Write-Warning "Could not create shortcut: $_"
}

Write-Host ""
Write-Host "Firewall Suite deployed." -ForegroundColor Green
"""

PS_FIREWALL_REMOVE = r"""
param()
#Requires -RunAsAdministrator

$taskName        = "Firewall Scheduler"
$firewallRule    = "Block All Internet"
$suiteDir        = "C:\Program Files\Restrictions\firewall_suite"
$allUsersDesktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
$shortcutPath    = Join-Path $allUsersDesktop "Timesheet Manager.lnk"

Write-Host "Removing scheduled task: $taskName" -ForegroundColor Cyan
$queryResult = (& schtasks /Query /TN $taskName /FO LIST 2>&1) -join " "
if ($LASTEXITCODE -eq 0) {
    & schtasks /End /TN $taskName 2>&1 | Out-Null
    $deleteResult = (& schtasks /Delete /TN $taskName /F 2>&1) -join " "
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Task deleted." -ForegroundColor Green
    } else {
        Write-Warning "Could not delete task: $deleteResult"
    }
} else {
    Write-Host "  Task not found (already removed)." -ForegroundColor Gray
}

Write-Host "Stopping any running firewall suite processes..." -ForegroundColor Cyan
$suiteExes = @("firewall_scheduler", "timesheet_manager_firewall")
foreach ($exeName in $suiteExes) {
    $procs = Get-Process -Name $exeName -ErrorAction SilentlyContinue
    if ($procs) {
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        Write-Host "  [OK] Stopped: $exeName" -ForegroundColor Green
    }
}

Write-Host "Removing firewall rules: '$firewallRule'" -ForegroundColor Cyan
$ruleCheck = (& netsh advfirewall firewall show rule name=$firewallRule 2>&1) -join " "
if ($ruleCheck -notmatch "No rules match") {
    $delOut = (& netsh advfirewall firewall delete rule name=$firewallRule 2>&1) -join " "
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Firewall rules deleted (inbound + outbound)." -ForegroundColor Green
    } else {
        Write-Warning "  netsh delete returned exit $LASTEXITCODE : $delOut"
    }
} else {
    Write-Host "  Firewall rules not found (already removed)." -ForegroundColor Gray
}

Write-Host "Removing suite directory: $suiteDir" -ForegroundColor Cyan
if (Test-Path $suiteDir) {
    Remove-Item -Path $suiteDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $suiteDir) {
        Write-Host "  Standard remove incomplete — taking ownership and retrying..." -ForegroundColor Yellow
        & takeown /F $suiteDir /R /D Y 2>&1 | Out-Null
        & icacls $suiteDir /grant "Administrators:(OI)(CI)F" /T /C /Q 2>&1 | Out-Null
        & cmd /c rd /s /q $suiteDir 2>&1 | Out-Null
        if (Test-Path $suiteDir) {
            Write-Warning "  Directory still locked after forced removal."
            Write-Warning "  Scheduling deletion on next reboot via reg RunOnce..."
            $rdCmd = "cmd /c rd /s /q `"$suiteDir`""
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            Set-ItemProperty -Path $regPath -Name "RemoveFirewallSuite" -Value $rdCmd -ErrorAction SilentlyContinue
            Write-Warning "  A REBOOT is required to finish removing: $suiteDir"
        } else {
            Write-Host "  [OK] Directory forcefully removed." -ForegroundColor Green
        }
    } else {
        Write-Host "  [OK] Directory removed." -ForegroundColor Green
    }
} else {
    Write-Host "  Directory not found (already removed)." -ForegroundColor Gray
}

Write-Host "Removing desktop shortcut: $shortcutPath" -ForegroundColor Cyan
if (Test-Path $shortcutPath) {
    Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Shortcut removed." -ForegroundColor Green
} else {
    Write-Host "  Shortcut not found (already removed)." -ForegroundColor Gray
}

Write-Host ""
Write-Host "Firewall Suite removed." -ForegroundColor Green
"""

# ─────────────────────────────────────────────────────────────────────────────
# ADAPTER GUARD POWERSHELL SCRIPTS
# ─────────────────────────────────────────────────────────────────────────────

PS_ADAPTER_GUARD_SETUP = r"""
param()
#Requires -RunAsAdministrator

$taskName   = "AdapterGuard"
$guardDir   = "C:\Program Files\Restrictions\adapter_guard_oneshot"
$guardExe   = "$guardDir\adapter_guard_oneshot.exe"

if (-not (Test-Path $guardExe)) {
    Write-Error "adapter_guard_oneshot.exe not found at: $guardExe`nExtraction may have failed."
    exit 1
}
Write-Host "  [OK] adapter_guard_oneshot.exe confirmed at: $guardDir" -ForegroundColor Green

Write-Host "Registering scheduled task: $taskName" -ForegroundColor Cyan

$taskXml = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2026-01-01T00:00:00</Date>
    <Author>SYSTEM</Author>
    <Description>Disables any network adapter not on the configured allowlist. Triggered the moment any adapter connects.</Description>
    <URI>\AdapterGuard</URI>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;
          &lt;Query Id="0" Path="Microsoft-Windows-Kernel-PnP/Configuration"&gt;
            &lt;Select Path="Microsoft-Windows-Kernel-PnP/Configuration"&gt;
              *[System[EventID=410] and EventData[Data[@Name='ClassGuid']='{4D36E972-E325-11CE-BFC1-08002BE10318}']]
            &lt;/Select&gt;
          &lt;/Query&gt;
        &lt;/QueryList&gt;</Subscription>
      <Delay>PT3S</Delay>
    </EventTrigger>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;
          &lt;Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"&gt;
            &lt;Select Path="Microsoft-Windows-NetworkProfile/Operational"&gt;
              *[System[EventID=10000]]
            &lt;/Select&gt;
          &lt;/Query&gt;
        &lt;/QueryList&gt;</Subscription>
      <Delay>PT3S</Delay>
    </EventTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT30S</Delay>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Program Files\Restrictions\adapter_guard_oneshot\adapter_guard_oneshot.exe</Command>
    </Exec>
  </Actions>
</Task>
'@

$tmpXml = [System.IO.Path]::GetTempFileName() + ".xml"
try {
    [System.IO.File]::WriteAllText($tmpXml, $taskXml, [System.Text.Encoding]::Unicode)
    $result = (& schtasks /Create /TN $taskName /XML $tmpXml /F 2>&1) -join " "
    if ($LASTEXITCODE -ne 0) {
        Write-Error "schtasks /Create failed (exit $LASTEXITCODE): $result"
        exit 1
    }
    Write-Host "  [OK] Task '$taskName' registered." -ForegroundColor Green
} finally {
    Remove-Item $tmpXml -Force -ErrorAction SilentlyContinue
}

Write-Host "Starting task: $taskName" -ForegroundColor Cyan
$startResult = (& schtasks /Run /TN $taskName 2>&1) -join " "
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Task started." -ForegroundColor Green
} else {
    Write-Warning "  Task start returned exit $LASTEXITCODE : $startResult"
}

Write-Host ""
Write-Host "AdapterGuard deployed." -ForegroundColor Green
"""

PS_ADAPTER_GUARD_REMOVE = r"""
param()
#Requires -RunAsAdministrator

$taskName = "AdapterGuard"
$guardExe = "adapter_guard_oneshot"
$guardDir = "C:\Program Files\Restrictions\adapter_guard_oneshot"

Write-Host "Removing scheduled task: $taskName" -ForegroundColor Cyan
$queryResult = (& schtasks /Query /TN $taskName /FO LIST 2>&1) -join " "
if ($LASTEXITCODE -eq 0) {
    & schtasks /End /TN $taskName 2>&1 | Out-Null
    Start-Sleep -Milliseconds 500
    $deleteResult = (& schtasks /Delete /TN $taskName /F 2>&1) -join " "
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Task deleted." -ForegroundColor Green
    } else {
        Write-Warning "Could not delete task: $deleteResult"
    }
} else {
    Write-Host "  Task not found (already removed)." -ForegroundColor Gray
}

Write-Host "Stopping any running AdapterGuard processes..." -ForegroundColor Cyan
$procs = Get-Process -Name $guardExe -ErrorAction SilentlyContinue
if ($procs) {
    $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Write-Host "  [OK] Stopped: $guardExe" -ForegroundColor Green
} else {
    Write-Host "  No running processes found." -ForegroundColor Gray
}

Write-Host "Removing directory: $guardDir" -ForegroundColor Cyan
if (Test-Path $guardDir) {
    Remove-Item -Path $guardDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $guardDir) {
        Write-Host "  Standard remove incomplete — taking ownership and retrying..." -ForegroundColor Yellow
        & takeown /F $guardDir /R /D Y 2>&1 | Out-Null
        & icacls $guardDir /grant "Administrators:(OI)(CI)F" /T /C /Q 2>&1 | Out-Null
        & cmd /c rd /s /q $guardDir 2>&1 | Out-Null
        if (Test-Path $guardDir) {
            Write-Warning "  Directory still locked.  Scheduling deletion on next reboot..."
            $rdCmd = "cmd /c rd /s /q `"$guardDir`""
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            Set-ItemProperty -Path $regPath -Name "RemoveAdapterGuard" -Value $rdCmd -ErrorAction SilentlyContinue
            Write-Warning "  A REBOOT is required to finish removing: $guardDir"
        } else {
            Write-Host "  [OK] Directory forcefully removed." -ForegroundColor Green
        }
    } else {
        Write-Host "  [OK] Directory removed." -ForegroundColor Green
    }
} else {
    Write-Host "  Directory not found (already removed)." -ForegroundColor Gray
}

Write-Host ""
Write-Host "AdapterGuard removed." -ForegroundColor Green
"""

# ─────────────────────────────────────────────────────────────────────────────
# DNS SUITE POWERSHELL SCRIPTS
# ─────────────────────────────────────────────────────────────────────────────

PS_DNS_MAKE_CAPABLE = r"""
param(
    [Parameter(Mandatory=$true)] [string[]]$AdapterNames
)
#Requires -RunAsAdministrator
foreach ($name in $AdapterNames) {
    Write-Host "Configuring DNS-capable: $name" -ForegroundColor Cyan
    $iface = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue
    if (-not $iface) {
        Write-Warning "  Adapter not found: $name — skipping."
        continue
    }
    $idx = $iface.InterfaceIndex

    try {
        Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses "127.0.0.1"
        Write-Host "  [OK] IPv4 DNS set to 127.0.0.1" -ForegroundColor Green
    } catch {
        Write-Warning "  Could not set IPv4 DNS on ${name}: $_"
    }

    try {
        Disable-NetAdapterBinding -Name $name -ComponentID ms_tcpip6 -ErrorAction Stop
        Write-Host "  [OK] IPv6 binding disabled" -ForegroundColor Green
    } catch {
        Write-Warning "  Could not disable IPv6 on ${name}: $_"
    }
}
"""

PS_DNS_MAKE_INCAPABLE = r"""
param(
    [Parameter(Mandatory=$true)] [string[]]$AdapterNames
)
#Requires -RunAsAdministrator
foreach ($name in $AdapterNames) {
    Write-Host "Reverting to DNS-incapable: $name" -ForegroundColor Cyan
    $iface = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue
    if (-not $iface) {
        Write-Warning "  Adapter not found: $name — skipping."
        continue
    }
    $idx = $iface.InterfaceIndex

    try {
        Set-DnsClientServerAddress -InterfaceIndex $idx -ResetServerAddresses
        Write-Host "  [OK] IPv4 DNS reset to automatic" -ForegroundColor Green
    } catch {
        Write-Warning "  Could not reset IPv4 DNS on ${name}: $_"
    }

    try {
        Enable-NetAdapterBinding -Name $name -ComponentID ms_tcpip6 -ErrorAction Stop
        Write-Host "  [OK] IPv6 binding re-enabled" -ForegroundColor Green
    } catch {
        Write-Warning "  Could not re-enable IPv6 on ${name}: $_"
    }
}
"""

PS_DNS_SUITE_SETUP = r"""
param()
#Requires -RunAsAdministrator

$taskName   = "DNS Server (Restrctions) (SYSTEM)"
$suiteDir   = "C:\Program Files\Restrictions\dns_suite"
$serverExe  = "$suiteDir\dns_whitelist_blacklist_server.exe"

if (-not (Test-Path $serverExe)) {
    Write-Error "dns_whitelist_blacklist_server.exe not found at: $serverExe"
    exit 1
}
Write-Host "  [OK] DNS suite files confirmed at: $suiteDir" -ForegroundColor Green

Write-Host "Registering scheduled task: $taskName" -ForegroundColor Cyan
$taskXml = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\DNS Server (Restrctions) (SYSTEM)</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"C:\Program Files\Restrictions\dns_suite\dns_whitelist_blacklist_server.exe"</Command>
    </Exec>
  </Actions>
</Task>
'@

$tmpXml = [System.IO.Path]::GetTempFileName() + ".xml"
try {
    [System.IO.File]::WriteAllText($tmpXml, $taskXml, [System.Text.Encoding]::Unicode)
    $result = (& schtasks /Create /TN $taskName /XML $tmpXml /F 2>&1) -join " "
    if ($LASTEXITCODE -ne 0) {
        Write-Error "schtasks /Create failed (exit $LASTEXITCODE): $result"
        exit 1
    }
    Write-Host "  [OK] Task '$taskName' registered." -ForegroundColor Green
} finally {
    Remove-Item $tmpXml -Force -ErrorAction SilentlyContinue
}

Write-Host "Starting task: $taskName" -ForegroundColor Cyan
$startResult = (& schtasks /Run /TN $taskName 2>&1) -join " "
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Task started." -ForegroundColor Green
} else {
    Write-Warning "  Task start returned exit $LASTEXITCODE : $startResult"
}

Write-Host ""
Write-Host "DNS Suite deployed." -ForegroundColor Green
"""

PS_DNS_SUITE_REMOVE = r"""
param()
#Requires -RunAsAdministrator

$taskName   = "DNS Server (Restrctions) (SYSTEM)"
$suiteDir   = "C:\Program Files\Restrictions\dns_suite"
$suiteExes  = @("dns_whitelist_blacklist_server", "dns_whitelist_logger", "merge_whitelists")

Write-Host "Removing scheduled task: $taskName" -ForegroundColor Cyan
$q = (& schtasks /Query /TN $taskName /FO LIST 2>&1) -join " "
if ($LASTEXITCODE -eq 0) {
    & schtasks /End /TN $taskName 2>&1 | Out-Null
    Start-Sleep -Milliseconds 500
    $del = (& schtasks /Delete /TN $taskName /F 2>&1) -join " "
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Task deleted." -ForegroundColor Green
    } else {
        Write-Warning "  Could not delete task: $del"
    }
} else {
    Write-Host "  Task not found (already removed)." -ForegroundColor Gray
}

Write-Host "Stopping any running DNS suite processes..." -ForegroundColor Cyan
foreach ($exe in $suiteExes) {
    $procs = Get-Process -Name $exe -ErrorAction SilentlyContinue
    if ($procs) {
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 300
        Write-Host "  [OK] Stopped: $exe" -ForegroundColor Green
    }
}

Write-Host "Removing directory: $suiteDir" -ForegroundColor Cyan
if (Test-Path $suiteDir) {
    Remove-Item -Path $suiteDir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $suiteDir) {
        Write-Host "  Standard remove incomplete — taking ownership and retrying..." -ForegroundColor Yellow
        & takeown /F $suiteDir /R /D Y 2>&1 | Out-Null
        & icacls $suiteDir /grant "Administrators:(OI)(CI)F" /T /C /Q 2>&1 | Out-Null
        & cmd /c rd /s /q $suiteDir 2>&1 | Out-Null
        if (Test-Path $suiteDir) {
            Write-Warning "  Directory still locked.  Scheduling deletion on next reboot..."
            $rdCmd  = "cmd /c rd /s /q `"$suiteDir`""
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            Set-ItemProperty -Path $regPath -Name "RemoveDnsSuite" -Value $rdCmd -ErrorAction SilentlyContinue
            Write-Warning "  A REBOOT is required to finish removing: $suiteDir"
        } else {
            Write-Host "  [OK] Directory forcefully removed." -ForegroundColor Green
        }
    } else {
        Write-Host "  [OK] Directory removed." -ForegroundColor Green
    }
} else {
    Write-Host "  Directory not found (already removed)." -ForegroundColor Gray
}

Write-Host ""
Write-Host "DNS Suite removed." -ForegroundColor Green
"""

# ─────────────────────────────────────────────────────────────────────────────
# BROWSERGUARD POWERSHELL SCRIPTS
# ─────────────────────────────────────────────────────────────────────────────

PS_BROWSERGUARD_DEPLOY = r"""
<#
.SYNOPSIS
    Deploy BrowserGuard.sys (embedded/extracted version for restriction_manager GUI).
#>
[CmdletBinding()]
param(
    [string] $SysPath              = ".\BrowserGuard.sys",
    [string] $ServiceName          = "BrowserGuard",
    [string] $CertSubject          = "BrowserGuardTestCert",
    [string] $WdacPolicyName       = "BlockRestrictedUser",
    [string] $WdacSupplementalName = "BrowserGuardDriverAllow",
    [switch] $SkipWdac
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step ([string]$m) { Write-Host "`n[STEP] $m"  -ForegroundColor Cyan   }
function Write-OK   ([string]$m) { Write-Host "   [OK] $m"   -ForegroundColor Green  }
function Write-Warn ([string]$m) { Write-Host "   [!!] $m"   -ForegroundColor Yellow }
function Write-Fail ([string]$m) { Write-Host "  [ERR] $m"   -ForegroundColor Red; exit 1 }
function Write-Info ([string]$m) { Write-Host "        $m"   -ForegroundColor Gray   }

function Get-TbsHash {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
    [byte[]] $raw = $Certificate.RawData
    [int]    $idx = 0
    if ($raw[$idx] -ne 0x30) { throw "Get-TbsHash: expected outer SEQUENCE tag 0x30" }
    $idx++
    if (($raw[$idx] -band 0x80) -ne 0) {
        [int] $outerLenBytes = $raw[$idx] -band 0x7F
        $idx += 1 + $outerLenBytes
    } else { $idx++ }
    [int] $tbsStart = $idx
    if ($raw[$idx] -ne 0x30) { throw "Get-TbsHash: expected TBSCertificate SEQUENCE tag 0x30" }
    $idx++
    [int] $tbsLen = 0
    if (($raw[$idx] -band 0x80) -ne 0) {
        [int] $tbsLenBytes = $raw[$idx] -band 0x7F; $idx++
        for ([int] $n = 0; $n -lt $tbsLenBytes; $n++) { $tbsLen = ($tbsLen -shl 8) -bor [int]$raw[$idx]; $idx++ }
    } else { $tbsLen = [int]$raw[$idx]; $idx++ }
    [int] $tbsEnd = $idx + $tbsLen; [int] $tbsTotal = $tbsEnd - $tbsStart
    [byte[]] $tbsBytes = [byte[]]::new($tbsTotal)
    [System.Array]::Copy($raw, $tbsStart, $tbsBytes, 0, $tbsTotal)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($tbsBytes); $sha256.Dispose()
    return ([System.BitConverter]::ToString($hashBytes)).Replace("-", "")
}

Write-Step "Locating BrowserGuard.sys"
$resolved = Resolve-Path $SysPath -ErrorAction SilentlyContinue
if (-not $resolved) { Write-Fail "Cannot find: $SysPath" }
$sysSource = $resolved.Path
Write-OK "Found: $sysSource"

Write-Step "Disabling Memory Integrity (HVCI) via registry"
$hvciKey = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
if (-not (Test-Path $hvciKey)) { New-Item -Path $hvciKey -Force | Out-Null }
$alreadyOff = $false
try { $val = Get-ItemPropertyValue -Path $hvciKey -Name "Enabled" -ErrorAction Stop; $alreadyOff = ($val -eq 0) } catch { }
if ($alreadyOff) { Write-OK "HVCI already disabled." }
else {
    Set-ItemProperty -Path $hvciKey -Name "Enabled" -Value 0 -Type DWord
    Write-Warn "HVCI disabled in registry — verify in Windows Security > Core isolation > Memory integrity = Off"
}

Write-Step "Enabling test-signing mode (bcdedit)"
$bcd = & bcdedit /enum "{current}" 2>&1 | Out-String
if ($bcd -match "testsigning\s+Yes") { Write-OK "Test signing already ON." }
else {
    $r = & bcdedit /set testsigning on 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Fail "bcdedit failed: $r`nDisable Secure Boot in BIOS/UEFI and retry." }
    Write-OK "Test signing enabled."; Write-Warn "A REBOOT is required for this to take effect."
}

Write-Step "Creating self-signed code-signing certificate: CN=$CertSubject"
$cert = Get-ChildItem "Cert:\LocalMachine\My" |
        Where-Object { $_.Subject -eq "CN=$CertSubject" } | Select-Object -First 1
if ($cert) { Write-OK "Reusing existing cert. Thumbprint: $($cert.Thumbprint)" }
else {
    $cert = New-SelfSignedCertificate `
        -Subject "CN=$CertSubject" -CertStoreLocation "Cert:\LocalMachine\My" `
        -Type CodeSigningCert -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 `
        -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(10) -KeyExportPolicy Exportable
    Write-OK "Created. Thumbprint: $($cert.Thumbprint)"
}

Write-Step "Installing certificate into trust stores"
foreach ($storeName in @("Root", "TrustedPublisher")) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        $storeName, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $already = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
    if (-not $already) { $store.Add($cert); Write-OK "Added to LocalMachine\$storeName" }
    else { Write-OK "Already in LocalMachine\$storeName" }
    $store.Close()
}

Write-Step "Re-signing BrowserGuard.sys with certificate CN=$CertSubject"
$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$localCopy  = Join-Path $scriptDir "BrowserGuard_signed.sys"
Copy-Item -Path $sysSource -Destination $localCopy -Force
$sigResult  = Set-AuthenticodeSignature -FilePath $localCopy -Certificate $cert `
                  -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com" `
                  -ErrorAction SilentlyContinue
$verify = Get-AuthenticodeSignature -FilePath $localCopy
if ($verify.Status -eq "NotSigned") {
    Write-Warn "Timestamp server unreachable. Retrying without timestamp..."
    Set-AuthenticodeSignature -FilePath $localCopy -Certificate $cert -HashAlgorithm SHA256 `
        -ErrorAction SilentlyContinue | Out-Null
    $verify = Get-AuthenticodeSignature -FilePath $localCopy
    if ($verify.Status -eq "NotSigned") { Write-Fail "Signing failed — check cert has private key." }
}
Write-OK "Signed. Status: $($verify.Status)"
Write-Info "Signer: $($verify.SignerCertificate.Subject)"

Write-Step "Deploying driver to System32\drivers"
$destSys = "$env:SystemRoot\System32\drivers\BrowserGuard.sys"
Copy-Item -Path $localCopy -Destination $destSys -Force
Remove-Item $localCopy -Force -ErrorAction SilentlyContinue
Write-OK "Deployed: $destSys"

Write-Step "Registering kernel service: $ServiceName"
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Warn "Service already exists — stopping and removing it first."
    if ($svc.Status -eq "Running") { & sc.exe stop $ServiceName | Out-Null; Start-Sleep 2 }
    & sc.exe delete $ServiceName | Out-Null; Start-Sleep 1
}
& sc.exe create $ServiceName type= kernel binPath= $destSys start= demand `
    DisplayName= "Browser Command-Line Guard"
if ($LASTEXITCODE -ne 0) { Write-Fail "sc.exe create failed." }
Write-OK "Service registered."

Write-Step "Configuring service to start at system boot"
& sc.exe config $ServiceName start= system
if ($LASTEXITCODE -ne 0) { Write-Warn "sc.exe config start=system returned $LASTEXITCODE" }
else { Write-OK "Service set to start= system." }

if ($SkipWdac) {
    Write-Warn "Skipping WDAC supplemental policy (-SkipWdac specified)."
} else {
    Write-Step "Generating WDAC supplemental policy to allow the test-signed driver"
    $md5       = [System.Security.Cryptography.MD5]::Create()
    $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($WdacPolicyName.ToLower())
    $guidBytes = $md5.ComputeHash($nameBytes); $md5.Dispose()
    $basePolicyGuid = "{" + [System.Guid]::new($guidBytes).ToString().ToUpper() + "}"
    $guidBare       = $basePolicyGuid.Trim("{").Trim("}")
    Write-Info "Base policy GUID: $basePolicyGuid"
    $activeDir = "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"
    $baseCipFiles = @()
    if (Test-Path $activeDir) {
        $baseCipFiles = @(Get-ChildItem $activeDir -Filter "*.cip" -ErrorAction SilentlyContinue |
                          Where-Object { $_.Name -like "*$guidBare*" })
    }
    if ($baseCipFiles.Count -eq 0) {
        Write-Warn "No base policy CIP found for GUID $basePolicyGuid — continuing anyway."
        Write-Warn "If policy name differs from '$WdacPolicyName', re-run with -WdacPolicyName 'YourName'."
    } else { Write-OK "Base policy CIP: $($baseCipFiles[0].Name)" }
    $tbsHash = Get-TbsHash -Certificate $cert
    Write-OK "TBS hash: $tbsHash"
    $suppGuid     = "{" + [System.Guid]::NewGuid().ToString().ToUpper() + "}"
    $suppGuidBare = $suppGuid.Trim("{").Trim("}")
    Write-Info "Supplemental policy GUID: $suppGuid"
    $wdacOutDir  = "C:\WDACPolicy"
    New-Item -ItemType Directory -Path $wdacOutDir -Force | Out-Null
    $suppSafe    = $WdacSupplementalName -replace '[^a-zA-Z0-9_\-]', '_'
    $suppXmlPath = "$wdacOutDir\${suppSafe}_supp.xml"
    $suppCipName = "{$suppGuidBare}.cip"
    $suppCipPath = "$wdacOutDir\$suppCipName"
    $suppXml = @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Supplemental Policy">
  <VersionEx>10.0.0.1</VersionEx>
  <PolicyID>$suppGuid</PolicyID>
  <BasePolicyID>$basePolicyGuid</BasePolicyID>
  <PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
  <Rules><Rule><Option>Enabled:Unsigned System Integrity Policy</Option></Rule></Rules>
  <EKUs/><FileRules/>
  <Signers>
    <Signer ID="ID_SIGNER_BROWSERGUARD" Name="$CertSubject">
      <CertRoot Type="TBS" Value="$tbsHash"/>
    </Signer>
  </Signers>
  <SigningScenarios>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_KMCI" FriendlyName="Kernel Mode">
      <ProductSigners><AllowedSigners><AllowedSigner SignerId="ID_SIGNER_BROWSERGUARD"/></AllowedSigners></ProductSigners>
    </SigningScenario>
    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_UMCI" FriendlyName="User Mode">
      <ProductSigners><AllowedSigners><AllowedSigner SignerId="ID_SIGNER_BROWSERGUARD"/></AllowedSigners></ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <UpdatePolicySigners/><CiSigners/><HvciOptions>0</HvciOptions>
  <Settings>
    <Setting Provider="PolicyInfo" Key="Information" ValueName="Name">
      <Value><String>$WdacSupplementalName</String></Value>
    </Setting>
    <Setting Provider="PolicyInfo" Key="Information" ValueName="Id">
      <Value><String>$suppGuidBare</String></Value>
    </Setting>
  </Settings>
</SiPolicy>
"@
    [System.IO.File]::WriteAllText($suppXmlPath, $suppXml, [System.Text.Encoding]::UTF8)
    Write-OK "Supplemental policy XML written: $suppXmlPath"
    if (-not (Get-Command "ConvertFrom-CIPolicy" -ErrorAction SilentlyContinue)) {
        $modPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\ConfigCI"
        if (Test-Path $modPath) { Import-Module $modPath -Force -ErrorAction SilentlyContinue }
    }
    if (Get-Command "ConvertFrom-CIPolicy" -ErrorAction SilentlyContinue) {
        ConvertFrom-CIPolicy -XmlFilePath $suppXmlPath -BinaryFilePath $suppCipPath -ErrorAction Stop
        if (-not (Test-Path $suppCipPath)) { Write-Fail "No .cip produced at: $suppCipPath" }
        Write-OK "Compiled: $suppCipPath"
        if (-not (Test-Path $activeDir)) { New-Item -ItemType Directory -Path $activeDir -Force | Out-Null }
        Get-ChildItem $activeDir -Filter "*.cip" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*$suppGuidBare*" } | ForEach-Object { Remove-Item $_.FullName -Force }
        Copy-Item $suppCipPath (Join-Path $activeDir $suppCipName) -Force
        Write-OK "Deployed: $activeDir\$suppCipName"
        "$suppGuidBare" | Set-Content "$wdacOutDir\supp_browserguard.txt" -Encoding UTF8
        Write-OK "Sidecar: $wdacOutDir\supp_browserguard.txt"
    } else {
        Write-Warn "ConvertFrom-CIPolicy not available. Compile manually:"
        Write-Warn "   ConvertFrom-CIPolicy -XmlFilePath '$suppXmlPath' -BinaryFilePath '$suppCipPath'"
        Write-Warn "   Copy-Item '$suppCipPath' '$activeDir\'"
    }
}

Write-Step "Attempting to start the driver (expected to fail before reboot)"
$startOut = & sc.exe start $ServiceName 2>&1
Write-Host "  $startOut"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " BrowserGuard deployment complete — PLEASE REBOOT NOW" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Driver   : $destSys"
Write-Host " Cert     : CN=$CertSubject  ($($cert.Thumbprint))"
Write-Host ""
Write-Host " After rebooting, the service starts automatically at boot." -ForegroundColor Yellow
"""

PS_BROWSERGUARD_REMOVE = r"""
$ErrorActionPreference = "Continue"

Write-Host "[BrowserGuard Remove]" -ForegroundColor Cyan

Write-Host "Stopping BrowserGuard service..." -ForegroundColor Cyan
$null = & sc.exe stop BrowserGuard 2>&1
Start-Sleep -Seconds 2

Write-Host "Deleting BrowserGuard service..." -ForegroundColor Cyan
$delOut = & sc.exe delete BrowserGuard 2>&1
Write-Host "  $delOut"

Write-Host "Disabling test signing (bcdedit /set testsigning off)..." -ForegroundColor Cyan
$bcdOut = & bcdedit /set testsigning off 2>&1
Write-Host "  $bcdOut"

Write-Host "Re-enabling HVCI (Memory Integrity) in registry..." -ForegroundColor Cyan
$hvciKey = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
if (Test-Path $hvciKey) {
    Set-ItemProperty -Path $hvciKey -Name "Enabled" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "  [OK] HVCI Enabled set back to 1." -ForegroundColor Green
} else {
    Write-Host "  HVCI key not found — skipping." -ForegroundColor Yellow
}

Write-Host "Removing driver from System32\drivers..." -ForegroundColor Cyan
$driverPath = "$env:SystemRoot\System32\drivers\BrowserGuard.sys"
if (Test-Path $driverPath) {
    Remove-Item $driverPath -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Driver removed." -ForegroundColor Green
} else {
    Write-Host "  Driver not found (already removed)." -ForegroundColor Yellow
}

Write-Host "Removing BrowserGuardTestCert from certificate stores..." -ForegroundColor Cyan
foreach ($storeName in @("Root", "TrustedPublisher", "My")) {
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            $storeName,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $certs = @($store.Certificates | Where-Object { $_.Subject -like "*BrowserGuardTestCert*" })
        foreach ($c in $certs) {
            $store.Remove($c)
            Write-Host "  [OK] Removed from LocalMachine\$storeName ($($c.Thumbprint))" -ForegroundColor Green
        }
        if ($certs.Count -eq 0) { Write-Host "  No cert found in LocalMachine\$storeName." -ForegroundColor Gray }
        $store.Close()
    } catch {
        Write-Host "  Could not open/modify store ${storeName}: $_" -ForegroundColor Yellow
    }
}

Write-Host "Removing WDAC supplemental policy (BrowserGuardDriverAllow)..." -ForegroundColor Cyan
$sidecar   = "C:\WDACPolicy\supp_browserguard.txt"
$activeDir = "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"
if (Test-Path $sidecar) {
    $suppGuidBare = (Get-Content $sidecar -Raw).Trim()
    Write-Host "  Supplemental GUID: $suppGuidBare" -ForegroundColor Gray
    $removed = $false
    $ciTool = "$env:SystemRoot\System32\CiTool.exe"
    if (Test-Path $ciTool) {
        $out = & $ciTool --remove-policy $suppGuidBare 2>&1
        Write-Host "  CiTool: $out" -ForegroundColor Gray
        if ($LASTEXITCODE -eq 0) { Write-Host "  [OK] CiTool removed supplemental policy." -ForegroundColor Green; $removed = $true }
    }
    if (-not $removed) {
        $cipPath = Join-Path $activeDir "{$suppGuidBare}.cip"
        if (Test-Path $cipPath) {
            $null = & takeown.exe /f "$cipPath" /A 2>&1
            $null = & icacls.exe "$cipPath" /grant "Administrators:F" 2>&1
            Remove-Item $cipPath -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] Supplemental CIP removed from Active directory." -ForegroundColor Green
        } else {
            Write-Host "  Supplemental CIP not found in Active directory." -ForegroundColor Yellow
        }
    }
    Remove-Item $sidecar -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Sidecar removed." -ForegroundColor Gray
} else {
    Write-Host "  No WDAC sidecar found — skipping supplemental policy removal." -ForegroundColor Yellow
}

Write-Host "Removing C:\BrowserGuard directory..." -ForegroundColor Cyan
if (Test-Path "C:\BrowserGuard") {
    Remove-Item "C:\BrowserGuard" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] C:\BrowserGuard removed." -ForegroundColor Green
} else {
    Write-Host "  C:\BrowserGuard not found (already removed)." -ForegroundColor Gray
}

Write-Host ""
Write-Host "BrowserGuard removed successfully." -ForegroundColor Green
Write-Host "Please REBOOT for test-signing and HVCI changes to fully take effect." -ForegroundColor Yellow
"""


# ─────────────────────────────────────────────────────────────────────────────
# BROWSERGUARD STATUS CHECK
# ─────────────────────────────────────────────────────────────────────────────

def check_browserguard_deployed() -> tuple[str, str]:
    try:
        r = subprocess.run(
            ["sc.exe", "query", "BrowserGuard"],
            capture_output=True, text=True, timeout=5,
            creationflags=_CREATE_NO_WINDOW,
        )
        if r.returncode == 0:
            if "RUNNING" in r.stdout.upper():
                return ("Running", "#4ade80")
            return ("Deployed — reboot to start", "#facc15")
        return ("Not deployed", "#f87171")
    except Exception:
        return ("Not deployed", "#f87171")


def check_firewall_suite_deployed() -> tuple[str, str]:
    exe_present  = FIREWALL_SUITE_EXE.exists()
    task_exists  = False
    try:
        r = subprocess.run(
            ["schtasks", "/Query", "/TN", FIREWALL_TASK_NAME, "/FO", "LIST"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
            creationflags=_CREATE_NO_WINDOW,
        )
        task_exists = (r.returncode == 0)
    except Exception:
        pass

    if exe_present and task_exists:
        return ("Deployed — task active", "#4ade80")
    if exe_present and not task_exists:
        return ("Files present — task missing", "#facc15")
    if not exe_present and task_exists:
        return ("Task registered — files missing", "#facc15")
    return ("Not deployed", "#f87171")


def _extract_firewall_suite() -> None:
    import io, zipfile as _zf
    FIREWALL_SUITE_DIR.mkdir(parents=True, exist_ok=True)
    data = _load_dat("FIREWALL_SUITE")
    with _zf.ZipFile(io.BytesIO(data)) as zf:
        members = zf.namelist()
        prefix = ""
        if members and "/" in members[0]:
            prefix = members[0].split("/")[0] + "/"
        for member in members:
            rel = member[len(prefix):] if prefix and member.startswith(prefix) else member
            if not rel:
                continue
            target = FIREWALL_SUITE_DIR / rel
            if member.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)


def _extract_adapter_guard() -> None:
    import io, zipfile as _zf
    ADAPTER_GUARD_DIR.mkdir(parents=True, exist_ok=True)
    data = _load_dat("ADAPTER_GUARD")
    with _zf.ZipFile(io.BytesIO(data)) as zf:
        members = zf.namelist()
        prefix = ""
        if members and "/" in members[0]:
            prefix = members[0].split("/")[0] + "/"
        for member in members:
            rel = member[len(prefix):] if prefix and member.startswith(prefix) else member
            if not rel:
                continue
            target = ADAPTER_GUARD_DIR / rel
            if member.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)


def check_adapter_guard_deployed() -> tuple[str, str]:
    exe_present = ADAPTER_GUARD_EXE.exists()
    task_exists = False
    try:
        r = subprocess.run(
            ["schtasks", "/Query", "/TN", ADAPTER_GUARD_TASK_NAME, "/FO", "LIST"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
            creationflags=_CREATE_NO_WINDOW,
        )
        task_exists = (r.returncode == 0)
    except Exception:
        pass

    if exe_present and task_exists:
        return ("Deployed — task active", "#4ade80")
    if exe_present and not task_exists:
        return ("Files present — task missing", "#facc15")
    if not exe_present and task_exists:
        return ("Task registered — files missing", "#facc15")
    return ("Not deployed", "#f87171")


def _read_active_adapter_names() -> list[str]:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-NetAdapter | Where-Object { $_.InterfaceDescription -ne '' -and "
             "$_.Status -ne 'Not Present' } | "
             "Sort-Object Name | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True, timeout=20,
            encoding="utf-8", errors="replace",
            creationflags=_CREATE_NO_WINDOW,
        )
        if r.returncode == 0:
            names = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
            if names:
                return names
    except Exception:
        pass

    try:
        import wmi as _wmi  # type: ignore
        c = _wmi.WMI()
        skip = {4, 5, 6}
        return [
            a.NetConnectionID
            for a in c.Win32_NetworkAdapter()
            if a.NetConnectionID
            and (a.NetConnectionStatus not in skip)
        ]
    except Exception:
        return []


def _extract_dns_suite() -> None:
    import io, zipfile as _zf
    DNS_SUITE_DIR.mkdir(parents=True, exist_ok=True)
    data = _load_dat("DNS_SUITE")
    with _zf.ZipFile(io.BytesIO(data)) as zf:
        members = zf.namelist()
        prefix = ""
        if members and "/" in members[0]:
            prefix = members[0].split("/")[0] + "/"
        for member in members:
            rel = member[len(prefix):] if prefix and member.startswith(prefix) else member
            if not rel:
                continue
            target = DNS_SUITE_DIR / rel
            if member.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)


def check_dns_suite_deployed(capable_count: int | None = None) -> tuple[str, str]:
    exe_present  = DNS_SERVER_EXE.exists()
    task_exists  = False
    try:
        r = subprocess.run(
            ["schtasks", "/Query", "/TN", DNS_TASK_NAME, "/FO", "LIST"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
            creationflags=_CREATE_NO_WINDOW,
        )
        task_exists = (r.returncode == 0)
    except Exception:
        pass

    if not exe_present and not task_exists:
        return ("Not deployed", "#f87171")
    if exe_present and not task_exists:
        return ("Files present — task missing", "#facc15")
    if not exe_present and task_exists:
        return ("Task registered — files missing", "#facc15")

    if capable_count is None:
        capable_count = 0
        if DNS_CAPABLE_FILE.is_file():
            try:
                capable_count = sum(
                    1 for ln in
                    DNS_CAPABLE_FILE.read_text(encoding="utf-8").splitlines()
                    if ln.strip()
                )
            except Exception:
                pass

    if capable_count == 0:
        return ("Deployed — WARNING: no DNS-capable adapters", "#fb923c")
    return ("Deployed — task active", "#4ade80")


def _is_task_running(task_name: str) -> bool:
    try:
        r = subprocess.run(
            ["schtasks", "/Query", "/TN", task_name, "/FO", "LIST"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
            creationflags=_CREATE_NO_WINDOW,
        )
        if r.returncode != 0:
            return False
        for line in r.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Status:"):
                return "Running" in stripped
    except Exception:
        pass
    return False


def _task_exists(task_name: str) -> bool:
    try:
        r = subprocess.run(
            ["schtasks", "/Query", "/TN", task_name, "/FO", "LIST"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
            creationflags=_CREATE_NO_WINDOW,
        )
        return r.returncode == 0
    except Exception:
        return False


def _is_exe_running(exe_name: str) -> bool:
    """Return True if a process named *exe_name* exists in the process list.

    Uses tasklist without the /FI filter to avoid truncation bugs with long names
    (like dns_whitelist_blacklist_server.exe) that cause false negatives.
    """
    try:
        r = subprocess.run(
            ["tasklist", "/NH", "/FO", "CSV"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace",
            creationflags=_CREATE_NO_WINDOW,
        )
        return exe_name.lower() in r.stdout.lower()
    except Exception:
        return False


# ── DNS domain-file helpers ───────────────────────────────────────────────────

def _load_json_list(path: Path) -> list[str]:
    """Load a JSON array of strings from *path*, returning [] on any error."""
    try:
        import json as _j
        return sorted(_j.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return []


def _save_json_list(path: Path, items: list[str]) -> None:
    """Write *items* as a sorted JSON array to *path*."""
    import json as _j
    path.write_text(_j.dumps(sorted(items), indent=2), encoding="utf-8")


def _load_access_log() -> dict[str, str]:
    """Return {domain: iso_timestamp} from domain_access_log.json, or {}."""
    try:
        import json as _j
        return _j.loads(DNS_ACCESS_LOG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _days_since(iso_ts: str) -> int:
    """Return whole days elapsed since *iso_ts* (UTC ISO-8601 string)."""
    from datetime import datetime, timezone
    try:
        last = datetime.fromisoformat(iso_ts)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - last
        return max(0, delta.days)
    except Exception:
        return 0


def _read_config_value(path: Path) -> str:
    """Read a single-value config file, returning '' on any error."""
    try:
        return path.read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def _get_all_adapter_names() -> list[str]:
    """Return display names of all network adapters visible in Network Connections.

    Tries PowerShell (Get-NetAdapter) first — reliable in background threads.
    Falls back to WMI if PowerShell fails.  Returns [] only if both fail.
    """
    # Primary: PowerShell Get-NetAdapter (no COM/WMI threading concerns)
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-NetAdapter | Where-Object { $_.InterfaceDescription -ne '' -and "
             "$_.Status -ne 'Not Present' } | "
             "Sort-Object Name | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True, timeout=20,
            encoding="utf-8", errors="replace",
            creationflags=_CREATE_NO_WINDOW,
        )
        if r.returncode == 0:
            names = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
            if names:
                return names
    except Exception:
        pass

    # Fallback: WMI (may be unreliable in some threading contexts)
    try:
        import wmi as _wmi  # type: ignore
        skip = {4, 5, 6}
        c = _wmi.WMI()
        names = sorted(
            a.NetConnectionID
            for a in c.Win32_NetworkAdapter()
            if a.NetConnectionID and (a.NetConnectionStatus not in skip)
        )
        if names:
            return names
    except Exception:
        pass

    return []


def _classify_adapters_live() -> tuple[list[str], list[str]]:
    """Query every visible adapter and split into (incapable, capable) lists.

    Uses a SINGLE PowerShell call to check all adapters at once — avoids the
    per-adapter process-spawn overhead and eliminates the race condition where
    individual timeouts left both listboxes empty.

    Guarantee: every adapter returned by _get_all_adapter_names() will appear
    in exactly one of the two returned lists.  On any error the entire adapter
    list goes into the incapable bucket so the UI is never left blank.
    """
    all_names = _get_all_adapter_names()
    if not all_names:
        return [], []

    # One PowerShell process classifies all adapters in a single round-trip.
    # Output format: "AdapterName|True"  or  "AdapterName|False"
    # True  = DNS-capable  (IPv4 DNS contains 127.0.0.1  AND  IPv6 binding disabled)
    # False = DNS-incapable (anything else, or any error on that adapter)
    _PS_CLASSIFY = r"""
$adapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -ne '' -and $_.Status -ne 'Not Present' } | Sort-Object Name
foreach ($a in $adapters) {
    $name = $a.Name
    $idx  = $a.InterfaceIndex
    try {
        $dnsAddrs    = (Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses
        $hasLoopback = ($dnsAddrs -contains '127.0.0.1')
        $ipv6Enabled = (Get-NetAdapterBinding -Name $name -ComponentID ms_tcpip6 -ErrorAction Stop).Enabled
        $capable     = ($hasLoopback -and (-not $ipv6Enabled))
    } catch {
        $capable = $false
    }
    Write-Output "${name}|${capable}"
}
"""
    capable_set:   set[str] = set()
    incapable_set: set[str] = set()
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_CLASSIFY],
            capture_output=True, text=True, timeout=45,
            encoding="utf-8", errors="replace",
            creationflags=_CREATE_NO_WINDOW,
        )
        if r.returncode == 0:
            for raw in r.stdout.splitlines():
                raw = raw.strip()
                if "|" not in raw:
                    continue
                name, _, state = raw.rpartition("|")
                name = name.strip()
                if not name:
                    continue
                if state.strip().lower() == "true":
                    capable_set.add(name)
                else:
                    incapable_set.add(name)
    except Exception:
        pass   # fall through to guarantee-pass below

    # Guarantee: every known adapter appears in exactly one list.
    # Adapters not returned by PowerShell (e.g. disabled/virtual) go incapable.
    classified = capable_set | incapable_set
    for n in all_names:
        if n not in classified:
            incapable_set.add(n)

    # Preserve sort order from all_names
    capable   = [n for n in all_names if n in capable_set]
    incapable = [n for n in all_names if n not in capable_set]
    return incapable, capable


def _extract_browserguard_sys() -> Path:
    """Read BROWSERGUARD_SYS.dat and extract BrowserGuard.sys to BROWSERGUARD_DIR.

    encode_decode.py always zips its targets, so BROWSERGUARD_SYS.dat is a zip
    archive containing a single entry named 'BrowserGuard.sys'.  We extract that
    one file and return its on-disk path.
    """
    import io, zipfile as _zf
    data = _load_dat("BROWSERGUARD_SYS")   # raw zip bytes from BROWSERGUARD_SYS.dat
    BROWSERGUARD_DIR.mkdir(parents=True, exist_ok=True)
    out_path = BROWSERGUARD_DIR / "BrowserGuard.sys"
    with _zf.ZipFile(io.BytesIO(data)) as zf:
        # The archive contains exactly one file; extract it directly.
        names = [n for n in zf.namelist() if not n.endswith("/")]
        if not names:
            raise RuntimeError("BROWSERGUARD_SYS.dat archive is empty.")
        with zf.open(names[0]) as src:
            out_path.write_bytes(src.read())
    return out_path


# ─────────────────────────────────────────────────────────────────────────────
# POWERSHELL RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def _get_powershell_exe() -> str:
    """Return a path to the 64-bit powershell.exe, even when called from a 32-bit process.

    Under WOW64 (32-bit Python on 64-bit Windows) the OS silently redirects
    System32 -> SysWOW64 for the calling process.  That means the bare name
    "powershell" resolves to the 32-bit shell, whose module search path also
    points into SysWOW64 — where ConfigCI (and several other admin modules)
    simply do not exist.

    "SysNative" is a virtual directory that WOW64 exposes *only* to 32-bit
    processes; it bypasses the redirect and points at the real 64-bit
    System32.  If we're already a 64-bit process SysNative won't exist, but
    then System32 is already the real one, so the explicit System32 path works.
    """
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    for candidate in (
        root / "SysNative"  / "WindowsPowerShell" / "v1.0" / "powershell.exe",  # 32-bit process on 64-bit OS
        root / "System32"   / "WindowsPowerShell" / "v1.0" / "powershell.exe",  # 64-bit process (or already resolved)
    ):
        if candidate.exists():
            return str(candidate)
    return "powershell"  # last-resort fallback


def run_ps(script: str, args: list[str], callback, workdir: str | None = None):
    with tempfile.NamedTemporaryFile(suffix=".ps1", mode="wb", delete=False) as f:
        f.write(b"\xef\xbb\xbf")
        f.write(script.encode("utf-8"))
        tmp = f.name
    cmd = [_get_powershell_exe(),
           "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
           "-ExecutionPolicy", "Bypass", "-File", tmp] + args
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
            cwd=workdir or str(APP_DIR),
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
        )
        for line in proc.stdout:
            callback(line.rstrip())
        proc.wait()
        rc = proc.returncode
        callback(f"\n[Exit code: {rc}]")
        return rc == 0
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────────────────
# STATE PERSISTENCE
# ─────────────────────────────────────────────────────────────────────────────

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {
        "restricted_user": "",
        "blocked_files": DEFAULT_BLOCKED_FILES,
        "wdac_policy_name": DEFAULT_WDAC_POLICY,
        "wdac_publishers": DEFAULT_WDAC_PUBLISHERS,
        "wdac_exe_hashes": [],
        "wdac_disable_script": True,
        "chrome_ext_allowlist": [],
        "edge_ext_allowlist": [],
        "proxy_username": "",
    }

def save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2))

# ─────────────────────────────────────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────────────────────────────────────

DARK   = "#0f1117"
PANEL  = "#1a1d27"
CARD   = "#21242f"
BORDER = "#2e3247"
ACCENT = "#6c8fff"
ACCENT2= "#a78bfa"
TEXT   = "#e2e8f0"
FG     = TEXT          # alias — some widgets reference FG, others TEXT
MUTED  = "#64748b"
GREEN  = "#4ade80"
YELLOW = "#facc15"
ORANGE = "#fb923c"
RED    = "#f87171"
FONT_MAIN = ("Consolas", 10)
FONT_HEAD = ("Consolas", 11, "bold")
FONT_TITLE= ("Consolas", 14, "bold")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Windows Restriction Manager")
        self.configure(bg=DARK)
        self.geometry("1080x780")
        self.minsize(900, 640)
        self.state = load_state()
        self._task_toggles = [] # holds refresh functions for the start/stop tasks
        self._build_ui()
        self.after(200, self.refresh_all_status)
        
        # Kick off specialized background monitor
        threading.Thread(target=self._focused_background_monitor, daemon=True).start()

    def _focused_background_monitor(self):
        """Dedicated background thread to monitor task toggles and DNS lists."""
        counter = 0
        while True:
            time.sleep(2.5)
            counter += 2.5

            # 1. Update all Start/Stop toggles actively
            for check_fn in self._task_toggles:
                try:
                    check_fn()
                except Exception:
                    pass

            # 2. Update DNS Whitelist/Blacklist (every ~7.5 seconds)
            if counter >= 7.5:
                counter = 0
                try:
                    # Only refresh if deployed and server is actively running
                    if DNS_SERVER_EXE.exists() and _is_exe_running("dns_whitelist_blacklist_server.exe"):
                        self.after(0, self._cb_refresh_wl)
                        self.after(0, self._cb_refresh_bl)
                except Exception:
                    pass

    def _build_ui(self):
        hdr = tk.Frame(self, bg=PANEL, pady=10)
        hdr.pack(fill="x")
        tk.Label(hdr, text="⚙  Windows Restriction Manager",
                 font=FONT_TITLE, fg=ACCENT, bg=PANEL).pack(side="left", padx=18)
        tk.Label(hdr, text="Run as Administrator",
                 font=FONT_MAIN, fg=GREEN, bg=PANEL).pack(side="right", padx=18)

        body = tk.Frame(self, bg=DARK)
        body.pack(fill="both", expand=True, padx=12, pady=8)

        canvas_frame = tk.Frame(body, bg=DARK)
        canvas_frame.pack(side="left", fill="both", expand=True)

        canvas = tk.Canvas(canvas_frame, bg=DARK, highlightthickness=0)
        v_scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
        h_scrollbar = ttk.Scrollbar(canvas_frame, orient="horizontal", command=canvas.xview)
        self.cards_frame = tk.Frame(canvas, bg=DARK)
        self.cards_frame.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        cards_window = canvas.create_window((0, 0), window=self.cards_frame, anchor="nw")
        canvas.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        # Keep cards_frame width flush with the canvas so they don't float narrow
        canvas.bind("<Configure>",
            lambda e: canvas.itemconfig(cards_window, width=e.width))
        h_scrollbar.pack(side="bottom", fill="x")
        canvas.pack(side="left", fill="both", expand=True)
        v_scrollbar.pack(side="right", fill="y")
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(-1*(e.delta//120), "units"))

        log_frame = tk.Frame(body, bg=PANEL, bd=0)
        log_frame.pack(side="right", fill="both", padx=(10, 0))
        log_frame.configure(width=340)
        log_frame.pack_propagate(False)

        tk.Label(log_frame, text="Output Log", font=FONT_HEAD,
                 fg=ACCENT, bg=PANEL).pack(anchor="w", padx=10, pady=(8, 2))
        self.log = scrolledtext.ScrolledText(
            log_frame, bg="#0b0d14", fg="#94a3b8",
            font=("Consolas", 9), wrap="word", state="disabled",
            relief="flat", borderwidth=0)
        self.log.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.log.tag_config("ok",   foreground=GREEN)
        self.log.tag_config("err",  foreground=RED)
        self.log.tag_config("warn", foreground=YELLOW)
        self.log.tag_config("info", foreground=ACCENT)
        self.log.tag_config("head", foreground=ACCENT2, font=("Consolas", 9, "bold"))

        btn_row = tk.Frame(log_frame, bg=PANEL)
        btn_row.pack(fill="x", padx=6, pady=(0, 8))
        self._btn(btn_row, "Clear Log",  self._clear_log,  MUTED, side="left")

        bar = tk.Frame(self, bg=PANEL, pady=8)
        bar.pack(fill="x", side="bottom")
        self.status_label = tk.Label(bar, text="Ready.", font=FONT_MAIN,
                                     fg=MUTED, bg=PANEL)
        self.status_label.pack(side="right", padx=18)

        self._build_cards()

    def _btn(self, parent, text, cmd, color=ACCENT, side="left", padx=6, pady=3, anchor=None):
        b = tk.Button(parent, text=text, command=cmd,
                      bg=color, fg="white" if color != MUTED else TEXT,
                      font=FONT_MAIN, relief="flat", cursor="hand2",
                      activebackground=color, activeforeground="white",
                      padx=10, pady=pady)
        if anchor:
            b.pack(side=side, padx=padx, anchor=anchor)
        else:
            b.pack(side=side, padx=padx)
        return b

    def _card(self, title: str, description: str) -> tk.Frame:
        outer = tk.Frame(self.cards_frame, bg=CARD, bd=1, relief="flat",
                         highlightbackground=BORDER, highlightthickness=1)
        outer.pack(fill="x", pady=4, padx=2)
        hdr = tk.Frame(outer, bg=CARD)
        hdr.pack(fill="x", padx=12, pady=(10, 2))
        tk.Label(hdr, text=title, font=FONT_HEAD, fg=TEXT, bg=CARD).pack(side="left")
        tk.Label(outer, text=description, font=("Consolas", 9),
                 fg=MUTED, bg=CARD, wraplength=460, justify="left").pack(
                     anchor="w", padx=12, pady=(0, 6))
        return outer

    def _status_row(self, parent, label="Status:") -> tk.Label:
        row = tk.Frame(parent, bg=CARD)
        row.pack(fill="x", padx=12, pady=(0, 4))
        tk.Label(row, text=label, font=FONT_MAIN, fg=MUTED, bg=CARD).pack(side="left")
        lbl = tk.Label(row, text="Checking...", font=FONT_MAIN, fg=YELLOW, bg=CARD)
        lbl.pack(side="left", padx=6)
        return lbl

    def _field(self, parent, label: str, default: str, width=44) -> tk.Entry:
        row = tk.Frame(parent, bg=CARD)
        row.pack(fill="x", padx=12, pady=2)
        tk.Label(row, text=label, font=FONT_MAIN, fg=MUTED, bg=CARD, width=20,
                 anchor="w").pack(side="left")
        var = tk.StringVar(value=default)
        e = tk.Entry(row, textvariable=var, font=FONT_MAIN, bg=PANEL,
                     fg=TEXT, insertbackground=TEXT, relief="flat",
                     highlightbackground=BORDER, highlightthickness=1, width=width)
        e.pack(side="left", fill="x", expand=True)
        e.var = var  # Expose the variable for trace bindings
        return e

    def _text_area(self, parent, label: str, default: str, height=3) -> tk.Text:
        tk.Label(parent, text=label, font=FONT_MAIN, fg=MUTED, bg=CARD).pack(
            anchor="w", padx=12, pady=(4, 0))
        t = tk.Text(parent, font=("Consolas", 9), bg=PANEL, fg=TEXT,
                    insertbackground=TEXT, relief="flat",
                    highlightbackground=BORDER, highlightthickness=1,
                    height=height, wrap="none")
        t.insert("1.0", default)
        t.pack(fill="x", padx=12, pady=(0, 4))
        return t

    def _btn_row(self, parent, apply_cmd, remove_cmd, extra=None):
        row = tk.Frame(parent, bg=CARD)
        row.pack(fill="x", padx=12, pady=(4, 10))
        self._btn(row, "Apply", apply_cmd, "#22c55e", side="left", padx=0)
        self._btn(row, "Remove", remove_cmd, RED, side="left", padx=6)
        if extra:
            for label, cmd, color in extra:
                self._btn(row, label, cmd, color, side="left", padx=6)

    def _task_toggle_row(self, parent: tk.Widget, task_name: str,
                         exe_name: str | None = None,
                         exe_path: "Path | None" = None) -> tk.Button:
        """Add a Start Task / Stop Task toggle button row to *parent*."""
        row = tk.Frame(parent, bg=CARD)
        row.pack(fill="x", padx=12, pady=(0, 10))

        btn = tk.Button(row, text="Start Task", command=lambda: None,
                        bg=MUTED, fg=MUTED,
                        font=FONT_MAIN, relief="flat",
                        activeforeground="white", padx=10, pady=3,
                        state="disabled", cursor="")
        btn.pack(side="left")

        def _is_deployed() -> bool:
            task_ok = _task_exists(task_name)
            exe_ok  = (exe_path is None or exe_path.exists())
            return task_ok and exe_ok

        def _running() -> bool:
            if exe_name:
                return _is_exe_running(exe_name)
            return _is_task_running(task_name)

        def _update(deployed: bool, running: bool) -> None:
            if not deployed:
                btn.configure(text="Start Task", bg=MUTED, fg=MUTED,
                              activebackground=MUTED, state="disabled", cursor="")
            elif running:
                btn.configure(text="Stop Task", bg=RED, fg="white",
                              activebackground=RED, state="normal", cursor="hand2")
            else:
                btn.configure(text="Start Task", bg=GREEN, fg="white",
                              activebackground=GREEN, state="normal", cursor="hand2")

        # Refresher method to be called by background thread or fast-poll
        def _check_and_update():
            d = _is_deployed()
            r = _running() if d else False
            self.after(0, lambda: _update(d, r))

        self._task_toggles.append(_check_and_update)

        def _toggle() -> None:
            def _worker():
                currently = _running()
                if currently:
                    subprocess.run(["schtasks", "/End", "/TN", task_name],
                                   capture_output=True, timeout=10,
                                   creationflags=_CREATE_NO_WINDOW)
                    self._log("ok", f"[OK] Task stop requested: {task_name}")
                    deadline = time.time() + 5
                    while time.time() < deadline:
                        if not _running(): break
                        time.sleep(0.4)
                else:
                    subprocess.run(["schtasks", "/Run", "/TN", task_name],
                                   capture_output=True, timeout=10,
                                   creationflags=_CREATE_NO_WINDOW)
                    self._log("ok", f"[OK] Task start requested: {task_name}")
                    deadline = time.time() + 5
                    while time.time() < deadline:
                        if _running(): break
                        time.sleep(0.4)
                _check_and_update()
            threading.Thread(target=_worker, daemon=True).start()

        btn.configure(command=_toggle)
        threading.Thread(target=_check_and_update, daemon=True).start()

        return btn

    def _build_cards(self):
        s = self.state

        # ── 1. ACL Restrictions
        c = self._card("🔒  ACL File Restrictions",
                       "Deny FullControl NTFS permissions on system executables for a restricted user.")
        self.acl_status = self._status_row(c)
        self.acl_user   = self._field(c, "Restricted Username:", s.get("restricted_user",""))
        self.acl_files  = self._text_area(c, "Files to block (one per line):",
                                          "\n".join(s.get("blocked_files", DEFAULT_BLOCKED_FILES)), height=4)

        def _apply_acl():
            user = self.acl_user.get().strip()
            files = [l.strip() for l in self.acl_files.get("1.0","end").splitlines() if l.strip()]
            if not user:
                messagebox.showerror("Missing input", "Please enter a restricted username.")
                return
            existing = sorted(glob.glob(ACL_BACKUP_GLOB))
            if existing:
                messagebox.showerror(
                    "Already Applied",
                    "ACL restrictions appear to already be active.\n\n"
                    f"An existing backup was found at:\n{existing[-1]}\n\n"
                    "Applying again would create a backup of already-modified permissions, "
                    "which could permanently corrupt the system's original NTFS state.\n\n"
                    "Click 'Remove' to restore original permissions first.")
                return
            s["restricted_user"] = user
            s["blocked_files"] = files
            save_state(s)
            args = ["-FileNamesCSV", ",".join(files), "-Username", user]
            self._run_threaded("ACL Restrictions", PS_RESTRICT_ACL, args,
                               after=self.refresh_all_status)

        def _restore_acl():
            backups = sorted(glob.glob(ACL_BACKUP_GLOB))
            if not backups:
                messagebox.showerror("No backup", "No ACL backup file found next to this script.")
                return
            latest = backups[-1]
            self._run_threaded("Restore ACL", PS_RESTORE_ACL, ["-BackupFile", latest],
                               after=self.refresh_all_status)

        def _pick_backup():
            init_dir = str(ACL_BACKUP_DIR) if ACL_BACKUP_DIR.exists() else str(Path.home())
            path = filedialog.askopenfilename(
                title="Select ACL backup XML",
                initialdir=init_dir,
                filetypes=[("XML backup", "acl_backup_multi_*.xml"), ("All XML", "*.xml")])
            if path:
                self._run_threaded("Restore ACL (custom)", PS_RESTORE_ACL,
                                   ["-BackupFile", path], after=self.refresh_all_status)

        self._btn_row(c, _apply_acl, _restore_acl,
                      extra=[("Restore from file...", _pick_backup, ACCENT)])

        # ── 2. WDAC Policy
        c2 = self._card("🛡  WDAC Application Control",
                        "Deploy a Windows Defender Application Control policy to block unauthorized executables.")
        self.wdac_status = self._status_row(c2)
        self.wdac_name   = self._field(c2, "Policy Name:", s.get("wdac_policy_name", DEFAULT_WDAC_POLICY))
        self.wdac_pubs   = self._text_area(c2, "Allow Publishers (one per line):",
                                            "\n".join(s.get("wdac_publishers", [])), height=2)
        self.wdac_paths  = self._text_area(c2, "Allow Extra Paths (one per line, e.g. %OSDRIVE%\\MyTools\\*):",
                                            "\n".join(s.get("wdac_extra_paths", [])), height=2)
        self.wdac_hashes = self._text_area(c2, "Allow EXE hash paths (one per line):",
                                            "\n".join(s.get("wdac_exe_hashes", [])), height=3)
        self.wdac_script_var = tk.BooleanVar(value=s.get("wdac_disable_script", True))
        tk.Checkbutton(c2, text="Disable Script Enforcement (keeps PowerShell unrestricted)",
                       variable=self.wdac_script_var, fg=TEXT, bg=CARD,
                       activebackground=CARD, selectcolor=PANEL,
                       font=FONT_MAIN).pack(anchor="w", padx=12)

        def _apply_wdac():
            name = self.wdac_name.get().strip()
            current_txt, _ = check_wdac_deployed(name)
            if current_txt.startswith("Active:") or current_txt.startswith("Built"):
                messagebox.showerror(
                    "Already Deployed",
                    f"A WDAC policy is already active or pending reboot:\n\n\"{current_txt}\"\n\n"
                    "Deploying a second policy while one is active can stack conflicting "
                    "policies and make the system difficult to recover.\n\n"
                    "Click 'Remove' and reboot before re-deploying.")
                return
            pubs   = [l.strip() for l in self.wdac_pubs.get("1.0","end").splitlines() if l.strip()]
            paths  = [l.strip() for l in self.wdac_paths.get("1.0","end").splitlines() if l.strip()]
            hashes = [l.strip() for l in self.wdac_hashes.get("1.0","end").splitlines() if l.strip()]
            s["wdac_policy_name"]    = name
            s["wdac_publishers"]     = pubs
            s["wdac_extra_paths"]    = paths
            s["wdac_exe_hashes"]     = hashes
            s["wdac_disable_script"] = self.wdac_script_var.get()
            save_state(s)
            args = ["-PolicyName", name, "-Mode", "Enforce", "-Deploy"]
            if pubs:   args += ["-AllowPublishersCSV",  ",".join(pubs)]
            if paths:  args += ["-AllowExtraPathsCSV",  ",".join(paths)]
            if hashes: args += ["-AllowExeHashesCSV",   ",".join(hashes)]
            if self.wdac_script_var.get(): args.append("-DisableScriptEnforcement")
            self._run_threaded("WDAC Policy", PS_WDAC_CREATE, args,
                               after=self.refresh_all_status)

        def _undo_wdac():
            name = self.wdac_name.get().strip()
            self._run_threaded("WDAC Undo", PS_WDAC_UNDO, ["-PolicyName", name],
                               after=self.refresh_all_status)

        self._btn_row(c2, _apply_wdac, _undo_wdac)

        # ── 3. Windows Store
        c3 = self._card("🛒  Block Windows Store",
                        "Disable InstallService and add an outbound firewall rule blocking the Store app.")
        self.store_status = self._status_row(c3)
        self._btn_row(c3,
            lambda: self._run_threaded("Block Store", PS_BLOCK_STORE, [], after=self.refresh_all_status),
            lambda: self._run_threaded("Unblock Store", PS_UNBLOCK_STORE, [], after=self.refresh_all_status))

        # ── 4. Chrome DoH
        c4 = self._card("🌐  Chrome -- Disable DoH",
                        "Set registry policy to force DNS-over-HTTPS off in Google Chrome.")
        self.chrome_doh_status = self._status_row(c4)
        self._btn_row(c4,
            lambda: self._run_reg_threaded("Chrome DoH", apply_doh_chrome, after=self.refresh_all_status),
            lambda: self._run_reg_threaded("Chrome DoH (remove)", remove_doh_chrome, after=self.refresh_all_status))

        # ── 5. Edge DoH
        c5 = self._card("🌐  Edge -- Disable DoH",
                        "Set registry policy to force DNS-over-HTTPS off in Microsoft Edge.")
        self.edge_doh_status = self._status_row(c5)
        self._btn_row(c5,
            lambda: self._run_reg_threaded("Edge DoH", apply_doh_edge, after=self.refresh_all_status),
            lambda: self._run_reg_threaded("Edge DoH (remove)", remove_doh_edge, after=self.refresh_all_status))

        # ── 6. Extension Lockdown
        c6 = self._card("🧩  Browser Extension Lockdown",
                        "Block all Chrome/Edge extension installs except an explicit allowlist.")
        self.ext_status = self._status_row(c6)

        def _detect_chrome():
            found = detect_chrome_extensions()
            if not found:
                self._log("warn", "No Chrome extensions detected.")
                return
            self._log("head", f"Detected {len(found)} Chrome extension(s):")
            for eid, name in found.items():
                self._log("info", f"  {eid}  --  {name}")
            self.chrome_ext.delete("1.0", "end")
            self.chrome_ext.insert("1.0", "\n".join(found.keys()))

        def _detect_edge():
            found = detect_edge_extensions()
            if not found:
                self._log("warn", "No Edge extensions detected.")
                return
            self._log("head", f"Detected {len(found)} Edge extension(s):")
            for eid, name in found.items():
                self._log("info", f"  {eid}  --  {name}")
            self.edge_ext.delete("1.0", "end")
            self.edge_ext.insert("1.0", "\n".join(found.keys()))

        tk.Button(c6, text="🔍 Auto-detect Chrome Extensions",
                  command=_detect_chrome, bg=ACCENT2, fg="white",
                  font=FONT_MAIN, relief="flat", cursor="hand2",
                  padx=8, pady=2).pack(anchor="w", padx=12, pady=(0, 4))

        self.chrome_ext = self._text_area(c6, "Chrome allowed extension IDs (one per line):",
                                           "\n".join(s.get("chrome_ext_allowlist", [])), height=3)
        tk.Button(c6, text="🔍 Auto-detect Edge Extensions",
                  command=_detect_edge, bg=ACCENT2, fg="white",
                  font=FONT_MAIN, relief="flat", cursor="hand2",
                  padx=8, pady=2).pack(anchor="w", padx=12, pady=(0, 4))
        self.edge_ext   = self._text_area(c6, "Edge allowed extension IDs (one per line):",
                                           "\n".join(s.get("edge_ext_allowlist", [])), height=2)

        def _apply_ext():
            c_ids = [l.strip() for l in self.chrome_ext.get("1.0","end").splitlines() if l.strip()]
            e_ids = [l.strip() for l in self.edge_ext.get("1.0","end").splitlines() if l.strip()]
            s["chrome_ext_allowlist"] = c_ids
            s["edge_ext_allowlist"]   = e_ids
            save_state(s)
            self._run_reg_threaded("Extension Lockdown",
                lambda: apply_ext_lockdown(c_ids, e_ids),
                after=self.refresh_all_status)

        self._btn_row(c6, _apply_ext,
            lambda: self._run_reg_threaded("Ext Lockdown (remove)", remove_ext_lockdown,
                                           after=self.refresh_all_status))

        # ── 7. Windows Proxy Lock
        c7 = self._card(
            "🔐  Windows Proxy Lock",
            "Prevent a non-admin user from toggling Windows proxy settings by applying a DENY ACE "
            "to their Internet Settings registry key.  The proxy is forced OFF before locking so the "
            "user is never permanently stuck with a proxy enabled.  MUST be a non-admin account.")
        self.proxy_status = self._status_row(c7)

        warn_row = tk.Frame(c7, bg=CARD)
        warn_row.pack(fill="x", padx=12, pady=(0, 2))
        tk.Label(warn_row,
                 text="⚠  Entering an administrator account name will be blocked.",
                 font=("Consolas", 9), fg=YELLOW, bg=CARD).pack(side="left")

        self.proxy_user = self._field(c7, "Non-admin Username:", s.get("proxy_username", ""))
        self._proxy_typing_timer = None

        def _on_proxy_type(*args):
            if self._proxy_typing_timer:
                self.after_cancel(self._proxy_typing_timer)
            self._proxy_typing_timer = self.after(500, _do_proxy_check)

        def _do_proxy_check():
            user = self.proxy_user.var.get().strip()
            def worker():
                txt, col = check_proxy_locked(user)
                self._set_status(self.proxy_status, txt, col)
            threading.Thread(target=worker, daemon=True).start()

        self.proxy_user.var.trace_add("write", _on_proxy_type)

        def _apply_proxy():
            user = self.proxy_user.var.get().strip()
            if not user:
                messagebox.showerror("Missing input",
                                     "Please enter the username of the non-admin account to lock.")
                return
            current_status = self.proxy_status.cget("text")
            if current_status.startswith("Locked"):
                messagebox.showinfo(
                    "Already locked",
                    f"Proxy settings are already locked for '{user}'.\n\n"
                    "Click \"Remove\" if you want to unlock them.")
                return
            if _is_user_local_admin(user):
                messagebox.showerror(
                    "Administrator account detected",
                    f"'{user}' is a member of the local Administrators group.\n\n"
                    "Applying a proxy lock to an admin account can permanently corrupt "
                    "the registry proxy state and is therefore blocked.\n\n"
                    "Enter the username of the RESTRICTED (non-admin) account.")
                return
            s["proxy_username"] = user
            save_state(s)
            self._run_threaded("Proxy Lock", PS_PROXY_LOCK, ["-Username", user],
                               after=self.refresh_all_status)

        def _remove_proxy():
            user = self.proxy_user.var.get().strip()
            if not user:
                messagebox.showerror("Missing input",
                                     "Please enter the username whose proxy lock should be removed.")
                return
            s["proxy_username"] = user
            save_state(s)
            self._run_threaded("Proxy Unlock", PS_PROXY_UNLOCK, ["-Username", user],
                               after=self.refresh_all_status)

        self._btn_row(c7, _apply_proxy, _remove_proxy)

        # ── 8. BrowserGuard
        c8 = self._card(
            "🛡  BrowserGuard — Browser Argument Lockdown",
            "Deploys the BrowserGuard kernel driver, which intercepts and blocks any attempt to "
            "pass command-line arguments to Google Chrome or Microsoft Edge — whether via a shortcut, "
            "command prompt, or script.  Requires test-signing mode and a reboot to activate.")
        self.bg_status = self._status_row(c8)

        skip_wdac_var = tk.BooleanVar(value=False)
        skip_row = tk.Frame(c8, bg=CARD)
        skip_row.pack(fill="x", padx=12, pady=(2, 0))
        tk.Checkbutton(skip_row, text="Skip WDAC supplemental policy  (use if no WDAC base policy is deployed)",
                       variable=skip_wdac_var, bg=CARD, fg=FG, selectcolor=CARD,
                       activebackground=CARD, activeforeground=FG,
                       font=("Consolas", 9)).pack(side="left")

        def _apply_browserguard():
            current = self.bg_status.cget("text")
            if current.startswith(("Running", "Deployed")):
                messagebox.showinfo("Already Deployed",
                    "BrowserGuard is already deployed on this machine.\n\n"
                    "Click Remove to uninstall it first.")
                return
            if not _has_dat("BROWSERGUARD_SYS"):
                messagebox.showerror("Driver Not Found",
                    "BROWSERGUARD_SYS.dat is not present.\n\n"
                    "To generate it:\n"
                    "  1. Place BrowserGuard.sys next to encode_decode.py and run:\n"
                    "         python encode_decode.py --encode\n"
                    "  2a. Un-compiled use: copy BROWSERGUARD_SYS.dat next to this script.\n"
                    "  2b. PyInstaller use: recompile with --add-data \"BROWSERGUARD_SYS.dat;\"")
                return
            try:
                sys_path = _extract_browserguard_sys()
            except Exception as exc:
                messagebox.showerror("Extraction Failed", str(exc))
                return
            wdac_name = self.state.get("wdac_policy_name", DEFAULT_WDAC_POLICY)
            args = ["-SysPath", str(sys_path), "-WdacPolicyName", wdac_name]
            if skip_wdac_var.get():
                args.append("-SkipWdac")

            def _after():
                self.refresh_all_status()
                messagebox.showinfo(
                    "Reboot Required",
                    "BrowserGuard has been deployed successfully.\n\n"
                    "IMPORTANT: You must REBOOT this machine for the kernel driver "
                    "and test-signing mode to take effect.\n\n"
                    "After rebooting, the status will update to 'Running'.")
            self._run_threaded("BrowserGuard Deploy", PS_BROWSERGUARD_DEPLOY, args, after=_after)

        def _remove_browserguard():
            if messagebox.askyesno("Confirm Remove",
                    "This will:\n"
                    "  • Stop and delete the BrowserGuard service\n"
                    "  • Disable test-signing mode (bcdedit /set testsigning off)\n"
                    "  • Re-enable HVCI (Memory Integrity)\n"
                    "  • Remove the self-signed certificate\n"
                    "  • Remove the WDAC supplemental policy\n\n"
                    "A REBOOT is required afterwards.  Continue?"):
                def _after():
                    self.refresh_all_status()
                    messagebox.showinfo("Reboot Required",
                        "BrowserGuard has been removed.\n\n"
                        "Please REBOOT for test-signing and HVCI changes to fully take effect.")
                self._run_threaded("BrowserGuard Remove", PS_BROWSERGUARD_REMOVE, [], after=_after)

        self._btn_row(c8, _apply_browserguard, _remove_browserguard)

        # ── 9. Firewall Suite
        c9 = self._card(
            "🔥  Firewall Suite",
            "Deploys firewall_scheduler.exe (auto-blocks all internet on boot/wake, "
            "then checks the timesheet to decide whether to unblock) and "
            "timesheet_manager_firewall.exe (lets the admin set daily access windows) to "
            "C:\\Program Files\\Restrictions\\firewall_suite.  "
            "Registers a Task Scheduler task that runs the scheduler on every boot and "
            "sleep-wake event, and creates a Timesheet Manager shortcut on all users' desktops.")
        self.firewall_status = self._status_row(c9)

        def _apply_firewall():
            current = self.firewall_status.cget("text")
            if current.startswith("Deployed"):
                messagebox.showinfo(
                    "Already Deployed",
                    "Firewall Suite is already deployed.\n\n"
                    "Click 'Remove' to uninstall it first.")
                return
            if not _has_dat("FIREWALL_SUITE"):
                messagebox.showerror(
                    "Payload Not Found",
                    "FIREWALL_SUITE.dat is not present.\n\n"
                    "To generate it:\n"
                    "  1. Run  python encode_decode.py --encode  (ensure the firewall\n"
                    "     suite dist folder is listed in TARGETS).\n"
                    "  2a. Un-compiled use: copy FIREWALL_SUITE.dat next to this script.\n"
                    "  2b. PyInstaller use: recompile with --add-data \"FIREWALL_SUITE.dat;\"")
                return

            def _worker():
                dismiss = self._loading_overlay("Deploying Firewall Suite…")
                self._log("head",
                    f"\n{'─'*40}\n▶ Firewall Suite  {datetime.now().strftime('%H:%M:%S')}\n{'─'*40}")
                self.after(0, lambda: self.status_label.configure(
                    text="Extracting Firewall Suite...", fg=YELLOW))
                self._log("info", f"Extracting to: {FIREWALL_SUITE_DIR}")
                try:
                    _extract_firewall_suite()
                    self._log("ok", f"[OK] Extracted to: {FIREWALL_SUITE_DIR}")
                except Exception as exc:
                    self._log("err", f"[ERROR] Extraction failed: {exc}")
                    dismiss()
                    self.after(0, lambda: self.status_label.configure(
                        text="✗ Firewall Suite extract failed", fg=RED))
                    return
                self.after(0, lambda: self.status_label.configure(
                    text="Registering task & shortcut...", fg=YELLOW))
                ok = run_ps(PS_FIREWALL_SETUP, [], self._log_line,
                            workdir=str(FIREWALL_SUITE_DIR))
                dismiss()
                self.after(0, lambda: self.status_label.configure(
                    text=f"{'✓' if ok else '✗'} Firewall Suite", fg=GREEN if ok else RED))
                self.after(300, self.refresh_all_status)

            threading.Thread(target=_worker, daemon=True).start()

        def _remove_firewall():
            if not messagebox.askyesno("Confirm Remove",
                    "This will:\n"
                    "  \u2022  Delete the 'Firewall Scheduler' Windows Task\n"
                    "  \u2022  Delete the 'Block All Internet' firewall rule\n\n"
                    "  \u2022  Delete C:\\Program Files\\Restrictions\\firewall_suite\\\n"
                    "  \u2022  Remove the Timesheet Manager desktop shortcut\n\n"
                    "Continue?"):
                return
            self._run_threaded("Firewall Suite Remove", PS_FIREWALL_REMOVE, [],
                               after=self.refresh_all_status)

        self._btn_row(c9, _apply_firewall, _remove_firewall)
        self._task_toggle_row(c9, FIREWALL_TASK_NAME, "firewall_scheduler.exe",
                              exe_path=FIREWALL_SUITE_EXE)
        
        # ── 10. Adapter Guard
        c10 = self._card(
            "🛡️  Adapter Guard",
            "Deploys adapter_guard_oneshot.exe to C:\\Program Files\\Restrictions\\adapter_guard_oneshot.  "
            "Registers a Task Scheduler task (AdapterGuard) that fires on boot and every time any "
            "network adapter connects — it immediately disables every adapter NOT on the allowlist below.  "
            "Edit the allowlist and click 'Update Allowlist' to change which adapters are permitted.")
        self.adapter_guard_status = self._status_row(c10)

        tk.Label(c10, text="Allowed Adapters (one per line):",
                 font=("Consolas", 9), fg=MUTED, bg=CARD).pack(
            anchor="w", padx=12, pady=(4, 0))
        self.adapter_allowlist_text = tk.Text(
            c10, font=("Consolas", 9), bg=PANEL, fg=TEXT,
            insertbackground=TEXT, relief="flat",
            highlightbackground=BORDER, highlightthickness=1,
            height=5, wrap="none")
        self.adapter_allowlist_text.pack(fill="x", padx=12, pady=(0, 4))

        _existing_allowed = ""
        if ADAPTER_GUARD_ALLOWED_FILE.is_file():
            try:
                _existing_allowed = ADAPTER_GUARD_ALLOWED_FILE.read_text(encoding="utf-8")
            except Exception:
                pass
        if _existing_allowed.strip():
            self.adapter_allowlist_text.insert("1.0", _existing_allowed.rstrip())
        else:
            _hint = "\n".join(_read_active_adapter_names())
            if _hint:
                self.adapter_allowlist_text.insert("1.0", _hint)

        def _update_allowlist():
            if not ADAPTER_GUARD_EXE.exists():
                messagebox.showerror(
                    "Not Deployed",
                    "adapter_guard_oneshot.exe is not present.  "
                    "Click 'Apply' first to deploy AdapterGuard.")
                return
            contents = self.adapter_allowlist_text.get("1.0", "end").rstrip("\n")
            try:
                ADAPTER_GUARD_ALLOWED_FILE.write_text(contents + "\n", encoding="utf-8")
                self._log("ok", f"[OK] ALLOWED_ADAPTERS.txt updated:\n{contents}")
            except Exception as exc:
                self._log("err", f"[ERROR] Could not write ALLOWED_ADAPTERS.txt: {exc}")
                messagebox.showerror("Write Error", f"Could not write allowlist:\n{exc}")
                return
            self._log("info", "Running adapter_guard_oneshot.exe to apply updated allowlist...")
            try:
                subprocess.Popen(
                    [str(ADAPTER_GUARD_EXE)],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                self._log("ok", "[OK] adapter_guard_oneshot.exe launched.")
            except Exception as exc:
                self._log("err", f"[ERROR] Could not run adapter_guard_oneshot.exe: {exc}")
            self.after(300, self.refresh_all_status)

        def _apply_adapter_guard():
            current = self.adapter_guard_status.cget("text")
            if current.startswith("Deployed"):
                messagebox.showinfo(
                    "Already Deployed",
                    "AdapterGuard is already deployed.\n\n"
                    "Click 'Remove' to uninstall it first, or use 'Update Allowlist' "
                    "to change the permitted adapters.")
                return
            if not _has_dat("ADAPTER_GUARD"):
                messagebox.showerror(
                    "Payload Not Found",
                    "ADAPTER_GUARD.dat is not present.\n\n"
                    "To generate it:\n"
                    "  1. Run  python encode_decode.py --encode  (ensure the\n"
                    "     adapter_guard_oneshot dist folder is listed in TARGETS).\n"
                    "  2a. Un-compiled use: copy ADAPTER_GUARD.dat next to this script.\n"
                    "  2b. PyInstaller use: recompile with --add-data \"ADAPTER_GUARD.dat;.\"")
                return

            allowed_text = self.adapter_allowlist_text.get("1.0", "end").rstrip("\n")
            active_now   = _read_active_adapter_names()

            def _worker():
                dismiss = self._loading_overlay("Deploying Adapter Guard…")
                self._log("head",
                    f"\n{'─'*40}\n▶ Adapter Guard  {datetime.now().strftime('%H:%M:%S')}\n{'─'*40}")
                self.after(0, lambda: self.status_label.configure(
                    text="Extracting Adapter Guard...", fg=YELLOW))
                self._log("info", f"Extracting to: {ADAPTER_GUARD_DIR}")
                try:
                    _extract_adapter_guard()
                    self._log("ok", f"[OK] Extracted to: {ADAPTER_GUARD_DIR}")
                except Exception as exc:
                    self._log("err", f"[ERROR] Extraction failed: {exc}")
                    dismiss()
                    self.after(0, lambda: self.status_label.configure(
                        text="✗ Adapter Guard extract failed", fg=RED))
                    return

                try:
                    ADAPTER_GUARD_ALLOWED_FILE.write_text(
                        allowed_text + "\n", encoding="utf-8")
                    self._log("ok", f"[OK] ALLOWED_ADAPTERS.txt written.")
                except Exception as exc:
                    self._log("err", f"[ERROR] Could not write ALLOWED_ADAPTERS.txt: {exc}")
                    dismiss()
                    self.after(0, lambda: self.status_label.configure(
                        text="✗ Adapter Guard allowlist write failed", fg=RED))
                    return

                try:
                    backup_content = "\n".join(active_now) + "\n" if active_now else "\n"
                    ADAPTER_GUARD_BACKUP_FILE.write_text(backup_content, encoding="utf-8")
                    self._log("ok",
                        f"[OK] BACKUP_ALLOWED_ADAPTERS.txt written "
                        f"({len(active_now)} adapter(s) recorded).")
                except Exception as exc:
                    self._log("warn", f"[WARN] Could not write backup allowlist: {exc}")

                self.after(0, lambda: self.status_label.configure(
                    text="Registering AdapterGuard task...", fg=YELLOW))
                ok = run_ps(PS_ADAPTER_GUARD_SETUP, [], self._log_line,
                            workdir=str(ADAPTER_GUARD_DIR))
                dismiss()
                self.after(0, lambda: self.status_label.configure(
                    text=f"{'✓' if ok else '✗'} Adapter Guard", fg=GREEN if ok else RED))
                self.after(300, self.refresh_all_status)

            threading.Thread(target=_worker, daemon=True).start()

        def _remove_adapter_guard():
            if not messagebox.askyesno("Confirm Remove",
                    "This will:\n"
                    "  \u2022  Stop the 'AdapterGuard' Windows Task\n"
                    "  \u2022  Delete the 'AdapterGuard' Windows Task\n"
                    "  \u2022  Restore the original adapter allowlist from backup\n"
                    "  \u2022  Run adapter_guard_oneshot.exe once to re-enable backed-up adapters\n"
                    "  \u2022  Delete C:\\Program Files\\Restrictions\\adapter_guard_oneshot\\\n\n"
                    "Continue?"):
                return

            def _worker():
                dismiss = self._loading_overlay("Removing Adapter Guard…")
                self._log("head",
                    f"\n{'─'*40}\n▶ Adapter Guard Remove  {datetime.now().strftime('%H:%M:%S')}\n{'─'*40}")
                self.after(0, lambda: self.status_label.configure(
                    text="Removing AdapterGuard...", fg=YELLOW))

                capable_to_revert: list[str] = []
                if ADAPTER_GUARD_BACKUP_FILE.is_file():
                    try:
                        backup = ADAPTER_GUARD_BACKUP_FILE.read_text(encoding="utf-8")
                        ADAPTER_GUARD_ALLOWED_FILE.write_text(backup, encoding="utf-8")
                        self._log("ok", "[OK] ALLOWED_ADAPTERS.txt restored from backup.")
                    except Exception as exc:
                        self._log("warn", f"[WARN] Could not restore backup allowlist: {exc}")

                    if ADAPTER_GUARD_EXE.exists():
                        self._log("info",
                            "Running adapter_guard_oneshot.exe to re-enable backed-up adapters...")
                        try:
                            proc = subprocess.run(
                                [str(ADAPTER_GUARD_EXE)],
                                capture_output=True, timeout=30,
                                creationflags=_CREATE_NO_WINDOW,
                            )
                            if proc.returncode == 0:
                                self._log("ok",
                                    "[OK] adapter_guard_oneshot.exe ran successfully — "
                                    "original adapters re-enabled.")
                            else:
                                self._log("warn",
                                    f"[WARN] adapter_guard_oneshot.exe exited with code "
                                    f"{proc.returncode}.")
                        except Exception as exc:
                            self._log("warn",
                                f"[WARN] Could not run adapter_guard_oneshot.exe: {exc}")
                    else:
                        self._log("warn",
                            "[WARN] adapter_guard_oneshot.exe not found — "
                            "cannot re-enable adapters automatically.")
                else:
                    self._log("warn",
                        "[WARN] No backup allowlist found — "
                        "adapter state will not be restored before removal.")

                ok = run_ps(PS_ADAPTER_GUARD_REMOVE, [], self._log_line,
                            workdir=str(APP_DIR))
                dismiss()
                self.after(0, lambda: self.status_label.configure(
                    text=f"{'✓' if ok else '✗'} Adapter Guard removed", fg=GREEN if ok else RED))

                def _reset_ag_text():
                    live = _read_active_adapter_names()
                    self.adapter_allowlist_text.delete("1.0", "end")
                    if live:
                        self.adapter_allowlist_text.insert("1.0", "\n".join(live))
                self.after(400, _reset_ag_text)
                self.after(300, self.refresh_all_status)

            threading.Thread(target=_worker, daemon=True).start()

        def _refresh_ag_adapters():
            if ADAPTER_GUARD_ALLOWED_FILE.is_file():
                try:
                    existing = ADAPTER_GUARD_ALLOWED_FILE.read_text(encoding="utf-8").rstrip()
                except Exception:
                    existing = ""
                self.adapter_allowlist_text.delete("1.0", "end")
                if existing:
                    self.adapter_allowlist_text.insert("1.0", existing)
            else:
                def _bg():
                    live = _read_active_adapter_names()
                    def _do():
                        self.adapter_allowlist_text.delete("1.0", "end")
                        if live:
                            self.adapter_allowlist_text.insert("1.0", "\n".join(live))
                    self.after(0, _do)
                threading.Thread(target=_bg, daemon=True).start()

        btn_row_ag = tk.Frame(c10, bg=CARD)
        btn_row_ag.pack(fill="x", padx=12, pady=(4, 10))
        self._btn(btn_row_ag, "Apply", _apply_adapter_guard, "#22c55e", side="left", padx=0)
        self._btn(btn_row_ag, "Remove", _remove_adapter_guard, RED, side="left", padx=6)
        self._btn(btn_row_ag, "Update Allowlist", _update_allowlist, ACCENT, side="left", padx=6)
        self._btn(btn_row_ag, "🔄 Refresh Adapters", _refresh_ag_adapters, MUTED, side="left", padx=6)
        self._task_toggle_row(c10, ADAPTER_GUARD_TASK_NAME, "adapter_guard_oneshot.exe",
                              exe_path=ADAPTER_GUARD_EXE)

        # ── 11. DNS Suite ─────────────────────────────────────────────────────
        c11 = self._card(
            "🌐  DNS Suite",
            "Deploys dns_whitelist_blacklist_server.exe (custom DNS server on port 53 with "
            "whitelist/blacklist filtering), dns_whitelist_logger.exe (captures DNS traffic to "
            "build a whitelist), and merge_whitelists.exe (merges captured domains into the "
            "whitelist) to C:\\Program Files\\Restrictions\\dns_suite.  "
            "Registers a boot Task Scheduler task that starts the server automatically.  "
            "Move adapters into the right-hand list to make them DNS-capable (IPv4\u2192127.0.0.1, "
            "IPv6 disabled); the DNS server only intercepts traffic from DNS-capable adapters.")
        self.dns_status = self._status_row(c11)

        pane_row = tk.Frame(c11, bg=CARD)
        pane_row.pack(fill="x", padx=12, pady=(4, 0))

        left_col = tk.Frame(pane_row, bg=CARD)
        left_col.pack(side="left", fill="both", expand=True)
        tk.Label(left_col, text="DNS-Incapable Adapters",
                 font=("Consolas", 9), fg=MUTED, bg=CARD).pack(anchor="w")
        self.dns_incapable_list = tk.Listbox(
            left_col, font=("Consolas", 9), bg=PANEL, fg=TEXT,
            selectbackground=ACCENT, selectforeground="white",
            relief="flat", highlightbackground=BORDER, highlightthickness=1,
            height=6, exportselection=False)
        self.dns_incapable_list.pack(fill="both", expand=True)

        arrow_col = tk.Frame(pane_row, bg=CARD)
        arrow_col.pack(side="left", padx=8)

        _move_to_capable_ref   = [None]
        _move_to_incapable_ref = [None]

        btn_to_cap = self._btn(arrow_col, "\u2192", lambda: _move_to_capable_ref[0](),
                               ACCENT, side="top", padx=4, pady=2)
        btn_to_inc = self._btn(arrow_col, "\u2190", lambda: _move_to_incapable_ref[0](),
                               ACCENT, side="top", padx=4, pady=2)

        right_col = tk.Frame(pane_row, bg=CARD)
        right_col.pack(side="left", fill="both", expand=True)
        tk.Label(right_col, text="DNS-Capable Adapters",
                 font=("Consolas", 9), fg=MUTED, bg=CARD).pack(anchor="w")
        self.dns_capable_list = tk.Listbox(
            right_col, font=("Consolas", 9), bg=PANEL, fg=TEXT,
            selectbackground=ACCENT, selectforeground="white",
            relief="flat", highlightbackground=BORDER, highlightthickness=1,
            height=6, exportselection=False)
        self.dns_capable_list.pack(fill="both", expand=True)

        def _refresh_dns_status_label():
            if DNS_SERVER_EXE.exists():
                if self.dns_capable_list.size() == 0:
                    self.dns_status.configure(
                        text="Deployed — WARNING: no DNS-capable adapters",
                        fg=ORANGE)
                else:
                    self.dns_status.configure(
                        text="Deployed — task active",
                        fg=GREEN)

        def _move_to_capable():
            sel = self.dns_incapable_list.curselection()
            if not sel:
                return
            name = self.dns_incapable_list.get(sel[0])
            self.dns_incapable_list.delete(sel[0])
            self.dns_capable_list.insert("end", name)
            _refresh_dns_status_label()
            self._log("info", f"Making DNS-capable: {name}")
            threading.Thread(
                target=lambda: run_ps(
                    PS_DNS_MAKE_CAPABLE, ["-AdapterNames", name], self._log_line),
                daemon=True).start()

        def _move_to_incapable():
            sel = self.dns_capable_list.curselection()
            if not sel:
                return
            name = self.dns_capable_list.get(sel[0])
            self.dns_capable_list.delete(sel[0])
            self.dns_incapable_list.insert("end", name)
            _refresh_dns_status_label()
            self._log("info", f"Reverting DNS-capable: {name}")
            threading.Thread(
                target=lambda: run_ps(
                    PS_DNS_MAKE_INCAPABLE, ["-AdapterNames", name], self._log_line),
                daemon=True).start()

        _move_to_capable_ref[0]   = _move_to_capable
        _move_to_incapable_ref[0] = _move_to_incapable

        def _populate_dns_listboxes():
            incapable, capable = _classify_adapters_live()
            def _do():
                self.dns_incapable_list.delete(0, "end")
                self.dns_capable_list.delete(0, "end")
                for n in incapable:
                    self.dns_incapable_list.insert("end", n)
                for n in capable:
                    self.dns_capable_list.insert("end", n)
                _refresh_dns_status_label()
            self.after(0, _do)
        self.after(0, _populate_dns_listboxes)

        def _apply_dns_suite():
            current = self.dns_status.cget("text")
            if current.startswith("Deployed"):
                messagebox.showinfo(
                    "Already Deployed",
                    "DNS Suite is already deployed.\n\n"
                    "Click 'Remove' to uninstall it first.")
                return
            if not _has_dat("DNS_SUITE"):
                messagebox.showerror(
                    "Payload Not Found",
                    "DNS_SUITE.dat is not present.\n\n"
                    "To generate it:\n"
                    "  1. Run  python encode_decode.py --encode  (ensure the merged\n"
                    "     dns_suite dist folder is listed in TARGETS).\n"
                    "  2a. Un-compiled use: copy DNS_SUITE.dat next to this script.\n"
                    "  2b. PyInstaller use: recompile with --add-data \"DNS_SUITE.dat;.\"")
                return

            capable_names   = list(self.dns_capable_list.get(0, "end"))
            incapable_names = list(self.dns_incapable_list.get(0, "end"))

            def _worker():
                dismiss = self._loading_overlay("Deploying DNS Suite…")
                self._log("head",
                    f"\n{'─'*40}\n▶ DNS Suite  {datetime.now().strftime('%H:%M:%S')}\n{'─'*40}")
                self.after(0, lambda: self.status_label.configure(
                    text="Configuring adapter DNS settings...", fg=YELLOW))

                self._log("info", "Applying DNS-capable / incapable settings to adapters...")
                if capable_names:
                    run_ps(PS_DNS_MAKE_CAPABLE,
                           ["-AdapterNames"] + capable_names, self._log_line)
                if incapable_names:
                    run_ps(PS_DNS_MAKE_INCAPABLE,
                           ["-AdapterNames"] + incapable_names, self._log_line)

                try:
                    DNS_SUITE_DIR.mkdir(parents=True, exist_ok=True)
                    DNS_CAPABLE_FILE.write_text(
                        "\n".join(capable_names) + "\n" if capable_names else "\n",
                        encoding="utf-8")
                    DNS_INCAPABLE_FILE.write_text(
                        "\n".join(incapable_names) + "\n" if incapable_names else "\n",
                        encoding="utf-8")
                    self._log("ok", "[OK] DNS_CAPABLE_ADAPTERS.txt and DNS_INCAPABLE_ADAPTERS.txt written.")
                except Exception as exc:
                    self._log("warn", f"[WARN] Could not write adapter list files: {exc}")

                self.after(0, lambda: self.status_label.configure(
                    text="Extracting DNS Suite...", fg=YELLOW))
                self._log("info", f"Extracting to: {DNS_SUITE_DIR}")
                try:
                    _extract_dns_suite()
                    self._log("ok", f"[OK] Extracted to: {DNS_SUITE_DIR}")
                except Exception as exc:
                    self._log("err", f"[ERROR] Extraction failed: {exc}")
                    dismiss()
                    self.after(0, lambda: self.status_label.configure(
                        text="\u2717 DNS Suite extract failed", fg=RED))
                    return

                self.after(0, lambda: self.status_label.configure(
                    text="Registering DNS task...", fg=YELLOW))
                ok = run_ps(PS_DNS_SUITE_SETUP, [], self._log_line,
                            workdir=str(DNS_SUITE_DIR))
                dismiss()
                self.after(0, lambda: self.status_label.configure(
                    text=f"{'✓' if ok else '✗'} DNS Suite", fg=GREEN if ok else RED))
                self.after(300, self.refresh_all_status)

            threading.Thread(target=_worker, daemon=True).start()

        def _remove_dns_suite():
            if not messagebox.askyesno("Confirm Remove",
                    "This will:\n"
                    "  \u2022  Revert all DNS-capable adapters to automatic DNS\n"
                    "  \u2022  Re-enable IPv6 on those adapters\n"
                    "  \u2022  Stop and delete the 'DNS Server' Windows Task\n"
                    "  \u2022  Kill any running DNS suite processes\n"
                    "  \u2022  Delete C:\\Program Files\\Restrictions\\dns_suite\\\n\n"
                    "Continue?"):
                return

            def _worker():
                dismiss = self._loading_overlay("Removing DNS Suite…")
                self._log("head",
                    f"\n{'─'*40}\n▶ DNS Suite Remove  {datetime.now().strftime('%H:%M:%S')}\n{'─'*40}")
                self.after(0, lambda: self.status_label.configure(
                    text="Removing DNS Suite...", fg=YELLOW))

                capable_to_revert: list[str] = []
                if DNS_CAPABLE_FILE.is_file():
                    try:
                        capable_to_revert = [
                            ln.strip() for ln in
                            DNS_CAPABLE_FILE.read_text(encoding="utf-8").splitlines()
                            if ln.strip()
                        ]
                    except Exception as exc:
                        self._log("warn", f"[WARN] Could not read DNS_CAPABLE_ADAPTERS.txt: {exc}")

                if capable_to_revert:
                    self._log("info",
                        f"Reverting {len(capable_to_revert)} adapter(s) to automatic DNS...")
                    run_ps(PS_DNS_MAKE_INCAPABLE,
                           ["-AdapterNames"] + capable_to_revert, self._log_line)
                else:
                    self._log("info", "No DNS-capable adapters on record — skipping revert.")

                ok = run_ps(PS_DNS_SUITE_REMOVE, [], self._log_line, workdir=str(APP_DIR))
                dismiss()
                self.after(0, lambda: self.status_label.configure(
                    text=f"{'✓' if ok else '✗'} DNS Suite removed",
                    fg=GREEN if ok else RED))

                self.after(0, _populate_dns_listboxes)
                self.after(300, self.refresh_all_status)

            threading.Thread(target=_worker, daemon=True).start()

        def _run_dns_logger():
            if not DNS_LOGGER_EXE.exists():
                messagebox.showerror(
                    "DNS Suite Not Deployed",
                    "dns_whitelist_logger.exe not found.\n"
                    "Click 'Apply' to deploy the DNS Suite first.")
                return

            def _worker():
                self._log("head",
                    f"\n{'─'*40}\n▶ DNS Whitelist Logger  {datetime.now().strftime('%H:%M:%S')}\n{'─'*40}")

                self._log("info", "Stopping DNS server task before launching logger...")
                try:
                    subprocess.run(
                        ["schtasks", "/End", "/TN", DNS_TASK_NAME],
                        capture_output=True, timeout=10,
                        creationflags=_CREATE_NO_WINDOW)
                except Exception:
                    pass
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/IM", "dns_whitelist_blacklist_server.exe"],
                        capture_output=True, timeout=10,
                        creationflags=_CREATE_NO_WINDOW)
                except Exception:
                    pass
                import time; time.sleep(0.5)
                self._log("ok", "[OK] DNS server stopped.")

                self.after(0, lambda: self.status_label.configure(
                    text="DNS Logger running — close its window to resume server",
                    fg=ORANGE))

                self._log("info",
                    f"Launching logger: {DNS_LOGGER_EXE}\n"
                    "  (DNS server will restart automatically when you close the logger window)")
                try:
                    subprocess.run(
                        [str(DNS_LOGGER_EXE)],
                        cwd=str(DNS_SUITE_DIR),
                    )
                except Exception as exc:
                    self._log("err", f"[ERROR] Logger exited with error: {exc}")

                self._log("ok", "[OK] Logger closed by user.")

                self._log("info", "Restarting DNS server task...")
                try:
                    r = subprocess.run(
                        ["schtasks", "/Run", "/TN", DNS_TASK_NAME],
                        capture_output=True, text=True, timeout=15,
                        encoding="utf-8", errors="replace",
                        creationflags=_CREATE_NO_WINDOW)
                    if r.returncode == 0:
                        self._log("ok", "[OK] DNS server task restarted.")
                    else:
                        self._log("warn",
                            f"[WARN] schtasks /Run returned {r.returncode}: "
                            f"{(r.stdout or r.stderr).strip()}")
                except Exception as exc:
                    self._log("err", f"[ERROR] Could not restart DNS server task: {exc}")

                self.after(0, lambda: self.status_label.configure(
                    text="✓ DNS Logger session complete — server restarted", fg=GREEN))
                self.after(300, self.refresh_all_status)

            threading.Thread(target=_worker, daemon=True).start()

        def _run_merge_whitelists():
            if not DNS_MERGE_EXE.exists():
                messagebox.showerror(
                    "DNS Suite Not Deployed",
                    "merge_whitelists.exe not found.\n"
                    "Click 'Apply' to deploy the DNS Suite first.")
                return

            def _worker():
                self._log("head",
                    f"\n{'─'*40}\n▶ Merge Whitelists  {datetime.now().strftime('%H:%M:%S')}\n{'─'*40}")
                self.after(0, lambda: self.status_label.configure(
                    text="Merge Whitelists running…", fg=YELLOW))

                self._log("info", f"Launching: {DNS_MERGE_EXE}")
                try:
                    subprocess.run(
                        [str(DNS_MERGE_EXE)],
                        cwd=str(DNS_SUITE_DIR),
                    )
                    self._log("ok", "[OK] Merge Whitelists completed.")
                except Exception as exc:
                    self._log("err", f"[ERROR] merge_whitelists.exe exited with error: {exc}")

                self._log("info", "Restarting DNS server to pick up updated whitelist...")
                try:
                    subprocess.run(
                        ["schtasks", "/End", "/TN", DNS_TASK_NAME],
                        capture_output=True, timeout=10,
                        creationflags=_CREATE_NO_WINDOW)
                except Exception:
                    pass
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/IM", "dns_whitelist_blacklist_server.exe"],
                        capture_output=True, timeout=10,
                        creationflags=_CREATE_NO_WINDOW)
                except Exception:
                    pass
                import time; time.sleep(0.5)

                try:
                    r = subprocess.run(
                        ["schtasks", "/Run", "/TN", DNS_TASK_NAME],
                        capture_output=True, text=True, timeout=15,
                        encoding="utf-8", errors="replace",
                        creationflags=_CREATE_NO_WINDOW)
                    if r.returncode == 0:
                        self._log("ok", "[OK] DNS server restarted with updated whitelist.")
                    else:
                        self._log("warn",
                            f"[WARN] schtasks /Run returned {r.returncode}: "
                            f"{(r.stdout or r.stderr).strip()}")
                except Exception as exc:
                    self._log("err", f"[ERROR] Could not restart DNS server task: {exc}")

                self.after(0, lambda: self.status_label.configure(
                    text="✓ Merge Whitelists complete — server restarted", fg=GREEN))
                self.after(300, self.refresh_all_status)

            threading.Thread(target=_worker, daemon=True).start()

        self._btn_row(c11, _apply_dns_suite, _remove_dns_suite)

        util_row = tk.Frame(c11, bg=CARD)
        util_row.pack(fill="x", padx=12, pady=(0, 6))
        self._btn(util_row, "Run DNS Whitelist Logger", _run_dns_logger,
                  ORANGE, side="left", padx=0)
        self._btn(util_row, "Run Merge Whitelists", _run_merge_whitelists,
                  ACCENT, side="left", padx=6)

        tk.Frame(c11, bg=BORDER, height=1).pack(fill="x", padx=12, pady=(2, 4))
        upload_hdr = tk.Frame(c11, bg=CARD)
        upload_hdr.pack(fill="x", padx=12, pady=(0, 2))
        tk.Label(upload_hdr,
                 text="File Operations  —  each upload stops the DNS server, copies the file, then restarts",
                 font=("Consolas", 9), fg=MUTED, bg=CARD).pack(side="left")

        upload_row = tk.Frame(c11, bg=CARD)
        upload_row.pack(fill="x", padx=12, pady=(0, 6))

        def _upload_file(label: str, target: Path, source_path: str):
            if not DNS_SUITE_DIR.exists():
                messagebox.showerror("Not Deployed",
                    "Deploy the DNS Suite first before uploading files.")
                return
            def _bg():
                self._log("head",
                    f"\n{'─'*40}\n▶ Upload {label}  {datetime.now().strftime('%H:%M:%S')}\n{'─'*40}")
                try:
                    subprocess.run(["schtasks", "/End", "/TN", DNS_TASK_NAME],
                                   capture_output=True, timeout=10,
                                   creationflags=_CREATE_NO_WINDOW)
                    subprocess.run(["taskkill", "/F", "/IM",
                                    "dns_whitelist_blacklist_server.exe"],
                                   capture_output=True, timeout=10,
                                   creationflags=_CREATE_NO_WINDOW)
                    import time as _t; _t.sleep(0.6)
                    self._log("ok", "[OK] DNS server stopped.")
                except Exception as exc:
                    self._log("warn", f"[WARN] Stop DNS: {exc}")
                try:
                    import shutil as _sh
                    _sh.copy2(source_path, str(target))
                    self._log("ok", f"[OK] Copied → {target}")
                except Exception as exc:
                    self._log("err", f"[ERROR] Copy failed: {exc}")
                    return
                try:
                    subprocess.run(["schtasks", "/Run", "/TN", DNS_TASK_NAME],
                                   capture_output=True, timeout=15,
                                   creationflags=_CREATE_NO_WINDOW)
                    self._log("ok", "[OK] DNS server restarted.")
                except Exception as exc:
                    self._log("warn", f"[WARN] Restart DNS: {exc}")
                self.after(300, self.refresh_all_status)
            threading.Thread(target=_bg, daemon=True).start()

        _DNS_UPLOAD_TARGETS = {
            "whitelisted_domains.json":  (DNS_WHITELIST_FILE,  "Whitelist"),
            "blacklisted_domains.json":  (DNS_BLACKLIST_FILE,  "Blacklist"),
            "domain_access_log.json":    (DNS_ACCESS_LOG_FILE, "Access Log"),
        }

        def _smart_upload():
            if not DNS_SUITE_DIR.exists():
                messagebox.showerror("Not Deployed",
                    "Deploy the DNS Suite first before uploading files.")
                return
            path = filedialog.askopenfilename(
                title="Select whitelisted_domains.json, blacklisted_domains.json, "
                      "or domain_access_log.json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
            if not path:
                return
            filename = Path(path).name.lower()
            if filename not in _DNS_UPLOAD_TARGETS:
                messagebox.showerror(
                    "Unrecognized File",
                    f"'{Path(path).name}' is not a recognized DNS data file.\n\n"
                    "Please upload one of:\n"
                    "  •  whitelisted_domains.json\n"
                    "  •  blacklisted_domains.json\n"
                    "  •  domain_access_log.json")
                return
            target_path, label = _DNS_UPLOAD_TARGETS[filename]
            _upload_file(label, target_path, path)

        smart_upload_col = tk.Frame(upload_row, bg=CARD)
        smart_upload_col.pack(side="left", padx=(0, 8))
        tk.Label(smart_upload_col,
                 text="whitelisted_domains.json\nblacklisted_domains.json\ndomain_access_log.json",
                 font=("Consolas", 8), fg=MUTED, bg=CARD, justify="left").pack(anchor="w")
        self._btn(smart_upload_col, "⬆  Upload File", _smart_upload,
                  ACCENT2, side="top", padx=0, pady=2, anchor="w")

        def _export_dns_files():
            if not DNS_SUITE_DIR.exists():
                messagebox.showerror("Not Deployed",
                    "Deploy the DNS Suite first before exporting files.")
                return
            save_path = filedialog.asksaveasfilename(
                title="Export DNS Files",
                defaultextension=".zip",
                initialfile=f"dns_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                filetypes=[("Zip archive", "*.zip"), ("All files", "*.*")])
            if not save_path:
                return
            def _bg():
                self._log("head",
                    f"\n{'─'*40}\n▶ Export DNS Files  {datetime.now().strftime('%H:%M:%S')}\n{'─'*40}")
                import zipfile as _zf
                try:
                    files_to_export = [
                        DNS_WHITELIST_FILE,
                        DNS_BLACKLIST_FILE,
                        DNS_ACCESS_LOG_FILE,
                    ]
                    with _zf.ZipFile(save_path, "w", _zf.ZIP_DEFLATED) as zf:
                        for f in files_to_export:
                            if f.exists():
                                zf.write(str(f), f.name)
                                self._log("ok", f"  [OK] Added: {f.name}")
                            else:
                                self._log("warn", f"  [SKIP] Not found: {f.name}")
                    self._log("ok", f"[OK] Exported → {save_path}")
                    self.after(0, lambda: self.status_label.configure(
                        text="✓ DNS files exported", fg=GREEN))
                except Exception as exc:
                    self._log("err", f"[ERROR] Export failed: {exc}")
                    self.after(0, lambda: self.status_label.configure(
                        text="✗ Export failed", fg=RED))
            threading.Thread(target=_bg, daemon=True).start()

        export_col = tk.Frame(upload_row, bg=CARD)
        export_col.pack(side="left", padx=(8, 0))
        tk.Label(export_col, text="Export all three files\n\n",
                 font=("Consolas", 8), fg=MUTED, bg=CARD, justify="left").pack(anchor="w")
        self._btn(export_col, "⬇ Export DNS Files", _export_dns_files,
                  ACCENT, side="top", padx=0, pady=2, anchor="w")

        self._task_toggle_row(c11, DNS_TASK_NAME, "dns_whitelist_blacklist_server.exe",
                              exe_path=DNS_SERVER_EXE)

        tk.Frame(c11, bg=BORDER, height=1).pack(fill="x", padx=12, pady=(0, 6))

        def _restart_dns_server(reason: str = "domain list change"):
            def _bg():
                self._log("info", f"Restarting DNS server ({reason})…")
                try:
                    subprocess.run(["schtasks", "/End", "/TN", DNS_TASK_NAME],
                                   capture_output=True, timeout=10,
                                   creationflags=_CREATE_NO_WINDOW)
                    subprocess.run(["taskkill", "/F", "/IM",
                                    "dns_whitelist_blacklist_server.exe"],
                                   capture_output=True, timeout=10,
                                   creationflags=_CREATE_NO_WINDOW)
                    import time; time.sleep(0.5)
                    subprocess.run(["schtasks", "/Run", "/TN", DNS_TASK_NAME],
                                   capture_output=True, timeout=15,
                                   creationflags=_CREATE_NO_WINDOW)
                    self._log("ok", "[OK] DNS server restarted.")
                except Exception as exc:
                    self._log("warn", f"[WARN] DNS server restart: {exc}")
            threading.Thread(target=_bg, daemon=True).start()

        def _make_config_row(label: str, file_path: Path, validate_fn=None):
            row = tk.Frame(c11, bg=CARD)
            row.pack(fill="x", padx=12, pady=2)
            tk.Label(row, text=label, font=FONT_MAIN, fg=MUTED, bg=CARD,
                     width=18, anchor="w").pack(side="left")
            init_val = _read_config_value(file_path)
            var = tk.StringVar(value=init_val)
            entry = tk.Entry(row, textvariable=var, font=FONT_MAIN,
                             bg=PANEL, fg=TEXT, insertbackground=TEXT,
                             relief="flat", highlightbackground=BORDER,
                             highlightthickness=1, width=22)
            entry.pack(side="left", padx=(0, 6))

            def _save():
                if not file_path.exists():
                    messagebox.showerror(
                        "DNS Suite Not Deployed",
                        f"{file_path.name} does not exist.\n"
                        "Click 'Apply' to deploy the DNS Suite first.")
                    return
                val = var.get().strip()
                if validate_fn and not validate_fn(val):
                    messagebox.showerror("Invalid Value",
                        f"'{val}' is not a valid value for {label.strip()}.")
                    return
                try:
                    file_path.write_text(val, encoding="utf-8")
                    self._log("ok", f"[OK] {file_path.name} saved: {val}")
                    _restart_dns_server(f"config updated ({file_path.name})")
                    messagebox.showinfo("Saved", f"{file_path.name} updated to: {val}\n\nDNS server has been restarted to apply changes.")
                except Exception as exc:
                    messagebox.showerror("Save Failed", str(exc))

            self._btn(row, "Save", _save, ACCENT, side="left", padx=0)
            return entry

        import re as _re
        def _valid_ip(v):
            return bool(_re.fullmatch(
                r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", v))
        def _valid_days(v):
            try: return int(v) > 0
            except: return False

        self._make_config_row = _make_config_row
        _make_config_row("Upstream DNS IP:", DNS_UPSTREAM_FILE,  _valid_ip)
        _make_config_row("Threshold Days:",  DNS_THRESHOLD_FILE, _valid_days)

        tk.Frame(c11, bg=BORDER, height=1).pack(fill="x", padx=12, pady=(6, 4))
        tk.Label(c11, text="Whitelist Domains",
                 font=FONT_HEAD, fg=TEXT, bg=CARD).pack(anchor="w", padx=12)
        tk.Label(c11,
                 text="Domains highlighted in red have not been accessed in longer than "
                      "Threshold Days.  The number shown is days since last access.",
                 font=("Consolas", 9), fg=ORANGE, bg=CARD, wraplength=460,
                 justify="left").pack(anchor="w", padx=12, pady=(0, 4))

        wl_outer = tk.Frame(c11, bg=CARD)
        wl_outer.pack(fill="x", padx=12, pady=(0, 4))

        wl_lb_frame = tk.Frame(wl_outer, bg=CARD)
        wl_lb_frame.pack(side="left", fill="both", expand=True)
        wl_sb = tk.Scrollbar(wl_lb_frame, orient="vertical")
        self.wl_listbox = tk.Listbox(
            wl_lb_frame, font=("Consolas", 9), bg=PANEL, fg=TEXT,
            selectbackground=ACCENT, selectforeground="white",
            relief="flat", highlightbackground=BORDER, highlightthickness=1,
            height=8, exportselection=False,
            yscrollcommand=wl_sb.set)
        wl_sb.config(command=self.wl_listbox.yview)
        wl_sb.pack(side="right", fill="y")
        self.wl_listbox.pack(side="left", fill="both", expand=True)

        wl_right = tk.Frame(wl_outer, bg=CARD)
        wl_right.pack(side="left", padx=(8, 0), fill="y", anchor="n")
        tk.Label(wl_right, text="Add domain:", font=("Consolas", 9),
                 fg=MUTED, bg=CARD).pack(anchor="w")
        wl_add_entry = tk.Entry(wl_right, font=("Consolas", 9),
                                bg=PANEL, fg=TEXT, insertbackground=TEXT,
                                relief="flat", highlightbackground=BORDER,
                                highlightthickness=1, width=26)
        wl_add_entry.pack(fill="x", pady=(0, 4))

        def _wl_add():
            if not DNS_WHITELIST_FILE.exists():
                messagebox.showerror("Not Deployed",
                    "Deploy DNS Suite first."); return
            domain = wl_add_entry.get().strip().lower()
            if not domain:
                return
            import json as _j
            items = _load_json_list(DNS_WHITELIST_FILE)
            if domain in items:
                messagebox.showinfo("Already Present",
                    f"'{domain}' is already in the whitelist."); return
            items.append(domain)
            _save_json_list(DNS_WHITELIST_FILE, items)
            self._log("ok", f"[OK] Added to whitelist: {domain}")
            wl_add_entry.delete(0, "end")
            _refresh_wl_listbox()
            _restart_dns_server("whitelist add")
            self.after(300, self.refresh_all_status)

        self._btn(wl_right, "Add To Whitelist", _wl_add, GREEN, side="top",
                  padx=0, pady=2)

        def _wl_delete():
            if not DNS_WHITELIST_FILE.exists():
                messagebox.showerror("Not Deployed",
                    "Deploy DNS Suite first."); return
            sel = self.wl_listbox.curselection()
            if not sel:
                return
            raw = self.wl_listbox.get(sel[0])
            domain = raw.split("  (")[0].strip()
            if not messagebox.askyesno("Confirm Delete",
                    f"Remove '{domain}' from the whitelist?"):
                return
            items = _load_json_list(DNS_WHITELIST_FILE)
            if domain in items:
                items.remove(domain)
                _save_json_list(DNS_WHITELIST_FILE, items)
                self._log("ok", f"[OK] Removed from whitelist: {domain}")
                _refresh_wl_listbox()
                _restart_dns_server("whitelist delete")
                self.after(300, self.refresh_all_status)

        def _wl_delete_all():
            if not DNS_WHITELIST_FILE.exists():
                messagebox.showerror("Not Deployed", "Deploy DNS Suite first."); return
            if not messagebox.askyesno("Confirm Delete", "Are you sure you want to delete ALL domains in the whitelist?"):
                return
            _save_json_list(DNS_WHITELIST_FILE, [])
            self._log("ok", "[OK] Whitelist cleared.")
            _refresh_wl_listbox()
            _restart_dns_server("whitelist cleared")
            self.after(300, self.refresh_all_status)

        wl_btn_row = tk.Frame(c11, bg=CARD)
        wl_btn_row.pack(fill="x", padx=12, pady=(0, 6))
        self._btn(wl_btn_row, "Delete Selected", _wl_delete, RED, side="left", padx=0)
        self._btn(wl_btn_row, "Delete Whitelist", _wl_delete_all, RED, side="left", padx=6)

        def _refresh_wl_listbox():
            domains = _load_json_list(DNS_WHITELIST_FILE)
            access  = _load_access_log()

            try:
                threshold_days = int(_read_config_value(DNS_THRESHOLD_FILE))
            except (ValueError, TypeError):
                threshold_days = 7

            from datetime import datetime, timezone, timedelta
            cutoff = datetime.now(timezone.utc) - timedelta(days=threshold_days)

            new_labels = []
            new_colors = []

            for d in domains:
                ts = access.get(d, "")
                stale = False
                days  = 0
                if ts:
                    try:
                        last = datetime.fromisoformat(ts)
                        if last.tzinfo is None:
                            last = last.replace(tzinfo=timezone.utc)
                        days  = max(0, (datetime.now(timezone.utc) - last).days)
                        stale = last < cutoff
                    except Exception:
                        pass

                if stale:
                    label = f"{d}  ({days} day{'s' if days != 1 else ''})"
                    color = RED
                else:
                    label = d
                    color = TEXT

                new_labels.append(label)
                new_colors.append(color)

            # In-place synchronized update loop
            scroll_pos = self.wl_listbox.yview()
            old_size = self.wl_listbox.size()

            for i in range(max(old_size, len(new_labels))):
                if i < len(new_labels) and i < old_size:
                    # Sync structural details for items existing in both
                    current_text = self.wl_listbox.get(i)
                    current_color = self.wl_listbox.itemcget(i, "fg") or TEXT
                    
                    if current_text != new_labels[i]:
                        # Preserve focus targets on modification bounds
                        is_sel = self.wl_listbox.selection_includes(i)
                        is_act = (self.wl_listbox.index(tk.ACTIVE) == i)
                        
                        self.wl_listbox.delete(i)
                        self.wl_listbox.insert(i, new_labels[i])
                        
                        if is_sel:
                            self.wl_listbox.selection_set(i)
                        if is_act:
                            self.wl_listbox.activate(i)
                    
                    if current_color != new_colors[i]:
                        self.wl_listbox.itemconfig(i, fg=new_colors[i])
                        
                elif i < len(new_labels):
                    # Add newly registered items cleanly onto the bottom
                    self.wl_listbox.insert("end", new_labels[i])
                    self.wl_listbox.itemconfig("end", fg=new_colors[i])
                else:
                    # Trim stale tails without full-wipe side effects
                    self.wl_listbox.delete(len(new_labels), "end")
                    break

            # Only enforce coordinate snapping if structure lengths altered
            if old_size != len(new_labels):
                self.wl_listbox.yview_moveto(scroll_pos[0])

        self.after(0, _refresh_wl_listbox)

        # ── Blacklist panel ───────────────────────────────────────────────────
        tk.Frame(c11, bg=BORDER, height=1).pack(fill="x", padx=12, pady=(4, 4))
        tk.Label(c11, text="Blacklist Domains",
                 font=FONT_HEAD, fg=TEXT, bg=CARD).pack(anchor="w", padx=12)

        bl_outer = tk.Frame(c11, bg=CARD)
        bl_outer.pack(fill="x", padx=12, pady=(4, 4))

        bl_lb_frame = tk.Frame(bl_outer, bg=CARD)
        bl_lb_frame.pack(side="left", fill="both", expand=True)
        bl_sb = tk.Scrollbar(bl_lb_frame, orient="vertical")
        self.bl_listbox = tk.Listbox(
            bl_lb_frame, font=("Consolas", 9), bg=PANEL, fg=TEXT,
            selectbackground=ACCENT, selectforeground="white",
            relief="flat", highlightbackground=BORDER, highlightthickness=1,
            height=8, exportselection=False,
            yscrollcommand=bl_sb.set)
        bl_sb.config(command=self.bl_listbox.yview)
        bl_sb.pack(side="right", fill="y")
        self.bl_listbox.pack(side="left", fill="both", expand=True)

        bl_right = tk.Frame(bl_outer, bg=CARD)
        bl_right.pack(side="left", padx=(8, 0), fill="y", anchor="n")
        tk.Label(bl_right, text="Add domain:", font=("Consolas", 9),
                 fg=MUTED, bg=CARD).pack(anchor="w")
        bl_add_entry = tk.Entry(bl_right, font=("Consolas", 9),
                                bg=PANEL, fg=TEXT, insertbackground=TEXT,
                                relief="flat", highlightbackground=BORDER,
                                highlightthickness=1, width=26)
        bl_add_entry.pack(fill="x", pady=(0, 4))

        def _bl_add():
            if not DNS_BLACKLIST_FILE.exists():
                messagebox.showerror("Not Deployed",
                    "Deploy DNS Suite first."); return
            domain = bl_add_entry.get().strip().lower()
            if not domain:
                return
            items = _load_json_list(DNS_BLACKLIST_FILE)
            if domain in items:
                messagebox.showinfo("Already Present",
                    f"'{domain}' is already in the blacklist."); return
            items.append(domain)
            _save_json_list(DNS_BLACKLIST_FILE, items)
            self._log("ok", f"[OK] Added to blacklist: {domain}")
            bl_add_entry.delete(0, "end")
            _refresh_bl_listbox()
            _restart_dns_server("blacklist add")
            self.after(300, self.refresh_all_status)

        self._btn(bl_right, "Add To Blacklist", _bl_add, RED, side="top",
                  padx=0, pady=2)

        def _bl_delete():
            if not DNS_BLACKLIST_FILE.exists():
                messagebox.showerror("Not Deployed",
                    "Deploy DNS Suite first."); return
            sel = self.bl_listbox.curselection()
            if not sel:
                return
            domain = self.bl_listbox.get(sel[0]).strip()
            if not messagebox.askyesno("Confirm Delete",
                    f"Remove '{domain}' from the blacklist?"):
                return
            items = _load_json_list(DNS_BLACKLIST_FILE)
            if domain in items:
                items.remove(domain)
                _save_json_list(DNS_BLACKLIST_FILE, items)
                self._log("ok", f"[OK] Removed from blacklist: {domain}")
                _refresh_bl_listbox()
                _restart_dns_server("blacklist delete")
                self.after(300, self.refresh_all_status)

        def _bl_delete_all():
            if not DNS_BLACKLIST_FILE.exists():
                messagebox.showerror("Not Deployed", "Deploy DNS Suite first."); return
            if not messagebox.askyesno("Confirm Delete", "Are you sure you want to delete ALL domains in the blacklist?"):
                return
            _save_json_list(DNS_BLACKLIST_FILE, [])
            self._log("ok", "[OK] Blacklist cleared.")
            _refresh_bl_listbox()
            _restart_dns_server("blacklist cleared")
            self.after(300, self.refresh_all_status)

        bl_btn_row = tk.Frame(c11, bg=CARD)
        bl_btn_row.pack(fill="x", padx=12, pady=(0, 10))
        self._btn(bl_btn_row, "Delete Selected", _bl_delete, RED, side="left", padx=0)
        self._btn(bl_btn_row, "Delete Blacklist", _bl_delete_all, RED, side="left", padx=6)

        def _refresh_bl_listbox():
            new_domains = _load_json_list(DNS_BLACKLIST_FILE)
            scroll_pos = self.bl_listbox.yview()
            old_size = self.bl_listbox.size()

            for i in range(max(old_size, len(new_domains))):
                if i < len(new_domains) and i < old_size:
                    current_text = self.bl_listbox.get(i)
                    if current_text != new_domains[i]:
                        is_sel = self.bl_listbox.selection_includes(i)
                        is_act = (self.bl_listbox.index(tk.ACTIVE) == i)
                        
                        self.bl_listbox.delete(i)
                        self.bl_listbox.insert(i, new_domains[i])
                        
                        if is_sel:
                            self.bl_listbox.selection_set(i)
                        if is_act:
                            self.bl_listbox.activate(i)
                elif i < len(new_domains):
                    self.bl_listbox.insert("end", new_domains[i])
                else:
                    self.bl_listbox.delete(len(new_domains), "end")
                    break

            if old_size != len(new_domains):
                self.bl_listbox.yview_moveto(scroll_pos[0])

        self.after(0, _refresh_bl_listbox)

        self._cb_populate_dns   = _populate_dns_listboxes
        self._cb_refresh_wl     = _refresh_wl_listbox
        self._cb_refresh_bl     = _refresh_bl_listbox

    # ── Logging

    def _log(self, tag: str, text: str):
        def _do():
            self.log.configure(state="normal")
            self.log.insert("end", text + "\n", tag)
            self.log.see("end")
            self.log.configure(state="disabled")
        self.after(0, _do)

    def _log_line(self, line: str):
        tag = "ok" if ("[OK]" in line or "Done" in line or "Completed" in line or "successfully" in line.lower()) \
              else "err" if ("Error" in line or "failed" in line.lower() or ("[Exit code: " in line and "0]" not in line)) \
              else "warn" if ("Warning" in line or "WARN" in line) \
              else "info"
        self._log(tag, line)

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _set_status(self, label: tk.Label, text: str, color: str):
        self.after(0, lambda: label.configure(text=text, fg=color))

    # ── Loading overlay

    def _loading_overlay(self, title: str):
        """Show a modal progress overlay that blocks GUI interaction."""
        overlay = tk.Toplevel(self, bg=PANEL)
        overlay.title("")
        overlay.resizable(False, False)
        overlay.grab_set()
        overlay.protocol("WM_DELETE_WINDOW", lambda: None)

        self.update_idletasks()
        px, py = self.winfo_rootx(), self.winfo_rooty()
        pw, ph = self.winfo_width(),  self.winfo_height()
        w, h = 340, 110
        overlay.geometry(f"{w}x{h}+{px + (pw - w)//2}+{py + (ph - h)//2}")
        overlay.transient(self)
        overlay.lift()

        tk.Label(overlay, text=title, font=FONT_HEAD, fg=TEXT, bg=PANEL,
                 wraplength=300, justify="center").pack(pady=(18, 8))

        pb = ttk.Progressbar(overlay, mode="indeterminate", length=280)
        pb.pack(pady=(0, 10))
        pb.start(12)

        def dismiss():
            self.after(0, lambda: (pb.stop(), overlay.grab_release(),
                                   overlay.destroy()))
        return dismiss

    # ── Threading helpers

    def _run_threaded(self, title: str, script: str, args: list[str], after=None):
        self._log("head", f"\n{'─'*40}\n▶ {title}  {datetime.now().strftime('%H:%M:%S')}\n{'─'*40}")
        self.status_label.configure(text=f"Running: {title}...", fg=YELLOW)
        dismiss = self._loading_overlay(f"Running: {title}…")

        def _worker():
            ok = run_ps(script, args, self._log_line, workdir=str(APP_DIR))
            dismiss()
            self.after(0, lambda: self.status_label.configure(
                text=f"{'✓' if ok else '✗'} {title}", fg=GREEN if ok else RED))
            if after:
                self.after(300, after)
        threading.Thread(target=_worker, daemon=True).start()

    def _run_reg_threaded(self, title: str, fn, after=None):
        self._log("head", f"\n{'─'*40}\n▶ {title}  {datetime.now().strftime('%H:%M:%S')}\n{'─'*40}")
        self.status_label.configure(text=f"Running: {title}...", fg=YELLOW)
        dismiss = self._loading_overlay(f"Running: {title}…")

        def _worker():
            try:
                fn()
                self._log("ok", f"[OK] {title} completed.")
                self.after(0, lambda: self.status_label.configure(text=f"✓ {title}", fg=GREEN))
            except Exception as ex:
                self._log("err", f"[ERROR] {title}: {ex}")
                self.after(0, lambda: self.status_label.configure(text=f"✗ {title}", fg=RED))
            dismiss()
            if after:
                self.after(300, after)
        threading.Thread(target=_worker, daemon=True).start()

    # ── Status refresh

    def refresh_all_status(self):
        def _check():
            user  = self.state.get("restricted_user", "")
            wdac  = self.state.get("wdac_policy_name", DEFAULT_WDAC_POLICY)
            proxy = getattr(self, "proxy_user", None)
            proxy_name = proxy.get().strip() if proxy else self.state.get("proxy_username", "")
            pairs = [
                (self.acl_status,        check_acl_applied(user)),
                (self.wdac_status,       check_wdac_deployed(wdac)),
                (self.store_status,      check_store_blocked()),
                (self.chrome_doh_status, check_doh("chrome")),
                (self.edge_doh_status,   check_doh("edge")),
                (self.ext_status,        check_ext_lockdown("chrome")),
                (self.proxy_status,      check_proxy_locked(proxy_name)),
                (self.bg_status,         check_browserguard_deployed()),
                (self.firewall_status,   check_firewall_suite_deployed()),
                (self.adapter_guard_status, check_adapter_guard_deployed()),
                (self.dns_status,           check_dns_suite_deployed(self.dns_capable_list.size())),
            ]
            for lbl, (txt, col) in pairs:
                self._set_status(lbl, txt, col)
        threading.Thread(target=_check, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    App().mainloop()