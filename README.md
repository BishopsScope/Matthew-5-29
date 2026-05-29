# Windows Restriction Manager

A GUI-driven restriction framework for Windows 11 that lets an administrator deploy a comprehensive suite of internet-access and application-execution restrictions on a shared machine — with the click of a button, entirely for free.

---

> **What this is:** This software is designed to make it **impossible** — not just difficult — for someone using a restricted account on a Windows 11 computer to access pornography or other blocked content. It was built because existing solutions are either expensive, ineffective, or require advanced technical knowledge to configure. This one is free, works on **Windows 11 Home**, and is designed so that a non-technical person can set it up by following the steps in this document.

---

## ⚠️ This Is Completely Free — No Paid Software Required

Every restriction here uses tools already built into Windows 11, **including Windows 11 Home**. This is worth saying explicitly, because experienced Windows users may immediately think of:

- **AppLocker** — requires Windows 11 Pro/Enterprise
- **Local Security Policy** (`secpol.msc`) — requires Windows 11 Pro/Enterprise
- **Group Policy Editor** (`gpedit.msc`) — requires Windows 11 Pro/Enterprise

**None of those are used here.** This project works on a stock Windows 11 Home machine with no purchases, no subscriptions, and no third-party services.

---

## Table of Contents

1. [Requirements](#requirements)
2. [Deployment Quick-Start](#deployment-quick-start)
3. [Restrictions Reference](#restrictions-reference)
   - [1. ACL File Restrictions](#1-acl-file-restrictions)
   - [2. WDAC Application Control](#2-wdac-application-control)
   - [3. Block Windows Store](#3-block-windows-store)
   - [4. Disable DNS-over-HTTPS (DoH)](#4-disable-dns-over-https-doh)
   - [5. Browser Extension Lockdown](#5-browser-extension-lockdown)
   - [6. Windows Proxy Lock](#6-windows-proxy-lock)
   - [7. BrowserGuard Kernel Driver](#7-browserguard-kernel-driver)
   - [8. Firewall Suite](#8-firewall-suite)
   - [9. Adapter Guard](#9-adapter-guard)
   - [10. DNS Suite](#10-dns-suite)
4. [How the Restrictions Reinforce Each Other](#how-the-restrictions-reinforce-each-other)
5. [Q&A](#qa)
6. [Extra Hardening Notes](#extra-hardening-notes)
7. [Architecture & Build Guide](#architecture--build-guide)

---

## Requirements

1. **Windows 11** (Home edition is fine).
2. **Two user accounts on the machine:**
   - An **administrator account** — runs the Restriction Manager and controls all settings.
   - A **non-administrator (standard) account** — the account the restricted person uses day-to-day.
   - If you only have one admin account, create a standard account before proceeding. The restrictions target the standard account specifically.
3. **Only Chrome and/or Edge installed as browsers.** Other browsers (Firefox, Brave, Opera, etc.) bypass the DNS and DoH restrictions and must be removed.
4. **After setup, the administrator password must be given to an accountability partner** — not kept by the person subject to the restrictions. Every restriction in this project can be undone by someone who can log in as an administrator.

---

## Deployment Quick-Start

> Follow these steps in order. Detailed explanations for each restriction are in the [Restrictions Reference](#restrictions-reference) section below.

**Before you start:**
- Install any Chrome/Edge extensions the restricted user will need *before* Step 5 (Extension Lockdown). Once that's applied, no new extensions can be added.
- Read the WDAC note in Step 3 carefully before clicking Apply.

### Step 1 — Run the Restriction Manager
Right-click `restriction_manager.exe` → **Run as administrator** → click Yes on the UAC prompt.

### Step 2 — ACL File Restrictions
Enter the restricted user's account name → click **Apply**.

### Step 3 — WDAC Application Control

> ⚠️ **Read this before clicking Apply.**
>
> WDAC blocks any executable not in `C:\Program Files` or `C:\Program Files (x86)`. This includes the Restriction Manager itself if it lives somewhere like `C:\Users\YourAdminName\Downloads`. **Before applying the policy, add `C:\Users\<your admin account name>\*` to the "Allow Extra Paths" field in the WDAC card** so the Restriction Manager remains runnable.
>
> If you forget and find yourself locked out of running the Restriction Manager (or any other exe), don't panic. Navigate to `C:\Windows\System32\CodeIntegrity\CiPolicies\Active`, delete or move the `.cip` file in that folder, and restart the computer. Everything will work normally again.
>
> It is strongly recommended to **test WDAC on your specific setup** before finalizing the restrictions — any program installed outside `C:\Program Files` (for example in `AppData`) will stop working. Reinstall those programs using a system installer and choose "Install for all users" to put them in `C:\Program Files`. The policy can be removed with one click in the Restriction Manager at any time.

Add `C:\Users\<your admin account name>\*` to the "Allow Extra Paths" field, then click **Apply**. **Reboot when prompted.**

### Step 4 — Block Windows Store
Click **Apply**.

### Step 5 — Disable DoH
Click **Apply** in both the **Chrome — Disable DoH** and **Edge — Disable DoH** cards. This is required for the DNS Suite to work.

### Step 6 — Extension Lockdown
Click **Auto-detect Chrome Extensions** and **Auto-detect Edge Extensions** to populate the allowlist from what's already installed, then click **Apply**.

### Step 7 — Proxy Lock
Enter the restricted user's account name → click **Apply**.

### Step 8 — BrowserGuard

> **Note about the desktop watermark:** BrowserGuard enables Windows test-signing mode, which puts a small watermark in the lower-right corner of the desktop. This is harmless and disappears the moment you click **Remove** in the BrowserGuard card and reboot.

Click **Apply**. **Reboot when prompted.**

### Step 9 — Firewall Suite *(optional)*
Click **Apply**. Use the **Timesheet Manager** shortcut that appears on the desktop to set allowed internet access hours. See the [Q&A](#qa) section for when to use this component and when to skip it.

### Step 10 — Adapter Guard
Review the adapters shown in the text box, remove any virtual or unwanted adapters, then click **Apply**.

### Step 11 — DNS Suite *(most important)*

1. In the DNS Suite card, move **all** network adapters from the **DNS-Incapable** box to the **DNS-Capable** box using the → button. Any adapter left in the DNS-Incapable box bypasses the restrictions entirely.
2. Click **Run DNS Whitelist Logger** and browse all websites the restricted user should have access to. Close the window when done.
3. Click **Run Merge Whitelists** and walk through the prompts to approve the captured domains.
4. Click **Apply** to deploy the DNS server.

### Step 12 — Hand Over the Password
Give the administrator account password to the accountability partner. Setup is complete.

---

## Restrictions Reference

---

### 1. ACL File Restrictions

**What it does:** Denies the restricted user the ability to execute a configurable list of powerful Windows system tools — by default: `powershell.exe`, `powershell_ise.exe`, `bitsadmin.exe`, `certutil.exe`, `cscript.exe`, `curl.exe`, `nslookup.exe`, and `wsl.exe`. Attempting to run any of these from the restricted account results in an "access denied" error.

**Why it's needed:** These tools are the most common bypass vectors. `curl.exe` and `nslookup.exe` can query DNS directly by IP address, bypassing the DNS server entirely. `powershell.exe` can execute arbitrary scripts, download files, and reconfigure network settings. `certutil.exe` and `bitsadmin.exe` are frequently abused as download utilities.

**Why not just block the folders?** Several of these executables (especially `powershell.exe`) exist in multiple locations under `C:\Windows` — `System32`, `SysWOW64`, `WinSxS`, etc. A folder-level block is bypassed by finding a copy elsewhere. This restriction searches recursively and blocks every instance.

> **You can add more executables to the list** in the Restriction Manager before clicking Apply. If you find other system tools that could be used to bypass the restrictions, add them here.

**Does not affect** the administrator account. Does not block read access — only execution.

**ACL backups** are saved to `C:\NTFS_ACL_Backups\` before any changes, enabling a clean one-click restore.

---

### 2. WDAC Application Control

**What it does:** Deploys a Windows Defender Application Control (WDAC) policy in Enforce mode that blocks any executable not covered by the policy from running. By default, execution is allowed from `C:\Program Files\*`, `C:\Program Files (x86)\*`, and any additional paths you specify. When a blocked file tries to run, Windows displays a notification informing the user that the file is blocked by policy.

**Why it's needed:** NTFS ACL restrictions alone can't prevent a user from downloading and running arbitrary executables. A user could download a VPN installer, a custom browser, or a DNS bypass tool to their Desktop and run it. WDAC operates at the kernel level and blocks execution regardless of where the file came from.

**Why not AppLocker?** WDAC is enforced by the Windows kernel directly and is available on Windows 11 Home. AppLocker requires Pro/Enterprise.

> ⚠️ **Critical — add your admin account path before applying:**
> Any exe not in `C:\Program Files` or `C:\Program Files (x86)` will be blocked — including the Restriction Manager itself if it's running from somewhere like `C:\Users\YourAdminName\`. Before clicking Apply, add `C:\Users\<your admin account name>\*` to the "Allow Extra Paths" field.
>
> **If you get locked out** (can't run the Restriction Manager or other exes after a reboot), navigate to `C:\Windows\System32\CodeIntegrity\CiPolicies\Active`, delete or move the `.cip` file there, and restart. All exes will run normally again immediately.

**Does not restrict** the administrator account independently — WDAC is a machine-wide policy. Any exe in the allowed paths runs for everyone. Script enforcement can optionally be disabled (the "Disable Script Enforcement" checkbox) to leave PowerShell unrestricted for the administrator.

**Test before finalizing.** Programs installed outside `C:\Program Files` — typically anything installed "for this user only" — will stop working. Reinstall them using a system-level installer and choose "Install for all users" to place them in `C:\Program Files`.

---

### 3. Block Windows Store

**What it does:** Disables the `InstallService` Windows service and adds a firewall outbound block rule targeting the Store's package family name. The Microsoft Store becomes non-functional — it cannot connect to the internet or install applications.

**Why it's needed:** The Store is a direct installation path for VPN apps, proxy clients, and alternative browsers that require no web download and no administrator credentials. Blocking it removes this vector.

**Does not** uninstall already-installed Store applications or affect apps installed before this restriction was applied.

---

### 4. Disable DNS-over-HTTPS (DoH)

**What it does:** Writes machine-level Registry policy keys that unconditionally disable DNS-over-HTTPS in Chrome and Edge. Both browsers will display "Use secure DNS is managed by your organization" in settings — the option cannot be changed by the user.

**Why it's needed:** DoH routes DNS queries over encrypted HTTPS to a remote resolver chosen by the user, completely bypassing the local DNS server. Without this restriction, the restricted user could enable DoH in browser settings in under a minute and immediately circumvent the entire DNS Suite. This must be applied for restriction #10 to work.

**Only covers Chrome and Edge.** Any other browser with DoH capability must be removed or separately restricted.

*Writes to `HKLM\SOFTWARE\Policies\Google\Chrome` and `HKLM\SOFTWARE\Policies\Microsoft\Edge`. No reboot required — takes effect on next browser launch.*

---

### 5. Browser Extension Lockdown

**What it does:** Installs a wildcard extension block (`*`) for both Chrome and Edge via Registry policy, then writes an allowlist of specific extension IDs. Every extension not on the allowlist is disabled; no new extensions can be installed from any source.

**Why it's needed:** A single browser extension can act as a VPN, proxy client, or DoH enabler — any of which bypasses the DNS restrictions. This restriction prevents new extensions from being installed at the policy level.

> **Install all extensions you need *before* applying this.** Use the **Auto-detect** buttons to automatically populate the allowlist from whatever is currently installed — this ensures nothing the user already has gets unexpectedly blocked.

Extensions disabled by this restriction show as "Blocked by administrator" in the browser. Their data is preserved if they're later added to the allowlist.

---

### 6. Windows Proxy Lock

**What it does:** Accesses the restricted user's registry hive, forces the system proxy to off, and applies a Deny ACE that prevents the restricted user from modifying the proxy registry key. The user can see their proxy settings in Windows Settings but cannot change them.

**Why it's needed:** A proxy server routes traffic through an external address, bypassing the DNS server. This restriction removes that option at the registry level.

The proxy is forced **off** before the lock is applied — the user will never be stuck with a proxy enabled. The GUI refuses to apply this restriction to any account in the local Administrators group.

---

### 7. BrowserGuard Kernel Driver

**What it does:** Installs `BrowserGuard.sys` as a kernel-mode driver that intercepts process creation events. When Chrome (`chrome.exe`) or Edge (`msedge.exe`) is launched with any command-line arguments, the driver returns **Access Denied** — the browser simply won't open if arguments are passed to it. Chrome and Edge launched normally (via shortcut, Start menu, or by clicking a file) work without issue.

**Why it's needed:** Both browsers accept command-line arguments that can override security policies — for example, `--dns-servers=8.8.8.8` to bypass the DNS server, or `--proxy-server` to set a proxy. A kernel driver is the only reliable way to block this because user-mode approaches (NTFS permissions, Registry tricks) can be worked around by copying the exe elsewhere.

> **About the desktop watermark:** BrowserGuard requires Windows test-signing mode, which puts a small watermark in the lower-right corner of the desktop (e.g. "Test Mode — Windows 11"). This is harmless and not permanent — clicking **Remove** in the BrowserGuard card and rebooting removes it completely.

**WDAC interaction:** If a WDAC policy is deployed, the Restriction Manager automatically generates and deploys a supplemental WDAC policy that whitelists the driver's signing certificate, so the kernel driver isn't blocked by code integrity enforcement.

Deployment also disables HVCI (Memory Integrity) via Registry, which is required for test-signed drivers to load. Both test-signing and HVCI are automatically restored when BrowserGuard is removed.

---

### 8. Firewall Suite

**What it does:** Deploys two executables and a Task Scheduler task that controls internet access based on a time schedule:

- **`firewall_scheduler.exe`** — runs on every boot and sleep-wake event. Creates a "Block All Internet" Windows Firewall rule and activates it, then enters a polling loop checking the timesheet. When the current time falls inside an approved window, the rule is disabled (internet allowed); otherwise it remains enabled (internet blocked).

- **`timesheet_manager.exe`** — a desktop application for editing the schedule. A shortcut called **Timesheet Manager** is placed on the desktop for all users. It requires administrator elevation to run, so the restricted user cannot modify the schedule. Run this shortcut to configure the allowed access windows.

**Timesheet format:**
```
Format:  M/D/YYYY HH(am/pm)-HH(am/pm)
Example: 3/5/2026 10am-12pm   or   3/5/2026 2:30pm-4pm
```

**This component is optional** — see the [Q&A](#qa) for when to use it and the important warning about using it without the DNS Suite.

---

### 9. Adapter Guard

**What it does:** Deploys `adapter_guard_oneshot.exe` and a Task Scheduler task that fires on boot and whenever any network adapter connects. It reads an allowlist of approved adapter names and disables any adapter not on the list.

**Why it's needed, reason 1 — multiple adapters:** If the machine has both Wi-Fi and Ethernet, a user might switch to whichever adapter doesn't have the DNS restrictions configured. Adapter Guard ensures only approved adapters stay enabled.

**Why it's needed, reason 2 — new hardware:** If the restricted user physically plugs in a USB Wi-Fi dongle or any other network adapter, Adapter Guard fires the moment the adapter connects (via the Windows Kernel PnP event system) and disables it before it can be used. It is literally impossible to add a new internet connection to bypass the DNS restrictions — the adapter is blocked before any traffic can flow through it.

Note: The Firewall Suite's blanket block applies regardless of adapter, so even if a new adapter somehow slipped past Adapter Guard, the Firewall Suite's rule would still prevent internet access during blocked hours. But the Firewall Suite does not provide content filtering — the DNS Suite does. The Adapter Guard exists specifically to protect the DNS restrictions from adapter-switching bypasses.

The allowlist is managed entirely through the Restriction Manager GUI — no file editing required.

---

### 10. DNS Suite

**This is the most important restriction in the entire project.** Everything else exists to protect it or close gaps around it.

**What it does at a high level:** Installs a custom DNS server that intercepts every domain lookup on the machine. Before any website can be loaded, the browser asks this server "where does this website live?" The server checks the request against two lists:

- **Whitelist** — domains the restricted user is allowed to visit. Approved lookups are forwarded to an upstream resolver and the result is returned normally.
- **Blacklist** — domains that are always refused, even if they'd otherwise be covered by the whitelist. Used for blocking specific subdomains of otherwise-allowed sites.

If a domain is on neither list, the server returns NXDOMAIN — the browser cannot connect to the site at all. **Everything is blocked by default unless explicitly approved.**

**Why a whitelist instead of a blacklist?**

Every major DNS filtering service — CleanBrowsing, NextDNS, Cloudflare Family — works by maintaining a blacklist of known bad domains. The fundamental problem with this approach is that **it cannot be complete**. The internet changes constantly, new domains appear daily, and a motivated person will find a domain that the filter missed. A blacklist that blocks 99.9999% of adult websites still leaves a gap, and that gap is all that's needed. You cannot prove a blacklist blocks *everything* — only that it blocks everything you thought to add.

A whitelist inverts this: it blocks *everything except* what you've explicitly approved. You don't need to catalogue every bad website on the internet. You just need to approve the good ones. If a domain isn't on the whitelist, it doesn't matter what it contains — the DNS server refuses to resolve it.

**The whitelist + blacklist combination** is what makes this practical day-to-day. The whitelist provides the broad "only approved sites" policy. The blacklist provides fine-grained overrides — for example, `google.com` can be whitelisted for Search while `accounts.google.com` is blacklisted to prevent account switching.

**Three executables are deployed:**

- **`dns_whitelist_blacklist_server.exe`** — the DNS server itself. Binds to `0.0.0.0:53`. Queries matching the blacklist → NXDOMAIN. Queries matching the whitelist → forwarded to upstream resolver (default: `8.8.8.8`, configurable in the GUI). All other queries → NXDOMAIN. Also logs the last-access timestamp for each whitelisted domain to `domain_access_log.json`.

- **`dns_whitelist_logger.exe`** — a capture-only DNS server with no filtering. Run this while the restricted user (or the administrator acting on their behalf) browses the sites they need. Every queried domain is recorded to `new_whitelisted_domains.json`. Close the window when done.

- **`merge_whitelists.exe`** — walks through every domain in `new_whitelisted_domains.json` not already in `whitelisted_domains.json` and prompts the administrator to approve or skip it. Supports wildcard entries and deduplicates automatically.

**Stale domain tracking:** The Restriction Manager displays the whitelist with any domain not accessed within a configurable number of days highlighted in red with a day-count. This helps keep the whitelist lean over time.

> **All network adapters must be DNS-Capable.** Move every adapter from the DNS-Incapable box to the DNS-Capable box in the DNS Suite card. Any adapter left in DNS-Incapable bypasses the DNS server and the restrictions entirely. The Restriction Manager automatically disables IPv6 on each adapter when it is moved to DNS-Capable — this prevents IPv6-based DNS bypasses. (When you uncheck IPv6 this way, Windows will not re-enable it automatically.)

> **Run the DNS Logger first, then Merge Whitelists, then start the server.** The DNS server blocks everything by default. If you start it before populating the whitelist, no website will resolve at all until you populate and apply the whitelist.

---

## How the Restrictions Reinforce Each Other

No single restriction here is unbreakable in isolation. They are designed to be deployed together:

| Bypass attempt | Blocked by |
|---|---|
| Download and run a VPN installer | WDAC (#2) blocks exe; Store block (#3) prevents Store installs |
| Install a VPN/proxy extension in Chrome or Edge | Extension Lockdown (#5) |
| Enable DoH in the browser to bypass DNS | DoH disable (#4) removes this from the browser UI |
| Launch Chrome with `--dns-servers` argument | BrowserGuard (#7) returns Access Denied when any arguments are passed |
| Use `curl.exe` or `nslookup.exe` for direct IP queries | ACL restrictions (#1) deny execution |
| Run PowerShell to reconfigure DNS or network | ACL restrictions (#1) deny execution of `powershell.exe` |
| Enable a proxy server to bypass DNS | Proxy Lock (#6) denies all writes to the proxy registry key |
| Switch to a different network adapter | Adapter Guard (#9) disables all non-approved adapters |
| Plug in a USB Wi-Fi dongle or Ethernet adapter | Adapter Guard (#9) fires on the PnP connect event and disables it immediately |
| Access any unapproved website | DNS Suite (#10) refuses to resolve any domain not on the whitelist |
| Access the internet outside approved hours | Firewall Suite (#8) blocks all traffic outside configured time windows |

---

## Q&A

### Do I need the Firewall Suite?

**The Firewall Suite is optional.** It controls *when* internet is available, not *what* content is accessible.

Use it if you want to completely cut off internet access outside of specific hours — for example, a shared family computer where internet is allowed from 4pm–9pm on weekdays.

**Critical warning:** If you deploy the Firewall Suite without the DNS Suite, during every internet window the user has fully unrestricted internet access — every other restriction in this project can be worked around if you have unrestricted internet and enough time. **There is no possible way to have an internet access window where the restrictions cannot be bypassed unless the DNS Suite is also deployed.** The Firewall Suite is designed for situations where the user is trusted during the allowed window (for example, because an accountability partner is physically present, or the restriction is self-imposed).

If content filtering is your goal, the DNS Suite is non-negotiable. The Firewall Suite is an add-on for time control, not a content filter.

### Why not just use CleanBrowsing, NextDNS, or Cloudflare Family?

All of those services operate on blacklists. The fundamental problem with any blacklist is that it can never be complete — the internet adds new domains constantly, content moves between domains, and a motivated person will eventually find something that wasn't catalogued. Even the best commercial filters with dedicated teams maintaining them will miss things. You cannot prove a blacklist blocks *everything*, and one missed domain is all it takes.

A whitelist-based DNS server doesn't have this problem because it starts from "everything is blocked" and only opens what you've explicitly approved. If a new domain appears tomorrow that has never been seen before, it is blocked by default — no one has to add it to any list.

### What about Firefox, Brave, or other browsers?

**Remove them.** The DoH restriction, BrowserGuard, and Extension Lockdown only cover Chrome and Edge. Any other browser is a complete bypass vector for the DNS and proxy restrictions. If you can't uninstall a browser, use the WDAC policy to block its executable by adding its file hash or publisher to the policy.

---

## Extra Hardening Notes

- **iCloud:** If the machine has an iPhone connected, iCloud can transfer files outside of normal access controls. Block iCloud domains via the DNS Suite blacklist to prevent this.

- **Admin password hygiene:** The administrator account password must not be known to the restricted person. All restrictions can be undone by anyone who can log in as administrator.

---

## Architecture & Build Guide

### How it works

The Restriction Manager is a single compiled `.exe` that bundles all dependencies internally. Each auxiliary tool (DNS server, firewall scheduler, etc.) is compiled separately with PyInstaller into a `--onedir` folder, zipped into a `.dat` payload file, and embedded in the main exe via `--add-data`. At runtime, clicking an Apply button extracts the relevant payload to the correct system directory, registers Task Scheduler tasks, and creates shortcuts — no Python or manual file placement required on the target machine.

```
restriction_manager.exe
├── FIREWALL_SUITE.dat    ← firewall_scheduler.exe + timesheet_manager.exe (merged onedir)
├── DNS_SUITE.dat         ← dns_server.exe + dns_logger.exe + merge_whitelists.exe (merged onedir)
├── ADAPTER_GUARD.dat     ← adapter_guard_oneshot.exe (onedir)
└── BROWSERGUARD_SYS.dat  ← BrowserGuard.sys (kernel driver binary)
```

### Build prerequisites *(dev machine only)*

Python 3.10+, PyInstaller, and `dnslib`:
```
pip install --upgrade pyinstaller dnslib
```

### Step 1 — Compile payload scripts

**Groups** are used when multiple `--onedir` compilations need to share the same output directory (their `_internal/` folders are merged). The DNS suite tools must share a directory so they can read and write the same JSON data files at runtime. **Standalone scripts** are compiled independently.

```python
GROUPS: dict[str, list[dict]] = {
    "dns_suite": [
        {"file": "ScriptsToCompile/dns_whitelist_blacklist_server.py", "command": "pyinstaller --clean --onedir ScriptsToCompile/dns_whitelist_blacklist_server.py"},
        {"file": "ScriptsToCompile/dns_whitelist_logger.py",           "command": "pyinstaller --clean --onedir ScriptsToCompile/dns_whitelist_logger.py"},
        {"file": "ScriptsToCompile/merge_whitelists.py",               "command": "pyinstaller --onedir ScriptsToCompile/merge_whitelists.py"},
    ],
    "firewall_suite": [
        {"file": "ScriptsToCompile/firewall_scheduler.py",             "command": "pyinstaller --onedir --noconsole ScriptsToCompile/firewall_scheduler.py"},
        {"file": "ScriptsToCompile/timesheet_manager_firewall.py",     "command": "pyinstaller --onedir ScriptsToCompile/timesheet_manager_firewall.py"},
    ],
}

STANDALONE_SCRIPTS: list[dict] = [
    {"file": "ScriptsToCompile/adapter_guard_oneshot.py", "command": "pyinstaller --onedir --noconsole ScriptsToCompile/adapter_guard_oneshot.py"},
    # {"file": "ScriptsToCompile/restriction_manager.py", "command": "pyinstaller --onefile --noconsole --uac-admin restriction_manager.py --add-data \"FIREWALL_SUITE.dat;.\" --add-data \"BROWSERGUARD_SYS.dat;.\" --add-data \"ADAPTER_GUARD.dat;.\" --add-data \"DNS_SUITE.dat;.\""},
]
```

### Step 2 — Encode payloads

Running the encode step produces one `.dat` file per group and standalone:
```
FIREWALL_SUITE.dat
DNS_SUITE.dat
ADAPTER_GUARD.dat
BROWSERGUARD_SYS.dat    ← encoded directly from the BrowserGuard.sys binary
```

### Step 3 — Compile the Restriction Manager

Place all `.dat` files next to `restriction_manager.py`, then:

```
pyinstaller --onefile --noconsole --uac-admin restriction_manager.py ^
  --add-data "FIREWALL_SUITE.dat;."    ^
  --add-data "BROWSERGUARD_SYS.dat;." ^
  --add-data "ADAPTER_GUARD.dat;."    ^
  --add-data "DNS_SUITE.dat;."
```

`--uac-admin` makes Windows automatically request administrator elevation on launch. `--onefile` bundles everything — including all `.dat` payloads — into a single distributable exe.
