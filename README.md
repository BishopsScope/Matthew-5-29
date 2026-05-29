# Matthew 5:29

> *"If your right eye causes you to sin, tear it out and throw it away."*

---

## Motive

<!-- Fill in your personal reason for creating this software here -->

---

## Demo

<!-- YouTube demo link: [Watch the demo](https://www.youtube.com/watch?v=YOUR_LINK_HERE) -->

---

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
Run `restriction_manager.exe`. Windows will immediately present a UAC elevation prompt — click **Yes**. The executable is compiled with `--uac-admin`, so administrator rights are requested automatically; no right-click required.

### Step 2 — ACL File Restrictions
Enter the restricted user's account name → click **Apply**.

> **Restore from backup:** If the ACL restrictions were previously applied, the **Restore from file…** button in the ACL card lets you select an existing XML backup. Backups are stored at `C:\NTFS_ACL_Backups\<backup file>.xml` — navigate there if you need to locate one manually.

### Step 3 — WDAC Application Control

> ⚠️ **Read this before clicking Apply.**
>
> WDAC blocks any executable not in `C:\Program Files` or `C:\Program Files (x86)`. This includes the Restriction Manager itself if it lives somewhere like `C:\Users\YourAdminName\Downloads`. **Before applying the policy, the "Allow Extra Paths" field is pre-loaded with `C:\Users\Admin\*` — edit this to match your actual admin account name** (e.g. `C:\Users\<Your Admin Account Name>\*`) so the Restriction Manager remains runnable.
>
> If you forget and find yourself locked out of running the Restriction Manager (or any other exe), **DO NOT PANIC**. Navigate to `C:\Windows\System32\CodeIntegrity\CiPolicies\Active`, delete or move the `.cip` file in that folder, and restart the computer. Everything will work normally again.
>
> It is strongly recommended to **test WDAC on your specific setup** before finalizing the restrictions — any program installed outside `C:\Program Files` (for example in `AppData`) will stop working. Reinstall those programs using a system installer and choose "Install for all users" to put them in `C:\Program Files`. The policy can be removed with one click in the Restriction Manager at any time.

Edit the pre-loaded `C:\Users\Admin\*` in the "Allow Extra Paths" field to match your admin account name, then click **Apply**. **Reboot when prompted.**

### Step 4 — Block Windows Store
Click **Apply**.

### Step 5 — Disable DoH
Click **Apply** in both the **Chrome — Disable DoH** and **Edge — Disable DoH** cards. This is required for the DNS Suite to work.

### Step 6 — Extension Lockdown
Click **Auto-detect Chrome Extensions** and **Auto-detect Edge Extensions** to populate the allowlist from what's already installed, then click **Apply**.

### Step 7 — Proxy Lock
Enter the restricted user's account name → click **Apply**.

> **Status note:** If the restricted user's account is currently signed in, the status will show **"Locked (\<username\>)"** confirming the lock is active. If the restricted user is fully signed out, Windows unloads their registry hive and the status will indicate the hive could not be loaded — this does not mean the lock is missing. To verify: log in to the restricted account, then switch back to the admin account without signing out. The GUI will update the status correctly once the hive is loaded and you type in the restricted username.

### Step 8 — BrowserGuard

> **Note about the desktop watermark:** BrowserGuard enables Windows test-signing mode, which puts a small watermark in the lower-right corner of the desktop. This is harmless and disappears the moment you click **Remove** in the BrowserGuard card and reboot. You can also remove the watermark manually by doing the following:
> 1) Type `cmd` into the task bar
> 2) Right click `Command Prompt` and select `Run as administrator`
> 3) Type `bcdedit /set testsigning off` and press Enter.
> 4) Reboot the computer

Click **Apply**. **Reboot when prompted.**

### Step 9 — Firewall Suite *(optional)*
Click **Apply**. Use the **Timesheet Manager** shortcut that appears on the desktop to set allowed internet access hours. See the [Q&A](#qa) section for when to use this component and when to skip it. To use the **Timesheet Manager** shortcut, decide on which hours you'll want to have internet access enabled and then do the following:
1) Open the shortcut link provided on the desktop
2) Type `a`
3) Enter the specific time you want internet access from (e.g. 7:00PM-9:30PM on January 1st, 2026 would be `01/01/2026 7:00pm-9:30pm`) and then press Enter
4) Do step 3 for as many times as you need intervals of internet access
5) Press Enter again
6) Press `q` again and then press Enter

Now the timesheet will be updated and the restricted user will have internet during the given time interval(s).

> **Note:** when the **Firewall Suite** is applied, by default you won't have any internet access on the machine, so you (and your accountability partner) will need to maintain the timesheet regularly.

### Step 10 — Adapter Guard
Review the adapters shown in the text box and keep only the adapters the restricted user should legitimately use (e.g. the "Wi-Fi" adapter). Remove anything else you don't need access to — virtual adapters, VirtualBox/Hyper-V adapters, Ethernet if Wi-Fi is the intended connection, etc. Click **Apply**.

> ⚠️ **If Adapter Guard is not applied, there is a hole in the restrictions.** A user could plug in a USB Wi-Fi dongle or Ethernet cable that has no DNS restrictions configured and connect to a wireless network, completely bypassing the DNS Suite in Step 11.

### Step 11 — DNS Suite *(most important)*

1. In the DNS Suite card, move **all** network adapters from the **DNS-Incapable** box to the **DNS-Capable** box using the → button. Any adapter left in the DNS-Incapable box bypasses the restrictions entirely.
2. Click **Run DNS Whitelist Logger**, open up a **Google Chrome** or **Microsoft Edge** browser window and browse all websites the restricted user should have access to. Close the window when done.
3. Click **Run Merge Whitelists** and for every domain the **DNS Whitelist Logger** caught that **wasn't** present in the whitelist before, it'll prompt you to type `y`, `n` or `w`(hitelist) and then press Enter to add it to the whitelist.

> For example, in order for **youtube.com** to properly render, you need to allow sub-domains of
> * `rr1---sn-a5mlrnlz.googlevideo.com`
> * `rr2---sn-a5mekndd.googlevideo.com`
> * `yt3.ggpht.com`
>
> and more in order for videos to render properly, but there's *two* problems with this:
>
> 1) Nobody wants to remember to manually to add `yt3.ggpht.com` to their whitelist for `youtube.com` to render (imagine having to remember dozens of irrelevant sub-domains in order to get a single website to be added to the whitelist)
> 2) Sub-domains like `rr1---sn-a5mlrnlz.googlevideo.com` change all the time, so if you whitelisted it word-for-word, then tomorrow the domain may not render
>
> The solution?
>
> When you run **Merge Whitelists** and a domain like `rr1---sn-a5mlrnlz.googlevideo.com` appears (which solves **problem 1** from above), you have **three** options:
>
> 1) Type `y` -- adds `rr1---sn-a5mlrnlz.googlevideo.com` to the whitelist (but if ANY part of that domain changes, the DNS server won't render it anymore)
> 2) Type `n` -- rejects `rr1---sn-a5mlrnlz.googlevideo.com` from being added to the whitelist
> 3) Type `w` -- **Merge Whitelists** will ask you if you want the domain name `googlevideo.com` included in the whitelist followed by asking if you want `*.googlevideo.com` (the `*` is a wildcard, which solves **problem 2**). If you answer `n` to `*.googlevideo.com`, then **Merge Whitelists** will move one domain higher and ask you if you want `rr1---sn-a5mlrnlz.googlevideo.com` followed by asking if you want `*.rr1---sn-a5mlrnlz.googlevideo.com` and it keeps asking that paired domain combination until you say `y` on the wildcard prompt **or** it asks you for `*.<the full remaining domain>`.
>
> **Note: Usually when you choose to whitelist a domain (because you think it may change in the future), the vast majority of the time you should enter `y` and `y` after choosing `w`, so try to default to doing this, but you will need to experiment depending on which websites you're whitelisting.**


4. Click **Apply** to deploy the DNS server.

> **Backup and restore:** Click **Export DNS Files** to save a snapshot of `whitelisted_domains.json`, `blacklisted_domains.json`, and `domain_access_log.json` to a folder of your choice. To restore from a backup, click **Upload JSON File** and select the file — it must be named *exactly* `whitelisted_domains.json`, `blacklisted_domains.json`, or `domain_access_log.json` for the upload to be routed to the correct destination automatically.
>
> **Settings:** The DNS card exposes two configurable values — **Upstream DNS IP** (default `8.8.8.8`; change this if you prefer a different upstream resolver such as `1.1.1.1`) and **Threshold Days** (default `7`). Click **Save** after changing either value. Whitelisted domain names that appear in **red** in the whitelist panel are domains whose last-access timestamp (stored in `domain_access_log.json`) exceeds `Threshold Days` — these have not been visited recently and should be considered for deletion to keep the whitelist lean.
>
> **Note:** It may be worth running steps 2-3 above occasionally as domain names and sub-domain names undergo updates.

### Step 12 — Hand Over the Password
Give the administrator account password to the accountability partner. Setup is complete.

---

## Restrictions Reference (Additional Details)

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
> **If you get locked out** (can't run the Restriction Manager or other exes after a reboot), navigate to `C:\Windows\System32\CodeIntegrity\CiPolicies\Active`, delete or move the file named **`{AE466EE3-68C3-20E7-A255-F6B84E1F225A}.cip`** (there will be several `.cip` files in that folder — this is the one created by the Restriction Manager), and restart. All exes will run normally again immediately.

**WDAC is a machine-wide policy**. Any exe in the allowed paths can run without restriction. Script enforcement can optionally be disabled (the "Disable Script Enforcement" checkbox) to leave PowerShell unrestricted for the administrator.

**Test before finalizing.** Programs installed outside `C:\Program Files` or `C:\Program Files (x86)` — typically any program installed "for this user only" — will stop working. Reinstall them using a system-level installer and choose "Install for all users" to place them in `C:\Program Files` or `C:\Program Files (x86)`.

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

**Why it's needed:** Both browsers accept command-line arguments that can override security policies — for example, `--dns-servers=8.8.8.8` to bypass the DNS server, or `--proxy-server` to set a proxy. A kernel driver is the only reliable way to block this because user-mode approaches (NTFS permissions, Registry tricks) aren't comprehensive.

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

**Why a whitelist instead of a blacklist?** See the [Q&A](#qa) section for the full explanation. In short: a blacklist can never be complete; a whitelist blocks everything by default and only opens what you've explicitly approved.

**The whitelist + blacklist combination** is what makes this practical day-to-day — the whitelist provides the broad "only approved sites" policy, while the blacklist provides fine-grained overrides for blocking specific subdomains of otherwise-allowed sites (e.g. blocking `drive.google.com` while keeping `accounts.google.com` available). It's worth noting that the blacklist is **NOT** mandatory for the **DNS Suite** to function properly, but the whitelist **is** mandatory to use the internet.

**Three executables are deployed:**

- **`dns_whitelist_blacklist_server.exe`** — the DNS server itself. Binds to `0.0.0.0:53`. Queries matching the blacklist → NXDOMAIN. Queries matching the whitelist → forwarded to upstream resolver (default: `8.8.8.8`, configurable in the GUI). All other queries → NXDOMAIN. Also logs the last-access timestamp for each whitelisted domain to `domain_access_log.json`.

- **`dns_whitelist_logger.exe`** — a capture-only DNS server with no filtering. Run this while the restricted user (or the administrator acting on their behalf) browses the sites they need. Every queried domain is recorded to `new_whitelisted_domains.json`. Close the window when done.

- **`merge_whitelists.exe`** — walks through every domain in `new_whitelisted_domains.json` not already in `whitelisted_domains.json` and prompts the administrator to approve or skip it. Supports wildcard entries and deduplicates automatically.

**Stale domain tracking:** The Restriction Manager displays the whitelist with any domain not accessed within a configurable number of days highlighted in red with a day-count. This helps keep the whitelist lean over time.

> **All network adapters must be DNS-Capable.** Move every adapter from the DNS-Incapable box to the DNS-Capable box. Any adapter left in DNS-Incapable bypasses the DNS server entirely. IPv6 is automatically disabled on each adapter when moved to DNS-Capable — this prevents a glitch where Windows sometimes randomly resets IPv6-based changes to adapters.

> **Run the DNS Logger first, then Merge Whitelists, then start using the server.** The DNS server blocks everything by default. If you start it before populating the whitelist, **no website will resolve at all until you populate and apply the whitelist.**

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

**Critical warning:** If you deploy the Firewall Suite without the DNS Suite, during every internet window the user has fully unrestricted internet access — every other restriction in this project can be worked around if you have unrestricted internet and enough time. **There is no possible way to have an internet access window where the restrictions cannot be bypassed unless the DNS Suite is also deployed.** The Firewall Suite is designed for situations where the user is trusted during the allowed window (ex: when an accountability partner is physically present).

If content filtering is your goal, the DNS Suite is non-negotiable. The Firewall Suite is an add-on for time control, not a content filter.

### Why not just use CleanBrowsing, NextDNS, or Cloudflare Family?

All of those services operate on blacklists. The fundamental problem with any blacklist is that it can never be complete — the internet adds new domains constantly, content moves between domains, and a motivated person will eventually find something that wasn't catalogued. Even the best commercial filters with dedicated teams maintaining them will miss things. You cannot prove a blacklist blocks *everything*, and one missed domain is all it takes.

A whitelist-based DNS server doesn't have this problem because it starts from "everything is blocked" and only opens what you've explicitly approved. If a new domain appears tomorrow that has never been seen before, it is blocked by default — no one has to add it to any list.

### What about Firefox, Brave, or other browsers?

**Remove them.** The DoH restriction, BrowserGuard, and Extension Lockdown only cover Chrome and Edge. Any other browser is a complete bypass vector for the DNS and proxy restrictions. Perhaps future updates will include support for additional browsers.


---

## Architecture & Build Guide

This assumes you want to compile the `restriction_manager.exe` file for yourself. If you just want to download and run the restrictions, then you can launch the pre-compiled `restriction_manager.exe` file I compiled by clicking the `Code` button (if you're viewing this from GitHub) and then clicking `Download ZIP` and locating and running the executable from there.

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

Python 3.10+ (I used Python 3.11.3), PyInstaller, and `dnslib`:
```
pip install --upgrade pyinstaller dnslib
```
or
```
pip install -r requirements.txt
```

### Compile the restriction_manager.py script into an exe file

Run
```
python main.py
```
and after a few minutes, you'll see `restriction_manager.exe` fully compiled