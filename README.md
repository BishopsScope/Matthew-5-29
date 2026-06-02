# Project Matthew 5:29

> *"If your right eye causes you to sin, tear it out and throw it away."* (ESV)
>
> \- Jesus (The Sermon on the Mount)

---

## Motive

If you are reading this, welcome.

This project has been a long time in the making. After years of searching for a comprehensive solution to block **all** avenues of access to pornographic content on the Windows operating system—and coming up empty-handed—I was driven by Jesus' words in **Matthew 5:29** to build my own accountability software.

Over time I've identified all of the major loopholes that one could use to access pornography on a Windows machine and patched them. One-by-one, I incrementally built dozens of scripts to close all forms of access. Eventually, I merged all of these scripts into a software you can now download and run called `restriction_manager.exe` as a centralized coordinator to harmonize all restrictions together in one place.

My goal has always been to create a software that makes Windows fully porn-proof and reaches as many people as possible. Now, in the click of a few buttons, **ANYONE** who wants to *"tear out"* the eye that causes them to sin can do so. No advanced programming knowledge needed. No subscription costs. No hidden fees. Just a tool for anyone with a Windows computer who shares a hatred for sin. Download the software, run it for **FREE**, and the problem of accessing pornographic content on your device is over.

Over the years, I faced countless objections:

> *"There's always going to be a way around whatever restrictions you set."*
> *"If you're determined enough, you'll be able to access it no matter what."*
> *"What Jesus was really saying is that you just have to make it hard enough to do."*

Where did Jesus say to make it merely *hard* to access your sin? Can you access an eye that you've **torn out** and **thrown away**? I challenge whoever is reading this, humbly and with grace: **you will not find that interpretation in Matthew 5:29 if you look at the text honestly.**

If this software blesses even **one** person, I will count it a success. If you have a programming background and would like to contribute, I encourage you to do so. If you know anyone this could help, please share it with them.

---

## Demo

Google Drive Link: [Project Matthew 5:29 Demo](https://drive.google.com/file/d/1GdTHLjwKmbEkjCCSzUABMynUTqXKROdh/view?usp=sharing)

## Overview: Windows Restriction Manager

A GUI-driven restriction framework for Windows 11 that lets an administrator deploy a comprehensive suite of internet-access and application-execution restrictions on a shared machine—with the click of a button, entirely for free.

**What this is:** This software is designed to make it **impossible**—not just difficult—for someone using a restricted (non-admin) account on a Windows 11 computer to access pornographic content. Existing solutions are often expensive, ineffective, or both. This tool is free, works on **Windows 11 Home**, and can be set up by anyone following the steps below.

### ⚠️ Completely Free — No Paid Software Required

Every restriction here uses tools already built into Windows 11. This is worth stating explicitly, because experienced Windows users may immediately think of features like **AppLocker**, **Local Security Policy** (`secpol.msc`), or **Group Policy Editor** (`gpedit.msc`)—all of which require Windows 11 Pro or Enterprise. 

**None of those are used here.** This project works on a stock Windows 11 Home machine with no purchases, no subscriptions, and no third-party services.

If you'd like to support development, see the [Support](#support) section at the bottom of this page.

---

## Table of Contents

1. [Motive](#motive)
2. [Demo](#demo)
3. [Overview: Windows Restriction Manager](#overview-windows-restriction-manager)
4. [Requirements](#requirements)
5. [Deployment Quick-Start](#deployment-quick-start)
6. [Restrictions Reference](#restrictions-reference)
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
7. [How the Restrictions Reinforce Each Other](#how-the-restrictions-reinforce-each-other)
8. [Q&A](#qa)
9. [Architecture & Build Guide](#architecture--build-guide)
10. [License](#license)
11. [Support](#support)

---

## Requirements

1. **Windows 11** (Home edition is supported).
2. **Two user accounts on the machine:**
   - An **Administrator account** (runs the Restriction Manager and controls all settings).
   - A **Standard (non-admin) account** (used day-to-day by the restricted person).
   - *Note: If you only have one account, create a standard account before proceeding. The restrictions target the standard account specifically.*
3. **Only Chrome and/or Edge installed.** Other browsers (Firefox, Brave, Opera, etc.) bypass the DNS/DoH restrictions and must be uninstalled.
4. **An Accountability Partner.** After setup, the administrator password must be given to a trusted partner. Every restriction in this project can be undone by an administrator.

---

## Deployment Quick-Start

> **Before you start:**
> Install any Chrome/Edge extensions the restricted user will need *before* completing Step 6. Once applied, the restrictions must be undone for new extensions can be added.

### Step 1 — Run the Restriction Manager
Run `restriction_manager.exe`. Windows will present a UAC elevation prompt — click **Yes**.

> Note: you can download the `restriction_manager.exe` file in the simplest way by:
> 1) Visiting `https://github.com/BishopsScope/Matthew-5-29`
> 2) On the right-hand side, locate the `Release` tab and click the latest release, scroll down and then click the `restriction_manager.exe` file to download it directly
>
> Another option is to compile it **manually** if you have Python installed. If you prefer this option, see the [Architecture and Build Guide](#architecture--build-guide)

**The remaining steps take place in the `restriction_manager.exe` window.**

### Step 2 — ACL File Restrictions
Enter the restricted user's account name, then click **Apply**.
*(To restore previous settings later, use the **Restore from file…** button to locate your backup at `C:\NTFS_ACL_Backups\`)*.

### Step 3 — WDAC Application Control
> ⚠️ **CRITICAL WARNING:** WDAC blocks any executable not in `C:\Program Files` or `C:\Program Files (x86)`. This includes the Restriction Manager itself if you are running it from your Downloads folder. 
> 
> **Action Required:** The "Allow Extra Paths" field is pre-loaded with `C:\Users\Admin\*`. **You must edit this to match your actual admin account name** (e.g., `C:\Users\JohnDoe\*`) so the Manager remains runnable.
>
> *If you accidentally lock yourself out, navigate to `C:\Windows\System32\CodeIntegrity\CiPolicies\Active`, delete the `{AE466EE3-68C3-20E7-A255-F6B84E1F225A}.cip` file generated by the Manager, and reboot.*

Edit the path to match your admin name, click **Apply**, and **Reboot when prompted.**

### Step 4 — Block Windows Store
Click **Apply**.

### Step 5 — Disable DoH
Click **Apply** in *both* the **Chrome — Disable DoH** and **Edge — Disable DoH** cards. 

### Step 6 — Extension Lockdown
Click **Auto-detect Chrome Extensions** and **Auto-detect Edge Extensions** to populate the allowlist with your currently installed extensions. Then, click **Apply**.

### Step 7 — Proxy Lock
Enter the restricted user's account name, then click **Apply**. 
*(Note: If the restricted user is currently signed out, the tool may indicate the registry hive could not be loaded. Log into the restricted account, switch back to the admin account without signing out, and try again).*

### Step 8 — BrowserGuard
Click **Apply**. **Reboot when prompted.**
*(Note: This enables Windows test-signing mode, which places a harmless "Test Mode" watermark in the lower-right corner of your desktop. Removing BrowserGuard removes this watermark).*

### Step 9 — Firewall Suite *(Optional)*
Click **Apply**. A shortcut called **Timesheet Manager** will appear on the desktop. Use this to set specific hours when internet access is allowed. By default, internet access is completely blocked when enabled.
**To configure the timesheet:**
1. Open the **Timesheet Manager** shortcut.
2. Type `a` and press Enter.
3. Enter your desired time interval (e.g., `01/01/2026 7:00pm-9:30pm`) and press Enter.
4. Repeat for as many intervals as needed.
5. Press Enter on a blank line to finish.
6. Type `q` and press Enter to quit. 

### Step 10 — Adapter Guard
Review the network adapters shown. Keep only the adapters the restricted user legitimately needs (e.g., "Wi-Fi"). Remove adapters that aren't needed by the restricted user from the list, then click **Apply**.

### Step 11 — DNS Suite *(Most Important)*

**What is DNS?**
The Domain Name System (DNS) maps website names (e.g., `youtube.com`) to IP addresses (e.g., `104.237.180.122`). This DNS Suite intercepts those lookups and only allows access to websites on your **Whitelist**. Everything else is blocked by default. 

**Configuration Steps:**
1. Move **all** network adapters from the **DNS-Incapable** box to the **DNS-Capable** box using the `→` button. 
2. Click **Run DNS Whitelist Logger**. Open Chrome/Edge and browse all websites the restricted user needs access to. Close the logger window when done.
3. Click **Run Merge Whitelists**. A terminal will appear asking which domains you'd like to send to the whitelist that you just logged. 

> **How to use "Merge Whitelists":**
> Modern websites rely on dozens of randomized sub-domains (e.g., `rr1---sn-a5mlrnlz.googlevideo.com` for YouTube). Adding these to your whitelist manually is impossible because they change constantly. 
> 
> When prompted with a logged domain, you have three options:
> * **`y` (Yes):** Whitelists the exact, full sub-domain you're presented with. (Not recommended for randomized URLs, as it will break when the URL changes).
> * **`n` (No):** Rejects the domain and moves on.
> * **`w` (Wildcard mode):** Helps you allow a broader pattern so the site won't break when sub-domains change.
> 
> **How the Wildcard (`w`) option works:**
> If the logger caught a long domain like `a.b.c.d.com` and you press `w`, the tool steps backward from the shortest part of the domain to the longest:
> 1. First, it asks for the base domain: `Add base 'd.com'?` (Saying `y` allows *exactly* `d.com`).
> 2. Next, it asks for the wildcard: `Add wildcard '*.d.com'?` (Saying `y` allows `anything.d.com` — like `mail.d.com` or `a.b.c.d.com`).
>    * **Crucial Note:** `*.d.com` is **NOT** the same as `d.com`. A wildcard only covers sub-domains, it doesn't cover the base domain itself. If a site requires both the base domain *and* its sub-domains to load properly, you must type `y` to both prompts!
> 3. If you say `y` to the wildcard, the tool saves it and moves on to the next completely new logged domain.
> 4. If you say `n` to the wildcard, the tool moves one level deeper and asks about `c.d.com`, then `*.c.d.com`. If you say `n` again, it asks for `b.c.d.com` and `*.b.c.d.com`, and so on, until you approve a wildcard or reach the full domain.

4. Click **Apply** to deploy the DNS server. 

### Step 12 — Hand Over the Password
Give the administrator account password to your accountability partner. Setup is complete.

---

## Restrictions Reference

### 1. ACL File Restrictions
**What it does:** Denies the restricted user the ability to execute powerful Windows system tools (e.g., `powershell.exe`, `curl.exe`, `nslookup.exe`).

**Why it's needed:** These tools are common bypass vectors. `curl.exe` and `nslookup.exe` can query DNS by IP address, bypassing the DNS server entirely. `powershell.exe` can execute scripts to reconfigure network settings. By applying recursive NTFS ACL Deny rules, the user cannot execute these files even if they find copies hidden elsewhere in the `C:\Windows` directory.

### 2. WDAC Application Control
**What it does:** Deploys a Windows Defender Application Control policy in "Enforce" mode, blocking any executable not located in `C:\Program Files` or `C:\Program Files (x86)`.

**Why it's needed:** Prevents the user from downloading and running arbitrary portable executables (like VPNs, custom browsers, or DNS bypass tools) directly from their Downloads or Desktop folders.

### 3. Block Windows Store
**What it does:** Disables the `InstallService` Windows service and adds an outbound firewall block rule targeting the Store.

**Why it's needed:** The Microsoft Store is a direct installation path for VPN apps and alternative browsers that require no administrator credentials. Blocking it seals this vector.

### 4. Disable DNS-over-HTTPS (DoH)
**What it does:** Writes machine-level Registry policy keys that unconditionally disable DoH in Chrome and Edge.

**Why it's needed:** DoH encrypts DNS queries, completely bypassing local DNS servers. If left enabled, the user could bypass the entire DNS Suite by clicking a single toggle in their browser settings. 

### 5. Browser Extension Lockdown
**What it does:** Uses a Registry policy to block all Chrome/Edge extensions by default, leaving only the explicitly allowed Extension IDs functional.

**Why it's needed:** Browser extensions can act as VPNs, proxy clients, or DoH enablers. This prevents the user from installing unapproved extensions to circumvent network restrictions.

### 6. Windows Proxy Lock
**What it does:** Forces the system proxy to "off" and applies a Registry Deny ACE that prevents the restricted user from modifying the proxy settings.

**Why it's needed:** A proxy server routes traffic through an external address, bypassing local DNS. This restriction hard-locks the proxy feature.

### 7. BrowserGuard Kernel Driver
**What it does:** Installs a kernel-mode driver (`BrowserGuard.sys`) that returns "Access Denied" if Chrome or Edge is launched using command-line arguments.

**Why it's needed:** Browsers accept command-line flags (like `--dns-servers=8.8.8.8` or `--proxy-server`) that override internal security policies. A kernel driver is the only reliable way to block these flags system-wide.

### 8. Firewall Suite
**What it does:** Deploys a Task Scheduler process that enforces a strict, time-based internet access schedule via Windows Firewall.

**Why it's needed:** Allows an administrator to ensure the internet is only accessible during approved windows (e.g., when an accountability partner is physically present). Useful if the restricted user needs to access the open internet for a limited period of time (should be used without the DNS Suite active).

### 9. Adapter Guard
**What it does:** A background task that fires instantly via Windows PnP events whenever a network adapter connects, disabling any adapter not explicitly whitelisted.

**Why it's needed:** Prevents the user from plugging in a USB Wi-Fi dongle or secondary Ethernet cable to bypass the configured DNS restrictions on the primary network adapter.

### 10. DNS Suite
**What it does:** Installs a custom, local DNS server (binding to `0.0.0.0:53`) that cross-references all web traffic against a strict Whitelist and Blacklist.

**Why it's needed:** This enforces the core content restriction. It utilizes a default-deny (whitelist) approach because blacklists can never be complete. If a domain isn't explicitly approved on the whitelist, the server returns an `NXDOMAIN` error, completely blocking access.

---

## How the Restrictions Reinforce Each Other

No single restriction here is unbreakable in isolation. They are designed to be deployed together as a web:

| Bypass Attempt | Blocked By |
|---|---|
| Download and run a VPN installer | **WDAC (#2)** blocks the executable; **Store block (#3)** prevents Store installs |
| Install a VPN/proxy browser extension | **Extension Lockdown (#5)** |
| Enable DoH in the browser settings | **DoH disable (#4)** locks the browser UI |
| Launch Chrome with `--dns-servers` | **BrowserGuard (#7)** returns Access Denied |
| Use `curl.exe` or `nslookup.exe` | **ACL restrictions (#1)** deny execution |
| Run PowerShell to reconfigure network | **ACL restrictions (#1)** block `powershell.exe` |
| Enable a proxy server in Windows | **Proxy Lock (#6)** locks the registry key |
| Switch to a different network adapter | **Adapter Guard (#9)** disables unapproved adapters |
| Plug in a USB Wi-Fi dongle | **Adapter Guard (#9)** disables it immediately upon connection |
| Access an unapproved website | **DNS Suite (#10)** refuses to resolve un-whitelisted domains |
| Access the internet late at night | **Firewall Suite (#8)** blocks traffic outside scheduled hours |

---

## Q&A

### Do I need the Firewall Suite?
**The Firewall Suite is optional.** It controls *when* internet is available, not *what* content is accessible. Use it if you want to cut off internet access outside of specific hours. 

**Critical warning:** If you deploy the Firewall Suite *without* the DNS Suite, the user will have fully unrestricted internet access during their allowed windows. The Firewall Suite is not a content filter.

### Why not just use CleanBrowsing, NextDNS, or Cloudflare Family?
Those services operate on blacklists. The fundamental problem with a blacklist is that it can never be complete. The internet adds new domains constantly, and a motivated person will eventually find something that wasn't catalogued. A whitelist-based DNS server starts from "everything is blocked" and only opens what you explicitly approve. 

### What about Firefox, Brave, or other browsers?
**Remove them.** The DoH restriction, BrowserGuard, and Extension Lockdown are specifically coded to lock down Chrome and Edge. Any other browser is a bypass vector. Support for additional browsers may be included in future updates.

---

## Architecture & Build Guide

*Note: If you just want to use the software, download the pre-compiled `restriction_manager.exe` from the Releases page or by clicking `Code -> Download ZIP` on GitHub. If you'd rather compile the software yourself, continue reading.*

### How it works
The Restriction Manager is a single compiled `.exe` that bundles all dependencies internally. Auxiliary tools are compiled separately with PyInstaller into `--onedir` folders, zipped into `.dat` payload files, and embedded into the main executable. At runtime, the manager extracts the payloads, registers Task Scheduler tasks, and configures the OS automatically.

```text
restriction_manager.exe
├── FIREWALL_SUITE.dat    ← firewall_scheduler.exe + timesheet_manager.exe
├── DNS_SUITE.dat         ← dns_server.exe + dns_logger.exe + merge_whitelists.exe
├── ADAPTER_GUARD.dat     ← adapter_guard_oneshot.exe
└── BROWSERGUARD_SYS.dat  ← BrowserGuard.sys (kernel driver binary)
```

### Build prerequisites *(dev machine only)*

Python 3.10+ (I used Python 3.11.3), `PyInstaller`, and `dnslib`:
```bash
pip install --upgrade pyinstaller dnslib
```
or
```bash
pip install -r requirements.txt
```

### Compile the restriction_manager.py script into an exe file

Run
```bash
python main.py
```
and after a few minutes, you'll see `restriction_manager.exe` fully compiled.

## License

This project is licensed under the CC BY-NC-SA 4.0 License. See the LICENSE file for details.

## Support

This software is free and open source. If it has been useful to you and you'd like to support future development, you can sponsor me on GitHub:

❤️ [Sponsor this project](https://github.com/sponsors/bishopsscope)

Thank you to everyone who contributes, reports bugs, submits pull requests, or shares the project with others.
