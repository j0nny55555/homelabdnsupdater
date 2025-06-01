# Homelab DNS Manager with Bind9 & Redis Integration

This script automates dynamic DNS updates for a homelab network using Bind9, Redis, OPNsense, and Portainer. It synchronizes device hostnames, IP addresses, and MAC addresses between your network infrastructure and DNS records.

---

## 📌 Prerequisites

Before running the script, ensure you have:

### 1. **Software Dependencies**
- Python 3.x (tested with 3.9+)
- Redis server (`redis`)
- OPNsense firewall (API enabled)
- Bind9 DNS server configured with TSIG key for updates
- Portainer (for Docker container metadata, optional)

Install required Python packages:
```bash
pip install redis requests dnspython python-dotenv configparser
```

---

## 🛠️ Configuration Setup

### 1. **Redis Configuration**
Update the Redis section in `cachedbindupdate.ini`:
```ini
[Redis]
Host = <redis_ip>
Port = 6379
DB = 0
Password = your_redis_password
```
Ensure Redis is running and accessible from your script's host.

---

### 2. **OPNsense API Access**
Enable the OPNsense REST API via:
- Web UI → System → Settings → Advanced → API Access

Update these values in `cachedbindupdate.ini`:
```ini
[OPNSense]
Key = <api_key>
Secret = <api_secret>
URL = https://<opnsense_ip>/api
```

---

### 3. **DNS Server Configuration**
- Ensure Bind9 is running on the specified DNS server (`192.168.0.1` by default)
- Create a TSIG key for dynamic updates:
```bash
dnssec-keygen -a HMAC-MD5 -b 128 -n HOST dnsipupdates
```
Copy the generated key secret to your config file:
```ini
[DNS]
KeyNameUpdates = dnsipupdates
KeySecretUpdate = <your_key_secret>
DNSServer = <bind_dns_ip>
```

---

### 4. **Portainer Configuration (Optional)**
If using Docker container metadata:
```ini
[Portainer]
URL = http://<portainer_ip>:9000
Username = admin
Password = <your_password>
```

---

## 📁 Config File Details

The `cachedbindupdate.ini` file contains critical settings:

| Section     | Key                 | Description                                                                 |
|------------|---------------------|-----------------------------------------------------------------------------|
| Redis      | Host/Port/DB        | Redis server connection details                                           |
| OPNSense   | Key/Secret          | API credentials for OPNsense                                              |
| DNS        | DNSServer           | IP address of your Bind9/DNS server                                     |
|            | KeyNameUpdates      | TSIG key name used by Bind9                                               |
|            | KeySecretUpdate     | TSIG key secret (from `dnssec-keygen`)                                  |
| Config     | ForwardZone         | DNS zone for FQDNs (e.g., `homelab.home.`)                               |
|            | IPv4Resolver/IPv6Resolver | IP addresses of DNS servers used for lookups                        |
|            | IPv4SubnetFilter    | Filter IPs from specific subnets (e.g., `192.168.`)                     |
|            | IPv6SubnetFilter    | Filter IPs from specific subnets (e.g., `2001:0db8:85a3::/48`)            |
|            | Subnets             | List of subnets to process for reverse DNS lookups                          |
|            | ReverseZones        | Corresponding reverse DNS zones for each subnet                             |

---

## 🚀 Usage

### 1. **Run the Script**
```bash
python cachedbindupdate.py
```

### 2. **Automate Updates (Recommended)**
Schedule the script as a cron job to run periodically:
```bash
crontab -e
# Run every 5 minutes
*/5 * * * * /usr/bin/python3 /path/to/cachedbindupdate.py >> /var/log/dnsmanager.log 2>&1
```

---

## 🔍 Notes & Best Practices

### 🔄 Redis Data Lifecycle
- The script filters out stale data older than 2 days by default. Adjust `last_seen` thresholds if needed.
- Use `KEY_PATTERNS` to control what data is collected from Redis.

### 🧪 IPv4 Only Hosts
For hosts that should only get A records (not AAAA):
```ini
IPv4OnlyHosts = hostname1
                hostname2
```

### 🔄 Reverse DNS Zones
Ensure reverse zones match your subnets. Example for `192.168.0.0/24`:
```
Subnets = 192.168.0
ReverseZones = 0.168.192.in-addr.arpa.
```

### 🔒 Security
- Never commit your Redis/OPNsense passwords to version control.
- Use a `.env` file or encrypted secrets for sensitive data.
- ⚠️ Security Tip:  
- The `cachedbindupdate.ini` template is meant for reference only. Replace placeholder values (e.g., `CHANGEME`) with your actual credentials.
- **Never commit sensitive information** like Redis passwords, OPNsense API keys, or Portainer credentials to version control.

---

## 📝 Troubleshooting Tips

| Issue                                | Solution                                                                 |
|-------------------------------------|--------------------------------------------------------------------------|
| No DNS updates applied              | Check Bind9 logs and ensure TSIG key matches both script & DNS server  |
| Redis connection failed             | Verify Redis is running, firewall rules allow access                   |
| OPNsense API errors                 | Ensure API token has correct permissions in OPNsense UI                |
| PTR records missing                 | Double-check reverse zone configuration in `ReverseZones`              |

---

## 🤖 AI Assistance Note

This content was generated with the assistance of AI tools to aid in its creation. However, **all information, configurations, and scripts have been manually reviewed, tested, and verified** for accuracy and functionality by the author prior to sharing. While AI provided assistance with drafting documentation and structure, the script itself was authored and tested entirely by the user. This final output reflects real-world testing and experienced validation to ensure reliability for your homelab setup.

---

## 📌 License
This script is open source and released under the MIT License. Modify as needed for your homelab environment.

---

## 🧰 Contributing

If you find issues, bugs, or want to improve this script, feel free to:
- Open an issue on GitHub (or your preferred platform)
- Submit a pull request with clear explanations
- Share improvements or bug fixes in comments below!