<img width="977" height="870" alt="image" src="https://github.com/user-attachments/assets/dad468c6-90b1-44af-b61e-d12896e70b0d" /><span align="center">

# NullSight - Authorized Bulk Penetration Testing Scanner

**Version:** 1.4 | **Year:** 2026 | **Author:** TheDEEP

</span>

##  ABOUT

**NullSight** is a professional, authorized mass penetration testing scanner designed for security researchers and penetration testers. It combines multiple attack vectors, misconfiguration detection, and supply chain analysis into a single powerful tool.

```text
╔═══════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                    == COVERAGE ==                                                 ║
╠═══════════════════════════════════════════════════════════════════════════════════════════════════╣
║                                                                                                   ║
║    40+ NEW CVE PAYLOADS                                                                           ║
║      • Vite, Next.js, Laravel, Yii, Rails, Spring, and more                                       ║
║                                                                                                   ║
║    FRAMEWORK-SPECIFIC INJECTIONS                                                                  ║
║      • ReactToShell • NginxToShell • SSI Injection Probes                                         ║
║                                                                                                   ║
║    MISCONFIGURATION ENGINE                                                                        ║
║      • Yii debug • Laravel debug • Django DEBUG=True                                              ║
║                                                                                                   ║
║    SUPPLY CHAIN SECURITY                                                                          ║
║      • Deep inspection: package.json, composer.json, requirements.txt                             ║
║                                                                                                   ║
║    SSRF PROBES                                                                                    ║
║      • Cloud metadata: AWS / GCP / Azure / Alibaba / DigitalOcean / Hetzner                       ║
║                                                                                                   ║
║    API SECURITY                                                                                   ║
║      • GraphQL introspection abuse • JWT weak secret / alg:none detection                         ║
║                                                                                                   ║
║    UNAUTHENTICATED DATABASE PROBES                                                                ║
║      • Redis • Memcached • MongoDB                                                                ║
║                                                                                                   ║
║    PROTOTYPE POLLUTION                                                                            ║
║      • JSON body injection probes                                                                 ║
║                                                                                                   ║
║    LFI CHAINING                                                                                   ║
║      • PHP wrappers: php://filter • expect:// • data://                                           ║
║                                                                                                   ║
║    SMART DETECTION ENGINE                                                                         ║
║      • Entropy-based FP filtering • Status-code aware • Redirect-aware                            ║
║                                                                                                   ║
║                                                                                                   ║
║    MULTI-FORMAT REPORT                                                                            ║
║      • JSON • CSV • Markdown • Terminal                                                           ║
║                                                                                                   ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝
```

---

## 🔧 INSTALLATION

```bash
# Clone the repository
git clone https://github.com/thedeep/NullSight.git
cd NullSight

# Install dependencies
pip install -r requirements.txt

# Or install manually
pip install requests beautifulsoup4 dnspython colorama urllib3
```

---

## 🚀 USAGE

### Basic Scan

```bash
# Single target
python3 nullsight.py -u https://example.com

# Multiple targets from file
python3 nullsight.py -l targets.txt

# fast mass scan
python3 nullsight.py -c 300 -t 6 --connect-timeout 3 --read-timeout 5

# With subdomain enumeration
python3 nullsight.py -d example.com --subdomains
```

### Advanced Options

```bash
# Thread count for mass scanning
python3 nullsight.py -l targets.txt -t 100

# Output format
python3 nullsight.py -u https://example.com -o json -r report.json
python3 nullsight.py -u https://example.com -o csv -r report.csv
python3 nullsight.py -u https://example.com -o md -r report.md
python3 nullsight.py -u https://example.com -o terminal

# Module-specific scans
python3 nullsight.py -u https://example.com --cve-only
python3 nullsight.py -u https://example.com --ssrf
python3 nullsight.py -u https://example.com --graphql
python3 nullsight.py -u https://example.com --lfi
```

### Full Command Reference

```text
┌────────────────────────────────────────────────────────────────────────────┐
│  NullSight - Authorized Mass Penetration Testing Scanner                   │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  USAGE:                                                                    │
│    python3 nullsight.py -u <URL>                                           │
│    python3 nullsight.py -l <file>                                          │
│    python3 nullsight.py -d <domain> --subdomains                           │
│                                                                            │
│  OPTIONS:                                                                  │
│    -u, --url           Target URL (http://example.com)                     │
│    -l, --list          File containing list of targets                     │
│    -d, --domain        Domain for subdomain enumeration                    │
│    -t, --threads       Number of threads (default: 20)                     │
│    -o, --output        Output format: json, csv, md, terminal              │
│    -r, --report        Report filename                                     │
│    --subdomains        Enable subdomain enumeration                        │
│    --cve-only          Scan only CVE payloads                              │
│    --ssrf              SSRF probes only                                    │
│    --graphql           GraphQL introspection only                          │
│    --lfi               LFI chaining only                                   │
│    --timeout           Request timeout (default: 10)                       │
│    --verbose           Verbose output                                      │
│    -v, --version       Show version                                        │
│    -h, --help          Show this help                                      │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

##   SEVERITY LEVELS

```text
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████████  CRITICAL  ─── Remote Code Execution, Full System Compromise    ║
║   ████████    HIGH      ─── Sensitive Data Exposure, Privilege Escalation    ║
║   ██████      MEDIUM    ─── Information Disclosure, Path Traversal           ║
║   ████        LOW       ─── Debug Mode Enabled, Version Disclosure           ║
║   ██          INFO      ─── Technology Detection, Open Ports                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## 📁 OUTPUT EXAMPLES

### JSON Format

```json
{
  "target": "https://example.uz",
  "timestamp": "2026-05-28T12:00:00",
  "severity": "CRITICAL",
  "findings": [
    {
      "type": "LFI",
      "payload": "php://filter/convert.base64-encode/resource=/etc/passwd",
      "severity": "CRITICAL",
      "evidence": "root:x:0:0:root:/root:/bin/bash"
    }
  ]
}
```

### Terminal Format

```text
╔═══════════════════════════════════════════════════════════════════╗
║  [CRITICAL] LFI detected on https://example.com                   ║
║  ───────────────────────────────────────────────────────────────  ║
║  Payload: php://filter/convert.base64-encode/resource=/etc/passwd ║
║  Evidence: root:x:0:0:root:/root:/bin/bash                        ║
╚═══════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════╗
║  [HIGH] SSRF - AWS Metadata accessible                           ║
║  ─────────────────────────────────────────────────────────────── ║
║  Endpoint: http://169.254.169.254/latest/meta-data/              ║
║  Response: instance-id, ami-id, hostname                         ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## DISCLAIMER

```text
╔══════════════════════════════════════════════════════════════════════════════╗
║                           ⚠️  WARNING  ⚠️                                   ║
║                                                                              ║
║   This tool is designed for AUTHORIZED penetration testing only.             ║
║   Unauthorized scanning of systems you don't own is ILLEGAL.                 ║
║                                                                              ║
║   The author (TheDEEP) is not responsible for any misuse of this tool.       ║
║   Always obtain proper written permission before testing.                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## 📞 CONTACT

- **Author**: TheDEEP
- **Version**: 1.4
- **Year**: 2026
- **Website**: https://www.thedeep.uz

---

## ⭐ LICENSE

This project is for educational and authorized testing purposes only.

---

<p align="center">
  <b>Use responsibly. Stay legal. Hack ethically.</b>
</p>
