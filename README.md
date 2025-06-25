# Website Vulnerability Scanner Pro

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Termux-lightgrey.svg)](https://github.com/HolyBytes/scanner)

**Alat pengujian keamanan web profesional** untuk identifikasi kerentanan keamanan dengan metodologi penetration testing yang komprehensif.

---

## ⚠️ DISCLAIMER PENTING

**PERINGATAN HUKUM**: Tool ini dikembangkan khusus untuk **authorized penetration testing** dan **security assessment**. Penggunaan tanpa izin tertulis dari pemilik sistem merupakan pelanggaran hukum yang serius.

**TANGGUNG JAWAB PENGGUNA**:
- Anda sepenuhnya bertanggung jawab atas penggunaan tool ini
- Dapatkan **written authorization** sebelum melakukan scanning
- Patuhi undang-undang cybersecurity di yurisdiksi Anda
- Developer tidak bertanggung jawab atas penyalahgunaan

---

## 🎯 OVERVIEW

Scanner ini dirancang untuk security professionals dalam melakukan comprehensive vulnerability assessment dengan menggunakan teknik advanced penetration testing. Tool ini mengintegrasikan multiple attack vectors dengan precision detection untuk mengidentifikasi critical security flaws.

### Keunggulan Kompetitif

- **Enterprise-Grade Detection**: 15+ kategori kerentanan dengan 240+ payload vectors
- **High-Performance Architecture**: Multi-threaded scanning dengan optimasi resource management
- **Cross-Platform Compatibility**: Native support untuk Linux, Windows, macOS, dan Termux
- **Professional Reporting**: Detailed vulnerability assessment dengan risk scoring
- **Stealth Capabilities**: Advanced evasion techniques untuk bypassing basic security measures

---

## 🔬 TECHNICAL SPECIFICATIONS

### Vulnerability Coverage Matrix

| Kategori Kerentanan | Payload Count | Detection Method | Severity Level |
|---------------------|---------------|------------------|----------------|
| **Cross-Site Scripting (XSS)** | 25 | DOM Analysis, Response Pattern | High |
| **SQL Injection** | 30 | Error-based, Boolean-based, Time-based | Critical |
| **Remote Code Execution (RCE)** | 20 | Command Output Analysis | Critical |
| **Local File Inclusion (LFI)** | 18 | File Content Fingerprinting | High |
| **Server-Side Request Forgery (SSRF)** | 15 | Internal Service Probing | High |
| **XML External Entity (XXE)** | 12 | XML Parser Exploitation | Medium |
| **Command Injection** | 22 | System Command Response | Critical |
| **Open Redirect** | 15 | HTTP Header Analysis | Medium |
| **Server-Side Template Injection (SSTI)** | 18 | Template Engine Behavior | High |
| **Cross-Site Request Forgery (CSRF)** | 15 | Token Validation Testing | Medium |
| **Unrestricted File Upload** | 20 | MIME Type Bypass Testing | High |
| **Insecure Direct Object Reference (IDOR)** | 15 | Access Control Testing | Medium |
| **HTTP Header Injection** | 15 | Response Header Manipulation | Low |
| **JWT Vulnerabilities** | 18 | Token Cryptographic Analysis | High |
| **Directory Traversal** | 22 | Path Manipulation Testing | High |

### Performance Metrics

- **Concurrent Threads**: 1000 parallel execution threads
- **Request Timeout**: 10 seconds with exponential backoff
- **Memory Optimization**: Dynamic payload loading with garbage collection
- **Network Efficiency**: Connection pooling dengan keep-alive support
- **False Positive Rate**: <5% dengan advanced pattern matching

---

## 🛠 SYSTEM REQUIREMENTS

### Minimum Requirements
```
- Python 3.6 atau lebih tinggi
- RAM: 2GB minimum, 4GB recommended
- Storage: 100MB free space
- Network: Stable internet connection
- OS: Windows 7+, Linux (Ubuntu 16.04+), macOS 10.12+, Android (Termux)
```

### Recommended Specifications
```
- Python 3.8+
- RAM: 8GB untuk optimal performance
- CPU: Multi-core processor (4+ cores)
- Network: High-speed connection untuk bulk scanning
- VPN: Recommended untuk privacy dan security
```

---

## 📦 INSTALLATION GUIDE

### Universal Installation (Linux/Windows/macOS)

1. **Clone Repository**
   ```bash
   git clone https://github.com/HolyBytes/scanner.git
   cd scanner
   ```

2. **Setup Virtual Environment** (Recommended)
   ```bash
   python -m venv scanner_env
   source scanner_env/bin/activate  # Linux/macOS
   # scanner_env\Scripts\activate   # Windows
   ```

3. **Install Dependencies**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Verify Installation**
   ```bash
   python scanner.py --help
   ```

### Termux-Specific Installation

```bash
# Update package list
pkg update && pkg upgrade

# Install core dependencies
pkg install python git

# Clone and setup
git clone https://github.com/HolyBytes/scanner.git
cd scanner

# Install Python dependencies
pip install requests beautifulsoup4 colorama prettytable psutil urllib3
```

### Docker Installation (Advanced)

```dockerfile
# Create Dockerfile
FROM python:3.9-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
ENTRYPOINT ["python", "scanner.py"]
```

```bash
# Build and run
docker build -t vuln-scanner .
docker run --rm vuln-scanner -u https://example.com
```

---

## 🚀 USAGE MANUAL

### Basic Command Structure

```bash
python scanner.py [OPTIONS] -u <TARGET_URL>
python scanner.py [OPTIONS] -f <TARGET_FILE>
```

### Command Line Arguments

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-u, --url` | Single target URL | `-u https://example.com` |
| `-f, --file` | File containing target URLs | `-f targets.txt` |
| `-t, --threads` | Number of threads (default: 1000) | `-t 500` |
| `-o, --output` | Output file format (json/csv/txt) | `-o results.json` |
| `--timeout` | Request timeout in seconds | `--timeout 15` |
| `--user-agent` | Custom User-Agent string | `--user-agent "Custom Bot"` |
| `--proxy` | Proxy server configuration | `--proxy http://127.0.0.1:8080` |
| `--headers` | Custom HTTP headers | `--headers "X-Custom: Value"` |
| `--verbose` | Enable verbose logging | `--verbose` |
| `--stealth` | Enable stealth mode | `--stealth` |

### Usage Examples

#### 1. Basic Single Target Scan
```bash
python scanner.py -u https://testphp.vulnweb.com/
```

#### 2. Multi-Target Scanning
```bash
# Create targets.txt with URLs
echo "https://example1.com" > targets.txt
echo "https://example2.com" >> targets.txt

python scanner.py -f targets.txt
```

#### 3. Advanced Scanning with Custom Settings
```bash
python scanner.py -u https://example.com \
    --threads 500 \
    --timeout 20 \
    --output results.json \
    --user-agent "Mozilla/5.0 Security Scanner" \
    --verbose
```

#### 4. Stealth Mode Scanning
```bash
python scanner.py -u https://example.com \
    --stealth \
    --threads 100 \
    --proxy http://127.0.0.1:9050
```

#### 5. Corporate Network Scanning
```bash
python scanner.py -f internal_hosts.txt \
    --threads 50 \
    --timeout 30 \
    --headers "X-Forwarded-For: 192.168.1.100"
```

---

## 🔍 SCANNING METHODOLOGY

### Phase 1: Reconnaissance
- Target URL validation dan accessibility check
- Technology stack fingerprinting
- Directory enumeration dan hidden endpoint discovery
- Parameter identification untuk injection testing

### Phase 2: Vulnerability Detection
- Automated payload injection across identified parameters
- Response analysis menggunakan pattern matching algorithms
- Error-based detection untuk database interactions
- Time-based detection untuk blind vulnerabilities

### Phase 3: Exploitation Verification
- Proof-of-concept payload execution
- Impact assessment dan risk scoring
- False positive elimination
- Vulnerability chaining analysis

### Phase 4: Reporting
- Comprehensive vulnerability report generation
- Risk prioritization berdasarkan CVSS scoring
- Remediation recommendations
- Executive summary untuk management

---

## 📊 OUTPUT FORMATS

### Console Output
Real-time scanning progress dengan color-coded severity levels:
- 🔴 **CRITICAL**: RCE, SQLi dengan data exposure
- 🟠 **HIGH**: XSS, LFI, privilege escalation
- 🟡 **MEDIUM**: CSRF, open redirect, information disclosure
- 🟢 **LOW**: Header injection, minor misconfigurations

### JSON Report Format
```json
{
  "scan_metadata": {
    "target": "https://example.com",
    "scan_time": "2025-06-25T10:30:00Z",
    "duration": "00:05:23",
    "total_requests": 1500
  },
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "CRITICAL",
      "url": "https://example.com/login.php",
      "parameter": "username",
      "payload": "' UNION SELECT version()--",
      "evidence": "MySQL 8.0.23",
      "recommendation": "Use parameterized queries"
    }
  ]
}
```

### CSV Export
Compatible with Excel dan database import untuk vulnerability management systems.

---

## ⚡ PERFORMANCE OPTIMIZATION

### Threading Configuration
```python
# Optimal thread count berdasarkan system specs
LOW_END_DEVICE = 100    # Termux, single-core systems
STANDARD_SYSTEM = 500   # Dual-core, 4GB RAM
HIGH_END_SYSTEM = 1000  # Quad-core+, 8GB+ RAM
```

### Memory Management
- Dynamic payload loading untuk reduce memory footprint
- Automatic garbage collection setelah setiap target
- Connection pooling untuk efficient network usage
- Response caching untuk duplicate request reduction

### Network Optimization
- Adaptive timeout berdasarkan network latency
- Request queuing untuk prevent server overload
- Exponential backoff untuk failed requests
- DNS caching untuk faster hostname resolution

---

## 🛡 SECURITY CONSIDERATIONS

### Operational Security
- **Anonymity**: Gunakan VPN atau Tor untuk scanning
- **Traffic Encryption**: HTTPS-only untuk sensitive targets
- **Log Management**: Secure deletion dari scan logs
- **Credential Protection**: Jangan hardcode credentials dalam scripts

### Legal Compliance
- **Authorization Documentation**: Simpan written consent
- **Scope Limitation**: Scanning hanya pada authorized targets
- **Data Handling**: Proper handling dari sensitive data yang ditemukan
- **Incident Response**: Protocol untuk handling critical vulnerabilities

### Detection Evasion
- **User-Agent Rotation**: Randomized browser signatures
- **Request Timing**: Variable delays antara requests
- **Payload Obfuscation**: Encoded payloads untuk bypass WAF
- **Distributed Scanning**: Multiple source IPs untuk large targets

---

## 🚨 TROUBLESHOOTING GUIDE

### Common Issues & Solutions

#### Installation Problems
```bash
# SSL Certificate Issues
pip install --trusted-host pypi.org --trusted-host pypi.python.org <package>

# Permission Denied
sudo chown -R $USER:$USER /path/to/scanner/
chmod +x scanner.py

# Missing Dependencies
pip install --upgrade -r requirements.txt --force-reinstall
```

#### Runtime Errors
```bash
# Connection Timeout
python scanner.py -u <target> --timeout 30

# Memory Issues
python scanner.py -u <target> --threads 100

# SSL Verification Errors
export PYTHONHTTPSVERIFY=0  # Use with caution
```

#### Performance Issues
```bash
# Reduce thread count
python scanner.py -u <target> --threads 50

# Enable connection pooling
export PYTHONUNBUFFERED=1

# Monitor system resources
htop  # Linux
Activity Monitor  # macOS
Task Manager  # Windows
```

---

## 📈 ADVANCED FEATURES

### Custom Payload Development
```python
# Add custom payloads in payloads.py
CUSTOM_XSS = [
    "<script>alert('Custom XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    # Add more payloads
]
```

### Plugin Architecture
```python
# Create custom detection plugins
class CustomVulnDetector:
    def detect(self, response):
        # Custom detection logic
        return vulnerability_found
```

### Integration dengan CI/CD
```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    python scanner.py -u ${{ secrets.TARGET_URL }} \
      --output security_report.json
    
- name: Upload Results
  uses: actions/upload-artifact@v2
  with:
    name: security-report
    path: security_report.json
```

---

## 🤝 CONTRIBUTION GUIDELINES

### Development Setup
```bash
# Clone repository
git clone https://github.com/HolyBytes/scanner.git
cd scanner

# Create development branch
git checkout -b feature/new-vulnerability-check

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

### Code Standards
- **PEP 8** compliance untuk Python code
- **Type hints** untuk function signatures
- **Docstrings** untuk class dan method documentation
- **Unit tests** untuk new features

### Submission Process
1. Fork repository dan create feature branch
2. Implement changes dengan proper testing
3. Update documentation dan README
4. Submit pull request dengan detailed description
5. Pass CI/CD checks dan code review

---

## 📚 EDUCATIONAL RESOURCES

### Recommended Reading
- **OWASP Top 10**: Understanding common web vulnerabilities
- **PTES**: Penetration Testing Execution Standard
- **NIST Cybersecurity Framework**: Risk management guidelines
- **CVE Database**: Common Vulnerabilities and Exposures

### Training Materials
- Hands-on labs dengan DVWA (Damn Vulnerable Web Application)
- WebGoat security testing environment
- PortSwigger Web Security Academy
- OWASP WebSecurity Testing Guide

---

## 📞 SUPPORT & CONTACT

### Bug Reports
Create detailed issue reports di GitHub repository dengan:
- Operating system dan Python version
- Complete error messages dan stack traces
- Steps to reproduce the issue
- Expected vs actual behavior

### Feature Requests
Submit enhancement proposals dengan:
- Clear use case description
- Technical implementation suggestions
- Potential impact assessment

### Security Issues
Untuk security vulnerabilities dalam tool:
- **DO NOT** create public GitHub issues
- Email security concerns ke: security@holybytes.dev
- Use PGP encryption untuk sensitive communications

---

## 📄 LICENSE & LEGAL

### MIT License
```
Copyright (c) 2025 HolyBytes

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Terms of Use
By using this software, you agree to:
- Use tool hanya untuk authorized security testing
- Respect privacy dan intellectual property rights
- Comply dengan applicable laws dan regulations
- Indemnify developers dari any misuse consequences

---

## 🏆 ACKNOWLEDGMENTS

### Contributors
- **Lead Developer**: Ade Pratama (@HolyBytes)
- **Security Researchers**: Indonesian Cybersecurity Community
- **Beta Testers**: Penetration Testing professionals worldwide

### Special Thanks
- OWASP Foundation untuk vulnerability research
- Security community untuk responsible disclosure practices
- Open source projects yang menjadi foundation dari tool ini

---

## 🌟 PROJECT ROADMAP

### Version 2.0 (Planned)
- [ ] Machine Learning-based false positive reduction
- [ ] Advanced WAF bypass capabilities
- [ ] Real-time collaborative scanning
- [ ] Enterprise dashboard integration
- [ ] API fuzzing capabilities

### Version 2.5 (Future)
- [ ] Mobile application security testing
- [ ] Cloud infrastructure scanning
- [ ] IoT device vulnerability assessment
- [ ] Blockchain smart contract analysis

---

**Professional security testing tool developed by Indonesian cybersecurity experts for the global security community. Use responsibly and ethically.**

---

[![GitHub](https://img.shields.io/badge/GitHub-HolyBytes-black?style=flat-square&logo=github)](https://github.com/HolyBytes)
[![Saweria](https://img.shields.io/badge/Support-Saweria-orange?style=flat-square)](https://saweria.co/HolyBytes)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
