# Website Vulnerability Scanner Pro

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Termux-lightgrey.svg)](https://github.com/HolyBytes/scanner)

**Scanner Kerentanan Website Profesional** - Alat canggih untuk mengidentifikasi berbagai jenis kerentanan keamanan pada website dengan akurasi tinggi menggunakan metode penetration testing yang sistematis.

---

## ⚠️ PERINGATAN PENTING

**DISCLAIMER HUKUM**: Tool ini dikembangkan khusus untuk **authorized penetration testing** dan **educational purposes**. Penggunaan tanpa izin tertulis dari pemilik sistem merupakan pelanggaran hukum.

- Dapatkan **izin tertulis** sebelum melakukan scanning
- Developer tidak bertanggung jawab atas penyalahgunaan
- Patuhi undang-undang cybersecurity di wilayah Anda
- Gunakan hanya untuk testing legal dan pembelajaran keamanan

---

## 🔥 Fitur Unggulan

### Deteksi Kerentanan Komprehensif
- **15+ Jenis Kerentanan**: XSS, SQL Injection, RCE, LFI, SSRF, XXE, Command Injection, Open Redirect, SSTI, CSRF, File Upload, IDOR, Header Injection, JWT, Directory Traversal
- **100+ Payload Database**: Setiap jenis kerentanan memiliki payload ekstensif untuk testing menyeluruh
- **Pattern Recognition**: Advanced pattern matching untuk deteksi akurat
- **False Positive Reduction**: Algoritma cerdas untuk mengurangi hasil false positive

### Performa Tinggi
- **Multi-Threading**: 1000 thread paralel untuk scanning cepat
- **Smart Timeout**: Batas waktu 10 detik per request dengan adaptive timeout
- **Connection Pooling**: Manajemen koneksi efisien untuk optimasi network
- **Memory Optimization**: Penggunaan memory yang optimal untuk performa maksimal

### Cross-Platform Support
- **Universal Compatibility**: Berjalan di Termux, Linux, Windows, macOS
- **Lightweight Design**: Requirement minimal untuk berbagai spesifikasi hardware
- **Easy Installation**: Setup sederhana dengan dependency management

### Professional Reporting
- **Detailed Output**: Tampilan hasil dalam format tabel terstruktur
- **System Monitoring**: Real-time monitoring sistem selama proses scanning
- **Color-coded Results**: Hasil dengan color coding untuk mudah dibaca
- **Export Capability**: Kemampuan export hasil ke berbagai format file

---

## 📊 Daftar Kerentanan yang Dideteksi

| No | Jenis Kerentanan | Jumlah Payload | Metode Deteksi | Level Risiko |
|----|------------------|----------------|----------------|--------------|
| 1  | Cross-Site Scripting (XSS) | 15 | Pattern Matching, DOM Analysis | High |
| 2  | SQL Injection | 15 | Error-based, Boolean-based Detection | Critical |
| 3  | Remote Code Execution (RCE) | 15 | Command Output Detection | Critical |
| 4  | Local File Inclusion (LFI) | 15 | File Content Detection | High |
| 5  | Server-Side Request Forgery (SSRF) | 15 | Internal Service Response | High |
| 6  | XML External Entity (XXE) | 8 | XML Parser Behavior Analysis | Medium |
| 7  | Command Injection | 15 | System Command Response | Critical |
| 8  | Open Redirect | 15 | Header Location Analysis | Medium |
| 9  | Server-Side Template Injection (SSTI) | 15 | Template Engine Behavior | High |
| 10 | Cross-Site Request Forgery (CSRF) | 15 | Token Validation Check | Medium |
| 11 | File Upload Vulnerability | 15 | File Type Verification Bypass | High |
| 12 | Insecure Direct Object Reference (IDOR) | 15 | Access Control Testing | Medium |
| 13 | HTTP Header Injection | 15 | Response Header Analysis | Low |
| 14 | JWT Vulnerabilities | 15 | Token Validation Testing | High |

**Total Payload**: 238+ payload combinations untuk comprehensive testing

---

## 📦 Persyaratan Sistem

### Requirements Minimum
```
Python: 3.6 atau lebih tinggi
RAM: 1GB minimum (2GB recommended)
Storage: 50MB free space
Network: Koneksi internet stabil
OS Support: Windows 7+, Linux (Ubuntu 16.04+), macOS 10.12+, Android (Termux)
```

### Dependencies yang Diperlukan
```
- requests: HTTP library untuk web requests
- beautifulsoup4: HTML parsing dan analysis
- colorama: Cross-platform colored terminal output
- prettytable: Formatted table output
- psutil: System dan process monitoring
- urllib3: Advanced HTTP client library
```

---

## 🛠 Panduan Instalasi

### Instalasi Universal (Linux/Windows/macOS)

1. **Persiapan Sistem**
   ```bash
   # Cek versi Python
   python --version
   python3 --version
   
   # Update pip
   pip install --upgrade pip
   ```

2. **Clone Repository**
   ```bash
   git clone https://github.com/HolyBytes/scanner.git
   cd scanner
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Verifikasi Instalasi**
   ```bash
   python scanner.py --help
   ```

### Instalasi Khusus Termux (Android)

```bash
# Update package repository
pkg update && pkg upgrade

# Install core requirements
pkg install python git

# Install additional packages
pkg install libxml2 libxslt

# Clone repository
git clone https://github.com/HolyBytes/scanner.git
cd scanner

# Install Python dependencies
pip install requests beautifulsoup4 colorama prettytable psutil urllib3

# Test installation
python scanner.py --help
```

### Manual Dependencies Installation

Jika instalasi otomatis gagal:
```bash
pip install requests
pip install beautifulsoup4
pip install colorama
pip install prettytable
pip install psutil
pip install urllib3
```

---

## 🚀 Cara Penggunaan

### Format Perintah Dasar
```bash
python scanner.py -u <URL_TARGET>
python scanner.py -f <FILE_TARGET_LIST>
```

### Parameter dan Options

| Parameter | Deskripsi | Contoh Penggunaan |
|-----------|-----------|-------------------|
| `-u, --url` | URL target tunggal | `-u https://example.com` |
| `-f, --file` | File berisi daftar URL | `-f targets.txt` |

### Contoh Penggunaan Praktis

#### 1. Scanning Website Tunggal
```bash
python scanner.py -u https://testphp.vulnweb.com/
```

#### 2. Scanning Multiple Websites
```bash
# Buat file targets.txt
echo "https://example1.com" > targets.txt
echo "https://example2.com" >> targets.txt
echo "https://testphp.vulnweb.com/" >> targets.txt

# Jalankan scanning
python scanner.py -f targets.txt
```

#### 3. Scanning dengan Target Berbeda
```bash
# Target dengan parameter
python scanner.py -u "https://example.com/search.php?q=test"

# Target dengan subdomain
python scanner.py -u "https://admin.example.com"

# Target dengan port khusus
python scanner.py -u "https://example.com:8443"
```

### Format File Target

File target harus berisi satu URL per baris:
```
https://example1.com
https://example2.com/admin
https://subdomain.example3.com
http://example4.com:8080
```

---

## 🧠 Metodologi Scanning

### Phase 1: Initialization
1. **System Check**: Verifikasi spesifikasi hardware dan network
2. **Target Validation**: Validasi URL dan accessibility check
3. **Payload Loading**: Loading database payload untuk setiap jenis kerentanan
4. **Thread Preparation**: Setup multi-threading environment

### Phase 2: Reconnaissance
1. **Technology Detection**: Identifikasi teknologi yang digunakan target
2. **Parameter Discovery**: Pencarian parameter yang dapat diinjeksi
3. **Endpoint Enumeration**: Mapping available endpoints
4. **Response Analysis**: Analisis initial response patterns

### Phase 3: Vulnerability Testing
1. **Payload Injection**: Sistematis injection payload ke parameter target
2. **Response Monitoring**: Real-time monitoring response dari server
3. **Pattern Matching**: Analisis response menggunakan signature detection
4. **Confirmation Testing**: Verifikasi kerentanan yang terdeteksi

### Phase 4: Result Processing
1. **Data Aggregation**: Pengumpulan dan strukturing hasil scan
2. **Risk Assessment**: Penilaian tingkat risiko setiap kerentanan
3. **Report Generation**: Pembuatan laporan comprehensive
4. **System Cleanup**: Cleanup resources dan memory management

---

## 📈 Arsitektur dan Cara Kerja

### Core Architecture
```
Scanner Core
├── Target Manager: Handles URL processing dan validation
├── Payload Engine: Manages injection payloads dan patterns
├── Threading Manager: Controls concurrent execution
├── Response Analyzer: Processes server responses
├── Detection Engine: Identifies vulnerabilities
└── Report Generator: Creates formatted output
```

### Detection Methodology

1. **XSS Detection**:
   - Inject script tags dan event handlers
   - Monitor DOM manipulation responses
   - Check reflected content dalam response

2. **SQL Injection Detection**:
   - Error-based detection melalui database error messages
   - Boolean-based detection dengan logical queries
   - Time-based detection untuk blind SQL injection

3. **RCE Detection**:
   - Command execution payload injection
   - System command output analysis
   - Process execution indicators

4. **File Inclusion Detection**:
   - Path traversal payload testing
   - File content fingerprinting
   - Directory listing detection

### Performance Optimization Features

- **Connection Reuse**: HTTP connection pooling untuk efficiency
- **Request Batching**: Grouping requests untuk optimal throughput  
- **Adaptive Delays**: Smart delay management untuk avoid rate limiting
- **Memory Management**: Automatic garbage collection dan memory optimization
- **Error Handling**: Robust error handling untuk stability

---

## 📊 Output dan Reporting

### Console Output Format
```
[+] Target: https://example.com
[+] Starting vulnerability scan...
[!] CRITICAL: SQL Injection found at /login.php?user=
[!] HIGH: XSS vulnerability detected at /search.php?q=
[+] Scanning completed. Found 2 vulnerabilities.
```

### Detailed Results Table
```
+------------------+----------+----------------------------+------------+
| Vulnerability    | Severity | URL                        | Parameter  |
+------------------+----------+----------------------------+------------+
| SQL Injection    | CRITICAL | /login.php                 | user       |
| XSS              | HIGH     | /search.php                | q          |
| Open Redirect    | MEDIUM   | /redirect.php              | url        |
+------------------+----------+----------------------------+------------+
```

### System Monitoring Display
```
System Information:
- CPU Usage: 45%
- Memory Usage: 2.1GB / 8GB
- Active Threads: 856 / 1000
- Network I/O: 15.2 MB/s
- Scan Progress: 78% completed
```

---

## ⚡ Optimasi Performa

### Threading Configuration
```python
# Konfigurasi thread berdasarkan spesifikasi sistem
Low-end Device (Termux, 1-2 core): 100-200 threads
Standard System (2-4 core, 4GB RAM): 500-700 threads  
High-end System (4+ core, 8GB+ RAM): 800-1000 threads
```

### Memory Management
- Dynamic memory allocation untuk payload processing
- Automatic cleanup setelah setiap target completed
- Garbage collection optimization untuk long-running scans
- Buffer management untuk large response handling

### Network Optimization
- Connection pooling dengan keep-alive support
- Request queuing untuk prevent server overload
- Adaptive timeout berdasarkan network latency
- DNS caching untuk faster hostname resolution

### Performance Tuning Tips
1. **Untuk Device Low-end**: Kurangi `MAX_THREADS` dalam script
2. **Untuk Network Lambat**: Increase timeout value
3. **Untuk Memory Terbatas**: Scan targets dalam batch kecil
4. **Untuk Stealth Scanning**: Tambahkan delay antara requests

---

## 🛡 Keamanan dan Etika Penggunaan

### Prinsip Ethical Hacking
1. **Authorization First**: Selalu dapatkan izin tertulis sebelum scanning
2. **Scope Limitation**: Batasi scanning hanya pada target yang diauthorized
3. **Data Protection**: Jangan eksploitasi atau download data sensitif
4. **Responsible Disclosure**: Laporkan vulnerability ke pemilik sistem

### Legal Compliance
- **Indonesia**: UU ITE dan peraturan terkait cybersecurity
- **International**: Computer Fraud dan Abuse Acts di berbagai negara
- **Corporate**: Policy perusahaan tentang security testing
- **Academic**: Guidelines institusi untuk research purposes

### Best Practices
- Gunakan isolated environment untuk testing
- Backup data sebelum testing production systems
- Monitor system load selama scanning
- Document semua aktivitas untuk audit trail
- Coordinate dengan system administrators

### Detection Avoidance (Ethical Use)
- Randomized user agents untuk avoid basic detection
- Request throttling untuk prevent DoS conditions
- IP rotation jika diperlukan untuk large-scale testing
- WAF evasion techniques untuk comprehensive testing

---

## 🚨 Troubleshooting Guide

### Installation Issues

#### Python Version Problems
```bash
# Cek Python version
python --version
python3 --version

# Install Python 3.6+ jika belum ada
# Ubuntu/Debian:
sudo apt update && sudo apt install python3 python3-pip

# CentOS/RHEL:
sudo yum install python3 python3-pip
```

#### Dependencies Installation Failures
```bash
# SSL Certificate issues
pip install --trusted-host pypi.org --trusted-host pypi.python.org requests

# Permission denied
sudo pip install -r requirements.txt

# Specific module errors
pip install beautifulsoup4 --upgrade --force-reinstall
```

### Runtime Errors

#### Connection Issues
```bash
# Timeout errors
python scanner.py -u <target>  # Check if target is accessible

# SSL verification errors  
export PYTHONHTTPSVERIFY=0  # Disable SSL verification (use cautiously)

# Network connectivity
ping google.com  # Test internet connection
```

#### Memory Issues
```bash
# Reduce thread count dalam script
MAX_THREADS = 100  # Instead of 1000

# Monitor memory usage
htop  # Linux
top   # macOS/Linux
Task Manager  # Windows
```

#### Permission Issues
```bash
# File permission problems
chmod +x scanner.py
chown $USER:$USER scanner.py

# Directory access issues
ls -la /path/to/scanner/
```

### Performance Issues

#### Slow Scanning
- Reduce thread count untuk stability
- Check network bandwidth dan latency
- Monitor CPU usage selama scanning
- Close unnecessary applications

#### High Memory Usage
- Scan targets dalam smaller batches
- Restart scanner setelah large scans
- Monitor memory leaks dalam long-running scans

#### Network Timeouts
- Increase timeout values dalam script
- Check target server responsiveness
- Monitor network stability

---

## 📚 Educational Resources

### Recommended Learning Path
1. **Web Security Fundamentals**: OWASP Top 10 vulnerabilities
2. **Penetration Testing**: Metodologi dan tools
3. **Network Security**: Understanding protocols dan traffic analysis
4. **Secure Coding**: Best practices untuk developers

### Practice Environments
- **DVWA** (Damn Vulnerable Web Application): Basic vulnerability practice
- **bWAPP**: Extensive vulnerability collection
- **WebGoat**: OWASP educational platform  
- **VulnHub**: Vulnerable virtual machines

### Reference Materials
- OWASP Testing Guide: Comprehensive web security testing methodology
- PTES (Penetration Testing Execution Standard): Industry standard framework
- NIST Cybersecurity Framework: Risk management guidelines
- CVE Database: Common Vulnerabilities dan Exposures

---

## 🤝 Development dan Kontribusi

### Project Structure
```
scanner/
├── scanner.py          # Main scanner script
├── requirements.txt    # Dependencies list
├── payloads.py        # Vulnerability payloads
├── utils.py           # Helper functions
├── config.py          # Configuration settings
└── README.md          # Documentation
```

### Contributing Guidelines
1. **Fork Repository**: Create personal fork untuk development
2. **Feature Branch**: Buat branch untuk setiap feature baru
3. **Code Standards**: Follow PEP 8 untuk Python code style
4. **Testing**: Test thoroughly sebelum submit pull request
5. **Documentation**: Update README untuk changes yang significant

### Development Setup
```bash
# Clone untuk development
git clone https://github.com/HolyBytes/scanner.git
cd scanner

# Create development branch
git checkout -b feature/new-detection-method

# Make changes dan test
python scanner.py -u https://testphp.vulnweb.com/

# Commit changes
git add .
git commit -m "Add new vulnerability detection method"

# Push dan create pull request
git push origin feature/new-detection-method
```

---

## 📞 Support dan Kontak

### Bug Reports
Laporkan bugs melalui GitHub Issues dengan informasi:
- Operating system dan Python version
- Complete error message dan stack trace
- Steps untuk reproduce the issue
- Expected behavior vs actual behavior

### Feature Requests
Submit enhancement requests dengan detail:
- Clear description dari requested feature
- Use case scenarios
- Potential implementation approach
- Benefits untuk user community

### Contact Information
- **GitHub**: [@HolyBytes](https://github.com/HolyBytes)
- **Support**: [https://saweria.co/HolyBytes](https://saweria.co/HolyBytes)

### Community
- Join discussions dalam GitHub repository
- Share experiences dan best practices
- Contribute improvements dan bug fixes
- Help other users dalam troubleshooting

---

## 📄 Lisensi

### MIT License
```
MIT License

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

---

## 🏆 Acknowledgments

### Pengembangan
- **Lead Developer**: Ade Pratama (@HolyBytes)
- **Indonesian Cybersecurity Community**: Input dan feedback berharga
- **Beta Testers**: Security professionals yang membantu testing

### Referensi
- **OWASP Foundation**: Vulnerability research dan classification
- **Security Research Community**: Payload development dan detection methods
- **Open Source Projects**: Libraries dan frameworks yang digunakan

---

## 🌟 Roadmap Pengembangan

### Version 1.5 (Current)
- ✅ 15+ vulnerability types detection
- ✅ Multi-threading support (1000 threads)
- ✅ Cross-platform compatibility
- ✅ Professional reporting format

### Version 2.0 (Planned)
- [ ] GUI interface untuk easier usage
- [ ] Advanced WAF bypass techniques
- [ ] Custom payload editor
- [ ] Automated report generation (PDF/HTML)
- [ ] Integration dengan popular security tools

### Version 2.5 (Future)
- [ ] Machine learning untuk false positive reduction
- [ ] Cloud-based scanning capabilities
- [ ] Real-time collaboration features
- [ ] Mobile app security testing

---

**Professional vulnerability scanner developed by Indonesian cybersecurity experts. Digunakan oleh security professionals, researchers, dan students untuk authorized security testing dan educational purposes.**

*Gunakan dengan bijak, bertanggung jawab, dan selalu patuhi hukum yang berlaku.*

---

[![GitHub Stars](https://img.shields.io/github/stars/HolyBytes/scanner?style=social)](https://github.com/HolyBytes/scanner)
[![Follow on GitHub](https://img.shields.io/github/followers/HolyBytes?style=social)](https://github.com/HolyBytes)
[![Support](https://img.shields.io/badge/Support-Saweria-orange)](https://saweria.co/HolyBytes)
