"""
ACCURATE CYBER STAR - ULTIMATE EDITION
Author: Ian Carter Kulani
Version: Ultimate v4.0
Features: SSH, Wget, Nmap, Traceroute, Network Scanner, Telegram Bot, Database, Monitoring
"""

import socket
import threading
import time
import requests
import json
import subprocess
import os
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Set, Tuple, Optional, Any
import sys
import random
import platform
import psutil
import getpass
import hashlib
import sqlite3
from pathlib import Path
import ipaddress
import re
import shutil
import select
import configparser
from collections import deque, defaultdict
import argparse
import signal
import base64
import zipfile
import tempfile
import urllib.parse
import urllib.request
import ssl

# SSH imports
try:
    import paramiko
    from paramiko import SSHClient, AutoAddPolicy, RSAKey, SSHException
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    print("Warning: paramiko not available. SSH features will be limited.")

# Security imports
try:
    import scapy.all as scapy
    from scapy.all import IP, ICMP, TCP, UDP, ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not available. Some security features will be limited.")

# Nmap imports
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("Warning: python-nmap not available. Some scan features will be limited.")

# Configuration
CONFIG_FILE = "cyber_security_config.json"
SSH_CONFIG_FILE = "ssh_config.json"
DATABASE_FILE = "network_data.db"
REPORT_DIR = "reports"
DOWNLOAD_DIR = "downloads"
LOG_FILE = "cyber_star.log"
MAX_HISTORY = 1000

class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class WgetManager:
    """Advanced wget/download manager with resume and parallel downloads"""
    
    def __init__(self):
        self.download_dir = DOWNLOAD_DIR
        os.makedirs(self.download_dir, exist_ok=True)
        self.active_downloads = {}
        self.download_history = []
        
    def download_file(self, url: str, output_path: str = None, resume: bool = True, 
                     parallel: int = 4, timeout: int = 30) -> Dict[str, Any]:
        """Download file with advanced options"""
        try:
            if not output_path:
                filename = os.path.basename(urllib.parse.urlparse(url).path)
                if not filename:
                    filename = f"download_{int(time.time())}.bin"
                output_path = os.path.join(self.download_dir, filename)
            
            # Create download session
            download_id = hashlib.md5(f"{url}{output_path}".encode()).hexdigest()[:8]
            self.active_downloads[download_id] = {
                'url': url,
                'output': output_path,
                'start_time': time.time(),
                'status': 'starting'
            }
            
            result = {
                'success': False,
                'url': url,
                'output_path': output_path,
                'download_id': download_id
            }
            
            # Try using wget if available (more reliable)
            if shutil.which('wget'):
                cmd = ['wget', '-c' if resume else '', '-O', output_path, url]
                cmd = [c for c in cmd if c]  # Remove empty strings
                
                try:
                    process = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout
                    )
                    
                    if process.returncode == 0:
                        result['success'] = True
                        result['method'] = 'wget'
                        result['size'] = os.path.getsize(output_path) if os.path.exists(output_path) else 0
                    else:
                        result['error'] = process.stderr
                    
                except subprocess.TimeoutExpired:
                    result['error'] = "Download timeout"
                except Exception as e:
                    result['error'] = str(e)
            
            # Fallback to requests if wget fails
            elif not result.get('success'):
                try:
                    headers = {}
                    if resume and os.path.exists(output_path):
                        existing_size = os.path.getsize(output_path)
                        headers['Range'] = f'bytes={existing_size}-'
                    
                    response = requests.get(url, stream=True, timeout=timeout, headers=headers)
                    
                    if response.status_code in [200, 206]:  # OK or Partial Content
                        mode = 'ab' if resume and os.path.exists(output_path) else 'wb'
                        with open(output_path, mode) as f:
                            for chunk in response.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                        
                        result['success'] = True
                        result['method'] = 'requests'
                        result['size'] = os.path.getsize(output_path)
                        result['status_code'] = response.status_code
                    else:
                        result['error'] = f"HTTP {response.status_code}"
                        
                except Exception as e:
                    result['error'] = str(e)
            
            # Update download status
            if result['success']:
                self.active_downloads[download_id]['status'] = 'completed'
                self.active_downloads[download_id]['end_time'] = time.time()
                self.active_downloads[download_id]['size'] = result.get('size', 0)
                
                # Add to history
                self.download_history.append({
                    'timestamp': datetime.now().isoformat(),
                    'url': url,
                    'output': output_path,
                    'size': result.get('size', 0),
                    'duration': time.time() - self.active_downloads[download_id]['start_time']
                })
            else:
                self.active_downloads[download_id]['status'] = 'failed'
                self.active_downloads[download_id]['error'] = result.get('error', 'Unknown error')
            
            return result
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def download_multiple(self, urls: List[str], output_dir: str = None) -> List[Dict[str, Any]]:
        """Download multiple files in parallel"""
        results = []
        threads = []
        
        def download_thread(url):
            result = self.download_file(url, output_path=output_dir)
            results.append(result)
        
        for url in urls:
            thread = threading.Thread(target=download_thread, args=(url,))
            threads.append(thread)
            thread.start()
            time.sleep(0.1)  # Stagger starts
        
        for thread in threads:
            thread.join()
        
        return results
    
    def get_download_status(self, download_id: str = None) -> Dict[str, Any]:
        """Get download status"""
        if download_id:
            return self.active_downloads.get(download_id, {})
        else:
            return {
                'active': len([d for d in self.active_downloads.values() if d.get('status') == 'downloading']),
                'completed': len([d for d in self.active_downloads.values() if d.get('status') == 'completed']),
                'failed': len([d for d in self.active_downloads.values() if d.get('status') == 'failed']),
                'total': len(self.active_downloads)
            }
    
    def list_downloads(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List recent downloads"""
        return self.download_history[-limit:] if self.download_history else []
    
    def clear_downloads(self):
        """Clear download history"""
        self.active_downloads.clear()
        self.download_history.clear()
        return "✅ Download history cleared"

class NmapScanner:
    """Advanced Nmap scanner with comprehensive scanning options"""
    
    def __init__(self):
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
    
    def scan(self, target: str, scan_type: str = "normal", ports: str = None, 
            arguments: str = None, timeout: int = 600) -> Dict[str, Any]:
        """Perform Nmap scan with various types"""
        
        if not self.nm:
            return {'success': False, 'error': 'Nmap not available'}
        
        try:
            # Default ports based on scan type
            if not ports:
                if scan_type == "quick":
                    ports = "1-1000"
                elif scan_type == "full":
                    ports = "1-65535"
                elif scan_type == "common":
                    ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
                else:  # normal
                    ports = "1-10000"
            
            # Default arguments based on scan type
            if not arguments:
                if scan_type == "stealth":
                    arguments = "-sS -T2 -f"
                elif scan_type == "aggressive":
                    arguments = "-A -T4"
                elif scan_type == "vuln":
                    arguments = "--script vuln"
                elif scan_type == "os":
                    arguments = "-O"
                elif scan_type == "service":
                    arguments = "-sV"
                elif scan_type == "udp":
                    arguments = "-sU"
                else:  # normal
                    arguments = "-sS -sV -O"
            
            start_time = time.time()
            
            # Perform scan
            self.nm.scan(hosts=target, ports=ports, arguments=arguments, timeout=timeout)
            
            scan_duration = time.time() - start_time
            
            # Parse results
            results = {
                'success': True,
                'target': target,
                'scan_type': scan_type,
                'arguments': arguments,
                'ports': ports,
                'duration': scan_duration,
                'scan_time': datetime.now().isoformat(),
                'hosts': {}
            }
            
            for host in self.nm.all_hosts():
                host_info = {
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'open_ports': [],
                    'os_info': {},
                    'scripts': {}
                }
                
                # Get OS information
                if 'osmatch' in self.nm[host]:
                    host_info['os_info'] = self.nm[host]['osmatch']
                
                # Get open ports
                for proto in self.nm[host].all_protocols():
                    ports_list = self.nm[host][proto].keys()
                    for port in ports_list:
                        port_info = self.nm[host][proto][port]
                        if port_info['state'] == 'open':
                            host_info['open_ports'].append({
                                'protocol': proto,
                                'port': port,
                                'state': port_info['state'],
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'extra': port_info.get('extrainfo', ''),
                                'cpe': port_info.get('cpe', '')
                            })
                
                # Get script results
                if 'script' in self.nm[host]:
                    host_info['scripts'] = self.nm[host]['script']
                
                results['hosts'][host] = host_info
            
            return results
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def scan_network(self, network: str, scan_type: str = "normal") -> Dict[str, Any]:
        """Scan entire network"""
        return self.scan(network, scan_type=scan_type)
    
    def service_scan(self, target: str) -> Dict[str, Any]:
        """Service version detection scan"""
        return self.scan(target, scan_type="service")
    
    def os_scan(self, target: str) -> Dict[str, Any]:
        """OS detection scan"""
        return self.scan(target, scan_type="os")
    
    def vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """Vulnerability scan using NSE scripts"""
        return self.scan(target, scan_type="vuln")
    
    def stealth_scan(self, target: str) -> Dict[str, Any]:
        """Stealth SYN scan"""
        return self.scan(target, scan_type="stealth")
    
    def aggressive_scan(self, target: str) -> Dict[str, Any]:
        """Aggressive scan with OS and version detection"""
        return self.scan(target, scan_type="aggressive")
    
    def udp_scan(self, target: str) -> Dict[str, Any]:
        """UDP port scan"""
        return self.scan(target, scan_type="udp")
    
    def get_nmap_version(self) -> str:
        """Get Nmap version"""
        if self.nm:
            try:
                return self.nm.nmap_version()
            except:
                pass
        return "N/A"

class SSHManager:
    """Comprehensive SSH client management"""
    
    def __init__(self):
        self.connections = {}
        self.saved_sessions = self.load_ssh_sessions()
        self.current_session = None
        
    def load_ssh_sessions(self) -> Dict:
        """Load saved SSH sessions from file"""
        try:
            if os.path.exists(SSH_CONFIG_FILE):
                with open(SSH_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}
    
    def save_ssh_sessions(self):
        """Save SSH sessions to file"""
        try:
            with open(SSH_CONFIG_FILE, 'w') as f:
                json.dump(self.saved_sessions, f, indent=4)
        except Exception as e:
            logging.error(f"Failed to save SSH sessions: {e}")
    
    def add_session(self, name: str, host: str, port: int, username: str, 
                   password: str = None, key_path: str = None):
        """Add or update SSH session"""
        session = {
            'host': host,
            'port': port,
            'username': username,
            'password': password,
            'key_path': key_path,
            'last_used': datetime.now().isoformat()
        }
        self.saved_sessions[name] = session
        self.save_ssh_sessions()
        return f"✅ SSH session '{name}' saved"
    
    def remove_session(self, name: str):
        """Remove SSH session"""
        if name in self.saved_sessions:
            del self.saved_sessions[name]
            self.save_ssh_sessions()
            return f"✅ SSH session '{name}' removed"
        return f"❌ Session '{name}' not found"
    
    def list_sessions(self) -> str:
        """List all saved SSH sessions"""
        if not self.saved_sessions:
            return "📋 No SSH sessions saved"
        
        result = "📋 <b>SSH Sessions</b>\n\n"
        for name, session in self.saved_sessions.items():
            result += f"• <code>{name}</code>\n"
            result += f"  Host: {session['host']}:{session['port']}\n"
            result += f"  User: {session['username']}\n"
            result += f"  Last Used: {session['last_used'][:10]}\n\n"
        return result
    
    def connect(self, session_name: str = None, **kwargs) -> Tuple[bool, str]:
        """Connect to SSH server"""
        if not SSH_AVAILABLE:
            return False, "SSH not available (paramiko not installed)"
        
        try:
            if session_name and session_name in self.saved_sessions:
                session = self.saved_sessions[session_name]
                host = kwargs.get('host', session['host'])
                port = kwargs.get('port', session['port'])
                username = kwargs.get('username', session['username'])
                password = kwargs.get('password', session.get('password'))
                key_path = kwargs.get('key_path', session.get('key_path'))
            else:
                host = kwargs.get('host')
                port = kwargs.get('port', 22)
                username = kwargs.get('username')
                password = kwargs.get('password')
                key_path = kwargs.get('key_path')
            
            if not all([host, username]):
                return False, "Missing required parameters (host, username)"
            
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            
            if key_path and os.path.exists(key_path):
                key = RSAKey.from_private_key_file(key_path)
                client.connect(hostname=host, port=port, username=username, pkey=key)
            elif password:
                client.connect(hostname=host, port=port, username=username, password=password)
            else:
                return False, "No authentication method provided"
            
            conn_id = f"{username}@{host}:{port}"
            self.connections[conn_id] = client
            
            if session_name:
                self.saved_sessions[session_name]['last_used'] = datetime.now().isoformat()
                self.save_ssh_sessions()
            
            return True, f"✅ Connected to {conn_id}"
            
        except SSHException as e:
            return False, f"SSH connection failed: {str(e)}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    def execute_command(self, conn_id: str, command: str) -> Tuple[bool, str]:
        """Execute command on SSH server"""
        if conn_id not in self.connections:
            return False, f"Connection '{conn_id}' not found"
        
        try:
            client = self.connections[conn_id]
            stdin, stdout, stderr = client.exec_command(command)
            
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            if error:
                return False, f"Error: {error}"
            
            return True, output
            
        except Exception as e:
            return False, f"Command execution failed: {str(e)}"
    
    def upload_file(self, conn_id: str, local_path: str, remote_path: str) -> Tuple[bool, str]:
        """Upload file to SSH server"""
        if conn_id not in self.connections:
            return False, f"Connection '{conn_id}' not found"
        
        if not os.path.exists(local_path):
            return False, f"Local file not found: {local_path}"
        
        try:
            client = self.connections[conn_id]
            sftp = client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            return True, f"✅ File uploaded to {remote_path}"
        except Exception as e:
            return False, f"Upload failed: {str(e)}"
    
    def download_file(self, conn_id: str, remote_path: str, local_path: str) -> Tuple[bool, str]:
        """Download file from SSH server"""
        if conn_id not in self.connections:
            return False, f"Connection '{conn_id}' not found"
        
        try:
            client = self.connections[conn_id]
            sftp = client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            return True, f"✅ File downloaded to {local_path}"
        except Exception as e:
            return False, f"Download failed: {str(e)}"
    
    def disconnect(self, conn_id: str):
        """Disconnect from SSH server"""
        if conn_id in self.connections:
            try:
                self.connections[conn_id].close()
                del self.connections[conn_id]
                return f"✅ Disconnected from {conn_id}"
            except:
                return f"⚠️ Error disconnecting from {conn_id}"
        return f"❌ Connection '{conn_id}' not found"
    
    def list_connections(self) -> str:
        """List active SSH connections"""
        if not self.connections:
            return "🔌 No active SSH connections"
        
        result = "🔌 <b>Active SSH Connections</b>\n\n"
        for conn_id in self.connections.keys():
            result += f"• <code>{conn_id}</code>\n"
        return result

class TracerouteTool:
    """Enhanced interactive traceroute tool"""
    
    @staticmethod
    def is_ipv4_or_ipv6(address: str) -> bool:
        """Check if input is valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_hostname(name: str) -> bool:
        """Check if input is valid hostname"""
        if name.endswith('.'):
            name = name[:-1]
        HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
        return bool(HOSTNAME_RE.match(name))

    @staticmethod
    def choose_traceroute_cmd(target: str) -> List[str]:
        """Return appropriate traceroute command for the system"""
        system = platform.system()

        if system == 'Windows':
            return ['tracert', '-d', target]

        if shutil.which('traceroute'):
            return ['traceroute', '-n', '-q', '1', '-w', '2', target]
        if shutil.which('tracepath'):
            return ['tracepath', target]
        if shutil.which('ping'):
            return ['ping', '-c', '4', target]

        raise EnvironmentError('No traceroute/tracepath/ping utilities found on this system.')

    @staticmethod
    def stream_subprocess(cmd: List[str]) -> Tuple[int, str]:
        """Run subprocess and capture output"""
        output_lines = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

            if proc.stdout:
                for line in proc.stdout:
                    cleaned_line = line.rstrip()
                    output_lines.append(cleaned_line)
                    print(cleaned_line)

            proc.wait()
            return proc.returncode, '\n'.join(output_lines)
        except KeyboardInterrupt:
            print('\n[+] User cancelled. Terminating traceroute...')
            try:
                proc.terminate()
            except Exception:
                pass
            return -1, '\n'.join(output_lines)
        except Exception as e:
            error_msg = f'[!] Error running command: {e}'
            print(error_msg)
            output_lines.append(error_msg)
            return -2, '\n'.join(output_lines)

    def interactive_traceroute(self, target: str = None) -> str:
        """Run interactive traceroute with validation"""
        if not target:
            target = self.prompt_target()
            if not target:
                return "Traceroute cancelled."

        if not (self.is_ipv4_or_ipv6(target) or self.is_valid_hostname(target)):
            return f"❌ Invalid IP address or hostname: {target}"

        try:
            cmd = self.choose_traceroute_cmd(target)
        except EnvironmentError as e:
            return f"❌ Traceroute error: {e}"

        print(f'Running: {" ".join(cmd)}\n')
        
        start_time = time.time()
        returncode, output = self.stream_subprocess(cmd)
        execution_time = time.time() - start_time

        result = f"🛣️ <b>Traceroute to {target}</b>\n\n"
        result += f"Command: <code>{' '.join(cmd)}</code>\n"
        result += f"Execution time: {execution_time:.2f}s\n"
        result += f"Return code: {returncode}\n\n"
        
        if len(output) > 3000:
            result += f"<code>{output[-3000:]}</code>"
        else:
            result += f"<code>{output}</code>"

        return result

    def prompt_target(self) -> Optional[str]:
        """Prompt user for target (for standalone use)"""
        while True:
            user_input = input('Enter target IP address or hostname to traceroute (or type "quit" to exit): ').strip()
            if not user_input:
                print('Please enter a non-empty value.')
                continue
            if user_input.lower() in ('q', 'quit', 'exit'):
                return None

            if self.is_ipv4_or_ipv6(user_input) or self.is_valid_hostname(user_input):
                return user_input
            else:
                print('Invalid IP address or hostname. Examples: 8.8.8.8, 2001:4860:4860::8888, example.com')

class DatabaseManager:
    """Manage SQLite database for storing network data and threats"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # IP monitoring table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP
            )
        ''')
        
        # Threat detection table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0
            )
        ''')
        
        # Command history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT 1
            )
        ''')
        
        # Network scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Traceroute results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traceroute_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT,
                execution_time REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # SSH sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssh_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_name TEXT UNIQUE NOT NULL,
                host TEXT NOT NULL,
                port INTEGER DEFAULT 22,
                username TEXT NOT NULL,
                key_path TEXT,
                last_used TIMESTAMP,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Download history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS download_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                output_path TEXT,
                size INTEGER,
                status TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Nmap scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS nmap_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                ports TEXT,
                arguments TEXT,
                results TEXT,
                duration REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_command(self, command: str, source: str = 'local', success: bool = True):
        """Log command to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO command_history (command, source, success) VALUES (?, ?, ?)',
            (command, source, success)
        )
        conn.commit()
        conn.close()
    
    def log_traceroute(self, target: str, command: str, output: str, execution_time: float):
        """Log traceroute results to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO traceroute_results (target, command, output, execution_time) VALUES (?, ?, ?, ?)',
            (target, command, output, execution_time)
        )
        conn.commit()
        conn.close()
    
    def get_command_history(self, limit: int = 50) -> List[Tuple]:
        """Get command history from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT command, source, timestamp, success FROM command_history ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    
    def log_threat(self, ip_address: str, threat_type: str, severity: str, description: str = ""):
        """Log threat detection to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO threat_logs (ip_address, threat_type, severity, description) VALUES (?, ?, ?, ?)',
            (ip_address, threat_type, severity, description)
        )
        conn.commit()
        conn.close()
    
    def get_recent_threats(self, limit: int = 20) -> List[Tuple]:
        """Get recent threats from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT ip_address, threat_type, severity, timestamp FROM threat_logs ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    
    def save_ssh_session(self, name: str, host: str, port: int, username: str, key_path: str = None):
        """Save SSH session to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT OR REPLACE INTO ssh_sessions 
               (session_name, host, port, username, key_path, last_used) 
               VALUES (?, ?, ?, ?, ?, ?)''',
            (name, host, port, username, key_path, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
    
    def get_ssh_sessions(self) -> List[Tuple]:
        """Get all SSH sessions from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT session_name, host, port, username, last_used FROM ssh_sessions ORDER BY last_used DESC')
        results = cursor.fetchall()
        conn.close()
        return results
    
    def log_nmap_scan(self, target: str, scan_type: str, ports: str, arguments: str, results: str, duration: float):
        """Log Nmap scan to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO nmap_history (target, scan_type, ports, arguments, results, duration) VALUES (?, ?, ?, ?, ?, ?)',
            (target, scan_type, ports, arguments, results, duration)
        )
        conn.commit()
        conn.close()
    
    def get_nmap_history(self, limit: int = 20) -> List[Tuple]:
        """Get Nmap scan history"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT target, scan_type, ports, duration, timestamp FROM nmap_history ORDER BY timestamp DESC LIMIT ?',
                      (limit,))
        results = cursor.fetchall()
        conn.close()
        return results

class NetworkScanner:
    """Enhanced network scanning capabilities"""
    
    def __init__(self):
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
        self.traceroute_tool = TracerouteTool()
        self.nmap_scanner = NmapScanner()
    
    def ping_ip(self, ip: str) -> str:
        """Simple ping that works reliably"""
        try:
            if os.name == 'nt':  # Windows
                cmd = ['ping', '-n', '4', ip]
            else:  # Linux/Mac
                cmd = ['ping', '-c', '4', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"Ping timeout for {ip}"
        except Exception as e:
            return f"Ping error: {str(e)}"
    
    def traceroute(self, target: str) -> str:
        """Perform enhanced traceroute using the dedicated tool"""
        return self.traceroute_tool.interactive_traceroute(target)
    
    def port_scan(self, ip: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Perform port scan"""
        if self.nm:
            try:
                self.nm.scan(ip, ports, arguments='-T4')
                open_ports = []
                
                if ip in self.nm.all_hosts():
                    for proto in self.nm[ip].all_protocols():
                        lport = self.nm[ip][proto].keys()
                        for port in lport:
                            if self.nm[ip][proto][port]['state'] == 'open':
                                open_ports.append({
                                    'port': port,
                                    'state': self.nm[ip][proto][port]['state'],
                                    'service': self.nm[ip][proto][port].get('name', 'unknown')
                                })
                
                return {
                    'success': True,
                    'target': ip,
                    'open_ports': open_ports,
                    'scan_time': datetime.now().isoformat()
                }
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            return {'success': False, 'error': 'Nmap not available'}
    
    def nmap_scan(self, target: str, scan_type: str = "normal", ports: str = None, arguments: str = None) -> Dict[str, Any]:
        """Perform Nmap scan"""
        return self.nmap_scanner.scan(target, scan_type, ports, arguments)
    
    def get_ip_location(self, ip: str) -> str:
        """Get IP location using ip-api.com"""
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return json.dumps({
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A'),
                        'timezone': data.get('timezone', 'N/A')
                    }, indent=2)
                else:
                    return f"Location error: {data.get('message', 'Unknown error')}"
            else:
                return f"Location error: HTTP {response.status_code}"
        except Exception as e:
            return f"Location error: {str(e)}"

class EnhancedTools:
    """Additional security tools"""
    
    @staticmethod
    def get_service_name(port: int) -> str:
        """Get service name for common ports"""
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 113: "Ident", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy"
        }
        return service_map.get(port, "Unknown")
    
    @staticmethod
    def analyze_network_health(ip_address: str) -> str:
        """Perform additional network health analysis"""
        result = "🔍 <b>Network Health Analysis</b>\n\n"
        
        try:
            # DNS resolution test
            start_time = time.time()
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
                dns_time = time.time() - start_time
                result += f"DNS Resolution: {hostname} ({dns_time:.3f}s)\n"
            except:
                result += "DNS Resolution: Failed\n"
            
            # Port connectivity quick test
            common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                conn_result = sock.connect_ex((ip_address, port))
                sock.close()
                if conn_result == 0:
                    open_ports.append(port)
            
            if open_ports:
                result += f"Open common ports: {open_ports}\n"
            else:
                result += "No common ports open\n"
                
        except Exception as e:
            result += f"Analysis error: {str(e)}\n"
        
        return result

class TelegramBotHandler:
    """Enhanced Telegram bot handler with all capabilities"""
    
    def __init__(self, monitor):
        self.monitor = monitor
        self.last_update_id = 0
        self.command_handlers = self.setup_command_handlers()
    
    def setup_command_handlers(self) -> Dict[str, callable]:
        """Setup comprehensive command handlers"""
        handlers = {
            '/start': self.handle_start,
            '/help': self.handle_help,
            '/ping_ip': self.handle_ping_ip,
            '/start_monitoring_ip': self.handle_start_monitoring_ip,
            '/stop': self.handle_stop,
            '/history': self.handle_history,
            '/add_ip': self.handle_add_ip,
            '/remove_ip': self.handle_remove_ip,
            '/list_ips': self.handle_list_ips,
            '/clear': self.handle_clear,
            '/tracert_ip': self.handle_tracert_ip,
            '/traceroute_ip': self.handle_traceroute_ip,
            '/scan_ip': self.handle_scan_ip,
            '/deep_scan': self.handle_deep_scan,
            '/location_ip': self.handle_location_ip,
            '/analyze_ip': self.handle_analyze_ip,
            '/status': self.handle_status,
            '/curl': self.handle_curl,
            '/whois': self.handle_whois,
            '/dns_lookup': self.handle_dns_lookup,
            '/network_info': self.handle_network_info,
            '/system_info': self.handle_system_info,
            '/threat_summary': self.handle_threat_summary,
            '/generate_report': self.handle_generate_report,
            '/advanced_traceroute': self.handle_advanced_traceroute,
            '/kill_ip': self.handle_kill_ip,
            '/export_data': self.handle_export_data,
            '/reboot_system': self.handle_reboot_system,
            
            # Wget commands
            '/wget': self.handle_wget,
            '/download': self.handle_download,
            '/download_status': self.handle_download_status,
            '/list_downloads': self.handle_list_downloads,
            '/clear_downloads': self.handle_clear_downloads,
            
            # Nmap commands
            '/nmap_scan': self.handle_nmap_scan,
            '/nmap_network': self.handle_nmap_network,
            '/nmap_service': self.handle_nmap_service,
            '/nmap_os': self.handle_nmap_os,
            '/nmap_vuln': self.handle_nmap_vuln,
            '/nmap_stealth': self.handle_nmap_stealth,
            '/nmap_aggressive': self.handle_nmap_aggressive,
            '/nmap_udp': self.handle_nmap_udp,
            '/nmap_history': self.handle_nmap_history,
        }
        
        # Add SSH commands if SSH is available
        if SSH_AVAILABLE:
            ssh_handlers = {
                '/ssh_connect': self.handle_ssh_connect,
                '/ssh_execute': self.handle_ssh_execute,
                '/ssh_upload': self.handle_ssh_upload,
                '/ssh_download': self.handle_ssh_download,
                '/ssh_disconnect': self.handle_ssh_disconnect,
                '/ssh_sessions': self.handle_ssh_sessions,
                '/ssh_add_session': self.handle_ssh_add_session,
                '/ssh_remove_session': self.handle_ssh_remove_session,
                '/ssh_list_connections': self.handle_ssh_list_connections,
            }
            handlers.update(ssh_handlers)
        
        return handlers
    
    def send_telegram_message(self, message: str, parse_mode: str = 'HTML') -> bool:
        """Send message to Telegram"""
        if not self.monitor.telegram_token or not self.monitor.telegram_chat_id:
            return False
            
        try:
            url = f"https://api.telegram.org/bot{self.monitor.telegram_token}/sendMessage"
            
            if len(message) > 4096:
                messages = [message[i:i+4096] for i in range(0, len(message), 4096)]
                for msg in messages:
                    payload = {
                        'chat_id': self.monitor.telegram_chat_id,
                        'text': msg,
                        'parse_mode': parse_mode,
                        'disable_web_page_preview': True
                    }
                    response = requests.post(url, json=payload, timeout=30)
                    if response.status_code != 200:
                        return False
                    time.sleep(0.5)
                return True
            else:
                payload = {
                    'chat_id': self.monitor.telegram_chat_id,
                    'text': message,
                    'parse_mode': parse_mode,
                    'disable_web_page_preview': True
                }
                response = requests.post(url, json=payload, timeout=30)
                return response.status_code == 200
        except Exception as e:
            logging.error(f"Telegram send error: {e}")
            return False
    
    def handle_start(self, args: List[str]) -> str:
        return """
🚀 <b>ACCURATE CYBER STAR - ULTIMATE EDITION v4.0</b> 🚀

Welcome! Your comprehensive cybersecurity assistant is ready.

🔍 <b>Network Commands</b>
/ping_ip [IP] - Ping IP address
/tracert_ip [IP] - Traceroute
/advanced_traceroute [IP] - Enhanced traceroute
/location_ip [IP] - Get IP location
/analyze_ip [IP] - Analyze IP threats
/whois [domain] - WHOIS lookup
/dns_lookup [domain] - DNS lookup
/kill_ip [IP] - Stress test IP

🛡️ <b>Nmap Scanning</b>
/nmap_scan [target] [type] - Nmap scan (normal,stealth,aggressive,udp,os,service,vuln)
/nmap_network [network] - Network scan
/nmap_service [target] - Service detection
/nmap_os [target] - OS detection
/nmap_vuln [target] - Vulnerability scan
/nmap_stealth [target] - Stealth scan
/nmap_aggressive [target] - Aggressive scan
/nmap_udp [target] - UDP scan
/nmap_history - Scan history

📥 <b>Download Manager</b>
/wget [url] [output] - Download file
/download [url] - Download with auto-naming
/download_status - Check download status
/list_downloads - List recent downloads
/clear_downloads - Clear download history

🔐 <b>SSH Commands</b>
/ssh_sessions - List saved SSH sessions
/ssh_add_session [name] [host] [port] [user] [password] - Add SSH session
/ssh_connect [session] - Connect to SSH
/ssh_execute [session] [command] - Execute command
/ssh_upload [session] [local] [remote] - Upload file
/ssh_download [session] [remote] [local] - Download file
/ssh_disconnect [session] - Disconnect SSH
/ssh_list_connections - List active connections

📊 <b>Monitoring</b>
/start_monitoring_ip [IP] - Start monitoring
/stop - Stop all monitoring
/add_ip [IP] - Add IP to list
/remove_ip [IP] - Remove IP
/list_ips - List monitored IPs
/threat_summary - Recent threats

💻 <b>System</b>
/network_info - Network information
/system_info - System information
/status - System status
/history - Command history
/clear - Clear history
/reboot_system - Reboot monitoring
/export_data - Export data

📡 <b>Web Tools</b>
/curl [URL] - HTTP request
/generate_report - Generate security report

❓ Type /help for detailed usage!
        """
    
    def handle_help(self, args: List[str]) -> str:
        return """
<b>🔒 Complete Command Reference</b>

<b>🌐 Network Diagnostics:</b>
<code>/ping_ip 8.8.8.8</code>
<code>/tracert_ip google.com</code>
<code>/kill_ip 192.168.1.1</code>

<b>🛡️ Nmap Scanning:</b>
<code>/nmap_scan 192.168.1.1 stealth</code>
<code>/nmap_network 192.168.1.0/24</code>
<code>/nmap_service 192.168.1.1</code>
<code>/nmap_vuln 192.168.1.1</code>

<b>📥 Download Manager:</b>
<code>/wget https://example.com/file.zip</code>
<code>/download https://example.com/image.jpg</code>

<b>🔐 SSH Management:</b>
<code>/ssh_add_session myserver 192.168.1.100 22 root mypassword</code>
<code>/ssh_connect myserver</code>
<code>/ssh_execute myserver "ls -la"</code>

<b>🛡️ Security Analysis:</b>
<code>/analyze_ip 192.168.1.1</code>
<code>/threat_summary</code>
<code>/generate_report</code>

<b>📊 Monitoring:</b>
<code>/start_monitoring_ip 192.168.1.1</code>
<code>/add_ip 10.0.0.1</code>
<code>/stop</code>

<b>💻 System Info:</b>
<code>/network_info</code>
<code>/system_info</code>
<code>/status</code>

All commands execute instantly! 🚀
        """
    
    # Existing command handlers (simplified versions)
    def handle_ping_ip(self, args: List[str]) -> str:
        if not args:
            return "❌ Usage: <code>/ping_ip [IP]</code>"
        ip = args[0]
        result = self.monitor.scanner.ping_ip(ip)
        return f"🏓 <b>Ping {ip}</b>\n\n<code>{result[-1000:]}</code>"
    
    def handle_start_monitoring_ip(self, args: List[str]) -> str:
        if not args:
            return "❌ Usage: <code>/start_monitoring_ip [IP]</code>"
        ip = args[0]
        try:
            ipaddress.ip_address(ip)
            self.monitor.monitored_ips.add(ip)
            self.monitor.save_config()
            self.monitor.db_manager.log_command(f"start_monitoring_ip {ip}", 'telegram', True)
            return f"✅ Started monitoring <code>{ip}</code>"
        except ValueError:
            return f"❌ Invalid IP: <code>{ip}</code>"
    
    def handle_stop(self, args: List[str]) -> str:
        if not self.monitor.monitored_ips:
            return "⚠️ No IPs are being monitored"
        ips = list(self.monitor.monitored_ips)
        self.monitor.monitored_ips.clear()
        self.monitor.save_config()
        return f"🛑 Stopped monitoring: {', '.join(ips)}"
    
    def handle_history(self, args: List[str]) -> str:
        history = self.monitor.db_manager.get_command_history(20)
        if not history:
            return "📝 No commands recorded"
        response = "📝 <b>Command History</b>\n\n"
        for i, (cmd, src, ts, success) in enumerate(history, 1):
            status = "✅" if success else "❌"
            response += f"{i}. {status} <code>{cmd}</code>\n   {src} | {ts}\n\n"
        return response
    
    def handle_add_ip(self, args: List[str]) -> str:
        if not args:
            return "❌ Usage: <code>/add_ip [IP]</code>"
        ip = args[0]
        try:
            ipaddress.ip_address(ip)
            self.monitor.monitored_ips.add(ip)
            self.monitor.save_config()
            return f"✅ Added <code>{ip}</code>"
        except ValueError:
            return f"❌ Invalid IP: <code>{ip}</code>"
    
    def handle_remove_ip(self, args: List[str]) -> str:
        if not args:
            return "❌ Usage: <code>/remove_ip [IP]</code>"
        ip = args[0]
        if ip in self.monitor.monitored_ips:
            self.monitor.monitored_ips.remove(ip)
            self.monitor.save_config()
            return f"✅ Removed <code>{ip}</code>"
        return f"❌ IP not in list: <code>{ip}</code>"
    
    def handle_list_ips(self, args: List[str]) -> str:
        if not self.monitor.monitored_ips:
            return "📋 No IPs are being monitored"
        response = "📋 <b>Monitored IPs</b>\n\n"
        for ip in sorted(self.monitor.monitored_ips):
            response += f"• <code>{ip}</code>\n"
        return response
    
    def handle_clear(self, args: List[str]) -> str:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM command_history')
        conn.commit()
        conn.close()
        return "✅ Command history cleared"
    
    def handle_tracert_ip(self, args: List[str]) -> str:
        if not args:
            return "❌ Usage: <code>/tracert_ip [IP/domain]</code>"
        target = args[0]
        result = self.monitor.scanner.traceroute(target)
        return result
    
    def handle_traceroute_ip(self, args: List[str]) -> str:
        return self.handle_tracert_ip(args)
    
    def handle_advanced_traceroute(self, args: List[str]) -> str:
        if not args:
            return "❌ Usage: <code>/advanced_traceroute [IP/domain]</code>"
        target = args[0]
        self.send_telegram_message(f"🛣️ <b>Starting advanced traceroute to {target}</b>...")
        result = self.monitor.scanner.traceroute(target)
        return result
    
    def handle_scan_ip(self, args: List[str]) -> str:
        if not args:
            return "❌ Usage: <code>/scan_ip [IP]</code>"
        ip = args[0]
        self.send_telegram_message(f"🔍 Scanning <code>{ip}</code>...")
        result = self.monitor.scanner.port_scan(ip)
        if result['success']:
            open_ports = result.get('open_ports', [])
            response = f"🔍 <b>Scan Results: {ip}</b>\n\n"
            response += f"Open Ports: {len(open_ports)}\n\n"
            if open_ports:
                for p in open_ports[:10]:
                    response += f"• Port {p['port']}: {p['service']}\n"
                if len(open_ports) > 10:
                    response += f"\n... and {len(open_ports)-10} more"
            else:
                response += "🔒 No open ports found"
            return response
        return f"❌ Scan error: {result.get('error', 'Unknown')}"
    
    def handle_deep_scan(self, args: List[str]) -> str:
        if not args:
            return "❌ Usage: <code>/deep_scan [IP]</code>"
        ip = args[0]
        self.send_telegram_message(f"🔍 Starting deep scan on <code>{ip}</code>...")
        result = self.monitor.scanner.nmap_scan(ip, "normal", "1-65535")
        if result['success']:
            hosts_info = []
            for host, info in result.get('hosts', {}).items():
                hosts_info.append(f"Host: {host}")
                hosts_info.append(f"Open Ports: {len(info.get('open_ports', []))}")
                for port in info.get('open_ports', [])[:10]:
                    hosts_info.append(f"  Port {port['port']}: {port['service']}")
            
            response = f"🔍 <b>Deep Scan Results: {ip}</b>\n\n"
            response += f"Duration: {result.get('duration', 0):.2f}s\n"
            response += "\n".join(hosts_info[:20])
            if len(hosts_info) > 20:
                response += "\n... (truncated)"
            return response
        return f"❌ Deep scan error: {result.get('error', 'Unknown')}"
    
    def handle_location_ip(self, args: List[str]) -> str:
        if not args:
            return "❌ Usage: <code>/location_ip [IP]</code>"
        ip = args[0]
        result = self.monitor.scanner.get_ip_location(ip)
        return f"🌍 <b>Location: {ip}</b>\n\n<code>{result}</code>"
    
    def handle_analyze_ip(self, args: List[str]) -> str:
        if not args:
            return "❌ Usage: <code>/analyze_ip [IP]</code>"
        ip = args[0]
        response = f"🔍 <b>Analysis: {ip}</b>\n\n"
        location = self.monitor.scanner.get_ip_location(ip)
        try:
            loc_data = json.loads(location)
            response += f"📍 Location: {loc_data.get('city', 'N/A')}, {loc_data.get('country', 'N/A')}\n"
            response += f"🏢 ISP: {loc_data.get('isp', 'N/A')}\n\n"
        except:
            pass
        threats = self.monitor.db_manager.get_recent_threats(5)
        ip_threats = [t for t in threats if t[0] == ip]
        if ip_threats:
            response += f"🚨 <b>Threats Found: {len(ip_threats)}</b>\n"
            for threat in ip_threats:
                response += f"• {threat[1]}: {threat[2]}\n"
        else:
            response += "✅ No recent threats detected"
        return response
    
    def handle_status(self, args: List[str]) -> str:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        response = "📊 <b>System Status</b>\n\n"
        response += f"✅ Bot: Online\n"
        response += f"🔍 Monitored IPs: {len(self.monitor.monitored_ips)}\n"
        response += f"💻 CPU: {cpu}%\n"
        response += f"🧠 Memory: {mem.percent}%\n"
        response += f"🌐 Connections: {len(psutil.net_connections())}\n"
        response += f"🔐 SSH Sessions: {len(self.monitor.ssh_manager.saved_sessions)}\n"
        response += f"📥 Active Downloads: {len([d for d in self.monitor.wget_manager.active_downloads.values() if d.get('status') == 'downloading'])}\n"
        return response
    
    def handle_curl(self, args: List[str]) -> str:
        if not args:
            return "❌ Usage: <code>/curl [URL]</code>"
        url = args[-1]
        try:
            response = requests.get(url, timeout=10)
            result = f"📡 <b>CURL Response</b>\n\n"
            result += f"Status: {response.status_code}\n"
            result += f"Size: {len(response.content)} bytes\n\n"
            preview = response.text[:500]
            result += f"<code>{preview}</code>"
            if len(response.text) > 500:
                result += "..."
            return result
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    def handle_whois(self, args: List[str]) -> str:
        if not args:
            return "❌ Usage: <code>/whois [domain]</code>"
        domain = args[0]
        try:
            result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=30)
            output = result.stdout[:1000]
            return f"🔍 <b>WHOIS: {domain}</b>\n\n<code>{output}</code>"
        except:
            return "❌ WHOIS lookup failed"
    
    def handle_dns_lookup(self, args: List[str]) -> str:
        if not args:
            return "❌ Usage: <code>/dns_lookup [domain]</code>"
        domain = args[0]
        try:
            ip = socket.gethostbyname(domain)
            return f"🌐 <b>DNS Lookup</b>\n\n{domain} → <code>{ip}</code>"
        except Exception as e:
            return f"❌ DNS lookup failed: {str(e)}"
    
    def handle_network_info(self, args: List[str]) -> str:
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            addrs = psutil.net_if_addrs()
            response = "🌐 <b>Network Information</b>\n\n"
            response += f"Hostname: <code>{hostname}</code>\n"
            response += f"Local IP: <code>{local_ip}</code>\n\n"
            response += f"<b>Network Interfaces:</b>\n"
            for iface, addresses in list(addrs.items())[:5]:
                response += f"\n{iface}:\n"
                for addr in addresses[:2]:
                    response += f"  {addr.address}\n"
            return response
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    def handle_system_info(self, args: List[str]) -> str:
        response = "💻 <b>System Information</b>\n\n"
        response += f"OS: {platform.system()} {platform.release()}\n"
        response += f"CPU Cores: {psutil.cpu_count()}\n"
        response += f"CPU Usage: {psutil.cpu_percent()}%\n"
        response += f"Memory: {psutil.virtual_memory().percent}%\n"
        response += f"Disk: {psutil.disk_usage('/').percent}%\n"
        response += f"Boot Time: {datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M')}\n"
        response += f"Nmap Available: {'Yes' if NMAP_AVAILABLE else 'No'}\n"
        response += f"SSH Available: {'Yes' if SSH_AVAILABLE else 'No'}\n"
        return response
    
    def handle_threat_summary(self, args: List[str]) -> str:
        threats = self.monitor.db_manager.get_recent_threats(10)
        if not threats:
            return "✅ No recent threats detected"
        response = "🚨 <b>Recent Threats</b>\n\n"
        for ip, ttype, severity, ts in threats:
            response += f"• <code>{ip}</code>\n"
            response += f"  Type: {ttype} | Severity: {severity}\n"
            response += f"  Time: {ts}\n\n"
        return response
    
    def handle_generate_report(self, args: List[str]) -> str:
        threats = self.monitor.db_manager.get_recent_threats(50)
        history = self.monitor.db_manager.get_command_history(100)
        report = {
            'generated_at': datetime.now().isoformat(),
            'monitored_ips': len(self.monitor.monitored_ips),
            'total_threats': len(threats),
            'high_severity': len([t for t in threats if t[2] == 'high']),
            'medium_severity': len([t for t in threats if t[2] == 'medium']),
            'low_severity': len([t for t in threats if t[2] == 'low']),
            'commands_executed': len(history)
        }
        filename = f"report_{int(time.time())}.json"
        os.makedirs(REPORT_DIR, exist_ok=True)
        filepath = os.path.join(REPORT_DIR, filename)
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        response = "📊 <b>Security Report</b>\n\n"
        response += f"Monitored IPs: {report['monitored_ips']}\n"
        response += f"Total Threats: {report['total_threats']}\n"
        response += f"High Severity: {report['high_severity']}\n"
        response += f"Medium Severity: {report['medium_severity']}\n"
        response += f"Low Severity: {report['low_severity']}\n"
        response += f"\n✅ Report saved: <code>{filename}</code>"
        return response
    
    def handle_kill_ip(self, args: List[str]) -> str:
        if not args:
            return "❌ Usage: <code>/kill_ip [IP]</code>"
        ip = args[0]
        self.send_telegram_message(f"⚠️ Starting traffic generation to {ip}...")
        # Note: Actual traffic generation should be used responsibly
        return f"⚠️ Traffic generation to {ip} not implemented for safety reasons"
    
    def handle_export_data(self, args: List[str]) -> str:
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                export_data = {
                    'export_time': datetime.now().isoformat(),
                    'monitored_ips': list(self.monitor.monitored_ips),
                    'ssh_sessions': self.monitor.ssh_manager.saved_sessions,
                    'system_status': 'ACTIVE'
                }
                json.dump(export_data, f, indent=2)
                temp_file = f.name
            
            filename = f"export_{int(time.time())}.json"
            shutil.move(temp_file, filename)
            return f"📤 <b>Data Export</b>\n\n✅ Data exported to <code>{filename}</code>"
        except Exception as e:
            return f"❌ Export failed: {str(e)}"
    
    def handle_reboot_system(self, args: List[str]) -> str:
        self.send_telegram_message("🔄 Rebooting monitoring system...")
        self.monitor.monitored_ips.clear()
        self.monitor.save_config()
        return "✅ Monitoring system rebooted. All monitoring stopped."
    
    # Wget Command Handlers
    def handle_wget(self, args: List[str]) -> str:
        if len(args) < 1:
            return "❌ Usage: <code>/wget [url] [output_path]</code>"
        
        url = args[0]
        output_path = args[1] if len(args) > 1 else None
        
        self.send_telegram_message(f"📥 Downloading from <code>{url}</code>...")
        result = self.monitor.wget_manager.download_file(url, output_path)
        
        if result['success']:
            return f"✅ <b>Download Complete</b>\n\nURL: <code>{url}</code>\nSaved to: <code>{result['output_path']}</code>\nSize: {result.get('size', 0)} bytes"
        else:
            return f"❌ <b>Download Failed</b>\n\nURL: <code>{url}</code>\nError: {result.get('error', 'Unknown error')}"
    
    def handle_download(self, args: List[str]) -> str:
        return self.handle_wget(args)
    
    def handle_download_status(self, args: List[str]) -> str:
        status = self.monitor.wget_manager.get_download_status()
        response = "📊 <b>Download Status</b>\n\n"
        response += f"Active: {status['active']}\n"
        response += f"Completed: {status['completed']}\n"
        response += f"Failed: {status['failed']}\n"
        response += f"Total: {status['total']}\n"
        return response
    
    def handle_list_downloads(self, args: List[str]) -> str:
        limit = int(args[0]) if args else 10
        downloads = self.monitor.wget_manager.list_downloads(limit)
        
        if not downloads:
            return "📋 No downloads in history"
        
        response = "📋 <b>Recent Downloads</b>\n\n"
        for i, dl in enumerate(downloads[::-1], 1):
            response += f"{i}. <code>{dl.get('url', 'N/A')[:50]}...</code>\n"
            response += f"   Saved as: {os.path.basename(dl.get('output', 'N/A'))}\n"
            response += f"   Size: {dl.get('size', 0)} bytes\n"
            response += f"   Time: {dl.get('timestamp', 'N/A')[:19]}\n\n"
        
        return response
    
    def handle_clear_downloads(self, args: List[str]) -> str:
        return self.monitor.wget_manager.clear_downloads()
    
    # Nmap Command Handlers
    def handle_nmap_scan(self, args: List[str]) -> str:
        if len(args) < 1:
            return "❌ Usage: <code>/nmap_scan [target] [type] [ports] [arguments]</code>\nTypes: normal, stealth, aggressive, udp, os, service, vuln"
        
        target = args[0]
        scan_type = args[1] if len(args) > 1 else "normal"
        ports = args[2] if len(args) > 2 else None
        arguments = ' '.join(args[3:]) if len(args) > 3 else None
        
        self.send_telegram_message(f"🔍 Starting Nmap {scan_type} scan on <code>{target}</code>...")
        result = self.monitor.scanner.nmap_scan(target, scan_type, ports, arguments)
        
        if result['success']:
            response = f"✅ <b>Nmap Scan Complete</b>\n\n"
            response += f"Target: <code>{target}</code>\n"
            response += f"Type: {scan_type}\n"
            response += f"Duration: {result.get('duration', 0):.2f}s\n"
            response += f"Hosts Found: {len(result.get('hosts', {}))}\n\n"
            
            for host, info in result.get('hosts', {}).items():
                response += f"Host: <code>{host}</code>\n"
                response += f"State: {info.get('state', 'unknown')}\n"
                response += f"Open Ports: {len(info.get('open_ports', []))}\n"
                
                for port in info.get('open_ports', [])[:5]:
                    response += f"  Port {port['port']}/{port['protocol']}: {port['service']}\n"
                
                if len(info.get('open_ports', [])) > 5:
                    response += f"  ... and {len(info.get('open_ports', []))-5} more\n"
                
                response += "\n"
            
            # Log to database
            self.monitor.db_manager.log_nmap_scan(
                target, scan_type, 
                ports or "default",
                arguments or "default",
                json.dumps(result),
                result.get('duration', 0)
            )
            
            return response[:4000]  # Telegram message limit
        else:
            return f"❌ Nmap scan failed: {result.get('error', 'Unknown error')}"
    
    def handle_nmap_network(self, args: List[str]) -> str:
        if len(args) < 1:
            return "❌ Usage: <code>/nmap_network [network] [type]</code>\nExample: /nmap_network 192.168.1.0/24"
        
        network = args[0]
        scan_type = args[1] if len(args) > 1 else "normal"
        
        return self.handle_nmap_scan([network, scan_type])
    
    def handle_nmap_service(self, args: List[str]) -> str:
        if len(args) < 1:
            return "❌ Usage: <code>/nmap_service [target]</code>"
        
        target = args[0]
        return self.handle_nmap_scan([target, "service"])
    
    def handle_nmap_os(self, args: List[str]) -> str:
        if len(args) < 1:
            return "❌ Usage: <code>/nmap_os [target]</code>"
        
        target = args[0]
        return self.handle_nmap_scan([target, "os"])
    
    def handle_nmap_vuln(self, args: List[str]) -> str:
        if len(args) < 1:
            return "❌ Usage: <code>/nmap_vuln [target]</code>"
        
        target = args[0]
        return self.handle_nmap_scan([target, "vuln"])
    
    def handle_nmap_stealth(self, args: List[str]) -> str:
        if len(args) < 1:
            return "❌ Usage: <code>/nmap_stealth [target]</code>"
        
        target = args[0]
        return self.handle_nmap_scan([target, "stealth"])
    
    def handle_nmap_aggressive(self, args: List[str]) -> str:
        if len(args) < 1:
            return "❌ Usage: <code>/nmap_aggressive [target]</code>"
        
        target = args[0]
        return self.handle_nmap_scan([target, "aggressive"])
    
    def handle_nmap_udp(self, args: List[str]) -> str:
        if len(args) < 1:
            return "❌ Usage: <code>/nmap_udp [target]</code>"
        
        target = args[0]
        return self.handle_nmap_scan([target, "udp"])
    
    def handle_nmap_history(self, args: List[str]) -> str:
        limit = int(args[0]) if args else 10
        history = self.monitor.db_manager.get_nmap_history(limit)
        
        if not history:
            return "📋 No Nmap scans in history"
        
        response = "📋 <b>Nmap Scan History</b>\n\n"
        for target, scan_type, ports, duration, timestamp in history:
            response += f"• <code>{target}</code>\n"
            response += f"  Type: {scan_type} | Ports: {ports}\n"
            response += f"  Duration: {duration:.2f}s | Time: {timestamp[:19]}\n\n"
        
        return response
    
    # SSH Command Handlers (simplified versions)
    def handle_ssh_connect(self, args: List[str]) -> str:
        if not SSH_AVAILABLE:
            return "❌ SSH not available (install paramiko)"
        
        if len(args) < 1:
            return "❌ Usage: <code>/ssh_connect [session_name]</code> or <code>/ssh_connect [host] [port] [user] [password]</code>"
        
        if len(args) == 1:
            session_name = args[0]
            success, message = self.monitor.ssh_manager.connect(session_name)
        else:
            host = args[0]
            port = int(args[1]) if len(args) > 1 else 22
            username = args[2] if len(args) > 2 else "root"
            password = args[3] if len(args) > 3 else None
            success, message = self.monitor.ssh_manager.connect(None, host=host, port=port, username=username, password=password)
        
        return message
    
    def handle_ssh_execute(self, args: List[str]) -> str:
        if not SSH_AVAILABLE:
            return "❌ SSH not available"
        
        if len(args) < 2:
            return "❌ Usage: <code>/ssh_execute [session] [command]</code>"
        
        session = args[0]
        command = ' '.join(args[1:])
        
        # Find connection ID
        conn_id = None
        for saved_session in self.monitor.ssh_manager.saved_sessions:
            if saved_session == session:
                session_data = self.monitor.ssh_manager.saved_sessions[saved_session]
                conn_id = f"{session_data['username']}@{session_data['host']}:{session_data['port']}"
                break
        
        if not conn_id:
            return f"❌ No active connection for session '{session}'"
        
        success, output = self.monitor.ssh_manager.execute_command(conn_id, command)
        if success:
            return f"✅ <b>Command Output:</b>\n\n<code>{output[:3000]}</code>"
        else:
            return f"❌ <b>Command Failed:</b>\n\n<code>{output}</code>"
    
    def handle_ssh_upload(self, args: List[str]) -> str:
        if not SSH_AVAILABLE:
            return "❌ SSH not available"
        
        if len(args) < 3:
            return "❌ Usage: <code>/ssh_upload [session] [local_path] [remote_path]</code>"
        
        session = args[0]
        local_path = args[1]
        remote_path = args[2]
        
        # Find connection ID
        conn_id = None
        for saved_session in self.monitor.ssh_manager.saved_sessions:
            if saved_session == session:
                session_data = self.monitor.ssh_manager.saved_sessions[saved_session]
                conn_id = f"{session_data['username']}@{session_data['host']}:{session_data['port']}"
                break
        
        if not conn_id:
            return f"❌ No active connection for session '{session}'"
        
        success, message = self.monitor.ssh_manager.upload_file(conn_id, local_path, remote_path)
        return message
    
    def handle_ssh_download(self, args: List[str]) -> str:
        if not SSH_AVAILABLE:
            return "❌ SSH not available"
        
        if len(args) < 3:
            return "❌ Usage: <code>/ssh_download [session] [remote_path] [local_path]</code>"
        
        session = args[0]
        remote_path = args[1]
        local_path = args[2]
        
        # Find connection ID
        conn_id = None
        for saved_session in self.monitor.ssh_manager.saved_sessions:
            if saved_session == session:
                session_data = self.monitor.ssh_manager.saved_sessions[saved_session]
                conn_id = f"{session_data['username']}@{session_data['host']}:{session_data['port']}"
                break
        
        if not conn_id:
            return f"❌ No active connection for session '{session}'"
        
        success, message = self.monitor.ssh_manager.download_file(conn_id, remote_path, local_path)
        return message
    
    def handle_ssh_disconnect(self, args: List[str]) -> str:
        if not SSH_AVAILABLE:
            return "❌ SSH not available"
        
        if len(args) < 1:
            return "❌ Usage: <code>/ssh_disconnect [session]</code>"
        
        session = args[0]
        
        # Find connection ID
        conn_id = None
        for saved_session in self.monitor.ssh_manager.saved_sessions:
            if saved_session == session:
                session_data = self.monitor.ssh_manager.saved_sessions[saved_session]
                conn_id = f"{session_data['username']}@{session_data['host']}:{session_data['port']}"
                break
        
        if not conn_id:
            return f"❌ No active connection for session '{session}'"
        
        message = self.monitor.ssh_manager.disconnect(conn_id)
        return message
    
    def handle_ssh_sessions(self, args: List[str]) -> str:
        return self.monitor.ssh_manager.list_sessions()
    
    def handle_ssh_add_session(self, args: List[str]) -> str:
        if len(args) < 4:
            return "❌ Usage: <code>/ssh_add_session [name] [host] [port] [username] [password]</code>"
        
        name = args[0]
        host = args[1]
        port = int(args[2]) if len(args) > 2 else 22
        username = args[3]
        password = args[4] if len(args) > 4 else None
        
        message = self.monitor.ssh_manager.add_session(name, host, port, username, password)
        return message
    
    def handle_ssh_remove_session(self, args: List[str]) -> str:
        if len(args) < 1:
            return "❌ Usage: <code>/ssh_remove_session [name]</code>"
        
        name = args[0]
        message = self.monitor.ssh_manager.remove_session(name)
        return message
    
    def handle_ssh_list_connections(self, args: List[str]) -> str:
        return self.monitor.ssh_manager.list_connections()
    
    def process_telegram_commands(self):
        """Process incoming Telegram commands"""
        if not self.monitor.telegram_token:
            return
            
        try:
            url = f"https://api.telegram.org/bot{self.monitor.telegram_token}/getUpdates"
            params = {'offset': self.last_update_id + 1, 'timeout': 10}
            response = requests.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                if data['ok'] and 'result' in data:
                    for update in data['result']:
                        self.last_update_id = update['update_id']
                        if 'message' in update and 'text' in update['message']:
                            self.process_message(update['message'])
        except Exception as e:
            logging.error(f"Telegram error: {e}")
    
    def process_message(self, message):
        """Process individual message"""
        text = message['text']
        chat_id = message['chat']['id']
        
        if not self.monitor.telegram_chat_id:
            self.monitor.telegram_chat_id = str(chat_id)
            self.monitor.save_config()
        
        self.monitor.db_manager.log_command(text, 'telegram', True)
        
        parts = text.split()
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        if command in self.command_handlers:
            try:
                def execute():
                    response = self.command_handlers[command](args)
                    self.send_telegram_message(response)
                
                thread = threading.Thread(target=execute, daemon=True)
                thread.start()
            except Exception as e:
                self.send_telegram_message(f"❌ Error: {str(e)}")
        else:
            self.send_telegram_message("❌ Unknown command. Type /help")

class CybersecurityMonitor:
    """Enhanced main monitor class with all capabilities"""
    
    def __init__(self):
        self.monitored_ips = set()
        self.monitoring_active = False
        self.telegram_token = None
        self.telegram_chat_id = None
        self.db_manager = DatabaseManager()
        self.scanner = NetworkScanner()
        self.traceroute_tool = TracerouteTool()
        self.enhanced_tools = EnhancedTools()
        self.ssh_manager = SSHManager()
        self.wget_manager = WgetManager()
        self.setup_logging()
        self.load_config()
    
    def setup_logging(self):
        """Setup logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    def load_config(self):
        """Load configuration"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.telegram_token = config.get('telegram_token')
                    self.telegram_chat_id = config.get('telegram_chat_id')
                    self.monitored_ips = set(config.get('monitored_ips', []))
        except Exception as e:
            logging.error(f"Config load error: {e}")
    
    def save_config(self):
        """Save configuration"""
        try:
            config = {
                'telegram_token': self.telegram_token,
                'telegram_chat_id': self.telegram_chat_id,
                'monitored_ips': list(self.monitored_ips)
            }
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            logging.error(f"Config save error: {e}")

def print_banner():
    """Print ultimate banner"""
    banner = f"""
    {Colors.GREEN}╔════════════════════════════════════════════════════════════╗{Colors.END}
    {Colors.GREEN}║                                                              ║{Colors.END}
    {Colors.GREEN}║          {Colors.BOLD}{Colors.CYAN}🛡️  ACCURATE CYBER STAR - ULTIMATE EDITION v4.0  🛡️{Colors.END}{Colors.GREEN}          ║{Colors.END}
    {Colors.GREEN}║                                                              ║{Colors.END}
    {Colors.GREEN}║          {Colors.YELLOW}SSH • Wget • Nmap • Traceroute • Monitoring{Colors.END}{Colors.GREEN}          ║{Colors.END}
    {Colors.GREEN}║          {Colors.MAGENTA}Network Scanner • Database • Telegram Bot{Colors.END}{Colors.GREEN}            ║{Colors.END}
    {Colors.GREEN}║                                                              ║{Colors.END}
    {Colors.GREEN}║  {Colors.WHITE}Community: https://github.com/Accurate-Cyber-Defense{Colors.END}{Colors.GREEN}   ║{Colors.END}
    {Colors.GREEN}║  {Colors.GREEN}✅ Telegram Bot: ACTIVE     {Colors.BLUE}✅ SSH Manager: READY{Colors.END}{Colors.GREEN}          ║{Colors.END}
    {Colors.GREEN}║  {Colors.YELLOW}✅ Nmap Scanner: READY     {Colors.MAGENTA}✅ Wget Manager: READY{Colors.END}{Colors.GREEN}          ║{Colors.END}
    {Colors.GREEN}║  {Colors.CYAN}✅ Database: READY         {Colors.WHITE}✅ Traceroute: READY{Colors.END}{Colors.GREEN}           ║{Colors.END}
    {Colors.GREEN}║                                                              ║{Colors.END}
    {Colors.GREEN}╚════════════════════════════════════════════════════════════╝{Colors.END}
    """
    print(banner)

def setup_telegram():
    """Setup Telegram configuration"""
    print(f"\n{Colors.CYAN}🔧 Telegram Bot Setup{Colors.END}")
    print(f"{Colors.CYAN}{'='*50}{Colors.END}")
    print(f"\n{Colors.WHITE}To use Telegram commands:{Colors.END}")
    print(f"{Colors.YELLOW}1. Create a bot with @BotFather on Telegram{Colors.END}")
    print(f"{Colors.YELLOW}2. Get your bot token{Colors.END}")
    print(f"{Colors.YELLOW}3. Start chat with your bot and send /start{Colors.END}")
    print(f"{Colors.YELLOW}4. Get your chat ID{Colors.END}\n")
    
    token = input(f"{Colors.GREEN}Enter Telegram bot token (or press Enter to skip): {Colors.END}").strip()
    if token:
        chat_id = input(f"{Colors.GREEN}Enter your chat ID: {Colors.END}").strip()
        return token, chat_id
    return None, None

def main():
    """Main function with ultimate capabilities"""
    monitor = CybersecurityMonitor()
    telegram_handler = TelegramBotHandler(monitor)
    
    print_banner()
    
    # Setup Telegram if not configured
    if not monitor.telegram_token:
        token, chat_id = setup_telegram()
        if token and chat_id:
            monitor.telegram_token = token
            monitor.telegram_chat_id = chat_id
            monitor.save_config()
            print(f"{Colors.GREEN}✅ Telegram configured!{Colors.END}")
        else:
            print(f"{Colors.YELLOW}⚠️ Telegram features disabled{Colors.END}")
    
    # Dependency checks
    print(f"\n{Colors.CYAN}🔍 Checking dependencies...{Colors.END}")
    if not SSH_AVAILABLE:
        print(f"{Colors.YELLOW}⚠️ Warning: paramiko not installed. SSH features disabled.{Colors.END}")
        print(f"{Colors.YELLOW}   Install with: pip install paramiko{Colors.END}")
    
    if not NMAP_AVAILABLE:
        print(f"{Colors.YELLOW}⚠️ Warning: python-nmap not installed. Scan features limited.{Colors.END}")
        print(f"{Colors.YELLOW}   Install with: pip install python-nmap{Colors.END}")
    
    if not SCAPY_AVAILABLE:
        print(f"{Colors.YELLOW}⚠️ Warning: scapy not installed. Traffic generation disabled.{Colors.END}")
        print(f"{Colors.YELLOW}   Install with: pip install scapy{Colors.END}")
    
    # Create necessary directories
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    os.makedirs(REPORT_DIR, exist_ok=True)
    
    # Start Telegram command processor
    def telegram_processor():
        while True:
            try:
                telegram_handler.process_telegram_commands()
                time.sleep(2)
            except Exception as e:
                logging.error(f"Telegram error: {e}")
                time.sleep(10)
    
    telegram_thread = threading.Thread(target=telegram_processor, daemon=True)
    telegram_thread.start()
    
    if monitor.telegram_token and monitor.telegram_chat_id:
        print(f"{Colors.GREEN}✅ Telegram bot ACTIVE{Colors.END}")
        print(f"{Colors.GREEN}📱 Send /start to your bot on Telegram{Colors.END}")
        
        # Test connection
        test_msg = "🔗 <b>Accurate Cyber Star v4.0 - Connected!</b>\n\n✅ Bot is online\n🚀 Type /help for commands\n🔐 All capabilities ready!"
        telegram_handler.send_telegram_message(test_msg)
    
    print(f"\n{Colors.CYAN}💻 Local terminal commands available{Colors.END}")
    print(f"{Colors.CYAN}📋 Type 'help' for command list{Colors.END}\n")
    
    # Local command interface
    while True:
        try:
            command = input(f"{Colors.BOLD}{Colors.GREEN}cyberstar#>{Colors.END} ").strip()
            if not command:
                continue
            
            monitor.db_manager.log_command(command, 'local', True)
            
            parts = command.split()
            cmd = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []
            
            if cmd == 'exit':
                print(f"{Colors.YELLOW}👋 Exiting...{Colors.END}")
                break
            
            elif cmd == 'help':
                print(f"""
{Colors.BOLD}{Colors.CYAN}Enhanced Commands:{Colors.END}

{Colors.GREEN}🌐 Network Diagnostics:{Colors.END}
  ping [ip]              - Ping IP address
  tracert [ip]           - Traceroute
  traceroute [ip]        - Traceroute
  advanced_traceroute [ip] - Enhanced traceroute
  location [ip]          - Get IP location
  analyze [ip]           - Analyze IP
  whois [domain]         - WHOIS lookup
  dns [domain]           - DNS lookup
  kill [ip]              - Generate test traffic

{Colors.YELLOW}🛡️ Nmap Scanning:{Colors.END}
  nmap [target] [type]   - Nmap scan
  nmap_network [network] - Network scan
  nmap_service [target]  - Service detection
  nmap_os [target]       - OS detection
  nmap_vuln [target]     - Vulnerability scan
  nmap_stealth [target]  - Stealth scan
  nmap_aggressive [target] - Aggressive scan
  nmap_udp [target]      - UDP scan
  nmap_history           - Scan history

{Colors.BLUE}📥 Download Manager:{Colors.END}
  wget [url] [output]    - Download file
  download [url]         - Download with auto-naming
  download_status        - Check download status
  list_downloads         - List recent downloads
  clear_downloads        - Clear download history

{Colors.MAGENTA}🔐 SSH Commands:{Colors.END}
  ssh_add [name] [host] [port] [user] [pass] - Add SSH session
  ssh_connect [session]  - Connect to SSH
  ssh_exec [session] [cmd] - Execute command
  ssh_upload [session] [local] [remote] - Upload file
  ssh_download [session] [remote] [local] - Download file
  ssh_disconnect [session] - Disconnect
  ssh_sessions          - List SSH sessions
  ssh_connections       - List active connections

{Colors.CYAN}📊 Monitoring:{Colors.END}
  start_monitoring [ip]  - Start monitoring IP
  add [ip]               - Add IP to monitoring
  remove [ip]            - Remove IP
  list                   - List monitored IPs
  stop                   - Stop monitoring

{Colors.WHITE}💻 System Info:{Colors.END}
  network_info           - Network information
  system_info            - System information
  status                 - System status
  history                - Command history
  threats                - Threat summary
  report                 - Generate report
  export                 - Export data

{Colors.GREEN}🔧 Configuration:{Colors.END}
  config                 - Configure Telegram
  clear                  - Clear screen
  exit                   - Exit program

All commands also available via Telegram!
                """)
            
            elif cmd == 'ping' and args:
                result = monitor.scanner.ping_ip(args[0])
                print(result)
            
            elif cmd in ['tracert', 'traceroute'] and args:
                print(f"Traceroute to {args[0]}...")
                result = monitor.scanner.traceroute(args[0])
                print(result)
            
            elif cmd == 'advanced_traceroute' and args:
                print(f"🚀 Advanced traceroute to {args[0]}...")
                result = monitor.traceroute_tool.interactive_traceroute(args[0])
                print(result)
            
            elif cmd == 'nmap' and args:
                target = args[0]
                scan_type = args[1] if len(args) > 1 else "normal"
                ports = args[2] if len(args) > 2 else None
                arguments = ' '.join(args[3:]) if len(args) > 3 else None
                
                print(f"🔍 Starting Nmap {scan_type} scan on {target}...")
                result = monitor.scanner.nmap_scan(target, scan_type, ports, arguments)
                
                if result['success']:
                    print(f"\n✅ Nmap Scan Complete")
                    print(f"Target: {target}")
                    print(f"Type: {scan_type}")
                    print(f"Duration: {result.get('duration', 0):.2f}s")
                    print(f"Hosts Found: {len(result.get('hosts', {}))}\n")
                    
                    for host, info in result.get('hosts', {}).items():
                        print(f"Host: {host}")
                        print(f"State: {info.get('state', 'unknown')}")
                        print(f"Open Ports: {len(info.get('open_ports', []))}")
                        
                        for port in info.get('open_ports', [])[:10]:
                            print(f"  Port {port['port']}/{port['protocol']}: {port['service']}")
                        
                        if len(info.get('open_ports', [])) > 10:
                            print(f"  ... and {len(info.get('open_ports', []))-10} more")
                        
                        print()
                else:
                    print(f"❌ Nmap scan failed: {result.get('error', 'Unknown error')}")
            
            elif cmd == 'nmap_network' and args:
                cmd = 'nmap'
                args = [args[0], args[1] if len(args) > 1 else "normal"]
                continue
            
            elif cmd == 'nmap_service' and args:
                cmd = 'nmap'
                args = [args[0], "service"]
                continue
            
            elif cmd == 'nmap_os' and args:
                cmd = 'nmap'
                args = [args[0], "os"]
                continue
            
            elif cmd == 'nmap_vuln' and args:
                cmd = 'nmap'
                args = [args[0], "vuln"]
                continue
            
            elif cmd == 'nmap_stealth' and args:
                cmd = 'nmap'
                args = [args[0], "stealth"]
                continue
            
            elif cmd == 'nmap_aggressive' and args:
                cmd = 'nmap'
                args = [args[0], "aggressive"]
                continue
            
            elif cmd == 'nmap_udp' and args:
                cmd = 'nmap'
                args = [args[0], "udp"]
                continue
            
            elif cmd == 'nmap_history':
                history = monitor.db_manager.get_nmap_history(10)
                if history:
                    print("\n📋 Nmap Scan History:")
                    for target, scan_type, ports, duration, timestamp in history:
                        print(f"  • {target}")
                        print(f"    Type: {scan_type} | Ports: {ports}")
                        print(f"    Duration: {duration:.2f}s | Time: {timestamp[:19]}\n")
                else:
                    print("📋 No Nmap scans in history")
            
            elif cmd == 'wget' and args:
                url = args[0]
                output_path = args[1] if len(args) > 1 else None
                
                print(f"📥 Downloading from {url}...")
                result = monitor.wget_manager.download_file(url, output_path)
                
                if result['success']:
                    print(f"✅ Download Complete")
                    print(f"URL: {url}")
                    print(f"Saved to: {result['output_path']}")
                    print(f"Size: {result.get('size', 0)} bytes")
                else:
                    print(f"❌ Download Failed")
                    print(f"Error: {result.get('error', 'Unknown error')}")
            
            elif cmd == 'download' and args:
                cmd = 'wget'
                continue
            
            elif cmd == 'download_status':
                status = monitor.wget_manager.get_download_status()
                print(f"\n📊 Download Status:")
                print(f"  Active: {status['active']}")
                print(f"  Completed: {status['completed']}")
                print(f"  Failed: {status['failed']}")
                print(f"  Total: {status['total']}")
            
            elif cmd == 'list_downloads':
                limit = int(args[0]) if args else 10
                downloads = monitor.wget_manager.list_downloads(limit)
                
                if downloads:
                    print(f"\n📋 Recent Downloads:")
                    for i, dl in enumerate(downloads[::-1], 1):
                        print(f"  {i}. {dl.get('url', 'N/A')[:50]}...")
                        print(f"     Saved as: {os.path.basename(dl.get('output', 'N/A'))}")
                        print(f"     Size: {dl.get('size', 0)} bytes")
                        print(f"     Time: {dl.get('timestamp', 'N/A')[:19]}\n")
                else:
                    print("📋 No downloads in history")
            
            elif cmd == 'clear_downloads':
                print(monitor.wget_manager.clear_downloads())
            
            elif cmd == 'ssh_add' and args:
                if len(args) >= 4:
                    name = args[0]
                    host = args[1]
                    port = int(args[2]) if len(args) > 2 else 22
                    username = args[3]
                    password = args[4] if len(args) > 4 else None
                    
                    message = monitor.ssh_manager.add_session(name, host, port, username, password)
                    print(message)
                else:
                    print("❌ Usage: ssh_add [name] [host] [port] [user] [pass]")
            
            elif cmd == 'ssh_connect' and args:
                if len(args) == 1:
                    success, message = monitor.ssh_manager.connect(args[0])
                    print(message)
                elif len(args) >= 3:
                    host = args[0]
                    port = int(args[1]) if len(args) > 1 else 22
                    username = args[2] if len(args) > 2 else "root"
                    password = args[3] if len(args) > 3 else None
                    
                    success, message = monitor.ssh_manager.connect(None, host=host, port=port, 
                                                                  username=username, password=password)
                    print(message)
                else:
                    print("❌ Usage: ssh_connect [session] or ssh_connect [host] [port] [user] [pass]")
            
            elif cmd == 'ssh_exec' and args:
                if len(args) >= 2:
                    session = args[0]
                    command = ' '.join(args[1:])
                    
                    # Find connection
                    conn_id = None
                    for saved_session in monitor.ssh_manager.saved_sessions:
                        if saved_session == session:
                            session_data = monitor.ssh_manager.saved_sessions[saved_session]
                            conn_id = f"{session_data['username']}@{session_data['host']}:{session_data['port']}"
                            break
                    
                    if conn_id and conn_id in monitor.ssh_manager.connections:
                        success, output = monitor.ssh_manager.execute_command(conn_id, command)
                        if success:
                            print(f"✅ Command Output:\n{output}")
                        else:
                            print(f"❌ Command Failed:\n{output}")
                    else:
                        print(f"❌ No active connection for session '{session}'")
                else:
                    print("❌ Usage: ssh_exec [session] [command]")
            
            elif cmd == 'ssh_upload' and args:
                if len(args) >= 3:
                    session = args[0]
                    local_path = args[1]
                    remote_path = args[2]
                    
                    # Find connection
                    conn_id = None
                    for saved_session in monitor.ssh_manager.saved_sessions:
                        if saved_session == session:
                            session_data = monitor.ssh_manager.saved_sessions[saved_session]
                            conn_id = f"{session_data['username']}@{session_data['host']}:{session_data['port']}"
                            break
                    
                    if conn_id and conn_id in monitor.ssh_manager.connections:
                        success, message = monitor.ssh_manager.upload_file(conn_id, local_path, remote_path)
                        print(message)
                    else:
                        print(f"❌ No active connection for session '{session}'")
                else:
                    print("❌ Usage: ssh_upload [session] [local] [remote]")
            
            elif cmd == 'ssh_download' and args:
                if len(args) >= 3:
                    session = args[0]
                    remote_path = args[1]
                    local_path = args[2]
                    
                    # Find connection
                    conn_id = None
                    for saved_session in monitor.ssh_manager.saved_sessions:
                        if saved_session == session:
                            session_data = monitor.ssh_manager.saved_sessions[saved_session]
                            conn_id = f"{session_data['username']}@{session_data['host']}:{session_data['port']}"
                            break
                    
                    if conn_id and conn_id in monitor.ssh_manager.connections:
                        success, message = monitor.ssh_manager.download_file(conn_id, remote_path, local_path)
                        print(message)
                    else:
                        print(f"❌ No active connection for session '{session}'")
                else:
                    print("❌ Usage: ssh_download [session] [remote] [local]")
            
            elif cmd == 'ssh_disconnect' and args:
                session = args[0]
                
                # Find connection
                conn_id = None
                for saved_session in monitor.ssh_manager.saved_sessions:
                    if saved_session == session:
                        session_data = monitor.ssh_manager.saved_sessions[saved_session]
                        conn_id = f"{session_data['username']}@{session_data['host']}:{session_data['port']}"
                        break
                
                if conn_id:
                    message = monitor.ssh_manager.disconnect(conn_id)
                    print(message)
                else:
                    print(f"❌ No active connection for session '{session}'")
            
            elif cmd == 'ssh_sessions':
                print(monitor.ssh_manager.list_sessions())
            
            elif cmd == 'ssh_connections':
                print(monitor.ssh_manager.list_connections())
            
            elif cmd == 'start_monitoring' and args:
                ip = args[0]
                try:
                    ipaddress.ip_address(ip)
                    monitor.monitored_ips.add(ip)
                    monitor.save_config()
                    print(f"✅ Started monitoring {ip}")
                except ValueError:
                    print(f"❌ Invalid IP: {ip}")
            
            elif cmd == 'add' and args:
                ip = args[0]
                try:
                    ipaddress.ip_address(ip)
                    monitor.monitored_ips.add(ip)
                    monitor.save_config()
                    print(f"✅ Added {ip}")
                except ValueError:
                    print(f"❌ Invalid IP: {ip}")
            
            elif cmd == 'remove' and args:
                ip = args[0]
                if ip in monitor.monitored_ips:
                    monitor.monitored_ips.remove(ip)
                    monitor.save_config()
                    print(f"✅ Removed {ip}")
                else:
                    print(f"❌ IP not in list: {ip}")
            
            elif cmd == 'list':
                if monitor.monitored_ips:
                    print("\n📋 Monitored IPs:")
                    for ip in sorted(monitor.monitored_ips):
                        print(f"  • {ip}")
                else:
                    print("📋 No IPs are being monitored")
            
            elif cmd == 'stop':
                if monitor.monitored_ips:
                    ips = list(monitor.monitored_ips)
                    monitor.monitored_ips.clear()
                    monitor.save_config()
                    print(f"🛑 Stopped monitoring: {', '.join(ips)}")
                else:
                    print("⚠️ No IPs are being monitored")
            
            elif cmd == 'network_info':
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                print(f"\n🌐 Network Information:")
                print(f"  Hostname: {hostname}")
                print(f"  Local IP: {local_ip}")
                print(f"  Connections: {len(psutil.net_connections())}")
                print(f"  SSH Sessions: {len(monitor.ssh_manager.saved_sessions)}")
                print(f"  Active Downloads: {len([d for d in monitor.wget_manager.active_downloads.values() if d.get('status') == 'downloading'])}")
            
            elif cmd == 'system_info':
                print(f"\n💻 System Information:")
                print(f"  OS: {platform.system()} {platform.release()}")
                print(f"  CPU Cores: {psutil.cpu_count()}")
                print(f"  CPU Usage: {psutil.cpu_percent()}%")
                print(f"  Memory: {psutil.virtual_memory().percent}%")
                print(f"  Disk: {psutil.disk_usage('/').percent}%")
                print(f"  Nmap Available: {'Yes' if NMAP_AVAILABLE else 'No'}")
                print(f"  SSH Available: {'Yes' if SSH_AVAILABLE else 'No'}")
                print(f"  Scapy Available: {'Yes' if SCAPY_AVAILABLE else 'No'}")
            
            elif cmd == 'status':
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                print(f"\n📊 System Status:")
                print(f"  Bot: {'Online' if monitor.telegram_token else 'Offline'}")
                print(f"  Monitored IPs: {len(monitor.monitored_ips)}")
                print(f"  CPU: {cpu}%")
                print(f"  Memory: {mem.percent}%")
                print(f"  Connections: {len(psutil.net_connections())}")
                print(f"  SSH Sessions: {len(monitor.ssh_manager.saved_sessions)}")
                print(f"  SSH Connections: {len(monitor.ssh_manager.connections)}")
                print(f"  Active Downloads: {len([d for d in monitor.wget_manager.active_downloads.values() if d.get('status') == 'downloading'])}")
            
            elif cmd == 'history':
                history = monitor.db_manager.get_command_history(20)
                if history:
                    print("\n📜 Command History:")
                    for cmd, src, ts, success in history:
                        status = "✅" if success else "❌"
                        print(f"  {status} [{src}] {cmd} | {ts}")
                else:
                    print("📜 No commands recorded")
            
            elif cmd == 'threats':
                threats = monitor.db_manager.get_recent_threats(10)
                if threats:
                    print("\n🚨 Recent Threats:")
                    for ip, ttype, severity, ts in threats:
                        print(f"  • {ip}")
                        print(f"    Type: {ttype} | Severity: {severity}")
                        print(f"    Time: {ts}\n")
                else:
                    print("✅ No recent threats detected")
            
            elif cmd == 'report':
                threats = monitor.db_manager.get_recent_threats(50)
                history = monitor.db_manager.get_command_history(100)
                
                report = {
                    'generated_at': datetime.now().isoformat(),
                    'monitored_ips': len(monitor.monitored_ips),
                    'total_threats': len(threats),
                    'high_severity': len([t for t in threats if t[2] == 'high']),
                    'medium_severity': len([t for t in threats if t[2] == 'medium']),
                    'low_severity': len([t for t in threats if t[2] == 'low']),
                    'commands_executed': len(history),
                    'ssh_sessions': len(monitor.ssh_manager.saved_sessions),
                    'downloads': len(monitor.wget_manager.download_history)
                }
                
                filename = f"report_{int(time.time())}.json"
                os.makedirs(REPORT_DIR, exist_ok=True)
                filepath = os.path.join(REPORT_DIR, filename)
                
                with open(filepath, 'w') as f:
                    json.dump(report, f, indent=2)
                
                print(f"\n📊 Security Report:")
                print(f"  Monitored IPs: {report['monitored_ips']}")
                print(f"  Total Threats: {report['total_threats']}")
                print(f"  High Severity: {report['high_severity']}")
                print(f"  Medium Severity: {report['medium_severity']}")
                print(f"  Low Severity: {report['low_severity']}")
                print(f"  SSH Sessions: {report['ssh_sessions']}")
                print(f"  Downloads: {report['downloads']}")
                print(f"\n✅ Report saved: {filename}")
            
            elif cmd == 'export':
                try:
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                        export_data = {
                            'export_time': datetime.now().isoformat(),
                            'monitored_ips': list(monitor.monitored_ips),
                            'ssh_sessions': monitor.ssh_manager.saved_sessions,
                            'download_history': monitor.wget_manager.download_history[-50:],
                            'system_status': 'ACTIVE'
                        }
                        json.dump(export_data, f, indent=2)
                        temp_file = f.name
                    
                    filename = f"export_{int(time.time())}.json"
                    shutil.move(temp_file, filename)
                    print(f"✅ Data exported to {filename}")
                except Exception as e:
                    print(f"❌ Export failed: {e}")
            
            elif cmd == 'config':
                token, chat_id = setup_telegram()
                if token and chat_id:
                    monitor.telegram_token = token
                    monitor.telegram_chat_id = chat_id
                    monitor.save_config()
                    print("✅ Telegram configured!")
            
            elif cmd == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                print_banner()
            
            else:
                print("Unknown command. Type 'help' for available commands.")
        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}👋 Exiting...{Colors.END}")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            monitor.db_manager.log_command(command, 'local', False)

if __name__ == "__main__":
    try:
        print(f"{Colors.CYAN}🔍 Checking dependencies...{Colors.END}")
        time.sleep(1)
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}👋 Thank you for using Accurate Cyber Star!{Colors.END}")
    except Exception as e:
        print(f"❌ Application error: {e}")
        logging.exception("Application crash")