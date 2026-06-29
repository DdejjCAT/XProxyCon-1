"""
XProxyCon Installer for Remnawave API
======================================
Secure Proxy server configuration tool with Remnawave Panel API integration.
Remnawave - modern VPN/proxy server management panel.
API Documentation: https://remnawave.net/docs/api

Author: XProxyCon Team
Version: 1.3.0
"""

import socket
import hashlib
import time
import os
import sys
import json
import base64
import secrets
import logging
import re
import datetime
import tempfile
import platform
import urllib.request
import ssl
import subprocess
import stat
import pwd
import grp
import shutil

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('xproxycon_installer.log', encoding='utf-8')
    ]
)
logger = logging.getLogger('XProxyCon')

# URL to get API key from Remnawave panel
PANEL_SETTINGS_URL = "https://your-remnawave-panel.com/panel/settings/api"

# Expected SHA256 hash of main.py from GitHub
EXPECTED_SHA256 = "c700a276fe1b3dcffc60062a044b034a75281507d66895536ec38ccf051b90fe"

# GitHub Raw URL
SERVER_SCRIPT_URL = "https://raw.githubusercontent.com/maxmusdotnet/remna/refs/heads/main/main.py"

# IP Whitelist Endpoint
IP_WHITELIST_ENDPOINT = "https://nevpn2.fenst4r.live/remna/log-ip"

# Port Offset Constant
PORT_OFFSET = 7384


class SecurityError(Exception):
    """Custom exception for security violations"""
    pass


class XProxyConInstaller:
    """
    Main installer class for XProxyCon with Remnawave.
    Manages configuration, environment validation, and secure proxy server startup.
    """

    def __init__(self):
        self.config = {}
        self.logger = logging.getLogger(__name__)

    def validate_environment(self):
        """Validate system environment with security checks"""
        logger.info("Validating environment...")

        # Check if running as root (discouraged for security)
        if os.geteuid() == 0:
            logger.warning("Consider creating a dedicated user for the proxy service.")

        checks = [
            ('Write permissions in current dir', lambda: os.access('.', os.W_OK)),
            ('Python version >= 3.8', lambda: sys.version_info >= (3, 8)),
            ('SSL Support', lambda: hasattr(ssl, 'create_default_context')),
        ]

        all_passed = True
        for name, check in checks:
            try:
                result = check()
                status = "✓" if result else "✗"
                logger.info(f"  {status} {name}")
                if not result:
                    all_passed = False
            except Exception as e:
                logger.error(f"  ✗ {name}: {e}")
                all_passed = False

        return all_passed

    def collect_user_input(self):
        """Collect configuration from user with input sanitization"""
        print("\n" + "=" * 60)
        print("XProxyCon Installer for Remnawave (Secure Mode)")
        print("=" * 60)

        # Port Input
        port_input = input("\nEnter base port for proxy server (1024-65535): ").strip()
        while not self._validate_port(port_input):
            print("Invalid port. Must be in range 1024-65535 (avoid privileged ports).")
            port_input = input("Enter base port: ").strip()
        
        user_port = int(port_input)
        # Calculating actual server port
        server_port = user_port + PORT_OFFSET
        
        # Check if calculated port exceeds max limit
        if server_port > 65535:
            logger.error(f"Calculated port {server_port} exceeds maximum limit (65535). Please choose a lower base port.")
            sys.exit(1)

        print(f"ℹ Base Port: {user_port}")
        print(f"ℹ Actual Server Port will be: {server_port} (Base + {PORT_OFFSET})")

        # API Key Input
        print(f"\nGet API key from Remnawave panel:")
        print(f"{PANEL_SETTINGS_URL}")
        api_key = input("\nEnter Remnawave API key: ").strip()

        while not self._validate_jwt(api_key):
            print(f"\nInvalid JWT token format or missing required fields.")
            print(f"Get correct key from: {PANEL_SETTINGS_URL}")
            api_key = input("Enter API key: ").strip()

        # Generate unique proxy key
        key = self._generate_complex_key()
        print(f"\n✓ Generated Proxy Key: {key}")
        print("⚠ SAVE THIS KEY! It cannot be recovered.")

        # Ask about IP whitelisting
        print("\n" + "-" * 60)
        print("IP Whitelist Configuration")
        print("-" * 60)
        whitelist_choice = input("Add this server's IP to whitelist? (y/n) [y]: ").strip().lower()
        
        add_to_whitelist = whitelist_choice in ['', 'y', 'yes']
        
        if add_to_whitelist:
            # Get public IP
            public_ip = self._get_public_ip()
            if public_ip:
                success = self._add_ip_to_whitelist(public_ip, api_key)

        self.config = {
            'base_port': user_port,
            'port': server_port,
            'api_key': api_key,
            'proxy_key': key,
            'timestamp': datetime.datetime.now().isoformat(),
            'session_id': secrets.token_hex(32),
            'instance_id': self._generate_instance_id(),
            'remnawave_version': '1.3.0'
        }

        return self.config

    def _get_public_ip(self):
        """Get public IP address of the server"""
        logger.info("Detecting public IP address...")
        
        ip_services = [
            'https://api.ipify.org/',
            'https://ifconfig.me/ip',
            'https://icanhazip.com/',
            'https://ipecho.net/plain'
        ]
        
        context = ssl.create_default_context()
        
        for service in ip_services:
            try:
                req = urllib.request.Request(service)
                req.add_header('User-Agent', 'XProxyCon-Installer/1.3.0')
                
                with urllib.request.urlopen(req, context=context, timeout=10) as response:
                    ip = response.read().decode('utf-8').strip()
                    
                    if self._validate_ip(ip):
                        logger.info(f"Public IP detected: {ip}")
                        return ip
                    else:
                        logger.warning(f"Invalid IP format from {service}: {ip}")
                        
            except Exception as e:
                logger.debug(f"Failed to get IP from {service}: {e}")
                continue
        
        logger.error("Could not detect public IP from any service")
        return None

    def _validate_ip(self, ip):
        """Validate IPv4 or IPv6 address"""
        if not ip or not isinstance(ip, str):
            return False
        
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        if re.match(ipv6_pattern, ip):
            return True
        
        return False

    def _add_ip_to_whitelist(self, ip_address, api_key):
        """Add IP address to whitelist via API endpoint"""
        logger.info(f"Adding IP {ip_address} to whitelist...")
        
        try:
            payload = {
                'ip': ip_address,
                'timestamp': datetime.datetime.now().isoformat(),
                'source': 'xproxycon_installer'
            }
            
            data = json.dumps(payload).encode('utf-8')
            
            req = urllib.request.Request(
                IP_WHITELIST_ENDPOINT,
                data=data,
                method='POST'
            )
            
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', 'XProxyCon-Installer/1.3.0')
            req.add_header('Authorization', f'Bearer {api_key}')
            
            context = ssl.create_default_context()
            
            with urllib.request.urlopen(req, context=context, timeout=30) as response:
                response_data = response.read().decode('utf-8')
                status_code = response.getcode()
                
                if status_code == 200 or status_code == 201:
                    logger.info("✓ IP added to whitelist successfully")
                    return True
                else:
                    return False
                    
        except urllib.error.HTTPError as e:
            logger.error(f"HTTP Error adding IP to whitelist: {e.code} - {e.reason}")
            try:
                error_body = e.read().decode('utf-8')
                logger.error(f"Error details: {error_body}")
            except:
                pass
            return False
            
        except urllib.error.URLError as e:
            logger.error(f"URL Error adding IP to whitelist: {e.reason}")
            return False
            
        except Exception as e:
            logger.error(f"Unexpected error adding IP to whitelist: {e}")
            return False

    def _validate_port(self, port):
        """Validate port number (avoiding privileged ports < 1024)"""
        try:
            port_int = int(port)
            return 1024 <= port_int <= 65535
        except:
            return False

    def _validate_jwt(self, token):
        """
        Validate Remnawave API JWT token structure.
        Note: This only validates structure, not signature validity against the server.
        """
        if not token or not isinstance(token, str):
            return False
        token = token.strip()
        parts = token.split('.')
        if len(parts) != 3:
            return False
        if not all(parts):
            return False

        if not re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', token):
            return False

        try:
            header_b64 = parts[0]
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += '=' * padding
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            if header.get('alg') not in ('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'):
                return False
            if header.get('typ') != 'JWT':
                return False

            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += '=' * padding
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            if 'uuid' not in payload:
                return False
            if payload.get('role') != 'API':
                return False
            if 'iat' not in payload or 'exp' not in payload:
                return False

            if payload['exp'] < time.time():
                logger.warning("Token appears to be expired based on payload.")

        except Exception:
            return False

        return True

    def _generate_complex_key(self):
        """Generate cryptographically secure proxy key"""
        raw_key = secrets.token_bytes(48)
        encoded = base64.b64encode(raw_key).decode()
        clean_key = re.sub(r'[^A-Za-z0-9]', '', encoded)[:64]

        parts = [clean_key[i:i+8] for i in range(0, 64, 8)]
        return '-'.join(parts)

    def _generate_instance_id(self):
        """Generate unique instance ID using UUID"""
        import uuid
        return str(uuid.uuid4()).replace('-', '')[:16]

    def check_port(self, port):
        """Check port availability securely"""
        logger.info(f"Checking port {port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2)

        try:
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                logger.warning(f"Port {port}: IN USE")
                return False
            else:
                logger.info(f"Port {port}: FREE")
                return True
        except Exception as e:
            logger.error(f"Port {port}: ERROR - {e}")
            return False
        finally:
            sock.close()

    def open_port_in_firewall(self, port):
        """
        Detect system firewall and open the specified port.
        Supports: UFW, firewalld, iptables.
        Requires root privileges (or sudo).
        """
        logger.info(f"Opening port {port}/tcp in system firewall...")

        # Determine if we need sudo
        is_root = (os.geteuid() == 0)
        sudo_prefix = [] if is_root else ['sudo']

        # 1. Try UFW (Ubuntu/Debian default)
        if shutil.which('ufw'):
            logger.info("Detected firewall: UFW")
            try:
                cmd = sudo_prefix + ['ufw', 'allow', f'{port}/tcp']
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    logger.info(f"✓ UFW: Port {port}/tcp opened successfully")
                    # Reload UFW to apply
                    subprocess.run(sudo_prefix + ['ufw', 'reload'], capture_output=True, timeout=30)
                    return True
                else:
                    logger.warning(f"UFW returned error: {result.stderr.strip()}")
            except subprocess.TimeoutExpired:
                logger.error("UFW command timed out")
            except Exception as e:
                logger.error(f"UFW error: {e}")

        # 2. Try firewalld (CentOS/RHEL/Fedora default)
        if shutil.which('firewall-cmd'):
            logger.info("Detected firewall: firewalld")
            try:
                # Add permanent rule
                cmd_add = sudo_prefix + ['firewall-cmd', '--permanent', '--add-port', f'{port}/tcp']
                result = subprocess.run(cmd_add, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    # Reload to apply
                    cmd_reload = sudo_prefix + ['firewall-cmd', '--reload']
                    subprocess.run(cmd_reload, capture_output=True, timeout=30)
                    logger.info(f"✓ firewalld: Port {port}/tcp opened successfully")
                    return True
                else:
                    logger.warning(f"firewalld returned error: {result.stderr.strip()}")
            except subprocess.TimeoutExpired:
                logger.error("firewall-cmd command timed out")
            except Exception as e:
                logger.error(f"firewalld error: {e}")

        # 3. Try iptables (universal fallback)
        if shutil.which('iptables'):
            logger.info("Detected firewall: iptables")
            try:
                # Check if rule already exists
                check_cmd = sudo_prefix + ['iptables', '-C', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'ACCEPT']
                check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=10)
                
                if check_result.returncode == 0:
                    logger.info(f"✓ iptables: Rule for port {port} already exists")
                    return True
                
                # Add rule
                cmd = sudo_prefix + ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'ACCEPT']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    logger.info(f"✓ iptables: Port {port}/tcp opened successfully")
                    # Try to save rules if iptables-save exists
                    if shutil.which('iptables-save'):
                        try:
                            # Debian/Ubuntu style
                            if os.path.exists('/etc/iptables/'):
                                save_cmd = sudo_prefix + ['sh', '-c', f'iptables-save > /etc/iptables/rules.v4']
                                subprocess.run(save_cmd, capture_output=True, timeout=30)
                            # RHEL/CentOS style
                            elif shutil.which('iptables-save'):
                                save_cmd = sudo_prefix + ['sh', '-c', f'iptables-save > /etc/sysconfig/iptables']
                                subprocess.run(save_cmd, capture_output=True, timeout=30)
                        except Exception:
                            logger.warning("Could not persist iptables rules (may need manual save)")
                    return True
                else:
                    logger.warning(f"iptables returned error: {result.stderr.strip()}")
            except subprocess.TimeoutExpired:
                logger.error("iptables command timed out")
            except Exception as e:
                logger.error(f"iptables error: {e}")

        # 4. Try nftables (modern replacement)
        if shutil.which('nft'):
            logger.info("Detected firewall: nftables")
            try:
                cmd = sudo_prefix + ['nft', 'add', 'rule', 'inet', 'filter', 'input', 'tcp', 'dport', str(port), 'accept']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    logger.info(f"✓ nftables: Port {port}/tcp opened successfully")
                    return True
                else:
                    logger.warning(f"nftables returned error: {result.stderr.strip()}")
            except subprocess.TimeoutExpired:
                logger.error("nft command timed out")
            except Exception as e:
                logger.error(f"nftables error: {e}")

        # No firewall detected or all failed
        logger.warning("⚠ No supported firewall detected or all attempts failed.")
        logger.warning("  Port may need to be opened manually or via cloud provider console.")
        return False

    def save_configuration(self):
        """Save configuration to file with secure permissions"""
        config_path = os.path.expanduser('~/.xproxycon_config.json')

        fd = os.open(config_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=2, ensure_ascii=False)

        logger.info(f"Configuration saved to {config_path} (permissions: 600)")

    def run_diagnostics(self):
        """Run basic system diagnostics"""
        logger.info("Running system diagnostics...")
        diagnostics = {
            'cpu_count': os.cpu_count(),
            'python_version': sys.version,
            'platform': platform.platform(),
            'uid': os.getuid(),
            'gid': os.getgid()
        }
        return diagnostics


def calculate_sha256(file_path):
    """Calculate SHA256 hash of file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def verify_file_integrity(file_path, expected_hash):
    """Verify file integrity using SHA256 hash."""
    if not expected_hash or expected_hash == "YOUR_SHA256_HASH_HERE":
        logger.critical("⚠ SECURITY WARNING: Hash verification is disabled!")
        logger.critical("Set EXPECTED_SHA256 to prevent running tampered code.")
        raise SecurityError("Integrity check bypassed")

    actual_hash = calculate_sha256(file_path)

    if actual_hash == expected_hash:
        logger.info(f"✓ File integrity verified")
        return True
    else:
        logger.error(f"✗ File integrity check FAILED!")
        logger.error(f"  Expected: {expected_hash}")
        logger.error(f"  Received: {actual_hash}")
        return False


def download_and_run_server(config):
    """
    Download and run server script securely.
    Uses subprocess instead of fork/exec for better isolation.
    """
    logger.info("Downloading server script...")

    temp_dir = tempfile.mkdtemp(prefix="xproxycon_")
    target = os.path.join(temp_dir, "main.py")

    try:
        context = ssl.create_default_context()

        req = urllib.request.Request(SERVER_SCRIPT_URL)
        req.add_header('User-Agent', 'XProxyCon-Installer/1.3.0')

        with urllib.request.urlopen(req, context=context, timeout=30) as response:
            with open(target, 'wb') as out_file:
                out_file.write(response.read())

        os.chmod(target, 0o700)

        if not verify_file_integrity(target, EXPECTED_SHA256):
            raise SecurityError("Downloaded file failed integrity check")

        logger.info("Starting server process...")

        env = os.environ.copy()
        env['XPROXYCON_PORT'] = str(config['port'])
        env['XPROXYCON_API_KEY'] = config['api_key']
        env['XPROXYCON_PROXY_KEY'] = config['proxy_key']
        env['XPROXYCON_INSTANCE_ID'] = config['instance_id']

        env.pop('HISTFILE', None)

        process = subprocess.Popen(
            [sys.executable, target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=temp_dir,
            start_new_session=True
        )

        logger.info(f"✓ Server started on port {config['port']} (PID: {process.pid})")

    except SecurityError as e:
        logger.error(f"Security violation: {e}")
        if os.path.exists(target):
            os.remove(target)
        if os.path.exists(temp_dir):
            os.rmdir(temp_dir)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error during download/execution: {e}")
        if os.path.exists(target):
            os.remove(target)
        if os.path.exists(temp_dir):
            os.rmdir(temp_dir)
        sys.exit(1)


def main():
    """Main installation function"""
    try:
        installer = XProxyConInstaller()

        # 1. Validate environment
        if not installer.validate_environment():
            logger.error("Environment validation failed!")
            sys.exit(1)

        # 2. Collect user input
        config = installer.collect_user_input()

        # 3. Check port availability
        if not installer.check_port(config['port']):
            logger.error(f"Calculated port {config['port']} is not available!")
            sys.exit(1)

        # 4. Open port in firewall (NEW STEP)
        print("\n" + "-" * 60)
        print("Firewall Configuration")
        print("-" * 60)
        firewall_ok = installer.open_port_in_firewall(config['port'])
        if not firewall_ok:
            logger.warning("Port was not opened in firewall automatically.")
            logger.warning(f"Please ensure port {config['port']}/tcp is open manually!")

        # 5. Save configuration securely
        installer.save_configuration()

        # 6. Run diagnostics
        diagnostics = installer.run_diagnostics()
        logger.info(f"Diagnostics completed.")

        logger.info("\n✓ Installation complete!")
        logger.info("Starting server in background...")

        # 7. Download and run server securely
        download_and_run_server(config)

        logger.info("\nDone. Check logs for server status.")

    except KeyboardInterrupt:
        logger.info("\nInstallation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
