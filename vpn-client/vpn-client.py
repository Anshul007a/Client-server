import os
import logging
import subprocess
import requests
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv("API_URL", "http://0.0.0.0:8001")
LOG_DIR = './logs'
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, 'installer.log'),
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

def is_interface_up(interface_name):
    try:
        # Commented out for macOS: run_command(f"sudo wg show {interface_name}")
        return True  # Interface exists and is up
    except subprocess.CalledProcessError:
        return False  # Interface does not exist or is not up

def run_command(command):
    logging.info(f"Running command: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    stdout_str = stdout.decode().strip()
    stderr_str = stderr.decode().strip()

    if stdout_str:
        logging.info(stdout_str)
    if stderr_str:
        logging.error(stderr_str)

    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, command)

def install_dependencies():
    logging.info("Installing dependencies...")

    # Commented out for macOS: apt_packages = ["wireguard", "tinyproxy", "python3-pip"]
    brew_packages = ["wireguard-tools", "tinyproxy", "python@3.9"]

    for package in brew_packages:
        run_command(f"brew install {package}")

    pip_packages = ["requests"]

    for package in pip_packages:
        try:
            run_command(f"pip3 install {package}")
        except subprocess.CalledProcessError:
            run_command(f"pip3 install {package} --ignore-installed")

def register_and_get_token(api_url):
    logging.debug(f"Sending registration request to {api_url}/register")
    response = requests.post(f"{api_url}/register", json={"geo_location": "RemoteLocation", "internet_speed": "100Mbps"})
    logging.debug(f"Request headers: {response.request.headers}")
    logging.debug(f"Request body: {response.request.body}")
    logging.debug(f"Response status code: {response.status_code}")
    logging.debug(f"Response headers: {response.headers}")
    logging.debug(f"Response text: {response.text}")
    response.raise_for_status()
    client_info = response.json()
    logging.info(f"Registered with client ID: {client_info['client_id']}")
    return client_info

def start_vpn(api_url, client_id):
    logging.debug(f"Starting VPN for client ID {client_id}")
    response = requests.post(f"{api_url}/start_vpn/{client_id}")
    logging.debug(f"Request headers: {response.request.headers}")
    logging.debug(f"Request body: {response.request.body}")
    logging.debug(f"Response status code: {response.status_code}")
    logging.debug(f"Response headers: {response.headers}")
    logging.debug(f"Response text: {response.text}")
    response.raise_for_status()
    logging.info(f"VPN started for client ID: {client_id}")

def get_wireguard_config(api_url, client_id):
    logging.debug(f"Fetching WireGuard config for client ID {client_id}")
    response = requests.get(f"{api_url}/wireguard_config/{client_id}")
    logging.debug(f"Request headers: {response.request.headers}")
    logging.debug(f"Response status code: {response.status_code}")
    logging.debug(f"Response headers: {response.headers}")
    logging.debug(f"Response text: {response.text}")
    response.raise_for_status()
    config_data = response.text.strip()
    sanitized_client_id = sanitize_uuid(client_id)
    # Commented out for macOS: config_path = f"/etc/wireguard/wg_{sanitized_client_id[:8]}.conf"
    config_path = os.path.expanduser(f"~/wg_{sanitized_client_id[:8]}.conf")
    with open(config_path, "w") as config_file:
        config_file.write(config_data)
    logging.info(f"WireGuard config written for client ID: {client_id}")

def sanitize_uuid(client_id: str) -> str:
    return client_id.replace("-", "")

def bring_up_vpn(client_id):
    sanitized_client_id = sanitize_uuid(client_id)
    interface_name = f"wg_{sanitized_client_id[:8]}"
    logging.debug(f"Bringing up VPN interface {interface_name}")

    try:
        # Check if the interface already exists
        if is_interface_up(interface_name):
            logging.info(f"VPN interface {interface_name} is already up")
        else:
            # macOS alternative: Load the configuration directly
            run_command(f"sudo wg setconf {interface_name} {os.path.expanduser(f'~/wg_{sanitized_client_id[:8]}.conf')}")
            run_command(f"sudo ifconfig {interface_name} up")
            logging.info(f"VPN interface {interface_name} brought up successfully")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error bringing up VPN interface {interface_name}: {e}")
        raise  # Re-raise the exception for higher-level handling

def get_vpn_ip():
    # macOS command to get IP address
    result = subprocess.run("ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -n 1", shell=True, capture_output=True, text=True)
    vpn_ip = result.stdout.strip()
    logging.info(f"VPN IP address: {vpn_ip}")
    return vpn_ip

def configure_tinyproxy(vpn_ip):
    try:
        run_command("sudo brew services stop tinyproxy")
        with open("/opt/homebrew/etc/tinyproxy.conf", "w") as config_file:
            config_file.write(f"""
User tinyproxy
Group tinyproxy
Port 8889
Listen {vpn_ip}
DefaultErrorFile "/usr/local/share/tinyproxy/default.html"
StatFile "/usr/local/share/tinyproxy/stats.html"
LogFile "/usr/local/var/log/tinyproxy/tinyproxy.log"
LogLevel Info
PidFile "/usr/local/var/run/tinyproxy/tinyproxy.pid"
Upstream http 0.0.0.0:8001
MaxClients 100
Allow 127.0.0.1
Allow ::1
ViaProxyName "tinyproxy"
ConnectPort 443
ConnectPort 563
""")
        run_command("sudo brew services start tinyproxy")
        logging.info(f"TinyProxy configured to listen on VPN IP: {vpn_ip}")
    except Exception as e:
        logging.error(f"Failed to configure TinyProxy: {e}")
        raise

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Proxy server is running')

def run_proxy_server(server_class=HTTPServer, handler_class=ProxyHTTPRequestHandler, vpn_ip='10.0.0.1', port=9888):
    server_address = (vpn_ip, port)
    httpd = server_class(server_address, handler_class)
    logging.info(f"Starting proxy server on {vpn_ip}:{port}")
    httpd.serve_forever()

def main():
    api_url = API_URL

    try:
        logging.info("Starting installation of dependencies...")
        install_dependencies()
        logging.info("Dependencies installed.")
        
        logging.info("Retrieving VPN IP address...")
        vpn_ip = get_vpn_ip()
        if not vpn_ip:
            raise RuntimeError("Failed to retrieve VPN IP address.")
        logging.info(f"VPN IP address retrieved: {vpn_ip}")

        logging.info("Configuring TinyProxy...")
        configure_tinyproxy(vpn_ip)
        logging.info("TinyProxy configured.")

        logging.info("Starting proxy server...")
        proxy_thread = threading.Thread(target=run_proxy_server, kwargs={'vpn_ip': vpn_ip})
        proxy_thread.start()
        logging.info("Proxy server started.")
        
        logging.info("Registering with API...")
        client_info = register_and_get_token(api_url)
        logging.info("Registered with API.")
        
        logging.info("Starting VPN...")
        start_vpn(api_url, client_info['client_id'])
        logging.info("VPN started.")
        
        logging.info("Fetching WireGuard config...")
        get_wireguard_config(api_url, client_info['client_id'])
        logging.info("WireGuard config fetched.")
        
        logging.info("Bringing up VPN...")
        bring_up_vpn(client_info['client_id'])
        logging.info("VPN brought up.")
        
        time.sleep(10)  # Wait for VPN to be fully up and IP address to be assigned

        # Continue with your application logic here
        
    except Exception as e:
        logging.error(f"Failed to set up VPN client: {e}")

if __name__ == '__main__':
    main()
