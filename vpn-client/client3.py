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

# Function to check if interface is up
def is_interface_up(interface_name):
    try:
        run_command(f"sudo wg show {interface_name}")
        return True  # Interface exists and is up
    except subprocess.CalledProcessError:
        return False  # Interface does not exist or is not up

# Function to run shell commands
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

# Function to install dependencies
def install_dependencies():
    logging.info("Installing dependencies...")
    apt_packages = ["wireguard", "tinyproxy", "python3-pip"]
    pip_packages = ["requests"]

    for package in apt_packages:
        run_command(f"sudo apt-get install -y {package}")

    for package in pip_packages:
        try:
            run_command(f"sudo pip3 install {package}")
        except subprocess.CalledProcessError:
            run_command(f"sudo pip3 install {package} --ignore-installed")

# Function to register and get token using tinyproxy
def register_and_get_token(api_url, proxies):
    logging.debug(f"Sending registration request to {api_url}/register via tinyproxy")
    response = requests.post(f"{api_url}/register", json={"geo_location": "RemoteLocation", "internet_speed": "100Mbps"}, proxies=proxies)
    logging.debug(f"Request headers: {response.request.headers}")
    logging.debug(f"Request body: {response.request.body}")
    logging.debug(f"Response status code: {response.status_code}")
    logging.debug(f"Response headers: {response.headers}")
    logging.debug(f"Response text: {response.text}")
    response.raise_for_status()
    client_info = response.json()
    logging.info(f"Registered with client ID: {client_info['client_id']}")
    return client_info

# Function to start VPN
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

# Function to get WireGuard configuration
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
    config_path = f"/etc/wireguard/wg_{sanitized_client_id[:8]}.conf"
    with open(config_path, "w") as config_file:
        config_file.write(config_data)
    logging.info(f"WireGuard config written for client ID: {client_id}")

# Function to sanitize UUID
def sanitize_uuid(client_id: str) -> str:
    return client_id.replace("-", "")

# Function to bring up VPN
def bring_up_vpn(client_id):
    sanitized_client_id = sanitize_uuid(client_id)
    interface_name = f"wg_{sanitized_client_id[:8]}"
    logging.debug(f"Bringing up VPN interface {interface_name}")

    try:
        if is_interface_up(interface_name):
            logging.info(f"VPN interface {interface_name} is already up")
        else:
            run_command(f"sudo wg-quick up {interface_name}")
            logging.info(f"VPN interface {interface_name} brought up successfully")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error bringing up VPN interface {interface_name}: {e}")
        raise

# Function to get VPN IP address
def get_vpn_ip():
    result = subprocess.run("ip -4 addr | grep -oP '(?<=inet\s)\d+(\.\d+){3}/24(?=.*wg)'", shell=True, capture_output=True, text=True)
    vpn_ip = result.stdout.strip().split('/')[0]
    logging.info(f"VPN IP address: {vpn_ip}")
    return vpn_ip

# Function to configure TinyProxy
def configure_tinyproxy(vpn_ip):
    try:
        run_command("sudo systemctl stop tinyproxy")
        with open("/etc/tinyproxy/tinyproxy.conf", "w") as config_file:
            config_file.write(f"""
User tinyproxy
Group tinyproxy
Port 8889
Listen {vpn_ip}
DefaultErrorFile "/usr/share/tinyproxy/default.html"
StatFile "/usr/share/tinyproxy/stats.html"
LogFile "/var/log/tinyproxy/tinyproxy.log"
LogLevel Info
PidFile "/run/tinyproxy/tinyproxy.pid"
Upstream {API_URL}
MaxClients 100
Allow 127.0.0.1
Allow ::1
ViaProxyName "tinyproxy"
ConnectPort 443
ConnectPort 563
""")
        run_command("sudo systemctl start tinyproxy")
        logging.info(f"TinyProxy configured to listen on VPN IP: {vpn_ip}")
    except Exception as e:
        logging.error(f"Failed to configure TinyProxy: {e}")
        raise

# HTTP request handler for proxy server
class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Proxy server is running')

# Function to run proxy server
def run_proxy_server(server_class=HTTPServer, handler_class=ProxyHTTPRequestHandler, vpn_ip='10.0.0.1', port=9888):
    server_address = (vpn_ip, port)
    httpd = server_class(server_address, handler_class)
    logging.info(f"Starting proxy server on {vpn_ip}:{port}")
    httpd.serve_forever()

# Main function
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

        logging.info("Registering with API via TinyProxy...")
        proxies = {
            'http': f'http://localhost:8889',  # Adjust based on your tinyproxy configuration
            'https': f'http://localhost:8889',
        }
        client_info = register_and_get_token(api_url, proxies)
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

    except Exception as e:
        logging.error(f"Failed to set up VPN client: {e}")

if __name__ == '__main__':
    main()
