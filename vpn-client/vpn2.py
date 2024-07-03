import os
import logging
import subprocess
import requests
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv("API_URL", "http://192.168.12.102:8001")
LOG_DIR = './logs'
TINYPROXY_CONF = '/etc/tinyproxy/tinyproxy.conf'
WIREGUARD_CONF_DIR = '/etc/wireguard'

os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(LOG_DIR, 'installer.log'),
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

def run_command(command):
    logging.info(f"Running command: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    logging.info(stdout.decode())
    if stderr:
        logging.error(stderr.decode())
    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, command)

def stop_services():
    logging.info("Stopping TinyProxy and VPN services...")
    try:
        run_command("sudo systemctl stop tinyproxy")
        run_command("sudo wg-quick down wg0")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error stopping services: {e}")

def delete_old_configs():
    logging.info("Deleting old TinyProxy and WireGuard configurations...")
    if os.path.exists(TINYPROXY_CONF):
        os.remove(TINYPROXY_CONF)
    for file in os.listdir(WIREGUARD_CONF_DIR):
        if file.endswith(".conf"):
            os.remove(os.path.join(WIREGUARD_CONF_DIR, file))

def remove_old_wireguard_adapters():
    logging.info("Removing old WireGuard adapters...")
    try:
        wg_interfaces = subprocess.check_output("sudo wg show interfaces", shell=True).decode().strip().split('\n')
        for wg_interface in wg_interfaces:
            if wg_interface:
                run_command(f"sudo wg-quick down {wg_interface}")
                run_command(f"sudo ip link delete {wg_interface}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error removing WireGuard adapters: {e}")

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
            run_command(f"sudo pip3 install {package} --break-system-packages")

def register_and_get_token(api_url):
    logging.debug(f"Sending registration request to {api_url}/register")
    response = requests.post(f"{api_url}/register", json={"geo_location": "RemoteLocation", "internet_speed": "100Mbps"})
    response.raise_for_status()
    client_info = response.json()
    logging.info(f"Registered with client ID: {client_info['client_id']}")
    return client_info

def start_vpn(api_url, client_id):
    logging.debug(f"Starting VPN for client ID {client_id}")
    response = requests.post(f"{api_url}/start_vpn/{client_id}")
    response.raise_for_status()
    logging.info(f"VPN started for client ID: {client_id}")

def get_wireguard_config(api_url, client_id):
    logging.debug(f"Fetching WireGuard config for client ID {client_id}")
    response = requests.get(f"{api_url}/wireguard_config/{client_id}")
    response.raise_for_status()
    config_data = response.text.strip()
    config_path = os.path.join(WIREGUARD_CONF_DIR, "wg0.conf")
    with open(config_path, "w") as config_file:
        config_file.write(config_data)
    logging.info(f"WireGuard config written for client ID: {client_id}")

def bring_up_vpn():
    logging.debug("Bringing up VPN interface wg0")
    run_command("sudo wg-quick up wg0")
    logging.info("VPN brought up")

def get_vpn_ip():
    result = subprocess.run("ip -4 addr show wg0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'", shell=True, capture_output=True, text=True)
    vpn_ip = result.stdout.strip()
    logging.info(f"VPN IP address: {vpn_ip}")
    if not vpn_ip:
        raise RuntimeError("Failed to retrieve VPN IP address.")
    return vpn_ip

def create_tinyproxy_config(vpn_ip):
    logging.info("Creating TinyProxy configuration...")
    config_content = f"""
User tinyproxy
Group tinyproxy
Port 8888
Listen {vpn_ip}
Timeout 600
Logfile /var/log/tinyproxy/tinyproxy.log
ErrorLogfile /var/log/tinyproxy/tinyproxy_errors.log
PidFile "/var/run/tinyproxy/tinyproxy.pid"
DefaultErrorFile "/usr/share/tinyproxy/default.html"
MaxClients 100
MinSpareServers 5
MaxSpareServers 20
StartServers 10
MaxRequestsPerChild 0
Allow 10.0.0.0/24
ConnectPort 443
"""
    with open(TINYPROXY_CONF, "w") as config_file:
        config_file.write(config_content)
    logging.info("TinyProxy configuration created.")

def start_tinyproxy():
    logging.info("Starting TinyProxy...")
    run_command("sudo systemctl start tinyproxy")
    logging.info("TinyProxy started.")

def configure_nat_rules(vpn_ip):
    run_command(f"sudo iptables -t nat -A POSTROUTING -s {vpn_ip}/24 -o eth0 -j MASQUERADE")
    logging.info(f"NAT rules configured for VPN IP: {vpn_ip}")

def setup_iptables(vpn_ip):
    try:
        run_command(f"sudo iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT")
        run_command(f"sudo iptables -A FORWARD -i eth0 -o wg0 -j ACCEPT")
        run_command(f"sudo iptables -A INPUT -i wg0 -j ACCEPT")
        run_command(f"sudo iptables -A INPUT -p tcp --dport 8888 -j ACCEPT")
        logging.info(f"iptables rules set up for VPN IP: {vpn_ip}")
    except Exception as e:
        logging.error(f"Failed to set up iptables: {e}")
        raise

def main():
    api_url = API_URL

    try:
        logging.info("Starting installation of dependencies...")
        install_dependencies()
        logging.info("Dependencies installed.")

        logging.info("Stopping services and deleting old configurations...")
        stop_services()
        delete_old_configs()

        logging.info("Removing old WireGuard adapters...")
        remove_old_wireguard_adapters()

        logging.info("Registering with API...")
        client_info = register_and_get_token(api_url)
        logging.info("Registered with API.")

        logging.info("Fetching WireGuard config...")
        get_wireguard_config(api_url, client_info['client_id'])
        logging.info("WireGuard config fetched.")

        logging.info("Bringing up VPN...")
        bring_up_vpn()
        logging.info("VPN brought up.")

        time.sleep(10)  # Wait for VPN to be fully up and IP address to be assigned
        logging.info("Retrieving VPN IP address...")
        vpn_ip = get_vpn_ip()
        logging.info(f"VPN IP address retrieved: {vpn_ip}")

        logging.info("Configuring NAT rules...")
        configure_nat_rules(vpn_ip)
        logging.info("NAT rules configured.")

        logging.info("Setting up iptables rules...")
        setup_iptables(vpn_ip)
        logging.info("iptables rules set up.")

        logging.info("Creating and starting TinyProxy configuration...")
        create_tinyproxy_config(vpn_ip)
        start_tinyproxy()
        logging.info("TinyProxy configured and started.")

    except Exception as e:
        logging.error(f"Failed to set up VPN client: {e}")

if __name__ == '__main__':
    main()

