import os
import docker
import logging
import shlex
import uuid
from fastapi import FastAPI, Request, HTTPException,BackgroundTasks
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
from typing import List
import pymongo
import subprocess
import threading
import requests
import time
from dotenv import load_dotenv
import os
import docker
from subprocess import CalledProcessError
from typing import Optional

load_dotenv()
# Initialize Docker client
client = docker.from_env()
# Example usage: List containers
containers = client.containers.list()
for container in containers:
    print("-->>",container.name)

# Configuration from .env file
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8001))
LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG")
LOG_DIR = os.getenv("LOG_DIR", "./logs")
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "wireguard_db")
SERVER_PRIVATE_KEY = os.getenv("PRIVATE_KEY")
SERVER_PUBLIC_KEY = os.getenv("PUBLIC_KEY")
WIREGUARD_PORT = os.getenv("WIREGUARD_PORT", 51820)
SERVER_IP = os.getenv("SERVER_IP")
DOCKER_IMAGE = os.getenv("DOCKER_IMAGE")

# Create logs directory if not exists
os.makedirs(LOG_DIR, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "api.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI()

client = pymongo.MongoClient(MONGO_URI)
db = client[MONGO_DB]
clients_collection = db["clients"]
proxies_collection = db["proxies"]

class ClientRegistration(BaseModel):
    geo_location: str
    internet_speed: str

class ClientInfo(BaseModel):
    client_id: str
    ip_address: str
    geo_location: str
    internet_speed: str
    proxy_port: int
    wireguard_token: str

class Proxy(BaseModel):
    ip_address: str
    proxy: str
    proxy_type: str = "all"

class ProxyUpdate(BaseModel):
    status: str

class ProxyList(BaseModel):
    proxies: List[Proxy]

def generate_wireguard_keys():
    private_key = subprocess.check_output("wg genkey", shell=True).strip().decode('utf-8')
    public_key = subprocess.check_output(f"echo {private_key} | wg pubkey", shell=True).strip().decode('utf-8')
    logger.debug(f"Generated WireGuard keys: {private_key}, {public_key}")
    return private_key, public_key

def sanitize_uuid(client_id: str) -> str:
    return client_id.replace("-", "")

def generate_wireguard_config(client_id: str, private_key: str):
    server_public_key = SERVER_PUBLIC_KEY
    allowed_ips = "0.0.0.0/0"
    endpoint = f"{SERVER_IP}:{WIREGUARD_PORT}"
    
    # Sanitize the UUID for a valid interface name
    sanitized_client_id = sanitize_uuid(client_id)
    interface_name = f"wg_{sanitized_client_id[:8]}"
    
    # Generate a valid client IP address (assuming a /24 subnet for simplicity)
    client_ip_suffix = int(sanitized_client_id[:8], 16) % 254 + 1
    client_ip_address = f"10.0.0.{client_ip_suffix}"

    config = f"""
[Interface]
PrivateKey = {private_key}
Address = {client_ip_address}/24

[Peer]
PublicKey = {server_public_key}
AllowedIPs = {allowed_ips}
Endpoint = {endpoint}
PersistentKeepalive = 25
"""
    config_path = f"/opt/homebrew/etc/wireguard/{interface_name}.conf"

    with open(config_path, 'w') as file:
        file.write(config.strip())
    os.chmod(config_path, 0o600)
    logger.info("im in generate_wireguard_config")
    logger.debug(f"Generated WireGuard config for client {client_id} at {config_path}")
    return config_path, interface_name, client_ip_address



def route_exists(route):
    try:
        subprocess.check_call(shlex.split(f"netstat -rn | grep {route}"))
        return True
    except subprocess.CalledProcessError:
        return False

def configure_routing():
    try:
        # Check and delete any conflicting routes if they exist
        if route_exists("10.0.0.0/24"):
            try:
                subprocess.check_call(shlex.split("route delete -net 10.0.0.0/24"))
                logger.info("Deleted route 10.0.0.0/24")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Route 10.0.0.0/24 cannot be deleted: {e}")
        else:
            logger.info("Route 10.0.0.0/24 does not exist")

        if route_exists("192.168.12.0/24"):
            try:
                subprocess.check_call(shlex.split("route delete -net 192.168.12.0/24"))
                logger.info("Deleted route 192.168.12.0/24")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Route 192.168.12.0/24 cannot be deleted: {e}")
        else:
            logger.info("Route 192.168.12.0/24 does not exist")

        # Add correct routes
        subprocess.check_call(shlex.split("route add -net 10.0.0.0/24 -interface wg0"))
        logger.info("Added route 10.0.0.0/24 via wg0")

        subprocess.check_call(shlex.split("route add -net 192.168.12.0/24 -interface en0"))
        logger.info("Added route 192.168.12.0/24 via en0")

        logger.info("Routing configured successfully")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to configure routing: {e}")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Incoming request: {request.method} {request.url}")
    response = await call_next(request)
    logger.info(f"Response status: {response.status_code}")
    return response

@app.exception_handler(Exception)
async def validation_exception_handler(request: Request, exc: Exception):
    logger.error(f"Server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"message": "Internal server error"},
    )

@app.post("/register", response_model=ClientInfo)
async def register_client(request: Request, client: ClientRegistration):
    client_ip = request.client.host
    logger.info(f"Client IP: {client_ip}")
    client_id = str(uuid.uuid4())
    private_key, public_key = generate_wireguard_keys()
    config_path, interface_name, client_ip_address = generate_wireguard_config(client_id, private_key)
    proxy_port = 8080  # Placeholder for proxy port
    wireguard_token = private_key  # Assuming the token is the private key

    new_client = {
        "client_id": client_id,
        "ip_address": client_ip,
        "geo_location": client.geo_location,
        "internet_speed": client.internet_speed,
        "proxy_port": proxy_port,
        "last_connected": "",
        "wireguard_config": config_path,
        "private_key": private_key,
        "public_key": public_key,
        "wireguard_token": wireguard_token
    }
    clients_collection.insert_one(new_client)

    logger.info(f"Registered new client: {client_id} with IP: {client_ip}")

    return {
        "client_id": client_id,
        "ip_address": client_ip,
        "geo_location": client.geo_location,
        "internet_speed": client.internet_speed,
        "proxy_port": proxy_port,
        "wireguard_token": wireguard_token
    }

@app.get("/client/{client_id}", response_model=ClientInfo)
def get_client_info(client_id: str):
    client = clients_collection.find_one({"client_id": client_id})
    if not client:
        logger.error(f"Client not found: {client_id}")
        raise HTTPException(status_code=404, detail="Client not found")
    if not client.get("wireguard_token"):
        client["wireguard_token"] = client["private_key"]
    return client

@app.put("/client/{client_id}")
def update_client_info(client_id: str, client_info: ClientInfo):
    update_result = clients_collection.update_one(
        {"client_id": client_id},
        {"$set": client_info.dict()}
    )
    if update_result.matched_count == 0:
        logger.error(f"Client not found: {client_id}")
        raise HTTPException(status_code=404, detail="Client not found")
    logger.info(f"Updated client information: {client_id}")
    return {"message": "Client information updated successfully"}

@app.get("/clients", response_model=List[ClientInfo])
def list_clients():
    clients = list(clients_collection.find({}, {"_id": 0}))
    for client in clients:
        if not client.get("wireguard_token"):
            client["wireguard_token"] = client["private_key"]
    return clients



def check_and_pull_docker_image(image_name):
    try:
        print("pulling the docker image")
        # Check if Docker image exists locally
        subprocess.run(["docker", "inspect", image_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        # If Docker image does not exist, pull it
        print(f"Docker image '{image_name}' not found. Pulling...")
        try:
            subprocess.run(["docker", "pull", image_name], check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to pull Docker image '{image_name}': {e}")

# @app.post("/start_vpn/{client_id}")
# def start_vpn(client_id: str, background_tasks: BackgroundTasks):
#     client = clients_collection.find_one({"client_id": client_id})
    
#     if not client:
#         raise HTTPException(status_code=404, detail=f"Client not found: {client_id}")

#     config_path = client.get("wireguard_config")
#     if not config_path or not os.path.exists(config_path):
#         logger.info(f"WireGuard config file not found for {client_id}. Creating new config.")
#         config_path, interface_name, client_ip_address = generate_wireguard_config(client_id, client["private_key"])
#         # Update client data (simulated with list in memory)
#         client["wireguard_config"] = config_path

#     check_and_pull_docker_image(DOCKER_IMAGE)
#     # Extract substring
#     docker_container_name = config_path.split('/')[-1].split('.')[0]

#     try:
#         # Docker command to run WireGuard
#         docker_command = [
#             "docker", "run", "-d",
#             "--name", docker_container_name,
#             "--cap-add=NET_ADMIN",
#             "--cap-add=SYS_MODULE",
#             "-e", "PUID=1000",
#             "-e", "PGID=1000",
#             "-e", "TZ=Etc/UTC",
#             "-e", f"SERVERURL={SERVER_IP}",
#             "-e", f"SERVERPORT={WIREGUARD_PORT}",
#             "-e", "PEERS=1",
#             "-e", "PEERDNS=auto",
#             "-e", "INTERNAL_SUBNET=10.13.13.0",
#             "-p", f"{WIREGUARD_PORT}:{WIREGUARD_PORT}/udp",
#             "-v", f"{config_path}:/config/wg0.conf",
#             "--sysctl=net.ipv4.conf.all.src_valid_mark=1",
#             "--sysctl=net.ipv4.ip_forward=1",
#             "lscr.io/linuxserver/wireguard:latest"
#         ]
#         subprocess.run(docker_command, check=True)
#     except subprocess.CalledProcessError as e:
#         logger.error(f"Failed to start VPN: {e}")
#         raise HTTPException(status_code=500, detail=f"Error running Docker command: {e}")
    
#     return {"status": "WireGuard container started successfully"}
@app.post("/start_vpn/{client_id}")
def start_vpn(client_id: str, background_tasks: BackgroundTasks):
    client = clients_collection.find_one({"client_id": client_id})
    
    if not client:
        raise HTTPException(status_code=404, detail=f"Client not found: {client_id}")

    config_path = client.get("wireguard_config")
    if not config_path or not os.path.exists(config_path):
        logger.info(f"WireGuard config file not found for {client_id}. Creating new config.")
        config_path, interface_name, client_ip_address = generate_wireguard_config(client_id, client["private_key"])
        # Update client data (simulated with list in memory)
        client["wireguard_config"] = config_path

    check_and_pull_docker_image(DOCKER_IMAGE)
    # Extract container name from config_path
    docker_container_name = config_path.split('/')[-1].split('.')[0]

    try:
        # Define Docker run options using docker-py
        volumes = {config_path: {'bind': '/config/wg0.conf', 'mode': 'rw'}}
        environment = {
            'PUID': '1000',
            'PGID': '1000',
            'TZ': 'Etc/UTC',
            'SERVERURL': SERVER_IP,
            'SERVERPORT': WIREGUARD_PORT,
            'PEERS': '1',
            'PEERDNS': 'auto',
            'INTERNAL_SUBNET': '10.13.13.0'
        }
        ports = {f'{WIREGUARD_PORT}/udp': WIREGUARD_PORT}
        sysctls = {
            'net.ipv4.conf.all.src_valid_mark': '1',
            'net.ipv4.ip_forward': '1'
        }
        print("--->>>",client.containers.list())
        container = client.containers.run(
            DOCKER_IMAGE,
            detach=True,
            name=docker_container_name,
            cap_add=['NET_ADMIN', 'SYS_MODULE'],
            environment=environment,
            ports=ports,
            volumes=volumes,
            sysctls=sysctls
        )
        # Optionally, you can handle additional tasks after starting the container
        # Example: background_tasks.add_task(stop_vpn_container, docker_container_name)

    except CalledProcessError as e:
        logger.error(f"Failed to start VPN: {e}")
        raise HTTPException(status_code=500, detail=f"Error running Docker command: {e}")
    
    return {"status": "WireGuard container started successfully"}




@app.post("/stop_vpn/{client_id}")
async def stop_wireguard(client_id: str):
    client = clients_collection.find_one({"client_id": client_id})
    if not client:
        logger.error(f"Client not found: {client_id}")
        raise HTTPException(status_code=404, detail="Client not found")

    interface_name = f"wg_{sanitize_uuid(client_id)[:8]}"
    # Docker command to stop the container
    stop_command = [
        "docker", "stop", interface_name
    ]

    # Docker command to remove the container
    remove_command = [
        "docker", "rm", interface_name
    ]

    # Run the Docker commands
    try:
        subprocess.run(stop_command, check=True)
        subprocess.run(remove_command, check=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Error stopping or removing Docker container: {e}")

    return {"status": "WireGuard container stopped and removed successfully"}

@app.get("/wireguard_config/{client_id}")
def get_wireguard_config(client_id: str):
    client = clients_collection.find_one({"client_id": client_id})
    if not client:
        logger.error(f"Client not found: {client_id}")
        raise HTTPException(status_code=404, detail="Client not found")

    config_path = client.get("wireguard_config")
    if not config_path or not os.path.exists(config_path):
        logger.error(f"WireGuard config file not found for {client_id}")
        raise HTTPException(status_code=404, detail="WireGuard config file not found")

    return FileResponse(config_path, media_type="application/octet-stream", filename=f"wg_{sanitize_uuid(client_id)[:8]}.conf")

@app.post("/proxy", response_model=dict)
def add_proxy(proxy: Proxy):
    new_proxy = {
        "ip_address": proxy.ip_address,
        "proxy": proxy.proxy,
        "proxy_type": proxy.proxy_type,
        "status": "unknown"
    }
    proxies_collection.insert_one(new_proxy)
    logger.info(f"Added new proxy: {proxy.ip_address}")
    return {"message": "Proxy added successfully"}

@app.post("/proxies", response_model=dict)
def add_proxy_list(proxy_list: ProxyList):
    proxies = [
        {
            "ip_address": proxy.ip_address,
            "proxy": proxy.proxy,
            "proxy_type": proxy.proxy_type,
            "status": "unknown"
        } for proxy in proxy_list.proxies
    ]
    proxies_collection.insert_many(proxies)
    logger.info("Added proxy list")
    return {"message": "Proxy list added successfully"}

@app.put("/proxy/{ip_address}", response_model=dict)
def update_proxy(ip_address: str, proxy_update: ProxyUpdate):
    update_result = proxies_collection.update_one(
        {"ip_address": ip_address},
        {"$set": {"status": proxy_update.status}}
    )
    if update_result.matched_count == 0:
        logger.error(f"Proxy not found: {ip_address}")
        raise HTTPException(status_code=404, detail="Proxy not found")
    logger.info(f"Updated proxy status: {ip_address}")
    return {"message": "Proxy status updated successfully"}

@app.delete("/proxy/{ip_address}", response_model=dict)
def delete_proxy(ip_address: str):
    delete_result = proxies_collection.delete_one({"ip_address": ip_address})
    if delete_result.deleted_count == 0:
        logger.error(f"Proxy not found: {ip_address}")
        raise HTTPException(status_code=404, detail="Proxy not found")
    logger.info(f"Deleted proxy: {ip_address}")
    return {"message": "Proxy deleted successfully"}

@app.get("/proxies", response_model=List[Proxy])
def get_proxies():
    proxies = list(proxies_collection.find({}, {"_id": 0}))
    logger.info("Fetched proxy list")
    return proxies

def test_proxy(proxy):
    try:
        response = requests.get("http://www.google.com", proxies={"http": proxy["proxy"], "https": proxy["proxy"]}, timeout=5)
        if response.status_code == 200:
            return "good"
    except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout):
        return "bad"
    return "bad"

def periodic_proxy_testing():
    while True:
        proxies = list(proxies_collection.find({"status": {"$ne": "bad"}}))
        for proxy in proxies:
            status = test_proxy(proxy)
            proxies_collection.update_one(
                {"ip_address": proxy["ip_address"]},
                {"$set": {"status": status}}
            )
        time.sleep(300)  # Sleep for 5 minutes

def start_periodic_testing():
    thread = threading.Thread(target=periodic_proxy_testing)
    thread.start()

if __name__ == "__main__":
    start_periodic_testing()
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT, log_level=LOG_LEVEL.lower())
