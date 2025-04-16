# src/backend/virtual_pc_backend.py
import docker
from docker.errors import APIError

class VirtualPCManager:
    def __init__(self):
        self.client = docker.from_env()
    
    def list_containers(self, show_all=False):
        """List containers with state handling"""
        try:
            containers = []
            for container in self.client.containers.list(all=show_all):
                try:
                    networks = container.attrs["NetworkSettings"]["Networks"]
                    ip = networks.get("admin-network", {}).get("IPAddress", "N/A")
                    
                    containers.append({
                        "id": container.id[:12],
                        "name": container.name,
                        "status": container.status,
                        "ip": ip,
                        "ports": container.ports,
                        "image": container.image.tags[0] if container.image.tags else "",
                        "alive": container.status == "running"
                    })
                except APIError as e:
                    # Handle containers in problematic states
                    containers.append({
                        "id": container.id[:12],
                        "name": container.name,
                        "status": "dead/removed",
                        "ip": "N/A",
                        "ports": {},
                        "image": "N/A",
                        "alive": False
                    })
            return containers
        except Exception as e:
            print(f"Error listing containers: {str(e)}")
            return []