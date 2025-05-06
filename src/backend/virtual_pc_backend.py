# src/backend/virtual_pc_backend.py
import docker
import logging
import os
import subprocess
from typing import Dict, List, Optional, Tuple, Any

class VirtualPCManager:
    """Manages virtual PC containers using Docker."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        try:
            self.client = docker.from_env()
            # Test Docker availability
            self.client.ping()
            self.docker_available = True
            self.logger.info("Docker client initialized successfully")
        except Exception as e:
            self.logger.warning(f"Docker not available: {str(e)}")
            self.docker_available = False
            self.client = None
    
    def list_containers(self, show_all=False) -> List[Dict[str, Any]]:
        """List available containers with their details."""
        if not self.docker_available:
            self.logger.warning("Docker is not available, returning empty container list")
            return []
            
        try:
            containers = self.client.containers.list(all=show_all)
            result = []
            
            for container in containers:
                container_data = {
                    'id': container.id,
                    'name': container.name,
                    'status': container.status,
                    'image': container.image.tags[0] if container.image.tags else 'unknown',
                }
                
                # Get container IP if it's running
                if container.status == 'running':
                    try:
                        networks = container.attrs['NetworkSettings']['Networks']
                        # Use admin-network if available, otherwise use the first network
                        if 'admin-network' in networks:
                            container_data['ip'] = networks['admin-network']['IPAddress']
                        else:
                            # Get the first network's IP
                            first_network = next(iter(networks.values()), {})
                            container_data['ip'] = first_network.get('IPAddress', 'N/A')
                    except Exception as e:
                        self.logger.error(f"Failed to get IP for container {container.name}: {str(e)}")
                        container_data['ip'] = 'N/A'
                else:
                    container_data['ip'] = 'N/A'
                
                result.append(container_data)
                
            return result
        except Exception as e:
            self.logger.error(f"Failed to list containers: {str(e)}")
            return []
    
    def get_container_logs(self, container_name: str, tail=100) -> str:
        """Get logs from a container."""
        if not self.docker_available:
            self.logger.warning("Docker is not available, cannot get container logs")
            return "Docker is not available"
            
        try:
            container = self.client.containers.get(container_name)
            logs = container.logs(tail=tail).decode('utf-8')
            return logs
        except Exception as e:
            self.logger.error(f"Failed to get logs for container {container_name}: {str(e)}")
            return f"Error retrieving logs: {str(e)}"
    
    def get_container_info(self, container_name: str) -> Dict[str, Any]:
        """Get detailed information about a container."""
        if not self.docker_available:
            self.logger.warning("Docker is not available, cannot get container info")
            return {"error": "Docker is not available"}
            
        try:
            container = self.client.containers.get(container_name)
            info = {
                'id': container.id,
                'name': container.name,
                'status': container.status,
                'image': container.image.tags[0] if container.image.tags else 'unknown',
                'created': container.attrs['Created'],
                'ports': container.attrs['NetworkSettings']['Ports'],
                'env': container.attrs['Config']['Env'],
            }
            
            # Add network info if available
            try:
                networks = container.attrs['NetworkSettings']['Networks']
                info['networks'] = {}
                for network_name, network_data in networks.items():
                    info['networks'][network_name] = {
                        'ip': network_data.get('IPAddress', 'N/A'),
                        'gateway': network_data.get('Gateway', 'N/A'),
                        'mac_address': network_data.get('MacAddress', 'N/A'),
                    }
            except Exception as e:
                self.logger.error(f"Failed to get network info for {container_name}: {str(e)}")
                info['networks'] = {'error': str(e)}
                
            return info
        except Exception as e:
            self.logger.error(f"Failed to get info for container {container_name}: {str(e)}")
            return {'error': str(e)}
    
    def execute_command(self, container_name: str, command: str) -> Tuple[str, Optional[str]]:
        """Execute a command in the container and return the output."""
        if not self.docker_available:
            self.logger.warning("Docker is not available, cannot execute command")
            return "", "Docker is not available"
            
        try:
            container = self.client.containers.get(container_name)
            result = container.exec_run(command)
            output = result.output.decode('utf-8')
            
            if result.exit_code != 0:
                error = f"Command exited with code {result.exit_code}"
                self.logger.error(f"Command '{command}' failed in container {container_name}: {error}")
                return output, error
            
            return output, None
        except Exception as e:
            self.logger.error(f"Failed to execute command in container {container_name}: {str(e)}")
            return "", str(e)