import docker

class VirtualPCManager:
    def __init__(self):
        self.client = docker.from_env()

    def list_containers(self):
        """List all Docker containers."""
        return self.client.containers.list()

    def start_container(self, name):
        """Start a Docker container."""
        container = self.client.containers.get(name)
        container.start()

    def stop_container(self, name):
        """Stop a Docker container."""
        container = self.client.containers.get(name)
        container.stop()

    def exec_command(self, container_name, command):
        """Execute a command inside a container."""
        container = self.client.containers.get(container_name)
        result = container.exec_run(command)
        return result.output.decode()