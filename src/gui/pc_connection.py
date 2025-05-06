import paramiko
from tkinter import messagebox

def ssh_into_container(container_name, username, password, role="junior"):
    try:
        port_mapping = {
            "pc1": 2221,
            "pc2": 2222,
            "pc3": 2223,
            "charming_volhard": 2221,
            "funny_keller": 2222
        }
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        port = port_mapping.get(container_name.lower(), 2221)
        ssh.connect('localhost',
                   port=port,
                   username=username,
                   password=password,
                   timeout=10)

        # Configure sudo to not require tty for senior admin
        if role == "senior":
            sudo_config = 'echo "admin ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/admin'
            stdin, stdout, stderr = ssh.exec_command(sudo_config)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                error = stderr.read().decode()
                raise Exception(f"Failed to configure sudo: {error}")

        # Execute appropriate command
        command = "htop" if role == "senior" else "top"
        
        if role == "senior":
            full_command = f"sudo -S {command}"
            stdin, stdout, stderr = ssh.exec_command(full_command)
            stdin.write(f"{password}\n")
            stdin.flush()
        else:
            stdin, stdout, stderr = ssh.exec_command(command)

        output = stdout.read().decode()
        error = stderr.read().decode()

        ssh.close()
        
        if error and "sudo: a terminal is required" in error:
            raise Exception("SSH session needs terminal allocation. Try adding -t flag.")
            
        return output, error
        
    except Exception as e:
        return None, f"SSH Error: {str(e)}"