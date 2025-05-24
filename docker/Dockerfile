FROM ubuntu:22.04

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    net-tools \
    iproute2 \
    iputils-ping \
    htop \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Create test users
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:password123" | chpasswd && \
    useradd -m -s /bin/bash adminuser && \
    echo "adminuser:admin123" | chpasswd && \
    usermod -aG sudo adminuser

# Configure SSH
RUN mkdir /var/run/sshd && \
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

# Expose SSH port
EXPOSE 22

# Start SSH service
CMD ["/usr/sbin/sshd", "-D"] 