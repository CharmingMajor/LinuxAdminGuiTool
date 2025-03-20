# Use a lightweight base image
FROM alpine:latest

# Install necessary packages (e.g., SSH, basic utilities)
RUN apk add --no-cache openssh \
    && echo "root:root" | chpasswd \
    && ssh-keygen -A

# Allow root login with password 
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Expose the SSH port
EXPOSE 22

# Start the SSH server
CMD ["/usr/sbin/sshd", "-D"]