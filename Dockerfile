FROM alpine:latest

RUN apk update && \
    apk add --no-cache \
    openssh \
    openssl \
    shadow \
    sudo \
    bash \
    iproute2

# Configure SSH
RUN mkdir /var/run/sshd && \
    echo 'root:password' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    ssh-keygen -A

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]