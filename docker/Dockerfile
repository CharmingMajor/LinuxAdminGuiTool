FROM alpine:latest

RUN apk add --no-cache openssh \
    && echo "root:root" | chpasswd \
    && ssh-keygen -A

RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]