# Alpine 3.22 ships OpenSSH 10, which supports mlkem768x25519-sha256.
# The lab only needs the server's clear-text KEXINIT, so no users or logins are set up.
FROM alpine:3.22
RUN apk add --no-cache openssh-server \
 && ssh-keygen -A
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
