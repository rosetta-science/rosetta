#!/bin/bash

# Exit on any error. More complex thing could be done in future
# (see https://stackoverflow.com/questions/4381618/exit-a-script-on-error)
set -e

# Fix FUSE and TUN permissions
chmod 777 /dev/fuse
chmod 777 /dev/net/tun

# Add rosetta.platform entry to /etc/hosts
#PROXY_IP=$(ping proxy -c1 | head -n1 | cut -d '(' -f2 | cut -d')' -f1)
#echo "$PROXY_IP rosetta.platform" >> /etc/hosts

# Create shared data directories
mkdir -p /shared/scratch
chmod 777 /shared/scratch

mkdir -p /shared/data/shared
chmod 777 /shared/data/shared

mkdir -p /shared/data/users
chown rosetta:rosetta /shared/data/users/

mkdir -p /shared/data/users/testuser
chown testuser:testuser /shared/data/users/testuser


#---------------------
#  Entrypoint command
#---------------------

if [[ "x$@" == "x" ]] ; then
    echo -n "[INFO] Executing Docker entrypoint command: /usr/sbin/sshd -D"
    /usr/sbin/sshd -D
else
    ENTRYPOINT_COMMAND=$@
    echo -n "[INFO] Executing Docker entrypoint command: "
    echo $ENTRYPOINT_COMMAND
    exec "$ENTRYPOINT_COMMAND"
fi
#exec sudo -i -u testuser /bin/bash -c "$ENTRYPOINT_COMMAND"
