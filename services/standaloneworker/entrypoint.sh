#!/bin/bash

# Exit on any error. More complex thing could be done in future
# (see https://stackoverflow.com/questions/4381618/exit-a-script-on-error)
set -e

# Fix FUSE permissions
chmod 777 /dev/fuse

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
