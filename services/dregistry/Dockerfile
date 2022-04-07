FROM registry:2

RUN set -ex && apk --no-cache add sudo bash

#------------------------
# Rosetta user
#------------------------

# Add group. We chose GID 65527 to try avoiding conflicts.
RUN addgroup -g 65527 rosetta

# Add user. We chose UID 65527 to try avoiding conflicts.
RUN adduser rosetta -D -h /rosetta -u 65527 -G rosetta -s /bin/bash

# Add rosetta user to sudoers
RUN adduser rosetta wheel

# Passwordless sudo
RUN sed -e 's;^# \(%wheel.*NOPASSWD.*\);\1;g' -i /etc/sudoers