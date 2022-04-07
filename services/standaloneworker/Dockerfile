FROM quay.io/podman/stable:v3.2.3

# This is necessary due to some base image permission errors.
RUN chown -R podman:podman /home/podman

# Change user
RUN usermod -l testuser podman
RUN usermod -d /home/testuser testuser
RUN ln -s /home/podman /home/testuser
RUN groupmod -n testuser podman

# Replace uid/gid mapping from podman to testuser user
COPY subuid /etc/subuid
COPY subgid /etc/subgid

#RUN dnf repolist 
#RUN dnf update --refresh
RUN dnf install -y docker singularity openssh-server
RUN ssh-keygen -A
RUN mkdir /home/testuser/.ssh
COPY keys/id_rsa.pub /home/testuser/.ssh/authorized_keys
RUN dnf install -y python wget

# Install iputils (fpr ping) and openssh-clients (for scp)
RUN dnf install -y iputils openssh-clients


# Copy registries.conf to allow insecure access to dregistry
COPY registries.conf /etc/containers/registries.conf


#------------------------
# Rosetta user
#------------------------

# Add group. We chose GID 65527 to try avoiding conflicts.
RUN groupadd -g 65527 rosetta

# Add user. We chose UID 65527 to try avoiding conflicts.
RUN useradd rosetta -d /rosetta -u 65527 -g 65527 -m -s /bin/bash

# Add rosetta user to sudoers
RUN usermod -aG wheel rosetta

# Passwordless sudo
RUN sed -e 's;^# \(%wheel.*NOPASSWD.*\);\1;g' -i /etc/sudoers

# Authorized keys
RUN mkdir /rosetta/.ssh
COPY keys/id_rsa.pub /rosetta/.ssh/authorized_keys


#----------------------
# Entrypoint
#----------------------

# Copy entrypoint
COPY entrypoint.sh /

# Give right permissions
RUN chmod 755 /entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]