FROM quay.io/podman/stable:v3.2.3

#RUN dnf repolist 
#RUN dnf update --refresh

# This is necessary due to some base image permission errors.
RUN chown -R podman:podman /home/podman

# Change user, from podman to rosetta
RUN usermod -l rosetta podman
RUN usermod -d /rosetta rosetta
RUN ln -s /home/podman /rosetta
RUN groupmod -n rosetta podman

# Replace uid/gid mapping from podman to rosetta user
COPY subuid /etc/subuid
COPY subgid /etc/subgid

# Authorized keys for rosetta
RUN mkdir /rosetta/.ssh
COPY keys/id_rsa.pub /rosetta/.ssh/authorized_keys

#RUN ssh-keygen -A

# Add rosetta user to sudoers
RUN usermod -aG wheel rosetta

# Passwordless sudo (for everyone)
RUN sed -e 's;^# \(%wheel.*NOPASSWD.*\);\1;g' -i /etc/sudoers

# Add testuser user
RUN groupadd -g 1001 testuser
RUN useradd testuser -d /home/testuser -u 1001 -g 1001 -m -s /bin/bash

# Authorized keys for testuser
RUN mkdir /home/testuser/.ssh
COPY keys/id_rsa.pub /home/testuser/.ssh/authorized_keys



# Install Docker, Singularity, various utilities including iputils (for ping) and openssh-clients (for scp)
RUN dnf install -y docker singularity openssh-server python wget iputils openssh-clients

# Copy registries.conf to allow insecure access to internal/dev registries
COPY registries.conf /etc/containers/registries.conf

# Copy entrypoint
COPY entrypoint.sh /

# Give right permissions
RUN chmod 755 /entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]