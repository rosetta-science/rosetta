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


#----------------------
# Entrypoint
#----------------------

# Copy entrypoint
COPY entrypoint.sh /

# Give right permissions
RUN chmod 755 /entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]