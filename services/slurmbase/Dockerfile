FROM rosetta/base_ubuntu18.04
MAINTAINER Stefano Alberto Russo <stefano.russo@gmail.com>

#----------------------
#  Singularity
#----------------------

# Dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    uuid-dev \
    libgpgme11-dev \
    squashfs-tools \
    libseccomp-dev \
    pkg-config \
    cryptsetup-bin \
    wget

# Install GO
RUN if [ "$(uname -i)" = "aarch64" ] ; then \
    cd /tmp && wget https://dl.google.com/go/go1.11.linux-arm64.tar.gz && \
    cd /tmp && tar -zxf go1.11.linux-arm64.tar.gz && mv go /usr/local; \
    else \
    cd /tmp && wget https://dl.google.com/go/go1.11.linux-amd64.tar.gz && \
    cd /tmp && tar -zxf go1.11.linux-amd64.tar.gz && mv go /usr/local; \
    fi
ENV GOROOT=/usr/local/go
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# Install Singularity
COPY singularity-3.4.1.tar.gz /tmp
RUN mkdir -p /usr/local/var/singularity/mnt && \
    mkdir -p $GOPATH/src/github.com/sylabs && \
    cd $GOPATH/src/github.com/sylabs && \
    mv /tmp/singularity-3.4.1.tar.gz ./ && \
    tar -xzvf singularity-3.4.1.tar.gz
RUN cd $GOPATH/src/github.com/sylabs/singularity && \
    ./mconfig -p /usr/local && \
    make -C builddir && \
    make -C builddir install

# Build test image
RUN mkdir /singularity_images && chmod 777 /singularity_images
COPY testimage.def /singularity_images/testimage.def
RUN singularity build /singularity_images/testimage.simg /singularity_images/testimage.def


#----------------------
#  Slurm
#----------------------

# Install Slurm
RUN apt-get -y install slurm-wlm

# Explicitly create /var/run/ dirs
RUN mkdir -p /var/run/munge
RUN mkdir -p /var/run/slurm-wlm

# Add munge key and set permissions
COPY munge.key /etc/munge/munge.key
RUN chown munge:munge /etc/munge/munge.key
RUN chmod 0400 /etc/munge/munge.key

# Add munge daemon supervisord coinf
COPY supervisord_munge.conf /etc/supervisor/conf.d/

# Add Slurm conf
COPY slurm.conf /etc/slurm-llnl/slurm.conf

# TODO: why do we need this?
RUN ln -s /var/lib/slurm-llnl /var/lib/slurm-wlm 
RUN ln -s /var/log/slurm-llnl /var/log/slurm-wlm


#----------------------
#  Test user and
#   prestartup
#----------------------

# Add testuser user
RUN useradd testuser
RUN mkdir -p /home/testuser/.ssh
RUN cat /rosetta/.ssh/id_rsa.pub >> /home/testuser/.ssh/authorized_keys
RUN chown -R testuser:testuser /home/testuser   

# Add prestartup
COPY prestartup_slurmbase.sh /prestartup/
RUN touch -m /prestartup/prestartup_slurmbase.sh
