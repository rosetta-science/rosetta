FROM rosetta/base
MAINTAINER Stefano Alberto Russo <stefano.russo@gmail.com>

# Always start with an apt-get update when extending Reyns images,
# otherwise apt repositories might get outdated (404 not found)
# and building without cache does not re-build Reyns services.
RUN apt-get update

# Install Apache
RUN apt-get install -y apache2
RUN apt-get install apache2-utils

# Copy conf
COPY supervisord_apache.conf /etc/supervisor/conf.d/
COPY run_Apache.sh /etc/supervisor/conf.d/
RUN chmod 755 /etc/supervisor/conf.d/run_Apache.sh

# Enable mod_proxy and SSL
RUN a2enmod proxy
RUN a2enmod proxy_http
RUN sudo a2enmod ssl
RUN a2enmod rewrite
RUN a2enmod headers
RUN a2enmod proxy_wstunnel
 
# Clean up default stuff
RUN rm /etc/apache2/sites-available/000-default.conf
RUN rm /etc/apache2/sites-enabled/000-default.conf
RUN rm /etc/apache2/sites-available/default-ssl.conf
#RUN rm /etc/apache2/sites-enabled/default-ssl.conf

# Copy certificates (snakeoil or real)
RUN mkdir /certificates
COPY certificates/rosetta_platform.crt /root/certificates/rosetta_platform/rosetta_platform.crt
COPY certificates/rosetta_platform.key /root/certificates/rosetta_platform/rosetta_platform.key
COPY certificates/rosetta_platform.ca-bundle /root/certificates/rosetta_platform/rosetta_platform.ca-bundle
COPY certificates/rosetta_tasks.crt /root/certificates/rosetta_platform/rosetta_tasks.crt
COPY certificates/rosetta_tasks.key /root/certificates/rosetta_platform/rosetta_tasks.key
COPY certificates/rosetta_tasks.ca-bundle /root/certificates/rosetta_platform/rosetta_tasks.ca-bundle

# Copy index and norobots.txt
COPY index.html /var/www/html/
COPY norobots.txt /var/www/html/

# Prestartup
COPY prestartup_proxy.sh /prestartup/

# Copy and enable conf for proxy and ssl. Warning: there are issues with precedences if splitting
# the conf over multiple files (including task proxy files), as the first conf found in files which
# are read in alphabetical order wins. You can cheeck ordering with "apachectl -t -D DUMP_VHOSTS".
COPY proxy-global.conf /etc/apache2/sites-available/
RUN ln -s /etc/apache2/sites-available/proxy-global.conf /etc/apache2/sites-enabled/proxy-global.conf


