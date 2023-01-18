FROM rosetta/base_ubuntu22.04
MAINTAINER Stefano Alberto Russo <stefano.russo@gmail.com>

# Always start with an apt-get update when extending Reyns images,
# otherwise apt repositories might get outdated (404 not found)
# and building without cache does not re-build Reyns services.
RUN apt-get update

# Install Apache
RUN apt-get install -y apache2
RUN apt-get install apache2-utils

# Install Certbot
RUN apt-get install certbot python3-certbot-apache -y

# Supervisord scripts
COPY supervisord_apache.conf /etc/supervisor/conf.d/
COPY run_apache.sh /etc/supervisor/conf.d/
RUN chmod 755 /etc/supervisor/conf.d/run_apache.sh

COPY supervisord_certbot.conf /etc/supervisor/conf.d/
COPY run_certbot.sh /etc/supervisor/conf.d/
RUN chmod 755 /etc/supervisor/conf.d/run_certbot.sh

# Enable mod_proxy and SSL
RUN a2enmod proxy
RUN a2enmod proxy_http
RUN a2enmod ssl
RUN a2enmod rewrite
RUN a2enmod headers
RUN a2enmod proxy_wstunnel

# Clean up default stuff
RUN rm /etc/apache2/sites-available/000-default.conf
RUN rm /etc/apache2/sites-enabled/000-default.conf
RUN rm /etc/apache2/sites-available/default-ssl.conf
#RUN rm /etc/apache2/sites-enabled/default-ssl.conf

# Apache conf
COPY apache2.conf /etc/apache2/apache2.conf 

# Copy self-signed (snakeoil) certificates
RUN mkdir /root/certificates
COPY certificates/selfsigned.crt /root/certificates/selfsigned.crt
COPY certificates/selfsigned.key /root/certificates/selfsigned.key
COPY certificates/selfsigned.ca-bundle /root/certificates/selfsigned.ca-bundle

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

# Create default log dir
RUN mkdir -p /var/log/proxy
