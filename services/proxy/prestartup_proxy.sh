#!/bin/bash

#-----------------------
# Rosetta Platform
#-----------------------

# Always create dir if not existent
mkdir -p /etc/letsencrypt/live/$ROSETTA_HOST/

# If there are no certificates, use snakeoils
if [ ! -f "/etc/letsencrypt/live/$ROSETTA_HOST/cert.pem" ]; then
    echo "Using default self-signed certificate cer file for $ROSETTA_HOST as not existent..."
    cp -a /root/certificates/selfsigned.crt /etc/letsencrypt/live/$ROSETTA_HOST/cert.pem
else
    echo "Not using default self-signed certificate cer file for $ROSETTA_HOST as already existent."
fi

if [ ! -f "/etc/letsencrypt/live/$ROSETTA_HOST/privkey.pem" ]; then
    echo "Using default self-signed certificate privkey file for $ROSETTA_HOST as not existent..."
    cp -a /root/certificates/selfsigned.key /etc/letsencrypt/live/$ROSETTA_HOST/privkey.pem
else
    echo "Not using default self-signed certificate privkey file for $ROSETTA_HOST as already existent."
fi

if [ ! -f "/etc/letsencrypt/live/$ROSETTA_HOST/fullchain.pem" ]; then
    echo "Using default self-signed certificate fullchain file for $ROSETTA_HOST as not existent..."
    cp -a /root/certificates/selfsigned.ca-bundle /etc/letsencrypt/live/$ROSETTA_HOST/fullchain.pem
else
    echo "Not using default self-signed certificate fullchain file for $ROSETTA_HOST as already existent."
fi

# Replace the ROSETTA_HOST in the Apache proxy conf. Directly using an env var doen not wotk
# with the letsencryot client, which has a bug: https://github.com/certbot/certbot/issues/8243
sudo sed -i "s/__ROSETTA_HOST__/$ROSETTA_HOST/g" /etc/apache2/sites-available/proxy-global.conf
    

#-----------------------
# Rosetta tasks
#-----------------------

# If the tasks host is equal to rosetta host or not set, do nothing as we have already habdled it above
if [ "x$ROSETTA_TASKS_PROXY_HOST" == "x$ROSETTA_HOST" ] || [ "x$ROSETTA_TASKS_PROXY_HOST" == "x" ]; then
    echo "[INFO] Not setting up certificates forRosetta tasks host as qual to Rosetta main host"
    ROSETTA_TASKS_PROXY_HOST=$ROSETTA_HOST
else

    # Always create dir if not existent
    mkdir -p /etc/letsencrypt/live/$ROSETTA_TASKS_PROXY_HOST/

    # If there are no certificates, use snakeoils
	if [ ! -f "/etc/letsencrypt/live/$ROSETTA_TASKS_PROXY_HOST/cert.pem" ]; then
	    echo "Using default self-signed certificate cer file for $ROSETTA_TASKS_PROXY_HOST as not existent..."
	    cp -a /root/certificates/selfsigned.crt /etc/letsencrypt/live/$ROSETTA_TASKS_PROXY_HOST/cert.pem
	else
	    echo "Not using default self-signed certificate cer file for $ROSETTA_TASKS_PROXY_HOST as already existent."
	fi
	
	if [ ! -f "/etc/letsencrypt/live/$ROSETTA_TASKS_PROXY_HOST/privkey.pem" ]; then
	    echo "Using default self-signed certificate privkey file for $ROSETTA_TASKS_PROXY_HOST as not existent..."
	    cp -a /root/certificates/selfsigned.key /etc/letsencrypt/live/$ROSETTA_TASKS_PROXY_HOST/privkey.pem
	else
	    echo "Not using default self-signed certificate privkey file for $ROSETTA_TASKS_PROXY_HOST as already existent."
	fi
	
	if [ ! -f "/etc/letsencrypt/live/$ROSETTA_TASKS_PROXY_HOST/fullchain.pem" ]; then
	    echo "Using default self-signed certificate fullchain file for $ROSETTA_TASKS_PROXY_HOST as not existent..."
	    cp -a /root/certificates/selfsigned.ca-bundle /etc/letsencrypt/live/$ROSETTA_TASKS_PROXY_HOST/fullchain.pem
	else
	    echo "Not using default self-signed certificate fullchain file for $ROSETTA_TASKS_PROXY_HOST as already existent."
	fi

fi

# Replace the __ROSETTA_TASKS_PROXY_HOST__ in the Apache proxy conf. Directly using an env var doen not wotk
# with the letsencryot client, which has a bug: https://github.com/certbot/certbot/issues/8243
sudo sed -i "s/__ROSETTA_TASKS_PROXY_HOST__/$ROSETTA_TASKS_PROXY_HOST/g" /etc/apache2/sites-available/proxy-global.conf
    
