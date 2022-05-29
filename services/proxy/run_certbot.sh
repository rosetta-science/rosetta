#!/bin/bash

# Source env
source /env.sh

# Exec certbot renew every hour
while true
do
    date
    sudo certbot renew
    sleep 86400
done
