#!/bin/bash
set -e

# Set proper permissions to the log dir
chown rosetta:rosetta /var/log/webapp

# Create and set proper permissions to the data/resources and shared dir
mkdir -p /data/resources 
chown rosetta:rosetta /data/resources
chown rosetta:rosetta /shared

