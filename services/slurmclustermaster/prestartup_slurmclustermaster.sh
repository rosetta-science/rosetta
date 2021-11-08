#!/bin/bash
set -e

# Generic rosetta user shared folder
mkdir -p /shared/rosetta && chown rosetta:rosetta /shared/rosetta

# Shared home for slurmtestuser to simulate a shared home folders filesystem
cp -a /home_slurmtestuser_vanilla /shared/home_slurmtestuser

# Create shared data directories
mkdir -p /shared/scratch
chmod 777 /shared/scratch

mkdir -p /shared/data/shared
chmod 777 /shared/data/shared

mkdir -p /shared/data/users/slurmtestuser
chown slurmtestuser:slurmtestuser /shared/data/users/slurmtestuser
