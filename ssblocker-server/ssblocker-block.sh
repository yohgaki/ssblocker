#!/usr/bin/env bash

# simple protection
# define secret $KEY
KEY="secret"
if [ "$2" != "$KEY" ]; then
    echo "Error: Wrong key"
    exit
fi

iptables -I ssblocker_server -s "$1" -j DROP
