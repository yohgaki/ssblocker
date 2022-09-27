#!/usr/bin/env bash

# simple protection
# define secret key!
KEY="secret"
if [ "$2" != "$KEY" ]; then
	echo "Error: Wrong key"
	exit
fi

iptables -D ssblocker_server -s "$1" -j DROP
