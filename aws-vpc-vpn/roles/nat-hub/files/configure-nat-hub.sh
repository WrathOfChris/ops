#!/bin/bash
#
# Configure NAT-HUB
# - Add an exclusion to the NAT/PAT rules to pass VPN traffic unmodified
#

# Set VPN network to TEST-NET-1 for obvious failure of configuration
VPN_NET="192.0.2.0/24"

# Load configuration
[ -f /etc/default/nat-hub ] && . /etc/default/nat-hub

function log { logger -t "NAT-HUB" -- $1; }

function die {
    [ -n "$1" ] && log "$1"
    log "Configuration of VPN failed!"
    exit 1
}

# Sanitize PATH
PATH="/usr/sbin:/sbin:/usr/bin:/bin"

log "Enabling NAT-HUB..."
(  iptables -t nat -C POSTROUTING -o eth0 -s ${VPN_NET} -d ${VPN_NET} -j ACCEPT 2> /dev/null ||
   iptables -t nat -A POSTROUTING -o eth0 -s ${VPN_NET} -d ${VPN_NET} -j ACCEPT ) ||
       die

iptables -n -t nat -L POSTROUTING | log

log "Configuration of NAT-HUB complete."
exit 0
