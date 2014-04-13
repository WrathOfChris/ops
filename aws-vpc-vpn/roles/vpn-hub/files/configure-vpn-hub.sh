#!/bin/bash
#
# Configure VPN-HUB
# - Add an exclusion to the NAT/PAT rules to pass VPN traffic unmodified
#

# Set VPN network to TEST-NET-1 for obvious failure of configuration
VPN_NET="192.0.2.0/24"
VPN_PSK="STUPID UNSAFE DEFAULT"
VPN_HUB="127.0.0.1"
VPN_SERVICE="nat"
VPN_REGIONS="us-east-1"

# Load configuration
[ -f /etc/default/vpn-hub ] && . /etc/default/vpn-hub

function log { logger -t "VPN-HUB" -- $1; }

function die {
    [ -n "$1" ] && log "$1"
    log "Configuration of VPN failed!"
    exit 1
}

# Sanitize PATH
PATH="/usr/sbin:/sbin:/usr/bin:/bin"

log "Determining the MAC address on eth0..."
ETH0_MAC=$(cat /sys/class/net/eth0/address) ||
    die "Unable to determine MAC address on eth0."
log "Found MAC ${ETH0_MAC} for eth0."

VPC_CIDR_URI="http://169.254.169.254/latest/meta-data/network/interfaces/macs/${ETH0_MAC}/vpc-ipv4-cidr-block"
log "Metadata location for vpc ipv4 range: ${VPC_CIDR_URI}"

VPC_CIDR_RANGE=$(curl --retry 3 --silent --fail ${VPC_CIDR_URI})
if [ $? -ne 0 ]; then
   log "Unable to retrive VPC CIDR range from meta-data, aborting"
   die
else
   log "Retrieved VPC CIDR range ${VPC_CIDR_RANGE} from meta-data."
fi

log "Enabling VPN..."
(  iptables -t nat -C POSTROUTING -o eth0 -s ${VPN_NET} -d ${VPN_NET} -j ACCEPT 2> /dev/null ||
   iptables -t nat -A POSTROUTING -o eth0 -s ${VPN_NET} -d ${VPN_NET} -j ACCEPT ) ||
       die

iptables -n -t nat -L POSTROUTING | log

for _region in $VPN_REGIONS; do
    /usr/local/sbin/vpnify.py -s $VPN_SERVICE -r $_region -f /etc/ipsec.d/${_region}.conf
done

service ipsec start || service ipsec restart

log "Configuration of VPN-HUB complete."
exit 0
