#!/bin/bash
#
# Configure NAT-VPN
# - Add an exclusion to the NAT/PAT rules to pass VPN traffic unmodified
#

# Set VPN network to TEST-NET-1 for obvious failure of configuration
VPN_NET="192.0.2.0/24"
VPN_PSK="STUPID UNSAFE DEFAULT"
VPN_HUB="127.0.0.1"

# Load configuration
[ -f /etc/default/nat-vpn ] && . /etc/default/nat-vpn

function log { logger -t "NAT-VPN" -- $1; }

function die {
    [ -n "$1" ] && log "$1"
    log "Configuration of NAT-VPN failed!"
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

VPN_ADDR_PUB_URI="http://169.254.169.254/latest/meta-data/public-ipv4"
VPN_ADDR_PUB=$(curl --retry 3 --silent --fail ${VPN_ADDR_PUB_URI})
if [ $? -ne 0 ]; then
   log "Unable to retrive VPN public IPv4 from meta-data, aborting"
   die
else
   log "Retrieved VPN public IPv4 ${VPN_ADDR_PUB} from meta-data."
fi

VPN_ADDR_PRIV_URI="http://169.254.169.254/latest/meta-data/network/interfaces/macs/${ETH0_MAC}/local-ipv4s"
VPN_ADDR_PRIV=$(curl --retry 3 --silent --fail ${VPN_ADDR_PRIV_URI} | tail -n 1)
if [ $? -ne 0 ]; then
   log "Unable to retrive VPN private IPv4 from meta-data, aborting"
   die
else
   log "Retrieved VPN private IPv4 ${VPN_ADDR_PUB} from meta-data."
fi

log "Enabling VPN..."
(  iptables -t nat -C POSTROUTING -o eth0 -s ${VPN_NET} -d ${VPN_NET} -j ACCEPT 2> /dev/null ||
   iptables -t nat -A POSTROUTING -o eth0 -s ${VPN_NET} -d ${VPN_NET} -j ACCEPT ) ||
       die

iptables -n -t nat -L POSTROUTING | log

cat >/etc/ipsec.d/vpn.conf <<__EOT
conn local
    type=passthrough
    authby=never
    auto=route
    left=${VPN_ADDR_PRIV}
    leftsubnet=${VPC_CIDR_RANGE}
    right=0.0.0.0
    rightsubnet=${VPC_CIDR_RANGE}

conn vpn-hub
    type=tunnel
    authby=secret

    left=${VPN_HUB}
    leftsubnet=${VPN_NET}

    right=%defaultroute
    rightid=${VPN_ADDR_PUB}
    rightnexthop=%defaultroute
    rightsubnet=${VPC_CIDR_RANGE}

    auto=start
    phase2=esp
    phase2alg=aes128-sha1
    ike=aes128-sha1
    ikelifetime=28800s
    salifetime=3600s
    pfs=yes
    rekey=yes
    keyingtries=%forever
    dpddelay=10
    dpdtimeout=60
    dpdaction=restart_by_peer
__EOT

cat >/etc/ipsec.d/vpn.secrets <<__EOT
${VPN_HUB} ${VPN_ADDR_PUB}: PSK "${VPN_PSK}"
__EOT
chmod 0600 /etc/ipsec.d/vpn.secrets

service ipsec start || service ipsec restart

log "Configuration of NAT-VPN complete."
exit 0
