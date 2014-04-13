#!/bin/bash

[[ -z $1 ]] && { echo "usage: $0 app-target env [region] [ami] [type]"; exit 1; }
[[ -z $2 ]] && { echo "usage: $0 app-target env [region] [ami] [type]"; exit 1; }
TARGET=$1
TARGETENV=$2

[[ -n $3 ]] && EXTREGION="-e ec2_region=$3"
[[ -n $4 ]] && EXTAMI="-e ec2_ami=$4"
[[ -n $5 ]] && EXTTYPE="-e ec2_type=$5"

ansible-playbook -v -i inventory/ec2.py -t amicleaner -e amibuilder=$TARGET -e env=$TARGETENV $EXTREGION $EXTAMI site.yml
ansible-playbook -v -i inventory/local -t amisecurity $EXTREGION site.yml || exit 1
ansible-playbook -v -i inventory/local -t amibuilder -e amibuilder=$TARGET -e env=$TARGETENV $EXTREGION $EXTAMI $EXTTYPE site.yml || exit 1
./inventory/ec2.py --refresh-cache >/dev/null
ansible-playbook -v -i inventory/ec2.py -t $TARGET site.yml || exit 1
ansible-playbook -v -i inventory/ec2.py -t amiimager -e amibuilder=$TARGET -e env=$TARGETENV $EXTREGION $EXTAMI site.yml || exit 1
ansible-playbook -v -i inventory/ec2.py -t amicleaner -e amibuilder=$TARGET -e env=$TARGETENV $EXTREGION $EXTAMI site.yml || exit 1
