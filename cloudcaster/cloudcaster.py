#!/usr/bin/python
#
# Copyright (c) 2013 Chris Maxwell <chris@wrathofchris.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Thanks to Mahesh Paolini-Subramanya (@dieswaytoofast) for his help
#
import argparse
import boto
import boto.ec2
import boto.ec2.autoscale
import boto.ec2.elb
import boto.route53
import boto.route53.zone
import boto.sts
import boto.vpc
import datetime
import json
import os
import re
import sys
import time
import copy
from pprint import pprint
from collections import OrderedDict

if 'AWS_ACCESS_KEY' in os.environ:
  aws_key = os.environ['AWS_ACCESS_KEY']
else:
  aws_key = None
if 'AWS_SECRET_KEY' in os.environ:
  aws_secret = os.environ['AWS_SECRET_KEY']
else:
  aws_secret = None

vpc_subnetids = []
vpc_pubsubnetids = []
nat_subnetidx = 0
nat_instances = []
nat_instwait = 5
nat_publicdns = None
eip_pendwait = 5

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help="verbosity", action="store_true")
parser.add_argument("file", help="cloudcaster JSON file")
args = parser.parse_args()
if args.file == None:
  parser.print_help()
  sys.exit(1)

verbose = args.verbose

conffile = open(args.file).read()
conf = json.loads(conffile)

awsvpc = boto.vpc.connect_to_region(conf['aws']['region'], aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
awsec2 = boto.ec2.connect_to_region(conf['aws']['region'], aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
awselb = boto.ec2.elb.connect_to_region(conf['aws']['region'], aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
awsiam = boto.connect_iam()
awsasg = boto.ec2.autoscale.connect_to_region(conf['aws']['region'], aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)

#
# VPC
#

def find_vpc(cidr, vpcs):
    for v in vpcs:
        if v.cidr_block == cidr:
            return v
    return None

def find_vpc_acl(acls, vpc):
    for acl in acls:
        if acl.vpc_id == vpc.id:
            return acl
    return None

#
# Attempts to validate an acl entry with the json in a cloudcaster config
#
# TODO: Implement icmp and port_range handling
#
def validate_acl(entry, acls):
    retval = True
    for acl in acls:
        if int(entry['rule_number']) != 32767 and int(entry['rule_number']) == int(acl['rule_number']):
            for key in acl.keys():
                if key == 'egress':
                    if json.loads(entry[key]) == acl[key] and retval == True:
                        retval = True
                elif key == "icmp" and retval == True: # not handled
                    retval = True
                elif key == "port_range" and retval == True: # not handled
                    retval = True
                elif str(entry[key]) == str(acl[key]) and retval == True:
                    retval = True
                else:
                    retval = False
            # so we're probably good.
            if retval == True:
                acls.remove(acl)

    return { "value": retval, "acls": acls }

# Validate VPCs
vpcs = awsvpc.get_all_vpcs()
vpc = find_vpc(conf['vpc']['cidr'], vpcs)
acls = awsvpc.get_all_network_acls()

if vpc == None:
    print "Creating VPC %s" % conf['vpc']['cidr']
    vpc = awsvpc.create_vpc(conf['vpc']['cidr'])
    acls = awsvpc.get_all_network_acls()
    if vpc == None:
        print "Failed creating VPC %s" % conf['vpc']['cidr']
        sys.exit(1)
    # NOTE: boto has no way to query this
    if awsvpc.modify_vpc_attribute(vpc.id, enable_dns_hostnames='true') != True:
        print "Failed enabling VPC DNS hostname resolution"
        sys.exit(1)
    if 'acls' in conf['vpc']:
        # Lets only proceed down this path if people actually care.
        # Otherwise, accept the defaults (allow 0.0.0.0/0, in out)
        acl = find_vpc_acl(acls, vpc)
        if acl != None:
            for entry in acl.network_acl_entries:
                # default deny rule is not deleteable
                # any rules < 32767 are fine, just not this one.
                #
                # converting to an int because in the resultset its a unicode string
                if int(entry.rule_number) != 32767:
                    if awsvpc.delete_network_acl_entry(acl.id, entry.rule_number, entry.egress) == False:
                        print "FAILED TO DELETE:"
                        pprint(vars(acl))
            for entry in conf['vpc']['acls']:
                if awsvpc.create_network_acl_entry(acl.id, **entry) == False:
                    print "FAILED TO CREATE:"
                    pprint(entry)
else:
    # VPC exists, validate ACLs
    if 'acls' in conf['vpc']:
        acl = find_vpc_acl(acls, vpc)
        # Make a copy, we're going to push stuff off this
        acls = copy.deepcopy(conf['vpc']['acls'])
        for entry in acl.network_acl_entries:
            if int(entry.__dict__['rule_number']) != 32767:
                retval = validate_acl(entry.__dict__, acls)
                if retval['value'] == False:
                    print "** FAILED RULE MATCH, PLEASE REMEDIATE **"
                    pprint(vars(entry))
                    sys.exit(1)
        if len(acls) > 0:
            for todo_acl in acls:
                if awsvpc.create_network_acl_entry(acl.id, **todo_acl) == False:
                    print "FAILED TO CREATE:"
                    pprint(todo_acl)
                else:
                    print "CREATED VPC ACL:"
                    pprint(todo_acl)

if verbose:
    print "VPC %s %s" % (vpc.id, vpc.cidr_block)
    print "VPC ACLS"
    for acl in find_vpc_acl(acls, vpc):
        pprint(vars(acl))


#
# VPC Internet Gateway
#

# Find InternetGateway by attachment to VPC
def find_igw(vpc, gws):
  for g in gws:
    for a in g.attachments:
      if a.vpc_id == vpc.id:
        return g
  return None

# Validate Internet Gateways
gws = awsvpc.get_all_internet_gateways()
gw = find_igw(vpc, gws)
if gw == None:
  print "Creating InternetGateway for VPC %s" % conf['vpc']['cidr']
  gw = awsvpc.create_internet_gateway()
  if gw == None:
    print "Failed creating IGW for VPC %s" % conf['vpc']['cidr']
    sys.exit(1)
  if awsvpc.attach_internet_gateway(gw.id, vpc.id) != True:
    print "Failed attaching IGW %s for VPC %s" % (gw.id, vpc.id)
    sys.exit(1)
if verbose:
  print "VPC-IGW %s" % gw.id

#
# VPC Subnets
#

def find_subnet(cidr, nets):
  for n in nets:
    if n.cidr_block == cidr:
      return n
  return None

# Validate Subnets
nets = awsvpc.get_all_subnets()
azi = iter(conf['vpc']['azs'])
if 'subnets' in conf['vpc']:
  for n in conf['vpc']['subnets']:
    net = find_subnet(n, nets)
    az = azi.next()
    if net == None:
      print "Creating VPC subnet %s AZ %s" % (n, az)
      net = awsvpc.create_subnet(vpc.id, n, availability_zone=az)
      if net == None:
        print "Failed creating VPC subnet %s" % n
        sys.exit(1)
    if verbose:
      print "VPC-SUBNET %s %s PRIVATE" % (net.id, net.cidr_block)

# Public subnets
azi = iter(conf['vpc']['azs'])
for n in conf['vpc']['pubsubnets']:
  net = find_subnet(n, nets)
  az = azi.next()
  if net == None:
    print "Creating VPC subnet %s AZ %s" % (n, az)
    net = awsvpc.create_subnet(vpc.id, n, availability_zone=az)
    if net == None:
      print "Failed creating VPC subnet %s" % n
      sys.exit(1)
  if verbose:
    print "VPC-SUBNET %s %s PUBLIC" % (net.id, net.cidr_block)

# Refresh and load subnet IDs
nets = awsvpc.get_all_subnets()
if 'subnets' in conf['vpc']:
  for n in conf['vpc']['subnets']:
    net = find_subnet(n, nets)
    vpc_subnetids.append(net.id)

# Public subnet IDs
for n in conf['vpc']['pubsubnets']:
  net = find_subnet(n, nets)
  while net == None:
    nets = awsvpc.get_all_subnets()
    print "Couldn't find %s, sleeping 10s" % n
    time.sleep(10)
  vpc_pubsubnetids.append(net.id)

#
# Security Groups
#

def find_sg(sg, sgs):
  for s in sgs:
    if s.name == sg:
      return s
  return None

def find_elb_conf(elb, elbs):
  for e in elbs:
    if e['name'] == elb:
      return e
  return None

# Create Security Group for service in VPC
vpcfilter = { 'vpc_id': vpc.id }
sgs = awsec2.get_all_security_groups(filters=vpcfilter)

#
# ELB security groups
#
for elb in conf['elbs']:
  elb_sg = find_sg(elb['group'], sgs)
  if elb_sg == None:
    print "Creating Security Group %s for VPC %s elb %s" % (elb['group'], conf['vpc']['cidr'], elb['name'])
    elb_sg = awsec2.create_security_group(elb['group'], elb['group'], vpc_id = vpc.id)
    if elb_sg == None:
      print "Failed creating SG %s for VPC %s elb %s" % (elb['group'], conf['vpc']['cidr'], elb['name'])
      sys.exit(1)
    sgs = awsec2.get_all_security_groups(filters=vpcfilter)
  if verbose:
    print "SECGRP-ELB %s %s" % (elb_sg.id, elb_sg.name)

#
# APP security groups
#
for app in conf['apps']:
  sg = find_sg(app['group'], sgs)
  if sg == None:
    print "Creating Security Group %s for VPC %s app %s" % (app['group'], conf['vpc']['cidr'], app['name'])
    sg = awsec2.create_security_group(app['group'], app['group'], vpc_id = vpc.id)
    if sg == None:
      print "Failed creating SG %s for VPC %s app %s" % (app['group'], conf['vpc']['cidr'], app['name'])
      sys.exit(1)
    sgs = awsec2.get_all_security_groups(filters=vpcfilter)
  if verbose:
    print "SECGRP-APP %s %s" % (sg.id, sg.name)

#
# Security Group Rules
#

def find_sg_rule_group(sg_id, owner_id, p_from, p_to, p_prot, rules):
  grant = '%s-%s' % (sg_id, owner_id)
  for r in rules:
    if int(r.from_port) == int(p_from) and int(r.to_port) == int(p_to) and str(r.ip_protocol) == str(p_prot):
      for g in r.grants:
        # grant is a unicode, use str() for comparison
        if str(g) == grant:
          return r
  return None

def find_sg_rule_cidr(cidr , p_from, p_to, p_prot, rules):
  for r in rules:
    if p_from == None or p_to == None or r.to_port == None or r.from_port == None:
      # cannot int() a NoneType, so handle it separately
      if p_from == None and p_to == None and r.to_port == None and r.from_port == None and str(r.ip_protocol) == str(p_prot):
        for g in r.grants:
          # grant is a unicode, use str() for comparison
          if str(g) == str(cidr):
            return r
      continue
    if int(r.from_port) == int(p_from) and int(r.to_port) == int(p_to) and str(r.ip_protocol) == str(p_prot):
      for g in r.grants:
        # grant is a unicode, use str() for comparison
        if str(g) == str(cidr):
          return r
  return None

#
# ELB Security Rules
#
for elb in conf['elbs']:
  elb_sg = find_sg(elb['group'], sgs)
  for port in elb['ports']:
    p_from = port['from']
    p_to = port['to']
    p_prot = port['prot']
    if p_prot != 'udp' and p_prot != 'icmp':
      p_prot = 'tcp'

    # ELB inbound rule
    rule = find_sg_rule_cidr('0.0.0.0/0', p_from, p_to, p_prot, elb_sg.rules)
    if rule == None:
      print "Creating SG rule for world -> ELB"
      if awsec2.authorize_security_group(group_id = elb_sg.id,
            cidr_ip = '0.0.0.0/0',
            ip_protocol = p_prot,
            from_port = p_from,
            to_port = p_to
          ) != True:
        print "Failed authorizing world -> ELB"
        sys.exit(1)
      sgs = awsec2.get_all_security_groups(filters=vpcfilter)
      elb_sg = find_sg(elb['group'], sgs)
      rule = find_sg_rule_cidr('0.0.0.0/0', p_from, p_to, p_prot, elb_sg.rules)
    if verbose:
      print "SGRULE %s src %s %s %s:%s" % (elb_sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

#
# APP Security Rules
#
for app in conf['apps']:
  if verbose:
    print "APP %s" % app['name']
  sg = find_sg(app['group'], sgs)

  if 'elb' in app:
        elb = find_elb_conf(app['elb'], conf['elbs'])
        if not elb:
            print "ERROR: APP %s ELB %s does not exist" % (app['name'], app['elb'])
            sys.exit(1)
        elb_sg = find_sg(elb['group'], sgs)
        if verbose:
            print "APP %s ELB %s ELBSG %s" % (app['name'], elb['name'], elb_sg.name)

        # ELB:APP rules
        for port in elb['listeners']:
            p_from = port['to']
            p_to = port['to']
            p_prot = port['to_prot']
            if p_prot != 'udp' and p_prot != 'icmp':
                p_prot = 'tcp'
            rule = find_sg_rule_group(elb_sg.id, elb_sg.owner_id, p_from, p_to, p_prot, sg.rules)
            if rule == None:
                print "Creating SG rule for ELB -> SG ( %s, %s )" % ( elb['name'], sg.name )
                if awsec2.authorize_security_group(group_id = sg.id,
                        src_security_group_group_id = elb_sg.id,
                        ip_protocol = p_prot,
                        from_port = p_from,
                        to_port = p_to
                        ) != True:
                    print "Failed authorizing ELB->SG"
                    sys.exit(1)
                sgs = awsec2.get_all_security_groups(filters=vpcfilter)
                sg = find_sg(app['group'], sgs)
                rule = find_sg_rule_group(elb_sg.id, elb_sg.owner_id, p_from, p_to, p_prot, sg.rules)
            if verbose:
                print "SGRULE %s src %s %s %s:%s" % (elb_sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

  # Introduce multiple ELBs
  if 'elbs' in app:
        for elbname in app['elbs']:
            # skip if previously created/registered
            if 'elb' in app and elbname == app['elb']:
                continue

            elb = find_elb_conf(elbname, conf['elbs'])
            if not elb:
                print "ERROR: APP %s ELB %s does not exist" % (app['name'],
                        elbname)
                sys.exit(1)
            elb_sg = find_sg(elb['group'], sgs)
            if verbose:
                print "APP %s ELB %s ELBSG %s" % (app['name'], elb['name'],
                        elb_sg.name)

            # ELB:APP rules
            for port in elb['listeners']:
                p_from = port['to']
                p_to = port['to']
                p_prot = port['to_prot']
                if p_prot != 'udp' and p_prot != 'icmp':
                    p_prot = 'tcp'
                rule = find_sg_rule_group(elb_sg.id, elb_sg.owner_id, p_from,
                        p_to, p_prot, sg.rules)
                if rule == None:
                    print "Creating SG rule for ELB -> SG ( %s, %s )" % (
                            elb['name'], sg.name )
                    if awsec2.authorize_security_group(group_id = sg.id,
                            src_security_group_group_id = elb_sg.id,
                            ip_protocol = p_prot,
                            from_port = p_from,
                            to_port = p_to
                            ) != True:
                        print "Failed authorizing ELB->SG"
                        sys.exit(1)
                    sgs = awsec2.get_all_security_groups(filters=vpcfilter)
                    sg = find_sg(app['group'], sgs)
                    rule = find_sg_rule_group(elb_sg.id, elb_sg.owner_id,
                            p_from, p_to, p_prot, sg.rules)
                if verbose:
                    print "SGRULE %s src %s %s %s:%s" % (elb_sg.name,
                            rule.grants, rule.ip_protocol, rule.from_port,
                            rule.to_port)

  # APP:APP rules
  for port in app['ports']:
    p_from = port['from']
    p_to = port['to']
    p_prot = port['prot']
    if p_prot != 'udp' and p_prot != 'icmp':
      p_prot = 'tcp'

    # Internal service rule
    rule = find_sg_rule_group(sg.id, sg.owner_id, p_from, p_to, p_prot, sg.rules)
    if rule == None:
      print "Creating SG rule for SG -> SG (%s, %s, %s)" % (p_from, p_to, p_prot)
      if awsec2.authorize_security_group(group_id = sg.id,
            src_security_group_group_id = sg.id,
            ip_protocol = p_prot,
            from_port = p_from,
            to_port = p_to
          ) != True:
        print "Failed authorizing SG->SG"
        sys.exit(1)
      sgs = awsec2.get_all_security_groups(filters=vpcfilter)
      sg = find_sg(app['group'], sgs)
      rule = find_sg_rule_group(sg.id, sg.owner_id, p_from, p_to, p_prot, sg.rules)
    if verbose:
      print "SGRULE %s src %s %s %s:%s" % (sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

  # APP:ALLOW rules
  if 'allow' in app:
    for allow in app['allow']:
        cidr = allow.get('cidr', None)
        group = allow.get('group', None)

        if cidr != None and group != None:
            print "CIDR and group defined:"
            pprint(allow)
            sys.exit(2)
        elif cidr == None and group == None:
            print "Neither CIDR or group defined!:"
            pprint(allow)
            sys.exit(2)

        p_from = allow['from']
        p_to = allow['to']
        p_prot = allow['prot']

        if p_prot != 'udp' and p_prot != 'icmp':
            p_prot = 'tcp'

        # ALLOW another APP in
        if cidr != None:
            rule = find_sg_rule_cidr(cidr, p_from, p_to, p_prot, sg.rules)
        elif group != None:
            allowsg = find_sg(group, sgs)
            rule = find_sg_rule_group(allowsg.id, allowsg.owner_id, p_from, p_to, p_prot, sg.rules)

        if rule == None:
            # Packed keyword arguments
            kwargs = {
                    "group_id": sg.id,
                    "ip_protocol": p_prot,
                    "from_port": p_from,
                    "to_port": p_to
                    }

            if cidr != None:
                kwargs['cidr_ip'] = cidr
                print "Creating SG rule for ALLOWSG -> CIDR (%s, %s, %s, %s)" % (cidr, p_from, p_to, p_prot)
            elif group != None:
                print "Creating SG rule for ALLOWSG -> SG (%s, %s, %s, %s)" % (group, p_from, p_to, p_prot)
                kwargs['src_security_group_group_id'] = allowsg.id

            if awsec2.authorize_security_group(**kwargs) != True:
                    print "Failed authorizing ALLOWSG-> (CIDR or SG)"
                    pprint(allow)
                    sys.exit(1)

            sgs = awsec2.get_all_security_groups(filters=vpcfilter)
            sg = find_sg(app['group'], sgs)

            if cidr != None:
                rule = find_sg_rule_cidr(cidr, p_from, p_to, p_prot, sg.rules)
            elif group != None:
                rule = find_sg_rule_group(allowsg.id, allowsg.owner_id, p_from, p_to, p_prot, sg.rules)
            if verbose and cidr != None:
                print "SGRULE %s src %s %s %s:%s" % (cidr, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)
            elif verbose and group != None:
                print "SGRULE %s src %s %s %s:%s" % (sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

  # APP:PUBLIC rules
  if 'pubports' in app:
    for port in app['pubports']:
      p_from = port['from']
      p_to = port['to']
      p_prot = port['prot']
      if p_prot != 'udp' and p_prot != 'icmp':
        p_prot = 'tcp'

      # Public rule
      rule = find_sg_rule_cidr('0.0.0.0/0', p_from, p_to, p_prot, sg.rules)
      if rule == None:
        print "Creating SG rule for PUBLIC -> SG (%s, %s, %s)" % (p_from, p_to, p_prot)
        if awsec2.authorize_security_group(group_id = sg.id,
            cidr_ip = '0.0.0.0/0',
            ip_protocol = p_prot,
            from_port = p_from,
            to_port = p_to
            ) != True:
          print "Failed authorizing PUBLIC->SG"
          sys.exit(1)
        sgs = awsec2.get_all_security_groups(filters=vpcfilter)
        sg = find_sg(app['group'], sgs)
        rule = find_sg_rule_cidr('0.0.0.0/0', p_from, p_to, p_prot, sg.rules)
      if verbose:
        print "SGRULE %s src %s %s %s:%s" % (sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

  # SSH:APP rule
  rule = find_sg_rule_cidr('0.0.0.0/0', 22, 22, 'tcp', sg.rules)
  if rule == None:
    print "Creating SG rule for SSH -> SG"
    if awsec2.authorize_security_group(group_id = sg.id,
          cidr_ip = '0.0.0.0/0',
          ip_protocol = 'tcp',
          from_port = 22,
          to_port = 22
        ) != True:
      print "Failed authorizing SSH->SG"
      sys.exit(1)
    sgs = awsec2.get_all_security_groups(filters=vpcfilter)
    sg = find_sg(app['group'], sgs)
    rule = find_sg_rule_cidr('0.0.0.0/0', 22, 22, 'tcp', sg.rules)
  if verbose:
    print "SGRULE %s src %s %s %s:%s" % (sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

  # icmp
  if 'privnet' in conf['aws'].keys():
    rule = find_sg_rule_cidr(conf['aws']['privnet'], -1, -1, 'icmp', sg.rules)
    if rule == None:
      print "Creating SG rule for ICMP -> SG"
      if awsec2.authorize_security_group(group_id = sg.id,
            cidr_ip = conf['aws']['privnet'],
            ip_protocol = 'icmp',
            from_port = -1,
            to_port = -1 
          ) != True:
        print "Failed authorizing ICMP->SG"
        sys.exit(1)
      sgs = awsec2.get_all_security_groups(filters=vpcfilter)
      sg = find_sg(app['group'], sgs)
      rule = find_sg_rule_cidr(conf['aws']['privnet'], -1, -1, 'icmp', sg.rules)
  if verbose:
    print "SGRULE %s src %s %s %s:%s" % (sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

#
# ELB ALLOW RULES - after APP for SG creation
#
for elb in conf['elbs']:
    if 'allow' in elb:
        elb_sg = find_sg(elb['group'], sgs)
        for allow in elb['allow']:
            cidr = allow.get('cidr', None)
            group = allow.get('group', None)

            if cidr != None and group != None:
                print "CIDR and group defined:"
                pprint(allow)
                sys.exit(2)
            elif cidr == None and group == None:
                print "Neither CIDR nor group defined!"
                pprint(allow)
                sys.exit(2)

            p_from = allow['from']
            p_to = allow['to']
            p_prot = allow['prot']

            if p_prot != 'udp' and p_prot != 'icmp':
               p_prot = 'tcp'


            # ALLOW APP to ELB
            if cidr != None:
                rule = find_sg_rule_cidr(cidr, p_from, p_to, p_prot, elb_sg.rules)
            elif group != None:
                allowsg = find_sg(allow['group'], sgs)
                rule = find_sg_rule_group(allowsg.id, allowsg.owner_id, p_from, p_to, p_prot, elb_sg.rules)
            else:
                print "No CIDR or rule found?"
                sys.exit(2)

            if rule == None:
                # Pack keyword arguments, then decide if 
                kwargs = {
                        "group_id": str(elb_sg.id),
                        "ip_protocol": p_prot,
                        "from_port": p_from,
                        "to_port": p_to
                        }

                if cidr != None:
                    kwargs['cidr_ip'] = cidr
                elif group != None:
                    kwargs['src_security_group_group_id'] = str(allowsg.id)

                if cidr != None:
                    print "Creating SG rule for ALLOWCIDR -> ELB (%s, %s, %s, %s)" % (cidr,p_from, p_to, p_prot)
                elif group != None:
                    print "Creating SG rule for ALLOWSG -> ELB (%s, %s, %s, %s)" % (allowsg.name, p_from, p_to, p_prot)
                if awsec2.authorize_security_group(**kwargs) != True:
                    print "Failed authorizing ALLOW(SG|CIDR)->ELB"
                    sys.exit(1)

                sgs = awsec2.get_all_security_groups(filters=vpcfilter)
                elb_sg = find_sg(elb['group'], sgs)
                if cidr != None:
                    rule = find_sg_rule_cidr(cidr, p_from, p_to, p_prot, elb_sg.rules)
                elif group != None:
                    rule = find_sg_rule_group(allowsg.id, allowsg.owner_id, p_from, p_to, p_prot, elb_sg.rules)
                else:
                    print "No CIDR or SG rule found?"
                    sys.exit(2)
                if verbose:
                    print "SGRULE %s src %s %s %s:%s" % (elb_sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

#
# IAM Certificate for SSL
#

def find_cert(name, certs):
  for c in certs:
    if c.server_certificate_name == name:
      return c
  return None

certs = awsiam.get_all_server_certs()

#
# Elastic Load Balancer
#

def find_elb(elb, elbs):
  for e in elbs:
    if e.name == elb:
      return e
  return None

elbs = awselb.get_all_load_balancers()

for confelb in conf['elbs']:

  # Load certificate ARN
  elb_listeners_full = []
  for elb_listener in confelb['listeners']:
    if 'cert' in elb_listener.keys():
      cert = find_cert(elb_listener['cert'], certs.list_server_certificates_response.list_server_certificates_result.server_certificate_metadata_list)
      if elb_listener['cert'] != '' and cert == None:
        print "Certificate %s does not exist" % elb_listener['cert']
        sys.exit(1)
      listener = (elb_listener['from'], elb_listener['to'], elb_listener['from_prot'], elb_listener['to_prot'], cert.arn)
    else:
      listener = (elb_listener['from'], elb_listener['to'], elb_listener['from_prot'], elb_listener['to_prot'])
    elb_listeners_full.append(listener)

  myname = "%s-%s" % (confelb['name'], conf['aws']['env'])
  elb_sg = find_sg(confelb['group'], sgs)
  elb = find_elb(myname, elbs)
  if elb == None:
    print "Creating ELB %s" % myname
    hc = boto.ec2.elb.HealthCheck(
      interval = confelb['interval'],
      healthy_threshold = confelb['healthy'],
      unhealthy_threshold = confelb['unhealthy'],
      target = confelb['target']
    )
    elb_scheme = 'internet-facing'
    if 'internal' in confelb:
      elb_scheme = 'internal'
    elb = awselb.create_load_balancer(myname, None,
      complex_listeners = elb_listeners_full,
      subnets = vpc_pubsubnetids,
      scheme = elb_scheme,
      security_groups = str(elb_sg.id)
    )
    if elb == None:
      print "Failed creating ELB %s" % myname
      sys.exit(1)
    newhc = elb.configure_health_check(hc)
    if newhc == None:
      print "Failed configuring health check for ELB %s" % myname
    # refresh
    elbs = awselb.get_all_load_balancers()
    elb = find_elb(myname, elbs)
  if verbose:
    print "ELB %s dns %s" % (elb.name, elb.dns_name)
    for l in elb.listeners:
      print "ELB-LISTEN %s %s/%s -> %s/%s" % (elb.name, l[0], l[2], l[1], l[4])

  if elb != None and elb.is_cross_zone_load_balancing() != True:
    print "ELB %s enabling cross-zone load balancing" % (elb.name)
    elb.enable_cross_zone_load_balancing()

  #
  # ELB Listeners
  #

  def find_elb_listener(find, listeners):
    for l in listeners:
      # XXX boto counts 0,1,2,4 for some reason.  Seriously.  WTF!
      # XXX https://github.com/boto/boto/blob/develop/boto/ec2/elb/listener.py#L83-84
      if l[0] == find[0] and l[1] == find[1] and l[2].lower() == find[2].lower() and l[4].lower() == find[3].lower():
        return l
    return None

  l_missing = []
  if len(elb.listeners) > 0:
    for l_conf in elb_listeners_full:
      l_elb = find_elb_listener(l_conf, elb.listeners)
      if l_elb == None:
        print "Adding missing ELB listener to queue (%u, %u, %s, %s)" % (l_conf[0], l_conf[1], l_conf[2], l_conf[3])
        l_missing.append(l_conf)

  if len(l_missing) > 0:
    print "Creating ELB listeners for %s" % myname
    elb_newlisteners = awselb.create_load_balancer_listeners(myname, complex_listeners = l_missing)
    if elb_newlisteners == None:
      print "Failed creating ELB listeners"
      sys.exit(1)
    if verbose:
      for l in l_missing:
        print "ELB-LISTEN %s %s/%s -> %s/%s" % (elb.name, l[0], l[2], l[1], l[4])

#
# BLOCK DEVICE MAPPINGS - http://aws.amazon.com/ec2/instance-types/
#
bdmapping={}
bdmapping['c1.medium'] = 1
bdmapping['c1.xlarge'] = 1
bdmapping['c3.2xlarge'] = 2
bdmapping['c3.4xlarge'] = 2
bdmapping['c3.8xlarge'] = 2
bdmapping['c3.large'] = 2
bdmapping['c3.xlarge'] = 2
bdmapping['cc2.8xlarge'] = 4
bdmapping['cg1.4xlarge'] = 2
bdmapping['cr1.8xlarge'] = 2
bdmapping['g2.2xlarge'] = 1
bdmapping['hi1.4xlarge'] = 2
bdmapping['hs1.8xlarge'] = 24
bdmapping['i2.2xlarge'] = 2
bdmapping['i2.4xlarge'] = 4
bdmapping['i2.8xlarge'] = 8
bdmapping['i2.xlarge'] = 1
bdmapping['m1.large'] = 2
bdmapping['m1.medium'] = 1
bdmapping['m1.small'] = 1
bdmapping['m1.xlarge'] = 4
bdmapping['m2.2xlarge'] = 1
bdmapping['m2.4xlarge'] = 2
bdmapping['m2.xlarge'] = 1
bdmapping['m3.2xlarge'] = 2
bdmapping['m3.large'] = 1
bdmapping['m3.medium'] = 1
bdmapping['m3.xlarge'] = 2

def find_amibyname(name, amis):
  for a in amis:
    if str(a.name) == name:
      return a
    if re.match("%s-\d{14}" % name, str(a.name)):
      return a
  return None

#
# Run Instances.  Ignored if mode is set to autoscale
# This does matching for aminame though.
#
for app in conf['apps']:

  if 'aminame' in app and not 'ami' in app:
    # Search ami list, find best match
    # 1. {{env}}-{{ami}}-{{date}}
    # 2. all-{{ami}}-{{date}}
    # 3. {{ami}}-{{date}}
    ami = None
    amifilter = { 'name': "%s-%s-*" % (conf['aws']['env'], app['aminame']) }
    amis = awsec2.get_all_images(filters=amifilter)
    if len(amis) > 0:
      ami = find_amibyname("%s-%s" % (conf['aws']['env'], app['aminame']),
          sorted(amis, key=lambda a: a.name, reverse=True))
    if ami == None:
      amifilter = { 'name': "all-%s-*" % app['aminame'] }
      amis = awsec2.get_all_images(filters=amifilter)
      if len(amis) > 0:
        ami = find_amibyname("all-%s" % app['aminame'],
            sorted(amis, key=lambda a: a.name, reverse=True))
    if ami == None:
      amifilter = { 'name': "%s-*" % app['aminame'] }
      amis = awsec2.get_all_images(filters=amifilter)
      if len(amis) > 0:
        ami = find_amibyname("%s" % app['aminame'],
            sorted(amis, key=lambda a: a.name, reverse=True))
    if ami != None:
      app['ami'] = ami.id
      if verbose:
        print "AMI mapping %s to %s %s (%s)" % (app['aminame'], ami.id, ami.name, ami.description)
    else:
      print "AMI mapping failed for \"%s\" as %s-%s-*, all-%s-*, %s" % (app['aminame'], conf['aws']['env'], app['aminame'], app['aminame'], app['aminame'])

  if 'autoscale' not in app:
    # First find how many are running
    tagfilter = {
        'tag:%s' % conf['aws']['svctag']: app['svctag'],
        'tag:%s' % conf['aws']['envtag']: conf['aws']['env'],
        'vpc-id': vpc.id,
        'instance-state-name': 'running'
    }
    running = awsec2.get_all_instances(filters=tagfilter)
    for r in running:
      for i in r.instances:
        if 'ami' not in app:
          print "APP-INST %s %s ami %s NOT MAPPED" % (app['name'], i.id, i.image_id)
        else:
          if i.image_id != app['ami']:
            print "APP-INST %s %s ami %s != %s" % (app['name'], i.id, i.image_id, app['ami'])
        if i.instance_type != app['type']:
          print "APP-INST %s %s type %s != %s" % (app['name'], i.id, i.instance_profile, app['role'])
        if verbose:
          print "APP-INST %s %s ami %s type %s host %s %s" % (app['name'], i.id, i.image_id, i.instance_type, i.private_dns_name, i.public_dns_name)
    sg = find_sg(app['group'], sgs)

    # error if we need more instances but have no AMI mapping
    if 'ami' not in app and app['count'] < len(running):
        print "ERROR: APP-INST %s running %d < %d instances with no AMI mapped" % (app['name'])
        sys.exit(1)

    mapping = None
    if app['type'] in bdmapping:
      mapping = boto.ec2.blockdevicemapping.BlockDeviceMapping()
      for b in range(0, bdmapping[app['type']]):
        # punt on dealing with complex case
        if b > 24:
          print "Seriously?  You want more than 24 devices?  Figure this out yourself."
          break
        # sdc..z
        devname= '/dev/sd%s' % chr(ord('b') + b)
        mapping[devname] = boto.ec2.blockdevicemapping.BlockDeviceType(ephemeral_name="ephemeral%d" % b)
        if verbose:
          print "APP-INST block device mapping %s to %s" % (mapping[devname].ephemeral_name, devname)

    # Split between defined subnets
    instances = []
    for i in range(app['count'] - len(running)):
      subnetidx = (i + len(running)) % len(vpc_subnetids)
      if 'public' in app:
        print "Creating PUBLIC instance %i of %i" % (i + 1, app['count'] - len(running))
        interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(
            subnet_id=vpc_pubsubnetids[subnetidx],
            groups=[ str(sg.id) ],
            associate_public_ip_address=True)
        interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)
        resv = awsec2.run_instances(
          security_groups = None,
          image_id = app['ami'],
          min_count = 1,
          max_count = 1,
          key_name = app['keypair'],
          instance_type = app['type'],
          network_interfaces = interfaces,
          block_device_map = mapping,
          instance_initiated_shutdown_behavior = 'terminate',
          instance_profile_name = app['role']
        )
      else:
        print "Creating instance %i of %i" % (i + 1, app['count'] - len(running))
        resv = awsec2.run_instances(
          security_groups = None,
          image_id = app['ami'],
          min_count = 1,
          max_count = 1,
          key_name = app['keypair'],
          security_group_ids = [ str(sg.id) ],
          instance_type = app['type'],
          subnet_id = vpc_subnetids[subnetidx],
          block_device_map = mapping,
          instance_initiated_shutdown_behavior = 'terminate',
          instance_profile_name = app['role']
        )
      for i in resv.instances:
        instances.append(str(i.id))
      if verbose:
        for i in resv.instances:
          print "APP-INST %s %s ami %s type %s host %s %s" % (app['name'], i.id, i.image_id, i.instance_type, i.private_dns_name, i.public_dns_name)

    if (len(instances) > 0):
      tags = {
        "Name": "%s-%s" % (app['name'], conf['aws']['env']),
        conf['aws']['svctag']: app['svctag'],
        conf['aws']['envtag']: conf['aws']['env']
      }
      if 'cluster' in app:
        tags['cluster'] = app['cluster']
      for inst in instances:
        awsec2.create_tags(inst, tags)
      # XXX make this idempotent
      if 'elb' in app:
        running = awselb.register_instances("%s-%s" % (app['elb'], conf['aws']['env']), instances)
      if 'elbs' in app:
          for elbname in app['elbs']:
              # skip if previously created/registered
              if 'elb' in app and elbname == app['elb']:
                  continue
              running = awselb.register_instances("%s-%s" % (elbname, conf['aws']['env']), instances)

    # ElasticIP
    addr_allocid = None
    if 'addrs' in app:
        # Check all addrs
        addrs = awsec2.get_all_addresses(app['addrs'])

        if (len(instances) > 0):
            # Wait for pending instances to start
            pending = len(instances)
            while pending > 0:
                tagfilter = {
                    'tag:%s' % conf['aws']['svctag']: app['svctag'],
                    'tag:%s' % conf['aws']['envtag']: conf['aws']['env'],
                    'vpc-id': vpc.id,
                    'instance-state-name': 'pending'
                }
                pending_inst = awsec2.get_all_instances(filters=tagfilter)
                if not pending_inst or len(pending_inst) == 0:
                    pending = 0
                else:
                    print "Waiting for pending instances to start"
                    time.sleep(eip_pendwait)

        # Pull list of running
        tagfilter = {
            'tag:%s' % conf['aws']['svctag']: app['svctag'],
            'tag:%s' % conf['aws']['envtag']: conf['aws']['env'],
            'vpc-id': vpc.id,
            'instance-state-name': 'running'
        }
        running = awsec2.get_all_instances(filters=tagfilter)
        for addr in addrs:
            if addr.association_id == None:
                for r in running:
                    for i in r.instances:
                        for ifce in i.interfaces:
                            if str(ifce.ipOwnerId) == 'amazon':
                                print "APP-INST %s allocating static %s" % (i.id, addr.public_ip)
                                awsec2.associate_address(
                                        instance_id=i.id,
                                        allocation_id = addr.allocation_id
                                        )
                                # XXX change to identify allocation
                                # reality is AWS account ID
                                ifce.ipOwnerId = 'self'

#
# AutoScale
#

# ASG Launch Configuration
def find_launch(name, ascs):
  for c in ascs:
    # Exact match
    if str(c.name) == name:
      return c
    # Regex match env-name-YYYYMMDDHHMMSS
    if re.match("%s-\d{14}" % name, str(c.name)):
      return c
  return None

def really_get_all_launch_configurations():
  res = []
  lcs = awsasg.get_all_launch_configurations()
  for l in lcs:
    res.append(l)

  while lcs.next_token != None:
    lcs = awsasg.get_all_launch_configurations(next_token=lcs.next_token)
    for l in lcs:
      res.append(l)

  return res

def really_get_all_autoscale_groups():
  res = []
  ags = awsasg.get_all_groups()
  for a in ags:
    res.append(a)

  while ags.next_token != None:
    ags = awsasg.get_all_groups(next_token=ags.next_token)
    for a in ags:
      res.append(a)

  return res

now = datetime.datetime.utcnow()
nowstr = now.strftime("%Y%m%d%H%M%S")

for app in conf['apps']:
  if 'autoscale' in app:
    sg = find_sg(app['group'], sgs)
    asgname = "%s-%s" % (app['name'], conf['aws']['env'])
    asgnamefull = "%s-%s" % (asgname, nowstr)
    asconfigs = sorted(really_get_all_launch_configurations(), key=lambda a: a.name, reverse=True)
    lc = find_launch(asgname, asconfigs)
    if lc != None and 'ami' in app and lc.image_id != app['ami']:
      print "APP-LAUNCH %s ami %s != %s" % (lc.name, lc.image_id, app['ami'])
      lc = None
    if lc != None and lc.instance_type != app['type']:
      print "APP-LAUNCH %s type %s != %s" % (lc.name, lc.instance_type, app['type'])
      lc = None
    if lc != None and lc.key_name != app['keypair']:
      print "APP-LAUNCH %s key %s != %s" % (lc.name, lc.key_name, app['keypair'])
      lc = None
    if lc == None:
      if 'ami' not in app:
          print "ERROR: APP-LAUNCH %s cannot create updated LaunchConfig without AMI mapping" % app['name']
          sys.exit(1)
      if 'public' in app:
        publicip = True
      else:
        publicip = False

      mapping = None
      if app['type'] in bdmapping:
        mapping = boto.ec2.blockdevicemapping.BlockDeviceMapping()
        for b in range(0, bdmapping[app['type']]):
          # punt on dealing with complex case
          if b > 24:
            print "Seriously?  You want more than 24 devices?  Figure this out yourself."
            break
          # sdc..z
          devname= '/dev/sd%s' % chr(ord('b') + b)
          mapping[devname] = boto.ec2.blockdevicemapping.BlockDeviceType(ephemeral_name="ephemeral%d" % b)
          if verbose:
            print "APP-INST block device mapping %s to %s" % (mapping[devname].ephemeral_name, devname)

      print "Creating Launch Config %s" % asgnamefull
      lc = boto.ec2.autoscale.LaunchConfiguration(
          name = asgnamefull,
          security_groups = [ str(sg.id) ],
          image_id = app['ami'],
          key_name = app['keypair'],
          instance_type = app['type'],
          instance_profile_name = app['role'],
          block_device_mappings = [mapping],
          associate_public_ip_address = publicip
      )
      req = awsasg.create_launch_configuration(lc)
      if req == None:
        print "Failed creating launch configuration"
        sys.exit(1)
    if verbose:
      print "APP-LAUNCH %s ami %s type %s key %s role %s" % (lc.name, lc.image_id, lc.instance_type, lc.key_name, lc.instance_profile_name)

    # AutoScaling Group
    astags = []
    astags.append(boto.ec2.autoscale.tag.Tag(
      key='Name', value=asgname,
      propagate_at_launch=True, resource_id=asgname))
    astags.append(boto.ec2.autoscale.tag.Tag(
      key=conf['aws']['envtag'], value=conf['aws']['env'],
      propagate_at_launch=True, resource_id=asgname))
    astags.append(boto.ec2.autoscale.tag.Tag(
      key=conf['aws']['svctag'], value=app['svctag'],
      propagate_at_launch=True, resource_id=asgname))
    astags.append(boto.ec2.autoscale.tag.Tag(
      key='cluster', value=app['cluster'],
      propagate_at_launch=True, resource_id=asgname))

    def find_autoscale(name, asgs):
      for g in asgs:
        if str(g.name) == name:
          return g
      return None

    app_lbname = None
    if 'elb' in app:
        elb = find_elb_conf(app['elb'], conf['elbs'])
        if not elb:
            print "ERROR: APP %s ELB %s does not exist" % (app['name'], app['elb'])
            sys.exit(1)
        elb_sg = find_sg(elb['group'], sgs)
        app_lbname = [ "%s-%s" % (elb['name'], conf['aws']['env']) ]
    if 'elbs' in app:
        for elbname in app['elbs']:
            # skip if previously created/registered
            if 'elb' in app and elbname == app['elb']:
                continue
            if app_lbname == None:
                app_lbname = []

            app_lbname.append("%s-%s" % (elbname, conf['aws']['env']))

    asgroups = really_get_all_autoscale_groups()
    if 'public' in app:
      subnetlist = ",".join(vpc_pubsubnetids)
    else:
      subnetlist = ",".join(vpc_subnetids)
    ag = find_autoscale(asgname, asgroups)
    if ag == None:
      print "Creating Autoscaling Group %s" % asgname
      ag = boto.ec2.autoscale.AutoScalingGroup(
          group_name = asgname,
          availability_zones = conf['vpc']['azs'],
          launch_config = lc,
          load_balancers = app_lbname,
          min_size = app['autoscale']['min'],
          max_size = app['autoscale']['max'],
          tags = astags,
          vpc_zone_identifier = subnetlist,
          connection = awsasg)
      req = awsasg.create_auto_scaling_group(ag)
      if req == None:
        print "Failed creating launch configuration"
        sys.exit(1)
    if verbose:
      print "APP-AUTOSCALE %s size %d-%d elb %s launch %s" % (ag.name, ag.min_size, ag.max_size, ag.load_balancers, ag.launch_config_name)
      if ag.instances != None:
        for i in ag.instances:
          print "APP-ASINST %s %s" % (ag.name, i.instance_id)

    ag_update = 0
    if ag.launch_config_name != lc.name:
      print "Updating Autoscaling Group Launch Config %s -> %s" % (ag.launch_config_name, lc.name)
      ag.launch_config_name = lc.name
      ag_update = 1
    if ag.min_size != app['autoscale']['min']:
      print "Updating Autoscaling Group minimum %d -> %d" % (ag.min_size, app['autoscale']['min'])
      ag.min_size = app['autoscale']['min']
      ag_update = 1
    if ag.max_size != app['autoscale']['max']:
      print "Updating Autoscaling Group maximum %d -> %d" % (ag.max_size, app['autoscale']['max'])
      ag.max_size = app['autoscale']['max']
      ag_update = 1
    if ag.desired_capacity != None and 'count' in app and ag.desired_capacity != app['count']:
        if ag.desired_capacity > app['count']:
            print "WARNING: not decrementing autoscale group %s from %d -> %d" % (
                    app['name'], ag.desired_capacity, app['count'])
        else:
            print "Updating Autoscaling Group capacity %d -> %d" % (ag.desired_capacity, app['count'])
            ag.desired_capacity = app['count']
            ag_update = 1
    if ag_update == 1:
      req = ag.update()

    # ElasticIP
    addr_allocid = None
    if 'addrs' in app:
        # Check all addrs
        addrs = awsec2.get_all_addresses(app['addrs'])

        ag = find_autoscale(asgname, asgroups)
        if ag and len(ag.instances) > 0:
            # Wait for pending instances to start
            pending = len(ag.instances)
            while pending > 0:
                tagfilter = {
                    'tag:%s' % conf['aws']['svctag']: app['svctag'],
                    'tag:%s' % conf['aws']['envtag']: conf['aws']['env'],
                    'vpc-id': vpc.id,
                    'instance-state-name': 'pending'
                }
                pending_inst = awsec2.get_all_instances(filters=tagfilter)
                if not pending_inst or len(pending_inst) == 0:
                    pending = 0
                else:
                    print "Waiting for pending instances to start"
                    time.sleep(eip_pendwait)

        # Pull list of running
        tagfilter = {
            'tag:%s' % conf['aws']['svctag']: app['svctag'],
            'tag:%s' % conf['aws']['envtag']: conf['aws']['env'],
            'vpc-id': vpc.id,
            'instance-state-name': 'running'
        }
        running = awsec2.get_all_instances(filters=tagfilter)
        for addr in addrs:
            if addr.association_id == None:
                for r in running:
                    for i in r.instances:
                        for ifce in i.interfaces:
                            if str(ifce.ipOwnerId) == 'amazon':
                                print "APP-INST %s allocating static %s" % (i.id, addr.public_ip)
                                awsec2.associate_address(
                                        instance_id=i.id,
                                        allocation_id = addr.allocation_id
                                        )
                                # XXX change to identify allocation
                                # reality is AWS account ID
                                ifce.ipOwnerId = 'self'

    # External IP ports
    if 'extports' in app:
        # Pull list of instances
        tagfilter = {
            'tag:%s' % conf['aws']['svctag']: app['svctag'],
            'tag:%s' % conf['aws']['envtag']: conf['aws']['env'],
            'vpc-id': vpc.id
        }
        running = awsec2.get_all_instances(filters=tagfilter)
        for r in running:
            for i in r.instances:
                for ifce in i.interfaces:
                    for port in app['extports']:
                        p_from = port['from']
                        p_to = port['to']
                        p_prot = port['prot']
                        if p_prot != 'udp' and p_prot != 'icmp':
                            p_prot = 'tcp'

                        rule = find_sg_rule_cidr('%s/32' % ifce.publicIp,
                                p_from, p_to, p_prot, sg.rules)
                        if rule == None:
                            print "Creating SG rule for EXTERNAL %s -> SG (%s, %s, %s)" % (
                                    ifce.publicIp, p_from, p_to, p_prot)
                            if awsec2.authorize_security_group(
                                    group_id = sg.id,
                                    cidr_ip = '%s/32' % ifce.publicIp,
                                    ip_protocol = p_prot,
                                    from_port = p_from,
                                    to_port = p_to
                                    ) != True:
                                print "Failed authorizing PUBLIC->SG"
                                sys.exit(1)
                            sgs = awsec2.get_all_security_groups(
                                    filters=vpcfilter)
                            sg = find_sg(app['group'], sgs)
                            rule = find_sg_rule_cidr('0.0.0.0/0', p_from, p_to,
                                    p_prot, sg.rules)
                        if verbose:
                            print "SGRULE %s src %s %s %s:%s" % (sg.name,
                                    rule.grants, rule.ip_protocol,
                                    rule.from_port, rule.to_port)

#
# NAT/VPN instance
#
if 'nat' in conf:
  nat_sg = find_sg(conf['nat']['group'], sgs)
  if nat_sg == None:
    print "Creating Security Group %s for NAT" % (conf['nat']['group'])
    nat_sg = awsec2.create_security_group(conf['nat']['group'], conf['nat']['group'], vpc_id = vpc.id)
    if nat_sg == None:
      print "Failed creating SG %s for NAT" % (conf['nat']['group'])
      sys.exit(1)
    # Refresh SG list to catch the egress rule
    sgs = awsec2.get_all_security_groups(filters=vpcfilter)
    nat_sg = find_sg(conf['nat']['group'], sgs)
  if verbose:
    print "SECGRP-NAT %s %s" % (nat_sg.id, nat_sg.name)

  # 22/ssh
  rule = find_sg_rule_cidr('0.0.0.0/0', 22, 22, 'tcp', nat_sg.rules)
  if rule == None:
    print "Creating SG rule for SSH -> NAT"
    if awsec2.authorize_security_group(group_id = nat_sg.id,
          cidr_ip = '0.0.0.0/0',
          ip_protocol = 'tcp',
          from_port = 22,
          to_port = 22
        ) != True:
      print "Failed authorizing SSH->NAT"
      sys.exit(1)
    sgs = awsec2.get_all_security_groups(filters=vpcfilter)
    nat_sg = find_sg(conf['nat']['group'], sgs)
    rule = find_sg_rule_cidr('0.0.0.0/0', 22, 22, 'tcp', nat_sg.rules)
  if verbose:
    print "SGRULE %s src %s %s %s:%s" % (nat_sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

  # icmp
  if 'privnet' in conf['aws'].keys():
    rule = find_sg_rule_cidr(conf['aws']['privnet'], -1, -1, 'icmp', nat_sg.rules)
    if rule == None:
      print "Creating SG rule for NAT ICMP -> SG"
      if awsec2.authorize_security_group(group_id = nat_sg.id,
            cidr_ip = conf['aws']['privnet'],
            ip_protocol = 'icmp',
            from_port = -1,
            to_port = -1 
          ) != True:
        print "Failed authorizing NAT ICMP->SG"
        sys.exit(1)
      sgs = awsec2.get_all_security_groups(filters=vpcfilter)
      nat_sg = find_sg(conf['nat']['group'], sgs)
      rule = find_sg_rule_cidr(conf['aws']['privnet'], -1, -1, 'icmp', nat_sg.rules)
    if verbose:
      print "SGRULE %s src %s %s %s:%s" % (nat_sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

  # icmp/echoreq
  rule = find_sg_rule_cidr('0.0.0.0/0', 8, -1, 'icmp', nat_sg.rules)
  if rule == None:
    print "Creating SG rule for NAT ICMP"
    if awsec2.authorize_security_group(group_id = nat_sg.id,
          cidr_ip = '0.0.0.0/0',
          ip_protocol = 'icmp',
          from_port = 8,
          to_port = -1 
        ) != True:
      print "Failed authorizing NAT ICMP"
      sys.exit(1)
    sgs = awsec2.get_all_security_groups(filters=vpcfilter)
    nat_sg = find_sg(conf['nat']['group'], sgs)
    rule = find_sg_rule_cidr('0.0.0.0/0', 8, -1, 'icmp', nat_sg.rules)
  if verbose:
    print "SGRULE %s src %s %s %s:%s" % (nat_sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

  # tcp/traceroute
  rule = find_sg_rule_cidr('0.0.0.0/0', 33434, 33534, 'udp', nat_sg.rules)
  if rule == None:
    print "Creating SG rule for TRACEROUTE -> NAT"
    if awsec2.authorize_security_group(group_id = nat_sg.id,
          cidr_ip = '0.0.0.0/0',
          ip_protocol = 'udp',
          from_port = 33434,
          to_port = 33534
        ) != True:
      print "Failed authorizing TRACEROUTE->NAT"
      sys.exit(1)
    sgs = awsec2.get_all_security_groups(filters=vpcfilter)
    nat_sg = find_sg(conf['nat']['group'], sgs)
    rule = find_sg_rule_cidr('0.0.0.0/0', 33434, 33534, 'udp', nat_sg.rules)
  if verbose:
    print "SGRULE %s src %s %s %s:%s" % (nat_sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

  for port in conf['nat']['ports']:
    p_from = port['from']
    p_to = port['to']
    p_prot = port['prot']
    if p_prot != 'udp' and p_prot != 'icmp':
      p_prot = 'tcp'

    # NAT host rule
    rule = find_sg_rule_cidr('0.0.0.0/0', p_from, p_to, p_prot, nat_sg.rules)
    if rule == None:
      print "Creating SG rule for world -> NAT (%u:%u)" % (p_from, p_to)
      if awsec2.authorize_security_group(group_id = nat_sg.id,
            cidr_ip = '0.0.0.0/0',
            ip_protocol = p_prot,
            from_port = p_from,
            to_port = p_to
          ) != True:
        print "Failed authorizing world -> NAT"
        sys.exit(1)
      sgs = awsec2.get_all_security_groups(filters=vpcfilter)
      nat_sg = find_sg(conf['nat']['group'], sgs)
      rule = find_sg_rule_cidr('0.0.0.0/0', p_from, p_to, p_prot, nat_sg.rules)
    if verbose:
      print "SGRULE %s src %s %s %s:%s" % (nat_sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

  # all/vpcnets
  rule = find_sg_rule_cidr(conf['vpc']['cidr'], None, None, '-1', nat_sg.rules)
  if rule == None:
    print "Creating SG rule for ALL-VPC -> NAT"
    if awsec2.authorize_security_group(group_id = nat_sg.id,
          cidr_ip = conf['vpc']['cidr'],
          ip_protocol = '-1'
        ) != True:
      print "Failed authorizing ALL-VPC->NAT"
      sys.exit(1)
    sgs = awsec2.get_all_security_groups(filters=vpcfilter)
    nat_sg = find_sg(conf['nat']['group'], sgs)
    rule = find_sg_rule_cidr(conf['vpc']['cidr'], None, None, '-1', nat_sg.rules)
  if verbose:
    print "SGRULE %s src %s %s %s:%s" % (nat_sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

  rule = find_sg_rule_cidr('0.0.0.0/0', None, None, '-1', nat_sg.rules_egress)
  if rule == None:
    if awsec2.authorize_security_group_egress(group_id = nat_sg.id,
          cidr_ip = '0.0.0.0/0',
          ip_protocol = '-1'
        ) != True:
      print "Failed authorizing NAT->EGRESS"
      sys.exit(1)
    sgs = awsec2.get_all_security_groups(filters=vpcfilter)
    nat_sg = find_sg(conf['nat']['group'], sgs)
    rule = find_sg_rule_cidr('0.0.0.0/0', None, None, '-1', nat_sg.rules_egress)
  if verbose:
    print "SGRULE %s src %s %s %s:%s" % (nat_sg.name, rule.grants, rule.ip_protocol, rule.from_port, rule.to_port)

  if 'aminame' in conf['nat'] and not 'ami' in conf['nat']:
      # Search ami list, find best match
      # 1. {{env}}-{{ami}}-{{date}}
      # 2. all-{{ami}}-{{date}}
      # 3. {{ami}}-{{date}}
      ami = None
      amifilter = { 'name': "%s-%s-*" % (conf['aws']['env'],
          conf['nat']['aminame']) }
      amis = awsec2.get_all_images(filters=amifilter)
      if len(amis) > 0:
          ami = find_amibyname("%s-%s" % (conf['aws']['env'],
              conf['nat']['aminame']),
              sorted(amis, key=lambda a: a.name, reverse=True))
      if ami == None:
          amifilter = { 'name': "all-%s-*" % conf['nat']['aminame'] }
          amis = awsec2.get_all_images(filters=amifilter)
          if len(amis) > 0:
              ami = find_amibyname("all-%s" % conf['nat']['aminame'],
                      sorted(amis, key=lambda a: a.name, reverse=True))
      if ami == None:
          amifilter = { 'name': "%s-*" % conf['nat']['aminame'] }
          amis = awsec2.get_all_images(filters=amifilter)
          if len(amis) > 0:
              ami = find_amibyname("%s" % conf['nat']['aminame'],
                      sorted(amis, key=lambda a: a.name, reverse=True))
      if ami != None:
          conf['nat']['ami'] = ami.id
          if verbose:
              print "AMI mapping %s to %s %s (%s)" % (conf['nat']['aminame'],
                      ami.id, ami.name, ami.description)
      else:
          print "AMI mapping failed for \"%s\" as %s-%s-*, all-%s-*, %s" % (
                  conf['nat']['aminame'], conf['aws']['env'],
                  conf['nat']['aminame'], conf['nat']['aminame'],
                  conf['nat']['aminame'])

  tagfilter = {
      'tag:%s' % conf['aws']['svctag']: conf['nat']['svctag'],
      'tag:%s' % conf['aws']['envtag']: conf['aws']['env'],
      'vpc-id': vpc.id,
      'instance-state-name': 'running'
  }
  running = awsec2.get_all_instances(filters=tagfilter)
  # Check running instances match specification
  for r in running:
    for i in r.instances:
      if i.image_id != conf['nat']['ami']:
        print "WARNING: NAT instance %s not run from requested AMI %s" % (i.id, conf['nat']['ami'])
      if verbose:
        print "NAT-INST %s %s ami %s type %s host %s %s" % (conf['nat']['name'], i.id, i.image_id, i.instance_type, i.private_dns_name, i.public_dns_name)
  if len(running) < 1:
    # create in first public subnet
    subnetidx = nat_subnetidx
    interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(
        subnet_id=vpc_pubsubnetids[subnetidx],
        groups=[ str(nat_sg.id) ],
        associate_public_ip_address=True)
    interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)
    print "Creating NAT instance"
    resv = awsec2.run_instances(
      security_groups = None,
      image_id = conf['nat']['ami'],
      min_count = 1,
      max_count = 1,
      key_name = conf['nat']['keypair'],
      instance_type = conf['nat']['type'],
      network_interfaces = interfaces,
      instance_initiated_shutdown_behavior = 'terminate',
      instance_profile_name =conf['nat']['role'] 
    )
    awsec2.create_tags(resv.instances[0].id, {
      "Name": "%s-%s" % (conf['nat']['name'], conf['aws']['env']),
      conf['aws']['svctag']: conf['nat']['svctag'],
      conf['aws']['envtag']: conf['aws']['env']
    })
    resv.instances[0].update()
    while resv.instances[0].state == 'pending':
      print "Waiting for NAT to start: %s" % resv.instances[0].state
      time.sleep(nat_instwait)
      resv.instances[0].update()
    if verbose:
      for i in resv.instances:
        print "NAT-INST %s %s ami %s type %s host %s" % (conf['nat']['name'], i.id, i.image_id, i.instance_type, i.private_dns_name)

  tagfilter = {
      'tag:%s' % conf['aws']['svctag']: conf['nat']['svctag'],
      'tag:%s' % conf['aws']['envtag']: conf['aws']['env'],
      'vpc-id': vpc.id,
      'instance-state-name': 'running'
  }
  running = awsec2.get_all_instances(filters=tagfilter)
  for resv in running:
    for i in resv.instances:
      nat_instances.append(i.id)
      # XXX use first NAT discovered
      if nat_publicdns == None:
        nat_publicdns = i.public_dns_name

  for inst in nat_instances:
    attr = awsec2.get_instance_attribute(inst, 'sourceDestCheck')
    if attr == None or attr['sourceDestCheck'] != False:
      print "Setting sourceDestCheck on NAT instance"
      if awsec2.modify_instance_attribute(inst, 'sourceDestCheck', False) != True:
        print "Cannot set sourceDestCheck on NAT instance"

#
# ROUTING TABLES
# 1. Main table, assoc priv subnets, connect 0.0.0.0/0 -> NAT
# 2. Public table, assoc pub subnets, connect 0.0.0.0/0 -> IGW
# 3. Public table, connect privnet -> NAT/VPN
#

def find_main_route_table(tables):
  for t in tables:
    for a in t.associations:
      if a.main == True:
        return t
  return None

def find_assoc_bysubnet(subnet, table):
  for a in table.associations:
    if str(a.subnet_id) == subnet:
      return a
  return None

def find_route_bycidr(cidr, table):
  for r in table.routes:
    if str(r.destination_cidr_block) == cidr:
      return r
  return None
    
tables = awsvpc.get_all_route_tables(filters=vpcfilter)
rtmain = find_main_route_table(tables)
if rtmain == None:
  print "No main routing table, I don't know how to help you"
  sys.exit(1)
# find public route table
rtpublic = None
for t in tables:
  if t != rtmain:
    rtpublic = t
    break;
if rtpublic == None:
  print "Creating PUBLIC route table"
  rtpublic = awsvpc.create_route_table(vpc.id)
  if rtpublic == None:
    print "No public routing table, I don't know how to help you"
    sys.exit(1)
if verbose:
  print "RT-MAIN %s" % rtmain.id
  print "RT-PUBLIC %s" % rtpublic.id

# Main routing table
for s in vpc_subnetids:
  if find_assoc_bysubnet(s, rtmain) == None:
    print "Creating MAIN subnet association %s -> %s" % (s, rtmain.id)
    if awsvpc.associate_route_table(rtmain.id, s) == None:
      print "Missing MAIN subnet assoc for %s" % s
      sys.exit(1)
  if verbose:
    print "ROUTE %s subnet %s" % (rtmain.id, s)
route = find_route_bycidr('0.0.0.0/0', rtmain)
if route == None:
  if 'nat' in conf:
    print "Creating MAIN route for 0.0.0.0/0 -> NAT"
    # XXX use first NAT discovered
    route = awsvpc.create_route(rtmain.id, destination_cidr_block='0.0.0.0/0',
        instance_id=nat_instances[0])
  if route == None:
    print "Missing MAIN route for 0.0.0.0/0 -> NAT"
    sys.exit(1)
else:
  if 'nat' in conf:
    if str(route.instance_id) != nat_instances[0]:
      print "WARNING: MAIN route 0.0.0.0/0 does NOT point to NAT %s" % rtmain.id
  if verbose:
    print "ROUTE %s %s instance %s" % (rtmain.id, route.destination_cidr_block, route.instance_id)

# Public routing table
for s in vpc_pubsubnetids:
  if find_assoc_bysubnet(s, rtpublic) == None:
    print "Creating PUBLIC subnet association %s -> %s" % (s, rtpublic.id)
    if awsvpc.associate_route_table(rtpublic.id, s) == None:
      print "Missing PUBLIC subnet assoc for %s" % s
      sys.exit(1)
  if verbose:
    print "ROUTE %s subnet %s" % (rtpublic.id, s)
route = find_route_bycidr('0.0.0.0/0', rtpublic)
if route == None:
  print "Creating PUBLIC route for 0.0.0.0/0 -> IGW"
  if awsvpc.create_route(rtpublic.id, destination_cidr_block='0.0.0.0/0',
      gateway_id=gw.id) != True:
    print "Missing PUBLIC route for 0.0.0.0/0 -> IGW"
    sys.exit(1)
else:
  if str(route.gateway_id) != gw.id:
    print "WARNING: PUBLIC route 0.0.0.0/0 does NOT point to IGW"
  if verbose:
    print "ROUTE %s %s instance %s" % (rtpublic.id, route.destination_cidr_block, route.gateway_id)

# Public routing table -> privnet via vpn
route = find_route_bycidr(conf['aws']['privnet'], rtpublic)
if route == None:
  if 'nat' in conf:
    print "Creating PUBLIC route for %s -> NAT/VPN" % conf['aws']['privnet']
    # XXX use first NAT discovered
    route = awsvpc.create_route(rtpublic.id, destination_cidr_block=conf['aws']['privnet'],
        instance_id=nat_instances[0])
  if route == None:
    print "Missing PUBLIC route for %s -> NAT/VPN" % conf['aws']['privnet']
    sys.exit(1)
else:
  if 'nat' in conf:
    if str(route.instance_id) != nat_instances[0]:
      print "WARNING: PUBLIC route %s does NOT point to NAT %s" % (conf['aws']['privnet'], rtpublic.id)
  if verbose:
    print "ROUTE %s %s instance %s" % (rtpublic.id, route.destination_cidr_block, route.instance_id)

#
# ROUTE53
#
if 'r53xacct' in conf['aws']:
    sts = boto.sts.connect_to_region(conf['aws']['region'], aws_access_key_id = aws_key, aws_secret_access_key = aws_secret)
    tok = sts.assume_role(conf['aws']['r53xacct'], 'cloudcaster')
    awsr53 = boto.connect_route53(
            aws_access_key_id = tok.credentials.access_key,
            aws_secret_access_key = tok.credentials.secret_key,
            security_token = tok.credentials.session_token
            )
else:
    awsr53 = boto.connect_route53()

zone = awsr53.get_zone(conf['aws']['zone'])

# Route53 - NAT instance
if 'nat' in conf:
  myname = "%s-%s.%s-%s.%s.%s" % (conf['nat']['name'], conf['aws']['env'], conf['aws']['provider'], conf['aws']['region'], conf['aws']['continent'], conf['aws']['zone'])
  zonerecs = zone.find_records(myname, 'CNAME')
  if zonerecs == None:
    print "Creating Route53 %s -> %s" % (myname, nat_publicdns)
    zone.add_cname(myname, nat_publicdns)
  else:
    if zonerecs.resource_records[0] != "%s." % nat_publicdns:
      print "Updating Route53 %s FROM %s TO %s" % (myname, zonerecs.resource_records[0], nat_publicdns)
      zone.update_cname(myname, nat_publicdns)
  if verbose:
    print "DNS %s -> %s" % (myname, nat_publicdns)

# Route53 - ELB
for confelb in conf['elbs']:
  elb = find_elb("%s-%s" % (confelb['name'], conf['aws']['env']), elbs)
  myname = "%s-%s.%s-%s.%s.%s" % (confelb['name'], conf['aws']['env'], conf['aws']['provider'], conf['aws']['region'], conf['aws']['continent'], conf['aws']['zone'])
  zonerecs = zone.find_records(myname, 'CNAME')
  if zonerecs == None:
    print "Creating Route53 %s -> %s" % (myname, elb.dns_name)
    zone.add_cname(myname, elb.dns_name)
  else:
    if zonerecs.resource_records[0] != "%s." % elb.dns_name:
      print "Updating Route53 %s FROM %s TO %s" % (myname, zonerecs.resource_records[0], elb.dns_name)
      zone.update_cname(myname, elb.dns_name)
  if verbose:
    print "DNS %s -> %s" % (myname, elb.dns_name)
