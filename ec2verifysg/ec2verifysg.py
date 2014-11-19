#!/usr/bin/env python
import argparse
import sys, os
try:
    import boto
except ImportError:
    print 'boto required'
    sys.exit(1)
from distutils.version import LooseVersion
if LooseVersion(boto.Version) < LooseVersion("2.34.0"):
    print 'boto >= 2.34.0 required'
    sys.exit(1)
import boto.ec2
import boto.vpc
import json, yaml

if 'AWS_ACCESS_KEY' in os.environ:
    aws_key = os.environ['AWS_ACCESS_KEY']
else:
    aws_key = None
if 'AWS_SECRET_KEY' in os.environ:
    aws_secret = os.environ['AWS_SECRET_KEY']
else:
    aws_secret = None

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help="verbosity", action="store_true")
parser.add_argument("-f", "--file", help="cloudcaster declaration")
parser.add_argument(
    'group',
    metavar='GROUP',
    nargs='*',
    type=str,
    help='security group name to verify')

args = parser.parse_args()
if args.file == None:
    parser.print_help()
    sys.exit(1)

verbose = args.verbose

conffile = open(args.file).read()

confrules = list()
liverules = list()

# If the file ends with .yaml, load as yaml
if args.file.lower().endswith(".yaml"):
    conf = yaml.load(conffile)
else:
    conf = json.loads(conffile)

awsvpc = boto.vpc.connect_to_region(
        conf['aws']['region'],
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret)
awsec2 = boto.ec2.connect_to_region(
        conf['aws']['region'],
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret
        )

def refresh_vpc():
    vpcs = awsvpc.get_all_vpcs()
    return vpcs

def find_vpc(cidr, vpcs):
    for v in vpcs:
        if v.cidr_block == cidr:
            return v
    return None

def find_elb(name, elbs):
    for e in elbs:
        if str(name) == str(e['name']):
            return e
    return None

vpcs = refresh_vpc()
vpc = find_vpc(conf['vpc']['cidr'], vpcs)

if vpc == None:
    print "VPC %s not found" % (conf['vpc']['cidr'])
    sys.exit(1)

def find_sg(sg, sgs):
    for s in sgs:
        if s.name == sg:
            return s
    return None

def compare_sgname(sg1, sg2):
    if str(sg1) == str(sg2):
        return True
    return False

def compare_sgnames(sgname, sglist):
    for sg in sglist:
        if compare_sgname(sgname, sg):
            return True
    return False

def compare_grants(rule1, rule2):
    if str(rule1['group_id']) != str(rule2['group_id']):
        return False
    if str(rule1['from_port']) != str(rule2['from_port']):
        return False
    if str(rule1['to_port']) != str(rule2['to_port']):
        return False
    if str(rule1['ip_protocol']) != str(rule2['ip_protocol']):
        return False
    if 'src_group_id' in rule1 and 'src_group_id' not in rule2:
        return False
    if 'src_group_id' in rule2 and 'src_group_id' not in rule1:
        return False
    if 'src_group_id' in rule1 and 'src_group_id' in rule2:
        if str(rule1['src_group_id']) != str(rule2['src_group_id']):
            return False
    if 'cidr_ip' in rule1 and 'cidr_ip' not in rule2:
        return False
    if 'cidr_ip' in rule2 and 'cidr_ip' not in rule1:
        return False
    if 'cidr_ip' in rule1 and 'cidr_ip' in rule2:
        if str(rule1['cidr_ip']) != str(rule2['cidr_ip']):
            return False
    return True

vpcfilter = {'vpc_id': vpc.id}
sgs = awsec2.get_all_security_groups(filters=vpcfilter)

def make_rule_grant(group_id, from_port, to_port, ip_protocol,
        src_group=None, src_group_id=None, cidr_ip=None):
    rule = dict()
    rule['group_id'] = str(group_id)
    rule['from_port'] = str(from_port)
    rule['to_port'] = str(to_port)
    rule['ip_protocol'] = str(ip_protocol)
    if src_group:
        sg = find_sg(src_group, sgs)
        if not sg:
            print "grant to unknown group %s" % src_group
            sys.exit(1)
        rule['src_group_id'] = str(sg.id)
    if src_group_id:
        rule['src_group_id'] = str(src_group_id)
    if cidr_ip:
        rule['cidr_ip'] = str(cidr_ip)
    return rule

def make_confrule(group_name, group_id, from_port, to_port, ip_protocol,
        src_group=None, src_group_id=None, cidr_ip=None):
    for rule in confrules:
        if rule['name'] == group_name:
            if 'grants' not in rule or not rule['grants']:
                rule['grants'] = list()
            rule['grants'].append(make_rule_grant(
                group_id, from_port, to_port, ip_protocol,
                src_group, src_group_id, cidr_ip))
            return
    rule = {
            'name': str(group_name),
            'grants': list()
            }
    rule['grants'].append(make_rule_grant(
        group_id, from_port, to_port, ip_protocol,
        src_group, src_group_id, cidr_ip))
    rule = confrules.append(rule)

def make_liverule(group_name, group_id, from_port, to_port, ip_protocol,
        src_group=None, src_group_id=None, cidr_ip=None):
    for rule in liverules:
        if rule['name'] == group_name:
            if 'grants' not in rule or not rule['grants']:
                rule['grants'] = list()
            rule['grants'].append(make_rule_grant(
                group_id, from_port, to_port, ip_protocol,
                src_group, src_group_id, cidr_ip))
            return
    rule = {
            'name': str(group_name),
            'grants': list()
            }
    rule['grants'].append(make_rule_grant(
        group_id, from_port, to_port, ip_protocol,
        src_group, src_group_id, cidr_ip))
    rule = liverules.append(rule)

print ""
print "security groups being verified"
print "------------------------------"

for elb in conf['elbs']:
    if compare_sgnames(elb['group'], args.group):
        sg = find_sg(elb['group'], sgs)
        print "%s %s" % (sg.id, elb['group'])

        # IN: ports: 0.0.0.0/0 -> port
        if 'ports' in elb:
            for port in elb['ports']:
                make_confrule(elb['group'], sg.id, port['from'], port['to'],
                        port['prot'], cidr_ip='0.0.0.0/0')

        # IN: allow:
        if 'allow' in elb:
            for allow in elb['allow']:
                src_group = None
                cidr_ip = None
                if 'group' in allow:
                    src_group = allow['group']
                if 'cidr' in allow:
                    cidr_ip = allow['cidr']
                make_confrule(elb['group'], sg.id, allow['from'],
                        allow['to'], allow['prot'],
                        src_group=src_group,
                        cidr_ip=cidr_ip)

    if 'groups' in elb:
        for elbgroup in elb['groups']:
            if compare_sgnames(elbgroup, args.group):
                print "ELB %s belongs to unverified group %s" % (
                        elb['name'], elbgroup)

for app in conf['apps']:
    if not compare_sgnames(app['group'], args.group):
        # XXX only compares the first group
        continue
    sg = find_sg(app['group'], sgs)
    print "%s %s" % (sg.id, app['group'])
    if not sg:
        print "APP %s has no security group" % app['name']
        sys.exit(1)
    if 'groups' in app:
        for appgroup in app['groups']:
            if compare_sgnames(appgroup, args.group):
                print "APP %s belongs to unverified group %s" % (
                        app['name'], appgroup)

    # ELB->APP: elb.listeners
    elbnames = list()
    if 'elb' in app:
        elbnames.append(app['elb'])
    if 'elbs' in app:
        for e in app['elbs']:
            elbnames.append(app['elb'])
    for e in elbnames:
        elb = find_elb(e, conf['elbs'])
        if not elb:
            print "APP %s cannot find ELB %s" % (app['name'], e)
            sys.exit(1)
        elb_sg = find_sg(elb['group'], sgs)
        if 'listeners' in elb:
            for l in elb['listeners']:
                make_confrule(app['group'], sg.id, l['from'], l['to'],
                        'tcp', src_group_id=elb_sg.id)

    # APP->APP: ports: (app) -> port
    if 'ports' in app:
        for port in app['ports']:
            make_confrule(app['group'], sg.id, port['from'], port['to'],
                    port['prot'], src_group_id=sg.id)

    # IN: allow:
    if 'allow' in app:
        for allow in app['allow']:
            src_group = None
            cidr_ip = None
            if 'group' in allow:
                src_group = allow['group']
            if 'cidr' in allow:
                cidr_ip = allow['cidr']
            make_confrule(app['group'], sg.id, allow['from'],
                    allow['to'], allow['prot'],
                    src_group=src_group,
                    cidr_ip=cidr_ip)

    # IN: pubports:
    if 'pubports' in app:
        for port in app['pubports']:
            make_confrule(app['group'], sg.id, port['from'], port['to'],
                    port['prot'], cidr_ip='0.0.0.0/0')

    # OUT: defaults:
    if 'default_rules' not in conf['vpc']:
        # SSH:APP
        make_confrule(app['group'], sg.id, '22', '22', 'tcp',
                cidr_ip='0.0.0.0/0')

        # ICMP:APP
        make_confrule(app['group'], sg.id, '-1', '-1', 'icmp',
                cidr_ip=conf['aws']['privnet'])

    # OUT: default_rules override defaults:
    if 'default_rules' in conf['vpc']:
        for rule in conf['vpc']['default_rules']:
            src_group = None
            cidr_ip = None
            if 'group' in rule:
                src_group = rule['group']
            if 'cidr_ip' in rule:
                cidr_ip = rule['cidr_ip']
            make_confrule(app['group'], sg.id, rule['from_port'],
                    rule['to_port'], rule['ip_protocol'],
                    src_group=src_group,
                    cidr_ip=cidr_ip)

# LOAD SECURITY GROUPS
for group in args.group:
    sg = find_sg(group, sgs)
    if not sg:
        print "cannot find live security group %s" % group
        sys.exit(1)
    for rule in sg.rules:
        src_group_id = None
        cidr_ip = None
        for r in rule.grants:
            if r.cidr_ip:
                cidr_ip = r.cidr_ip
            if r.group_id:
                src_group_id = r.group_id
            make_liverule(group, sg.id, rule.from_port, rule.to_port,
                    rule.ip_protocol, src_group_id=src_group_id,
                    cidr_ip=cidr_ip)

print ""
print "rules verified live"
print "-------------------"
for rule in liverules:
    for grant in rule['grants']:
        print "%s %s" % (rule['name'], json.dumps(grant))

for confrule in confrules:
    for liverule in liverules:
        if confrule['name'] == liverule['name']:
            for g1 in confrule['grants'][:]:
                for g2 in liverule['grants'][:]:
                    if compare_grants(g1, g2):
                        confrule['grants'].remove(g1)
                        liverule['grants'].remove(g2)
                        break

for liverule in confrules:
    for confrule in liverules:
        if confrule['name'] == liverule['name']:
            for g1 in liverule['grants'][:]:
                for g2 in confrule['grants'][:]:
                    if compare_grants(g1, g2):
                        liverule['grants'].remove(g1)
                        confrule['grants'].remove(g2)
                        break
print ""
print "rules in configuration, but not live"
print "------------------------------------"
for rule in confrules:
    for grant in rule['grants']:
        print "%s %s" % (rule['name'], json.dumps(grant))

print ""
print "rules live, but not in configuration"
print "------------------------------------"
for rule in liverules:
    for grant in rule['grants']:
        print "%s %s" % (rule['name'], json.dumps(grant))
