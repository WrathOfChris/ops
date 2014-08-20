#!/usr/bin/env python
#
# Copyright (c) 2014 Chris Maxwell <chris@wrathofchris.com>
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
import boto.utils
import boto.vpc
import filecmp
import os
import sys
import tempfile
from pprint import pprint

svctag = 'service'
envtag = 'env'

aws_key = None
aws_secret = None
if 'AWS_ACCESS_KEY' in os.environ:
  aws_key = os.environ['AWS_ACCESS_KEY']
if 'AWS_SECRET_KEY' in os.environ:
  aws_secret = os.environ['AWS_SECRET_KEY']

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--service", help="service tag")
parser.add_argument("-e", "--environ", help="environment tag")
parser.add_argument("-f", "--filename", help="file to write")
parser.add_argument("-r", "--region", help="region")
args = parser.parse_args()

if not args.region:
    if args.auto:
        identity = boto.utils.get_instance_identity()
        args.region = identity['document']['region']
    else:
        args.region = 'us-east-1'

awsec2 = boto.ec2.connect_to_region(args.region, aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret)
awsvpc = boto.vpc.connect_to_region(args.region, aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret)
meta = boto.utils.get_instance_metadata()

# Get own VPC IPv4
mac = meta['mac']
my_ipv4 = meta['network']['interfaces']['macs'][mac]['vpc-ipv4-cidr-block']

def find_vpc(vpc_id, vpcs):
  for v in vpcs:
    if v.id == vpc_id:
      return v
  return None

vpcs = awsvpc.get_all_vpcs()

tagfilter = { 'instance-state-name': 'running',
  'tag:%s' % svctag: args.service
}
if args.environ != None:
  tagfilter['tag:%s' % envtag] = args.environ
running = awsec2.get_all_instances(filters=tagfilter)

# Open temp file after all ec2 work is done
if args.filename != None:
  outfile = tempfile.NamedTemporaryFile(dir=os.path.dirname(args.filename), delete=False)
else:
  outfile = sys.stdout

for inst in running:
  for i in inst.instances:
    vpc = find_vpc(i.vpc_id, vpcs)
    # Skip local subnet
    if str(vpc.cidr_block) == str(my_ipv4):
      continue
    outfile.write("conn %s\n" % i.vpc_id)
    outfile.write("    right=%s\n" % i.ip_address)
    outfile.write("    rightsubnet=%s\n" % vpc.cidr_block)
    outfile.write("\n")

if args.filename != None:
  outfile.close()
  if os.path.exists(args.filename) == False or filecmp.cmp(outfile.name, args.filename) == False:
    os.rename(outfile.name, args.filename)
    os.chmod(args.filename, 0644)
    os.system("/sbin/service ipsec reload")
  else:
    os.remove(outfile.name)
