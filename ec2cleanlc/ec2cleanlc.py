#!/usr/bin/python
#
# Copyright (c) 2014 Vincent Janelle <randomfrequency@gmail.com>
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
# Tiny bits of logic taken from Cloudcaster.py, @WrathOfChris
#

import argparse
import boto
import boto.ec2
import boto.ec2.autoscale
import boto.ec2.elb
import boto.route53
import boto.route53.zone
import boto.vpc
import datetime
import json
import os
import re
import sys
import time
import pprint

from operator import itemgetter, attrgetter

MAX_COUNT=5
pp = pprint.PrettyPrinter(indent=4)

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
awsr53 = boto.connect_route53()
awsasg = boto.ec2.autoscale.connect_to_region(conf['aws']['region'], aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)

lc_groups = {}

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

def extract_lc_names(config):
    match = re.search("(.+)-(\d{14})", config.name)
    if match:
        # "%Y%m%d%H%M%S"
        date = time.strptime(match.group(2), "%Y%m%d%H%M%S")
        return [ match.group(1), date ]

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

var = {}

def keyitup(entry):
    name = entry[0]
    date = entry[1]
    if name in var:
        var[name].append(date)
    else:
        var[name] = [ date ]

lc = really_get_all_launch_configurations()

lc_groups = list(map(extract_lc_names, lc))

lc_groups = sorted(lc_groups, key=itemgetter(0,1), reverse=False)

map(keyitup, lc_groups)

for name in var:
    count = len(var[name])
    if count > MAX_COUNT:

        for i in range(0,count - MAX_COUNT):
            death = var[name][i]
            res = awsasg.delete_launch_configuration("%s-%s" % ( name, time.strftime("%Y%m%d%H%M%S",death) ) )

            pp.pprint(res)

