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
import os

try:
    import SoftLayer
except ImportError:
    print('SoftLayer required')
    sys.exit(1)

envtag = 'env'
svctag = 'service'
clutag = 'cluster'
env = ''
svc = ''
clu = ''
name = ''
extip = ''
region = ''

sfl_username = None
sfl_apikey = None
if 'SFL_USERNAME' in os.environ:
  sfl_username = os.environ['SFL_USERNAME']
if 'SFL_APIKEY' in os.environ:
  sfl_apikey = os.environ['SFL_APIKEY']

client = SoftLayer.Client(username=sfl_username, api_key=sfl_apikey,
        endpoint_url=SoftLayer.API_PRIVATE_ENDPOINT)

instid = client['Resource_Metadata'].getId()
tags = client['Resource_Metadata'].getTags()
region = client['Resource_Metadata'].getDatacenter()
extip = client['Resource_Metadata'].getPrimaryIpAddress()
name = client['Resource_Metadata'].getHostname()
fqdn = client['Resource_Metadata'].getFullyQualifiedDomainName()

for t in tags:
    if t.startswith(envtag + '_'):
        env = t
    elif t.startswith(svctag + '_'):
        svc = t
    elif t.startswith(clutag + '_'):
        clu = t

if env != '':
  print "environ: %s" % env
if svc != '':
  print "service: %s" % svc
if clu != '':
  print "cluster: %s" % clu
if name != '':
  print "name:    %s" % name
if fqdn != '':
  print "public:  %s" % fqdn
if extip != '':
  print "ipaddr:  %s" % extip
if region != '':
  print "region:  %s" % region
print "instid:  %s" % instid
