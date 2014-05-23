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
# CONFIGURATION
# -------------
#
# Environment: (optional)
#   SFL_USERNAME
#   SFL_APIKEY
#   SFL_CREDS_FILE
#
# ~/.softlayer_credentials:
#   [softlayer]
#   username=
#   apikey=
#
import ConfigParser
import os
import os.path
import sys
from pprint import pprint

try:
    import json
except ImportError:
    import simplejson as json

try:
    import SoftLayer
except ImportError:
    print('SoftLayer required')
    sys.exit(1)

SFL_CONFIG_SECTION = 'softlayer'
SFL_DEFAULT_CREDS_FILE = '~/.softlayer_credentials'

class SoftLayerInventory(object):
    def __init__(self):
        self.inventory = {}     # Ansible Inventory
        self.inventory['_meta'] = {}
        self.inventory['_meta']['hostvars'] = {}
        self.username = None
        self.apikey = None
        self.credsfile = None

        self.setup_creds()

        self.client = SoftLayer.Client(username=self.username,
                api_key=self.apikey)

        self.get_inventory()
        print json.dumps(self.inventory)

    def setup_creds(self):
        if 'SFL_CREDS_FILE' in os.environ:
            self.credsfile = os.path.expanduser(os.environ['SFL_CREDS_FILE'])
            if not os.path.isfile(self.credsfile):
                self.credsfile = None
        if not self.credsfile:
            self.credsfile = os.path.expanduser(SFL_DEFAULT_CREDS_FILE)
            if not os.path.isfile(self.credsfile):
                self.credsfile = None
        if self.credsfile:
            config = ConfigParser.SafeConfigParser()
            config.read(self.credsfile)
            self.username = config.get(SFL_CONFIG_SECTION, 'username')
            self.apikey = config.get(SFL_CONFIG_SECTION, 'apikey')

        # environment overrides config
        if 'SFL_USERNAME' in os.environ:
            self.username = os.environ['SFL_USERNAME']
        if 'SFL_APIKEY' in os.environ:
            self.apikey = os.environ['SFL_APIKEY']

        if not self.username or not self.apikey:
            sys.stderr.write('No environment set or no creds file %s\n'
                    % SFL_DEFAULT_CREDS_FILE)
            sys.exit(1)

    def get_inventory(self):
        # NOTE: API is eventually consistent, but returns partial data during
        #       creation and deletion of instances
        for v in self.client['Account'].getVirtualGuests(mask='datacenter, \
                host, operatingSystem, orderedPackageId, powerState, \
                serverRoom, sshKeys, status, tagReferences, userData, \
                networkComponents'):
            self.host = {}
            self.host['sfl_launch_time'] = ''
            if 'createDate' in v:
                self.host['sfl_launch_time'] = v['createDate']
            self.host['sfl_dns_name'] = ''
            if 'fullyQualifiedDomainName' in v:
                self.host['sfl_dns_name'] = v['fullyQualifiedDomainName']
            self.host['sfl_id'] = v['id']
            self.host['sfl_guid'] = v['globalIdentifier']
            self.host['sfl_uuid'] = v['uuid']
            self.host['sfl_state'] = v['powerState']['name']
            self.host['sfl_ip_address'] = ''
            if 'primaryIpAddress' in v:
                self.host['sfl_ip_address'] = v['primaryIpAddress']
            self.host['sfl_private_ip_address'] = ''
            if 'primaryBackendIpAddress' in v:
                self.host['sfl_private_ip_address'] = v['primaryBackendIpAddress']
            self.host['sfl_cpu'] = v['maxCpu']
            self.host['sfl_mem'] = v['maxMemory']
            self.host['sfl_hostname'] = ''
            if 'hostname' in v:
                self.host['sfl_hostname'] = v['hostname']
            self.host['sfl_domain'] = ''
            if 'domain' in v:
                self.host['sfl_domain'] = v['domain']
            self.host['sfl_region'] = ''
            if 'datacenter' in v:
                self.host['sfl_region'] = v['datacenter']['name']
            self.host['sfl_rack'] = ''
            if 'serverRoom' in v:
                self.host['sfl_rack'] = v['serverRoom']['name']
            self.host['sfl_key_name'] = ''
            if len(v['sshKeys']) > 0:
                self.host['sfl_key_name'] = v['sshKeys'][0]['label']
            self.host['sfl_kernel'] = ''
            if 'operatingSystem' in v:
                self.host['sfl_kernel'] = \
                        v['operatingSystem']['softwareLicense']['softwareDescription']['referenceCode']

            # Create a usable type by mashing cpu/memory/network
            # ie: 4 CPU, 8GB RAM, 100Mbit Net ==> c4m8n100
            self.host['sfl_type'] = 'c%sm%s' % (v['maxCpu'],
                    v['maxMemory'] / 1024)
            if 'networkComponents' in v:
                if len(v['networkComponents']) > 0:
                    self.host['sfl_type'] += \
                        'n%s' % v['networkComponents'][0]['maxSpeed']

            #
            # Inventory Mappings
            #

            # XXX really want a reachable hostname here
            hostkey = self.host['sfl_ip_address']

            # host -> _meta.hostvars.fqdn
            self.inventory['_meta']['hostvars'][hostkey] = self.host

            # host -> RPTR (a.b.c.d-static.reverse.softlayer.com.)
            ipbytes = self.host['sfl_ip_address'].split('.')
            rptr = "%s-%s-%s-%s-static.reverse.softlayer.com" % (
                    ipbytes[3], ipbytes[2], ipbytes[1], ipbytes[0])
            self.inventory[rptr] = list()
            self.inventory[rptr].append(hostkey)

            # host -> fqdn
            if self.host['sfl_dns_name'] not in self.inventory:
                self.inventory[ self.host['sfl_dns_name'] ] = list()
            self.inventory[ self.host['sfl_dns_name'] ].append(hostkey)

            # host -> domain
            if self.host['sfl_domain'] not in self.inventory:
                self.inventory[ self.host['sfl_domain'] ] = list()
            self.inventory[ self.host['sfl_domain'] ].append(hostkey)

            # host -> tags
            if 'tagReferences' in v:
                for t in v['tagReferences']:
                    if 'tag_' + t['tag']['name'] not in self.inventory:
                        self.inventory[ 'tag_' + t['tag']['name'] ] = list()
                    self.inventory[ 'tag_' + t['tag']['name'] ].append(hostkey)

            # host -> DC
            if self.host['sfl_region'] not in self.inventory:
                self.inventory[ self.host['sfl_region'] ] = list()
            self.inventory[ self.host['sfl_region'] ].append(hostkey)

# Run!
SoftLayerInventory()
