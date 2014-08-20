#!/usr/bin/env python

import json
import argparse
import yaml
from yaml import Loader, Dumper
from pprint import pprint

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

print yaml.safe_dump(conf)

