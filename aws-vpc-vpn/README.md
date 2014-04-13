## AWS VPC VPN

![aws-vpc-vpn](https://raw.githubusercontent.com/WrathOfChris/ops/cm-awsvpcvpn/aws-vpc-vpn/examples/aws-vpc-vpn.png)

### Build AMI images for the NAT-HUB, VPN-HUB, and NAT-VPN
- Change the vpn.hub address in group_vars/all to an ElasticIP you own.
- Change the apps.vpn-hub.address in examples/example-hub.json

```
./build.sh nat-hub all us-west-2
./build.sh vpn-hub all us-west-2
./build.sh nat-vpn all us-west-2
```

### Use cloudcaster to deploy HUB VPC and client VPC
Change the keypair names in:

- group_vars/all
- examples/example-hub.json
- examples/example-client.json

```
../cloudcaster/cloudcaster.py examples/example-hub.json
../cloudcaster/cloudcaster.py examples/example-client.json
```
