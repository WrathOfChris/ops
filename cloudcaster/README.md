# Cloudcaster

## NAME
**cloudcaster.py** -- cloud environment creator

## SYNOPSIS
**cloudcaster.py** [**-v**|**--verbose**] _filename.json_

## DESCRIPTION

**cloudcaster** is a tool to automate the building of cloud environments from a single specification file.  Its sole goal is to create VPC-based environments like I want them.  Cloudcaster costs money, it requests the creation of instances and infrastructure based on the credentials you have in your environment.

This tool is designed to interpret a comprehend-able specification file and ensure that the running cloud environment matches the specification.  The source-of-truth for the running system remains the cloud provider, however the specification can be source-controlled and re-run in an idempotent manner against live infrastructure to ensure compliance.  This tool is _additive_.  It does not consider any objects outside of the specification.  Removing an _app_ from the spec will not remove the app from production, nor terminate instances.  Changing the name will create a new app based on the new specification.  The only mutation of currently running instances is the app _count_ parameter in conjunction with AutoScaleGroups, which adjusts the _desired capacity_ of the ASG and will attempt to meet the desire, increasing or decreasing nodes as necessary.

A special "Ops" VPC is needed to pull together the infrastructure.  This VPC contains a VPN concentrator that pulls together the private networking of the VPCs for SSH access.  It is best if the VPN concentrator uses a static ElasticIP which has to be assigned manually post-cloudcast, and registered as ie: vpn.example.com.

Two special images are required for VPN operation:
* **ami-vpc-nat** - Amazon VPC-NAT base instance, needed for the VPN concentrator and the OPS-NAT instance
* **vpc-nat-vpn** - NAT+VPN instance, based on **ami-vpc-nat** but with VPN routes for all other VPCs.

## OPTIONS

**-v --verbose**
Print all settings of the AWS environment as the live settings are verified.

## DNS NAMING
DNS names within cloudcaster are designed to be stable, using CNAME pointers to abstract the AWS unique hostnames and allow swapping of services behind the scenes.

* **svc.example.com** - stable service endpoints for cloud services
* **_continent_.svc.example.com** - continents are for geo-balancing requests.  ie: us1.example.com
* **_region_.continent.svc.example.com** - regions are provider regions.  ie: ec2-us-east-1.us1.example.com

This naming pattern allows us to explicitly specify service locations if needed, yet provide geo-load-balanced service endpoints to clients in normal cases.  ie: myapp.example.com -> myapp.ec2-us-west-2.us1.example.com -> myapp-012345678910.us-west-2.elb.amazonaws.com => instance[1..n]

## FILE FORMAT
Cloudcaster uses JSON as a specification for the cloud environment to create.  A single specification corresponds to a single VPC/environment within AWS.  Multiple Elastic Load Balancers (ELBs) and Applications may be specified in an array.

### aws

```
  "aws": {
    "continent": "us1",
    "provider": "ec2",
    "region": "us-west-2",
    "privnet": "10.0.0.0/8",
    "svctag": "service",
    "envtag": "env",
    "env": "prod",
    "zone": "example.com."
  }
```

* **aws.continent** - subdomain of **aws.zone** that distinguishes groups of regions.  ie: (_us1_, _eu1_, _ap1_).  Used for stable DNS hostnames with per-continent delegation.
* **aws.provider** - cloud provider this specification is being used with.  Currently only supports _ec2_ but when needed may be extended to ie: _rax_, _joy_, _gce_, etc.  Used for stable DNS hostnames.
* **aws.region** - region to target for this specification.  Multi-region specifications are not supported, and you really don't want them.  Use two specifications.  Used for stable DNS hostnames.
* **aws.privnet** - VPN private network.  VPC networks must be within this range to communicate.
* **aws.svctag** - service tag to use for specifying app services.  Use "service"
* **aws.envtag** - environment tag to differentiating environments and setting per-env variables.  Use "env"
* **env** - environment this specification is targeting.  This is freeform, but only (dev, stage, prod) have understood meaning.  Using others such as "test" will require scaffolding in ansible for plays that rely on global settings.
* **zone** - DNS zone to register with for stable DNS hostnames.  Route53 is used to set stable endpoint names that direct to ELB's and instances.

### vpc

```
  "vpc": {
    "cidr": "10.0.0.0/22",
    "subnets": [ "10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24" ],
    "pubsubnets": [ "10.0.3.0/26", "10.0.3.64/26", "10.0.3.128/26" ],
    "azs": [ "us-west-2a", "us-west-2b", "us-west-2c" ]
  }
```

* **vpc.cidr** - network for this VPC.  This is permanent and unique.
* **vpc.subnets** - array of subnets to use for the **private** networks.  Must match the number of AZ's
* **vpc.pubsubnets** - array of subnets to use for the **public** networks.  Must match the number of AZ's
* **vpc.azs** - array of Availability Zones for this VPC to span

### nat

```
  "nat": {
    "name": "nat-example",
    "group": "nat-example",
    "svctag": "nat",
    "_comment": "Use amzn-ami-vpc-nat-pv-2013.09.0.x86_64-ebs for Ops VPC",
    "ami": "ami-f032acc0",
    "type": "t1.micro",
    "keypair": "wrathofchris-201401",
    "role": "discovery",
    "psk": "If I only had a secret to share",
    "ports": [
      { "from": 500, "to": 500, "prot": "udp" },
      { "from": 4500, "to": 4500, "prot": "udp" }
    ]
  }
```

* **nat.name** - name of the NAT/VPN instance.  Primarily for identification and DNS hostname
* **nat.group** - security group name for the NAT/VPN instance.  Used for inter-group security rules
* **nat.svctag** - service tag to be assigned.  "nat" is special and detected by cron scripts on the ops VPN concentrator to build OpenSWAN ipsec tunnel endpoints.
* **nat.ami** - ID of the AMI to use for the NAT/VPN instance.  Should be the 'ami-vpc-nat' instance from Amazon configured with the 'vpn' role in ansible.
* **nat.type** - instance type for the NAT/VPN instance.  t1.micro is good for command & control, however larger instances should be used if production traffic will be pushed over the VPN links.
* **nat.keypair** - keypair to use default access to the NAT/VPN instance.  We should define key usage and roles better.
* **nat.psk** - the Pre-Shared Key for IPsec tunnels.  Revisit this later when inter-VPC security is a concern.  Right now only encrypted SSH goes over the tunnels so this is a valid compromise.
* **nat.ports** - public ports allowed access to the NAT/VPN instance.  500 = ipsec, 4500 = ipsec-nat

### elbs
"elbs": [ {}, {} ]

```
  "elbs": [
    {
      "name": "example",
      "group": "example-elb-prod",
      "ports": [
        { "from": 80, "to": 80, "prot": "tcp" },
        { "from": 443, "to": 443, "prot": "tcp" }
      ],
      "listeners": [
        { "from": 80, "from_prot": "http", "to": 80, "to_prot": "http" },
        { "from": 443, "from_prot": "https", "to": 443, "to_prot": "https", "cert": "wrathofchris-example-2014" }
      ],
      "interval": 20,
      "healthy": 3,
      "unhealthy": 5,
      "target": "HTTP:80/"
    }
  ]
```

* **elbs[].name** - global name of the ELB, postfixed with the environment set globally (ie: -stage).  This could conflict with ANY other ELB in the account.
* **elbs[].group** - security group name for the ELB hosts.  VPC ELBs now belong to a normal security group, and can be restricted to IP-based ACL.  At present, cloudcaster by default uses 0.0.0.0/0 but may be extended in future to restrict this.
* **elbs[].internal** - make this ELB and _internal_ ELB for within the VPC only.
* **elbs[].ports[]** - list of public ports to authorize external access to.  Listeners are not automatically authorized.
* **elbs[].allow[]** - list of security groups to allow access to the ELB.  For internal groups when public ports are not authorized.
* **elbs[].listeners[]** - set up ELB listener based on { from, from_prot, to, to_prot, cert }.  From is the inbound listener.  To is the outbound connection to private hosts.  For SOA, use standard web 80/443 externally and redirect to erlang service ports internally.  Cert is matched based on the name of the cert registered in IAM.  Protocols are standard ELB: HTTP, HTTPS, TCP, SSL.
* **elbs[].interval** - interval in seconds to poll hosts for alive-ness
* **elbs[].healthy** - number of healthy polls required to return to service
* **elbs[].unhealthy** - number of unhealthy polls before instance is removed from rotation
* **elbs[].target** - the ELB healthcheck target.  See [ELB - Configuring Health Checks](http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/gs-ec2classic.html#ConfigureHealthCheck) for more information.

### apps
"apps": [ {}, {} ]

```
  "apps": [
    {
      "name": "exampleapp",
      "svctag": "example",
      "cluster": "blue",
      "group": "example-prod",
      "elb": "example",
      "ami": "ami-ccf297fc",
      "type": "t1.micro",
      "role": "discovery",
      "keypair": "wrathofchris-201401",
      "count": 1,
      "ports": [
        { "from": 22, "to": 22, "prot": "tcp" }
      ],
      "autoscale": {
        "min": 0,
        "max": 1
      }
    }
  ]
```

* **apps[].name** - name of the application.  Used for tag Name= and for autoscale group name (if specified)
* **apps[].svctag** - service tag for the application.  Should be unique within your account, however it is not enforced.  The tuple (env, service, cluster) should _definitely_ be unique.
* **apps[].cluster** - cluster name for the application.  Primarily for database clusters to co-exist in the same VPC environment, it allows instances to self-discover cluster members using ops tools such as [ec2nodefine](https://github.com/WrathOfChris/ops/tree/master/ec2nodefind).
* **apps[].group** - security group for the application.  Unique within the VPC
* **apps[].elb** - ELB to register the host instance or AutoScaleGroup with.  Does not register if not provided.
* **apps[].public** - if present, launches the instances into the _public_ subnets of the VPC and assigns external public IP addresses to the instances in addition to the private address.  Required to skip NAT or for public access without a load balancer (ie: UDP).  In general, if hosts can be isolated in private subnets, they should be.
* **apps[].ami** - the specific ID of an Amazon Machine Image to launch for the application.  Overrides _aminame_.  When modified on an AutoScaleGroup, cloudcaster creates a new launch config then updates the ASG with the new launch config.
* **apps[].aminame** - search the list of images and return the best match to the name.  Primarily for instances formed with a datestamp attached as -YYYYMMDDHHMMSS.  Matching order is (ENV)-(AMINAME)-(DATESTAMP), all-(AMINAME)-(DATESTAMP), (AMINAME)-(DATESTAMP), (AMINAME).  Reverse-sorted, first match.  The expected operational goal is to allow the newest environment-specific images to supersede the newest all-environment images.  Pinning to a specific older image without using the "ami" parameter is not supported.  On an AutoScaleGroup, when modified, or when a new image is published, cloudcaster will create a new launch config and update the ASG with the new launch config.
* **apps[].type** - instance type.  When modified, the AutoScaleGroup is updated with a new launch config.
* **apps[].role** - instance-profile role to assign to the application.  "myrole" is a generic read-only profile that allows reading of all EC2 environment.  Define another IAM role if needed.
* **apps[].keypair** - keypair to use for launching the instance.
* **apps[].count** - If _autoscale_ is also specified, updates the _desired capacity_ of the AutoScaleGroup.  When _autoscale_ is not specified, this is the target count of instances to manually run.
* **apps[].ports** - array of ports to open for intra-application communication.
* **apps[].pubports** - array of ports to open when _public_ is specified
* **apps[].allow** - array of ports to open from the specified security group for inter-application communication.
* **apps[].autoscale.min** - AutoScaleGroup minimum instance count
* **apps[].autoscale.max** - AutoScaleGroup maximum instance count

## NETWORK
Cloudcaster creates a VPC network as follows:
***
![CloudCasterVPC](https://raw.github.com/WrathOfChris/ops/master/cloudcaster/img/CloudCasterVPC.png)
* orange dashed boxes are regional Availability Zones (ie: us-west-2a, us-west-2b, us-west-2c)
* **public subnets** are connected to the **public routing table** which has the Internet GateWay attached for external access, ElasticIP support, ELB support, et.
* **private subnets** are connected to the **default routing table** which has the NAT/VPN instance attached for internal access, internet access via shared-address NAT, and VPN access.

## SECURITY
Below are the security rules created by cloudcaster based on the specification.

### ELB
* allow from 0.0.0.0/0 to **elb.ports[].from:to** - public access to ELB ports

### APP
* allow from _elb.group_ to **elb.listeners[].to** - allow ELB to access APP based on listener destination
* allow from _app.group_ to **app.ports[].from:to** - allow this APP instances access to port range
* allow from _app.allow[].group_ to **app.allow[].from:to** - allow another APP instances access to port range
* allow from 0.0.0.0/0 to **app.pubports[].from:to** - public access to APP ports.  Requires "public" flag.
* allow from 0.0.0.0/0 to **22/ssh** - public access to SSH
* allow from _aws.privnet_ to **icmp** - make all hosts ping-able within the VPN

### NAT
* allow from 0.0.0.0/0 to **22/ssh** - public access to SSH.  Useful for bounce-hosting into the private network.
* allow from _aws.privnet_ to *icmp* - make all hosts ping-able within the VPN
* allow from 0.0.0.0/0 to **nat.ports[].from:to** - public access to VPN ports, need 500 + 4500 for ipsec + ipsec-nat.
* allow from _vpc.cidr_ to **all** - needed for NAT and VPN routing, must allow all traffic inbound from the VPC network
* egress 0.0.0.0/0 **all** - all traffic is allowed to leave.  This isn't a firewall.

## ENVIRONMENT
Cloudcaster is backed by the boto library [boto - github](https://github.com/boto/boto) and uses its environment variables.  The most useful settings are **AWS_ACCESS_KEY** and **AWS_SECRET_KEY** described below.

Your credentials can be passed into the methods that create connections. Alternatively, boto will check for the existence of the following environment variables to ascertain your credentials:

* **AWS_ACCESS_KEY** - Your AWS Access Key ID

* **AWS_SECRET_KEY** - Your AWS Secret Access Key

## DISCUSSION
* This section is biased.
* This is cloud.  It fails.  Regularly.  2% host failure per-month is an expected failure rate.  Yes, that's per-month, not per-year.
* Use _autoscale_ groups unless you have a very specific, well-considered reason not to.  AutoScaleGroups allow instance health detection, application health detection, automatic multi-availability-zone distribution, and automatic recovery.
* Use Elastic Load Balancers unless you have a benchmarked proof of need, and the performance difference matters.  Default public IP addresses are not static, instances fail, and the only reasonable method of maintaining health-checked public endpoints is via ELB.
* Hostnames do not matter.  Service endpoints matter.  Automatically scaled instances cannot easily have useful, meaningful hostnames.  Give the ELB a meaningful stable DNS record, and allow the autoscale groups to automatically register hosts with the ELBs.  For configuration, use tags and filters to discover the current state of the system.  ie: ec2-describe-instances -F tag:service=myapp -F tag:env=dev
* If you expose it to the public, give it an Elastic IP.  EIP support is not yet built, I hope to not need to build it.  The manual pain is to discourage you from wanting to expose public hosts directly.

## UPDATING INSTANCES
When possible, use the burn-and-churn methodology for configuration updates:
* Use _aminame_ as the method of specifying the launch image.
* Create a new AMI image with the new configuration applied.  This will be named env-aminame-00000000000000 where 0's are replaced by the datestamp.  ie: dev-myapp-v7-20131211134737
* Run cloudcaster, which creates a new Launch Configuration and updates the AutoScaleGroup with the new LaunchConfig.
* Decide whether to replace in-place or grow & shrink the AutoScaleGroup
* If growing in place: _as-terminate-instance-in-auto-scaling-group i-000000 --no-decrement-desired-capacity_ - this will remove an instance from the ELB, terminate the instance and immediately spin a new instance of the new image type, then add back to the ELB once healthy
* If growing & shrinking: _as-set-desired-capacity ASGNAME --desired-capacity (+1)_ followed by _as-terminate-instance-in-auto-scaling-group i-000000_
* AutoScaleGroups by default terminate the oldest instance in the oldest LaunchConfig

## BUGS
* No input or sanitization is performed on the specification, as it is passed directly to cloud APIs.
* API errors are immediately fatal, but cloudcaster can be re-run safely
* Most parameters cannot be updated once deployed.  Cloudcaster ensures the specification as it is written currently exists.  It ignores anything not in the specification.

## PREREQUISITES

```
REGION=us-west-2
ec2-import-keypair example --region $REGION -f /path/to/your/sshkey

# Find regional AMI, replace "ami" values in example.json
ec2-describe-images --region $REGION -a -F name=amzn-ami-vpc-nat-pv-2013.09.0.x86_64-ebs

# Create iam role ie: "discovery"
ec2-rolecreate -r discovery -f examples/example.policy
```

## EXAMPLE RUN
Running --verbose, as second run after environment created by first run.

```
VPC vpc-d99a8abb 10.0.0.0/22
VPC-IGW igw-5cedfb3e
VPC-SUBNET subnet-4cd3c32e 10.0.0.0/24 PRIVATE
VPC-SUBNET subnet-a52615d1 10.0.1.0/24 PRIVATE
VPC-SUBNET subnet-58e4b61e 10.0.2.0/24 PRIVATE
VPC-SUBNET subnet-4dd3c32f 10.0.3.0/26 PUBLIC
VPC-SUBNET subnet-a62615d2 10.0.3.64/26 PUBLIC
VPC-SUBNET subnet-59e4b61f 10.0.3.128/26 PUBLIC
SECGRP-ELB sg-21415b43 example-elb-prod
SECGRP-APP sg-26415b44 example-prod
SGRULE example-elb-prod src [0.0.0.0/0] tcp 80:80
SGRULE example-elb-prod src [0.0.0.0/0] tcp 443:443
APP exampleapp
APP exampleapp ELB example ELBSG example-elb-prod
SGRULE example-elb-prod src [sg-21415b43-544643505425] tcp 80:80
SGRULE example-elb-prod src [sg-21415b43-544643505425] tcp 443:443
SGRULE example-prod src [sg-26415b44-544643505425] tcp 22:22
SGRULE example-prod src [0.0.0.0/0] tcp 22:22
SGRULE example-prod src [10.0.0.0/8] icmp -1:-1
ELB example-prod dns example-prod-1891025847.us-west-2.elb.amazonaws.com
ELB-LISTEN example-prod 80/HTTP -> 80/HTTP
ELB-LISTEN example-prod 443/HTTPS -> 443/HTTPS
APP-LAUNCH exampleapp-prod-20140106002258 ami ami-ccf297fc type t1.micro key wrathofchris-201401 role discovery
APP-AUTOSCALE exampleapp-prod size 0-1 elb [u'example-prod'] launch exampleapp-prod-20140106002258
Updating Autoscaling Group capacity 0 -> 1
SECGRP-NAT sg-2b415b49 nat-example
SGRULE nat-example src [0.0.0.0/0] tcp 22:22
SGRULE nat-example src [10.0.0.0/8] icmp -1:-1
SGRULE nat-example src [0.0.0.0/0] icmp 8:-1
SGRULE nat-example src [0.0.0.0/0] udp 33434:33534
SGRULE nat-example src [0.0.0.0/0] udp 500:500
SGRULE nat-example src [0.0.0.0/0] udp 4500:4500
SGRULE nat-example src [10.0.0.0/22] -1 None:None
SGRULE nat-example src [0.0.0.0/0] -1 None:None
NAT-INST nat-example i-f58b59fc ami ami-f032acc0 type t1.micro host ip-10-0-3-23.us-west-2.compute.internal ec2-54-200-164-213.us-west-2.compute.amazonaws.com
RT-MAIN rtb-9fadbdfd
RT-PUBLIC rtb-64aebe06
ROUTE rtb-9fadbdfd subnet subnet-4cd3c32e
ROUTE rtb-9fadbdfd subnet subnet-a52615d1
ROUTE rtb-9fadbdfd subnet subnet-58e4b61e
ROUTE rtb-9fadbdfd 0.0.0.0/0 instance i-f58b59fc
ROUTE rtb-64aebe06 subnet subnet-4dd3c32f
ROUTE rtb-64aebe06 subnet subnet-a62615d2
ROUTE rtb-64aebe06 subnet subnet-59e4b61f
ROUTE rtb-64aebe06 0.0.0.0/0 instance igw-5cedfb3e
ROUTE rtb-64aebe06 10.0.0.0/8 instance i-f58b59fc
DNS nat-example-prod.ec2-us-west-2.us1.example.wrathofchris.com. -> ec2-54-200-164-213.us-west-2.compute.amazonaws.com
DNS example-prod.ec2-us-west-2.us1.example.wrathofchris.com. -> example-prod-1891025847.us-west-2.elb.amazonaws.com
```

## SEE ALSO
* [boto - github](https://github.com/boto/boto)
* [cloudcaster - github](https://github.com/WrathOfChris/ops/tree/master/cloudcaster)

## CONTRIBUTERS
Thanks to Mahesh Paolini-Subramanya (@dieswaytoofast) for his help.

## AUTHOR
Chris Maxwell <chris@wrathofchris.com>
