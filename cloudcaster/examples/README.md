### First run, creating NAT instance and AutoScale Group

```
Creating VPC 10.0.0.0/22
Creating InternetGateway for VPC 10.0.0.0/22
Creating VPC subnet 10.0.0.0/24 AZ us-west-2a
Creating VPC subnet 10.0.1.0/24 AZ us-west-2b
Creating VPC subnet 10.0.2.0/24 AZ us-west-2c
Creating VPC subnet 10.0.3.0/26 AZ us-west-2a
Creating VPC subnet 10.0.3.64/26 AZ us-west-2b
Creating VPC subnet 10.0.3.128/26 AZ us-west-2c
Creating Security Group example-elb-prod for VPC 10.0.0.0/22 elb example
Creating Security Group example-prod for VPC 10.0.0.0/22 app exampleapp
Creating SG rule for world -> ELB
Creating SG rule for world -> ELB
Creating SG rule for ELB -> SG
Creating SG rule for ELB -> SG
Creating SG rule for SG -> SG (22, 22, tcp)
Creating SG rule for SSH -> SG
Creating SG rule for ICMP -> SG
Creating ELB example-prod
Creating Launch Config exampleapp-prod-20140106002258
Creating Autoscaling Group exampleapp-prod
Creating Security Group nat-example for NAT
Creating SG rule for SSH -> NAT
Creating SG rule for NAT ICMP -> SG
Creating SG rule for NAT ICMP
Creating SG rule for TRACEROUTE -> NAT
Creating SG rule for world -> NAT (500:500)
Creating SG rule for world -> NAT (4500:4500)
Creating SG rule for ALL-VPC -> NAT
Creating NAT instance
Waiting for NAT to start: pending
Waiting for NAT to start: pending
Waiting for NAT to start: pending
Waiting for NAT to start: pending
Waiting for NAT to start: pending
Waiting for NAT to start: pending
Setting sourceDestCheck on NAT instance
Creating PUBLIC route table
Creating MAIN subnet association subnet-4cd3c32e -> rtb-9fadbdfd
Creating MAIN subnet association subnet-a52615d1 -> rtb-9fadbdfd
Creating MAIN subnet association subnet-58e4b61e -> rtb-9fadbdfd
Creating MAIN route for 0.0.0.0/0 -> NAT
Creating PUBLIC subnet association subnet-4dd3c32f -> rtb-64aebe06
Creating PUBLIC subnet association subnet-a62615d2 -> rtb-64aebe06
Creating PUBLIC subnet association subnet-59e4b61f -> rtb-64aebe06
Creating PUBLIC route for 0.0.0.0/0 -> IGW
Creating PUBLIC route for 10.0.0.0/8 -> NAT/VPN
Creating Route53 nat-example-prod.ec2-us-west-2.us1.example.wrathofchris.com. -> ec2-54-200-164-213.us-west-2.compute.amazonaws.com
Creating Route53 example-prod.ec2-us-west-2.us1.example.wrathofchris.com. -> example-prod-1891025847.us-west-2.elb.amazonaws.com
```

### Second run, with verbose flag

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
APP-LAUNCH exampleapp-prod-20140106002258 ami ami-ccf297fc type t1.micro key
wrathofchris-201401 role discovery
APP-AUTOSCALE exampleapp-prod size 0-1 elb [u'example-prod'] launch
exampleapp-prod-20140106002258
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
NAT-INST nat-example i-f58b59fc ami ami-f032acc0 type t1.micro host
ip-10-0-3-23.us-west-2.compute.internal
ec2-54-200-164-213.us-west-2.compute.amazonaws.com
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
DNS nat-example-prod.ec2-us-west-2.us1.example.wrathofchris.com. ->
ec2-54-200-164-213.us-west-2.compute.amazonaws.com
DNS example-prod.ec2-us-west-2.us1.example.wrathofchris.com. ->
example-prod-1891025847.us-west-2.elb.amazonaws.com
```
