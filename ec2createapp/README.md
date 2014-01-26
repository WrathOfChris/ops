### ec2createapp
Usage: ec2createapp [-v] [-r region] -f cloudcaster.json appname

### Description

ec2createapp uses the ['app'] specification in the cloudcaster.json to create a new
LaunchConfig and update the AutoScaling group.

It will not create an ELB's, VPC, VPC-subnets, or other cloud infrastructure, so it
is useful for adding to an existing VPC.
