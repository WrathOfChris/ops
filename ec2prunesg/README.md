# ec2prunesg

## NAME
**ec2prunesg** - ec2 security group pruning tool

## SYNOPSIS
**ec2prunesg** [-aDv] [-s service] [-e environ] [-c cluster] [-f regionfile]
[-r region] regions...

## DESCRIPTION
ec2prunesg prunes security groups to remove terminated hosts from CIDR-based
rules.  It locates security groups named in the following format:

**service**-**region**-**environ**

It then uses three ec2 tags to discover instances running each listed region
and removes any not currently running.

**environ** the environment of the host, ie: "stage", "prod", or "dev"
**service** the service name of the host.  ie: "webservers", "db-seventeen"
**cluster** a selector for multiple clusters of the same service.

Specify either a **regionfile** or a list of regions... on the command-line,
not both

## OPTIONS
* **-a** enable autodiscovery from instance metadata of (environ, service, cluster)
* **-D** dry run - print intended actions but do not prune security groups
* **-v** be verbose
* **-e environ** specify environment value ie: (dev, stage, prod)
* **-s service** specify service name
* **-c cluster** specify cluster selector
* **-f regionfile** file containing list of regions to evaluate
* **-r region** specify region to prune security group rules from

## AUTODISCOVERY
Autodiscovery relies on an instance-profile role allowing the host to Describe
instances and tags.  The below IAM statement allows the instance to describe
any EC2 resource.

```
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "ec2:Describe*",
          "autoscaling:DescribeAutoScalingGroups"
        ],
        "Resource": [
          "*"
        ],
        "Effect": "Allow"
      }
    ]
  }
```

## EXAMPLES

Prune remote "stage" service "mycluster" in us-west-1, us-west-2 from security
groups in us-east-1

```
    ec2prunesg -r us-east-1 -s mycluster -e stage us-west-1 us-west-2
```

From a management instance, prune a known service with a list of regions

```
    ec2prunesg -a -s mycluster -f /etc/mycluster/mycluster.regions
```

## ENVIRONMENT
ec2prunesg uses [boto](https://github.com/boto/boto) and its environment variables.

Your credentials can be passed into the methods that create connections.
Alternatively, boto will check for the existence of the following environment
variables to ascertain your credentials:

* **AWS_ACCESS_KEY** - Your AWS Access Key ID

* **AWS_SECRET_KEY** - Your AWS Secret Access Key

## AUTHOR
Chris Maxwell <chris@wrathofchris.com>
