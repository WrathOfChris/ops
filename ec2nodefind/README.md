# ec2nodefind

## NAME
**ec2nodefind** - ec2 node discovery tool

## SYNOPSIS
**ec2nodefind** [-aipvF] [-e environ] [-s service] [-c cluster] [-f file]

## DESCRIPTION
ec2nodefind uses three ec2 tags to discover like hosts within the same region and create
a list of current running hosts.

**environ** the environment of the host, ie: "stage", "prod", or "dev"
**service** the service name of the host.  ie: "webservers", "db-seventeen"
**cluster** a selector for multiple clusters of the same service.

## OPTIONS
* **-a** enable autodiscovery from instance metadata of (environ, service, cluster)
* **-A** use autoscalegroup for instance ordering
* **-i** print IP addresses instead of hostnames
* **-p** print public hostname or IP address instead of private
* **-v** be verbose
* **-F** print Fully Qualified Domain Name
* **-e environ** specify environment value ie: (dev, stage, prod)
* **-s service** specify service name
* **-c cluster** specify cluster selector
* **-f file** output file.  If not specified, writes to _STDOUT_

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

Autodiscover peer hosts of the same environ, service, cluster:

```
    ec2nodefind -a
```

Autodiscover all hosts of service "nat" in environ "prod"

```
    ec2nodefind -e "prod" -s "nat"
```

## ENVIRONMENT
ec2nodefind uses [boto](https://github.com/boto/boto) and its environment variables.

Your credentials can be passed into the methods that create connections.
Alternatively, boto will check for the existence of the following environment
variables to ascertain your credentials:

* **AWS_ACCESS_KEY** - Your AWS Access Key ID

* **AWS_SECRET_KEY** - Your AWS Secret Access Key

## AUTHOR
Chris Maxwell <chris@wrathofchris.com>
