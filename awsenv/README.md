# awsenv
Outputs environment variables for AWS / Ansible tools.  Best used to import
into your shell ENVIRONMENT.

* Usage: eval `awsenv PROFILE`

## Requirements

Reads in AWS_ACCESS_KEY and AWS_SECRET_KEY from files in the ~/.aws/ directory
matching the pattern user-*

## Actions

* Reads ~/.aws/user-PROFILE
* Creates ~/.aws/iam-PROFILE for AwsAccessKeyId / AWSSecretKey required by IAM
  tools
* Outputs shell variables
  * AWSUSER="PROFILE"
  * AWS_ACCESS_KEY="--------------------"
  * AWS_SECRET_KEY="----------------------------------------"
  * AWS_ACCESS_KEY_ID="--------------------"
  * AWS_SECRET_ACCESS_KEY="----------------------------------------"
  * AWS_CREDENTIAL_FILE="~/.aws/iam-PROFILE "

## Example

```
AWS_ACCESS_KEY='--------------------'
AWS_SECRET_KEY='----------------------------------------'
```
