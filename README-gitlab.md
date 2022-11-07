# Working with Gitlab CI

## Gitlab Project CI/CD Variables

- REGISTRY: The container image registry you are using for pipeline component containers, i.e. Chef Workstation
- AWS_SSH_KEY_ID: The private keyname for connecting to your test AMI.
- POC_TAG: Name of the point of contact for EC2 instances created by this pipeline.
- SECURITY_GROUP_IDS: A list of the security groups that should apply to the test EC2 instances.
- AWS_REGION: ex. us-gov-west-1
- SUBNET_ID: The subnet in your AWS instance where the test EC2 instances will be created.
- VANILLA_AMI_ID: The AMI ID for the unhardened image for the operating system under test.
- HARDENED_AMI_ID: The AMI ID for the hardened image for the operating system under test.
- VANILLA_CONTAINER_IMAGE: The container ID for the unhardened Docker image for the operating system under test. 
- HARDENED_CONTAINER_IMAGE: The container ID for the hardened Docker image for the operating system under test.

## Template Variables

Be sure to check the README for the template files for a list of the Gitlab CI/CD variables the templates will need.