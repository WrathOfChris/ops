from setuptools import setup


setup(
    include_package_data=True,
    name='ops',
    author="Chris Maxwell",
    author_email="foo@bar.com",
    version='0.1',
    description="Building special snowflakes consistently",
    scripts=[
        "cloudcaster/cloudcaster.py",
        "ec2cleanlc/ec2cleanlc.py",
        "ec2cleanami/ec2cleanami.py"
    ]
)
