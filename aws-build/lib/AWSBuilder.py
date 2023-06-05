import errno
import json
import os
import os.path
import signal
import socket
import stat
import subprocess
import time

# HOSTTYPE should be more complete...
HOSTTYPE = {
    '32bit': {
        't1.micro':  { 'ebs-optimized': False, },    # free-tier, 1 cpu, 0.613 GB RAM, low network
        'm1.small':  { 'ebs-optimized': False, },    #            1 cpu,   1.7 GB RAM, low network
        'm1.medium': { 'ebs-optimized': False, },    #            1 cpu,   3.7 GB RAM, moderate nework
        'c1.medium': { 'ebs-optimized': False, },    #            2 cpus,  1.7 GB RAM, moderate network
        'c3.large':  { 'ebs-optimized': False, },    #            2 cpus, 3.75 GB RAM, moderate network
    },

    '64bit': {
        't2.micro':  { 'ebs-optimized': False, },    # free-tier  1 cpu,     1 GB RAM, low-moderate network
        't2.small':  { 'ebs-optimized': True, },     #            1 cpu,     2 GB RAM, low-moderate network
        'm3.xlarge': { 'ebs-optimized': True, },     #            4 cpus,   15 GB RAM, high network
        'c4.large':  { 'ebs-optimized': True, },     #            2 cpus, 3.75 GB RAM, moderate network
        'c3.xlarge': { 'ebs-optimized': True, },     #            4 cpus,  7.5 GB RAM, moderate network
        'c5.large':  { 'ebs-optimized': True, },     #            2 cpus,    4 GB RAM, Up to 10 Gigabit
        'c5.xlarge': { 'ebs-optimized': True, },     #            4 cpus,    8 GB RAM, Up to 10 Gigabit
        'c5.2xlarge':{ 'ebs-optimized': True, },     #            8 cpus,   16 GB RAM, Up to 10 Gigabit
    },
}

# IMAGE should be configurable
IMAGE = {
    # Official Debian AMIs image from https://wiki.debian.org/Cloud/AmazonEC2Image
    # Root Device specific to the above AMI
    'debian-11': {
        'ami': {'us-west-1': 'ami-0e9490b4112b79fad', 'us-west-2': 'ami-01b290b93957fd408'},
        'rootdevice': {'us-west-1': '/dev/xvda', 'us-west-2': '/dev/xvda'},
        'user': 'admin',
        'default-hosttype': 't2.micro',
        'hosttypes': HOSTTYPE['64bit'],
        'upcommand': '! ls -lL /etc/nologin',
        'packageinit': 'sudo systemctl stop apt-daily-upgrade apt-daily; sudo apt-get update',
        'packageinstall': 'sudo apt-get -qq -my install {} </dev/null',
    },
    'debian-10': {
        'ami': {'us-west-1': 'ami-0d1b86358bb4fe44d', 'us-west-2': 'ami-0db58da055ea7d7f9'},
        'rootdevice': {'us-west-1': '/dev/xvda', 'us-west-2': '/dev/xvda'},
        'user': 'admin',
        'default-hosttype': 't2.micro',
        'hosttypes': HOSTTYPE['64bit'],
        'upcommand': '! ls -lL /etc/nologin',
        'packageinit': 'sudo systemctl stop apt-daily-upgrade apt-daily; sudo apt-get update',
        'packageinstall': 'sudo apt-get -qq -my install {} </dev/null',
    },
    'debian-9': {
        'ami': {'us-west-1': 'ami-06b6fb23c63773015', 'us-west-2': 'ami-0eb547794877377c2'},
        'rootdevice': {'us-west-1': 'xvda', 'us-west-2': 'xvda'},
        'user': 'admin',
        'default-hosttype': 't2.micro',
        'hosttypes': HOSTTYPE['64bit'],
        'upcommand': '! ls -lL /etc/nologin',
        'packageinit': 'sudo systemctl stop apt-daily-upgrade apt-daily; sudo apt-get update',
        'packageinstall': 'sudo apt-get -qq -my install {} </dev/null',
    },
    'debian-8': {
        'ami': {'us-west-1': 'ami-00b78322f3c9beca7', 'us-west-2': 'ami-221ea342'},
        'rootdevice': {'us-west-1': '/dev/xvda', 'us-west-2': '/dev/xvda'},
        'user': 'admin',
        'default-hosttype': 't2.micro',
        'hosttypes': HOSTTYPE['64bit'],
        'upcommand': '! ls -lL /etc/nologin',
        'packageinit': 'sudo apt-get update',
        'packageinstall': 'sudo apt-get -qq -my install {} </dev/null',
    },
    'debian-7': {
        'ami': {'us-west-1': 'ami-b4869ff1', 'us-west-2': 'ami-f91a42c9'},
        'rootdevice': {'us-west-1': '/dev/xvda', 'us-west-2': '/dev/sda'},
        'user': 'admin',
        'default-hosttype': 't2.micro',
        'hosttypes': HOSTTYPE['64bit'],
        'upcommand': '! ls -lL /etc/nologin',
        'packageinit': 'sudo apt-get update',
        'packageinstall': 'sudo apt-get -qq -my install {} </dev/null',
    },
    # Official Ubuntu AMIs can be located at https://cloud-images.ubuntu.com/locator/ec2/
    'ubuntu-20.04': {
        'ami': {'us-west-1': 'ami-0b256f935d73b31de', 'us-west-2': 'ami-04c92c2862766d9ed'},
        'rootdevice': {'us-west-1': '/dev/sda1', 'us-west-2': '/dev/sda1'},
        'user': 'ubuntu',
        'default-hosttype': 't2.micro',
        'hosttypes': HOSTTYPE['64bit'],
        'upcommand': 'fgrep ec2 /etc/apt/sources.list',
        'packageinit': 'sudo apt-get update',
        'packageinstall': 'sudo apt-get -qq -my install {} </dev/null',
    },
    'ubuntu-18.04': {
        'ami': {'us-west-1': 'ami-0828e5172f57314a0', 'us-west-2': 'ami-02da34c96f69d525c'},
        'rootdevice': {'us-west-1': '/dev/sda1', 'us-west-2': '/dev/sda1'},
        'user': 'ubuntu',
        'default-hosttype': 't2.micro',
        'hosttypes': HOSTTYPE['64bit'],
        'upcommand': 'fgrep ec2 /etc/apt/sources.list',
        'packageinit': 'sudo apt-get update',
        'packageinstall': 'sudo apt-get -qq -my install {} </dev/null',
    },
    'ubuntu-16.04': {
        'ami': {'us-west-1': 'ami-2afbde4a', 'us-west-2': 'ami-08d70e59c07c61a3a'},
        'rootdevice': {'us-west-1': '/dev/sda1', 'us-west-2': '/dev/sda1'},
        'user': 'ubuntu',
        'default-hosttype': 't2.micro',
        'hosttypes': HOSTTYPE['64bit'],
        'upcommand': 'fgrep ec2 /etc/apt/sources.list',
        'packageinit': 'sudo apt-get update',
        'packageinstall': 'sudo apt-get -qq -my install {} </dev/null',
    },
    'ubuntu-14.04': {
        'ami': {'us-west-1': 'ami-f9f2e299', 'us-west-2': 'ami-ff6d0b87'},
        'rootdevice': {'us-west-1': '/dev/sda1', 'us-west-2': '/dev/sda1'},
        'user': 'ubuntu',
        'default-hosttype': 't2.micro',
        'hosttypes': HOSTTYPE['64bit'],
        'upcommand': 'fgrep ec2 /etc/apt/sources.list',
        'packageinit': 'sudo apt-get update',
        'packageinstall': 'sudo apt-get -qq -my install {} </dev/null',
    },
    'ubuntu-12.04': {
        'ami': {'us-west-1': 'ami-10acf170', 'us-west-2': 'ami-db2a91bb'},
        'rootdevice': {'us-west-1': '/dev/sda1', 'us-west-2': '/dev/sda1'},
        'user': 'ubuntu',
        'default-hosttype': 't2.micro',
        'hosttypes': HOSTTYPE['64bit'],
        'upcommand': 'fgrep ec2 /etc/apt/sources.list',
        'packageinit': 'sudo apt-get update',
        'packageinstall': 'sudo apt-get -qq -my install {} </dev/null',
    },
    'ubuntu-14.04-32bit': {
        'ami': {'us-west-1': 'ami-003b4960', 'us-west-2': 'ami-4eba532e'},
        'rootdevice': {'us-west-1': '/dev/sda1', 'us-west-2': '/dev/sda1'},
        'user': 'ubuntu',
        'default-hosttype': 't1.micro',
        'hosttypes': HOSTTYPE['32bit'],
        'upcommand': 'fgrep ec2 /etc/apt/sources.list',
        'packageinit': 'sudo apt-get update',
        'packageinstall': 'sudo apt-get -qq -my install {} </dev/null',
    },
    'ubuntu-12.04-32bit': {
        'ami': {'us-west-1': 'ami-05674365', 'us-west-2': 'ami-298b1649'},
        'rootdevice': {'us-west-1': '/dev/sda1', 'us-west-2': '/dev/sda1'},
        'user': 'ubuntu',
        'default-hosttype': 't1.micro',
        'hosttypes': HOSTTYPE['32bit'],
        'upcommand': 'fgrep ec2 /etc/apt/sources.list',
        'packageinit': 'sudo apt-get update',
        'packageinstall': 'sudo apt-get -qq -my install {} </dev/null',
    },
    'ubuntu-12.04-32bit-old': {
        'ami': {'us-west-1': 'ami-35a1f155', 'us-west-2': 'ami-48d46728'},
        'rootdevice': {'us-west-1': '/dev/sda1', 'us-west-2': '/dev/sda1'},
        'user': 'ubuntu',
        'default-hosttype': 't1.micro',
        'hosttypes': HOSTTYPE['32bit'],
        'upcommand': 'fgrep ec2 /etc/apt/sources.list',
        'packageinit': 'sudo apt-get update',
        'packageinstall': 'sudo apt-get -qq -my install {} </dev/null',
    },
    # AMIs are listed at https://www.freebsd.org/releases/13.1R/announce/
    'FreeBSD-13.1': {
        'ami': {'us-west-2': 'ami-08e0f4bcbfaef4846'},
        'rootdevice': {'us-west-2': '/dev/sda1'},
        'user': 'ec2-user',
        'default-hosttype': 'c5.large',
        'hosttypes': HOSTTYPE['64bit'],
        'upcommand': '! ls -lL /etc/nologin',
        'packageinit': 'su - root -c \'pkg update && pkg install -y sudo && echo "ec2-user ALL=(ALL) NOPASSWD: ALL" >/usr/local/etc/sudoers.d/ec2-user\'',
        'packageinstall': 'sudo pkg install -y {} </dev/null',
    },
}

DNS_TAGS = {
'Owner' : 'cie-eng.dns-team@cisco.com',
'Environment' : 'NonProd',
'Project' : 'SRE',
'CiscoMailAlias' : 'cie-eng.dns-team@cisco.com',
'DataClassification' : 'Cisco Confidential',
'DataTaxonomy' : 'Cisco Operations Data',
'ResourceOwner' : 'SBG CIE DNS Engineering',
'ApplicationName' : 'Jenkins build slave',
'ProductFamilyName' : 'DNS SEC',
}

BRAIN_TAGS = {
'Owner' : 'umbrella-eng.brain@cisco.com',
'Environment' : 'NonProd',
'Project' : 'Brain',
'CiscoMailAlias' : 'umbrella-eng.brain@cisco.com',
'DataClassification' : 'Cisco Confidential',
'DataTaxonomy' : 'Cisco Operations Data',
'ResourceOwner' : 'Umbrella_Brain',
'ApplicationName' : 'Brain3',
'ProductFamilyName' : 'Brain',
}

# Hostname and IP address of the master
HOSTNAME = socket.gethostname()
IP_ADDR  = socket.gethostbyname(HOSTNAME)

# Security group name when running in secure mode
SECURE_MODE_SG_NAME = "{}-workers".format(('.').join(HOSTNAME.split('.')[:2]))

class AWSBuilder:
    def __init__(self, region, subnet, vpc, unsecure, tags, profile=None, type='aws'):
        self.profile = profile                                 # The AWS profile
        self.region = region                                   # The AWS region
        self.type = type                                       # The builder type - controls the key name
        self.vpc = self.find_vpc(vpc)                          # The vpc
        self.tags = self.init_tags(tags)                       # The tags corresponding to a team. Options: dns, brain or an input file containing tags

        if not self.vpc:
            raise NameError("Cannot find the default vpc")
        self.subnet = self.find_subnet(subnet)                 # The subnet
        if not self.subnet:
            raise NameError("Cannot find subnet {}".format(subnet))
        self.sec = self.find_security_group(unsecure)          # The security group.  Will be created with self.ensure_security_group() later
        print("find_security_group returned {}".format(self.sec))

    def ec2cmd(self):
        command = ['aws']
        if self.profile:
            command.extend(['--profile', self.profile])
        command.extend(['--region', self.region])
        command.append('ec2')

        return command

    def find_vpc(self, name):
        # Get all VPCs as "name<tab>id"
        command = self.ec2cmd() + ['describe-vpcs', '--query', 'Vpcs[].[Tags[?Key==`Name`].Value|[0], VpcId]', '--output', 'text']

        for line in subprocess.check_output(command).decode().split('\n'):
            part = line.split('\t')
            if len(part) == 2:
                # print("Found {},{} (looking for {})".format(part[0],part[1], name))
                if part[0] == name:
                    return part[1]
        return None

    def get_vpc(self):
        return self.vpc

    def find_subnet(self, name):
        # Get all subnets in the VPC as "name<tab>id"
        command = self.ec2cmd() + ['describe-subnets',
            '--query', 'Subnets[?VpcId==`{}`].[Tags[?Key==`Name`].Value|[0],SubnetId]'.format(self.vpc),
            '--output', 'text']

        for line in subprocess.check_output(command).decode().split('\n'):
            part = line.split('\t')
            if len(part) == 2:
                # print("Found {},{} (looking for {})".format(part[0],part[1], name))
                if part[0] == name:
                    return part[1]
        return None

    def get_subnet(self):
        return self.subnet

    def find_security_group(self, unsecure, name=None):
        if not unsecure:
            name = SECURE_MODE_SG_NAME
        elif not name:
            name = '{}-builder'.format(self.type)

        # Get the matching security group
        command = self.ec2cmd() + ['describe-security-groups', '--query', 'SecurityGroups[?GroupName==`{}`].[GroupId]'.format(name), '--output', 'text']
        return subprocess.check_output(command).decode().rstrip()

    def get_security_group(self):
        return self.sec

    def ensure_security_group(self, unsecure, name=None, ingress_rules=[{'protocol': 'tcp', 'port': '22', 'cidr': '0.0.0.0/0'}]):
        if not self.sec:
            if not name:
                name = '{}-builder'.format(self.type)
            description = 'AWSBuilder automation' if unsecure else "Secure SSH access from aws-build master {}".format(HOSTNAME)

            sg_tags = 'ResourceType=security-group,Tags=['
            for k, v in self.tags.items():
                sg_tags += "{{Key={},Value={}}},".format(k,v)
            sg_tags += "{{Key=Name,Value={}}},".format(name)
            sg_tags += '{Key=ProtectedSG,Value=True}]'

            # Create the security group
            command = self.ec2cmd() + ['create-security-group', '--group-name', name, '--description', description,
                                                              '--vpc-id', self.vpc,
                                                              '--tag-specifications', sg_tags,
                                                              '--query', 'GroupId', '--output', 'text']
            self.sec = subprocess.check_output(command).decode().rstrip()
            for rule in ingress_rules:
                command = self.ec2cmd() + ['authorize-security-group-ingress', '--group-id', self.sec]
                for req in ['protocol', 'port', 'cidr']:
                    if req not in rule:
                        self.delete_security_group(self.sec)
                        self.sec = None
                        raise ValueError('Key "{}" missing from rule'.format(req))
                    command.append('--{}'.format(req))
                    command.append(rule[req])
                subprocess.call(command)
        return self.sec

    def delete_security_group(self, id=None):
        if not id:
            id = self.sec
        if id:
            command = self.ec2cmd() + ['delete-security-group', '--group-id', id]
            if self.sec == id:
                self.sec = None
            subprocess.call(command)

    def find_instances(self, state=None):
        # Get all instances in the VPC as "id<tab>name<tab>IPv4<tab>type<tab>state"
        command = self.ec2cmd() + ['describe-instances',
            '--query', 'Reservations[].Instances[].[InstanceId, Tags[?Key==`Name`].Value|[0], PrivateIpAddress, Tags[?Key==`Type`].Value|[0], State.Name]',
            '--output', 'text']

        for attempt in range(10):
            list = []
            try:
                for line in subprocess.check_output(command).decode().split('\n'):
                    part = line.split('\t')
                    if len(part) == 5:
                        # print("Found {},{} (looking for {})".format(part[0], part[1], self.type))
                        if part[3] == self.type:
                            if not state or state == part[4]:
                                list.append({'id': part[0], 'name': part[1], 'IPv4': part[2], 'state': part[4]})
                break
            except:
                if attempt == 9:
                    raise
                else:
                    print("Unable to obtain EC2 instance details. Sleep for 2 seconds and retry")
                    time.sleep(2)
                    continue
        return list

    def find_volumes(self, instance_id):
        # Return a list of all the EBS volumes associated with an EC2 instance
        # EBS volumes may take a bit of time to attach to the EC2 instance. Therefore retry
        # 10 times at half a second intervals to find the volumes.
        command = self.ec2cmd() + ['describe-instances', '--instance-ids', instance_id,
            '--query', 'Reservations[].Instances[].BlockDeviceMappings[].Ebs.VolumeId',
            '--output', 'text']
        for x in range(10):
            try:
                ebs_vols = subprocess.check_output(command).decode().strip().split()
                if ebs_vols:
                    return ebs_vols
                print("{} - Sleeping for 0.5 seconds to allow the EBS volume to be attached to the instance {}".format(time.ctime(), instance_id))
                time.sleep(0.5)
            except:
                if x == 9:
                    raise
                else:
                    continue
        return []

    def init_tags(self, tags):
        team_tags = {}
        if tags.lower() == 'dns':
            team_tags = DNS_TAGS
        elif tags.lower() == 'brain':
            team_tags = BRAIN_TAGS
        else:
            if os.path.isfile(tags):
                with open(tags, 'r') as f:
                    for line in f:
                        line.strip()
                        if line and not line.startswith("#"):
                            if '=' not in line:
                                raise ValueError('Line "{}" in file {} does not contain "{}"'.format(line, tags, '='))
                            key, value = line.partition("=")[::2]
                            team_tags[key.strip()] = value.strip()
            else:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), tags)
        return team_tags

class AWSInstance:
    def __init__(self, ami_region, builder, osname, sshkey, unsecure, volumesize, awstype=None, keep=False, signals=(signal.SIGINT, signal.SIGTERM)):
        if osname not in IMAGE:
            raise ValueError('Image {} not found'.format(osname))

        self.signals = signals
        self.original_handlers = {}
        self.keepinstance = keep
        self.builder = builder

        if unsecure:
            self.builder.ensure_security_group(unsecure)
        else:
            cidr = "{}/32".format(IP_ADDR)
            print("Running in secure mode. Build slaves can only be accessed via {}(IP: {})".format(HOSTNAME, IP_ADDR))
            self.builder.ensure_security_group(unsecure, name=SECURE_MODE_SG_NAME, ingress_rules=[{'protocol': 'tcp', 'port': '22', 'cidr': cidr}])

        self.remoteuser = IMAGE[osname]['user']                       # The name of the remote user is image-specific
        self.sshkey = sshkey                                          # The name of the ssh key on (local) disk, also

        if 'upcommand' in IMAGE[osname]:
            self.upcommand = IMAGE[osname]['upcommand']               # How to tell that the OS is up and running

        if 'packageinit' in IMAGE[osname]:
            self.packageinit = IMAGE[osname]['packageinit']           # What command(s) we should run to initialize the package system

        if 'packageinstall' in IMAGE[osname]:
            self.packageinstall = IMAGE[osname]['packageinstall']     # How do we install requested packages

        if 'env' in IMAGE[osname]:
            self.env = IMAGE[osname]['env']                           # Environment variables we want to set for specific architechtures

        if not os.path.isfile(self.sshkey):
            raise ValueError("Key '{}' not found".format(self.sshkey))

        # Device mapping ensures that the EC2 instances come up with encrypted disks.
        bdm = [
            {
                "DeviceName": IMAGE[osname]['rootdevice'][ami_region],
                "Ebs": {
                    "DeleteOnTermination": True,
                    "Encrypted": True,
                },
            },
        ]
        if volumesize != 0:
            bdm[0]["Ebs"]["VolumeSize"] = volumesize

        devicemapping = '--block-device-mappings=' + json.dumps(bdm)
        createargs = ['--instance-initiated-shutdown-behavior', 'terminate', devicemapping]
        if not awstype:
            awstype = IMAGE[osname]['default-hosttype']
        if awstype not in IMAGE[osname]['hosttypes']:
            raise ValueError("awstype {} is invalid for OS {}".format(awstype, osname))
        if IMAGE[osname]['hosttypes'][awstype]['ebs-optimized']:
            createargs.extend(['--ebs-optimized', '--placement', 'Tenancy=dedicated'])
        if 'user-data' in IMAGE[osname]:
            createargs.extend(['--user-data', '{}'.format(IMAGE[osname]['user-data'])])

        # Create and run an instance
        command = self.builder.ec2cmd() + ['run-instances'] + createargs + [
               '--image-id', IMAGE[osname]['ami'][ami_region], '--count', '1', '--instance-type', awstype, '--key-name', os.path.basename(self.sshkey),
               '--security-group-ids', self.builder.sec, '--subnet-id', self.builder.subnet, '--query', 'Instances[0].InstanceId', '--output', 'text']
        print('create an instance: {}'.format(command))
        self.instance = subprocess.check_output(command).decode().rstrip()

        hex = self.instance.split('-')[1]

        instance_tags = []
        for k, v in self.builder.tags.items():
            instance_tags.append("Key={},Value={}".format(k,v))
        instance_tags.append("Key=Name,Value=aws-build/slave-{}-{}-{}".format(hex, osname, self.builder.type))
        instance_tags.append("Key=Type,Value={}".format(self.builder.type))

        resources = [self.instance]
        volumes = self.builder.find_volumes(self.instance)
        if not volumes:
            print("ERROR: Unable to find any attached EBS volumes for EC2 instance {}".format(self.instance))
            self.terminate()
        resources.extend(volumes)

        command = self.builder.ec2cmd() + ['create-tags', '--resources'] + resources + ['--tags'] + instance_tags
        # print("Add tags: {}".format(command))
        subprocess.call(command)

        for ent in self.builder.find_instances():
            if ent['id'] == self.instance:
                self.IPv4 = ent['IPv4']

    def __enter__(self):
        for sig in self.signals:
            self.original_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, self.handler)
        return self

    def __exit__(self, type, value, traceback):
        self.terminate()
        return False

    def handler(self, signum, frame):
        self.terminate()

    def keep(self, keep):
        self.keepinstance = keep

    def get_instance(self):
        return self.instance

    def get_IPv4(self):
        return self.IPv4

    def wait_until_ready(self, timeout=180):
        if not self.instance:
            raise ValueError('The instance has been terminated')
        os.chmod(self.sshkey, stat.S_IRUSR)
        perm = oct(os.stat(self.sshkey)[stat.ST_MODE] & (stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO))
        if perm != '0o400':
            raise ValueError('{}: Invalid permissions ({}): must be 0o400'.format(perm, self.sshkey))
        command = self.builder.ec2cmd() + ['wait', 'instance-running', '--instance-ids', self.instance]
        subprocess.call(command)
        ret = -1
        out = []
        for i in range(0, timeout, 10):
            time.sleep(10)
            ret, out = self.ssh(self.upcommand, showoutput=False, returnoutput=True)
            if ret == 0:
                result = True
                break
        if ret != 0:
            raise ValueError("Executing '{}' failed after {}: {}".format(self.upcommand, timeout, out))
        if self.ssh('mkdir -p .ssh') != 0:
            raise ValueError("Cannot create remote '.ssh' directory")
        if self.ssh('rm -f .ssh/id_rsa') != 0:
            raise ValueError("Cannot remove remote '.ssh/id_rsa' file")

        # Need to initialize package installation and ensure that rsync is present
        if self.ssh(self.packageinit, verbose=True) != 0:
            raise ValueError("Failed to update packages")
        if self.ssh(self.packageinstall.format('rsync'), verbose=True) != 0:
            raise ValueError("Cannot ensure sync is present")

        if not self.rsync(local=self.sshkey, remote='.ssh/id_rsa', up=True, keeppermissions=True):
            raise ValueError("Cannot copy '{}' => remote '.ssh/id_rsa'".format(self.sshkey))
        if os.path.exists('{}.pub'.format(self.sshkey)):
            if not self.rsync(local='{}.pub'.format(self.sshkey), remote='.ssh/authorized_keys', up=True, keeppermissions=True):
                raise ValueError("Cannot copy '{}.pub' => remote '.ssh/authorized_keys'".format(self.sshkey))
        if self.ssh('''{
            echo "Host *"
            echo "  StrictHostKeyChecking no"
            echo "  UserKnownHostsFile=/dev/null"
            echo "  ServerAliveInterval 300"
            echo "  ServerAliveCountMax 2"
        } >.ssh/config''') != 0:
            raise ValueError("Cannot create remote '.ssh/config' file")

    def rsync(self, remote, local, up=False, down=False, recursive=False, verbose=False, keeppermissions=False, exclude=None):
        if (not up and not down) or (up and down):
            raise ValueError("Only one of 'up' or 'down' must be given")
        if not self.instance:
            raise ValueError('The instance has been terminated')

        opt = '-'
        if not verbose: opt += 'q'
        opt += 'Hzl'
        if recursive:
            # Ensure that the local and remote are used correctly.  Without a
            # trailing '/' rsync will push into a subdirectory if one exists
            if local[-1] != '/': local += '/'
            if remote[-1] != '/': remote += '/'
            opt += 'r'
        if keeppermissions:
            opt += 'ptgo'
        sshopt = '-e /usr/bin/ssh -i {} -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null'.format(self.sshkey)
        remote = '{}@{}:{}'.format(self.remoteuser, self.IPv4, remote)

        command = ['rsync', opt]
        if exclude: command += ['--exclude', exclude]
        command += [sshopt, remote if down else local, local if down else remote]
        if verbose:
            print('Copying: {} => {}'.format(remote if down else local, local if down else remote))
        result = False
        try:
            if subprocess.call(command) == 0:
                result = True
        except:
            pass
        if verbose:
            print('Copy {}'.format('successful' if result else 'failed'))
        return result

    def ssh(self, command, prefix=None, cd=None, verbose=False, showoutput=True, returnoutput=False):
        if not self.instance:
            raise ValueError('The instance has been terminated')
        if cd:
            command = 'cd {} && {} {}; {}'.format(cd, '{', command, '}')
        command = '{} {}; {}'.format('{', command, '} 2>&1')
        sshcmd = ['ssh', '-nq', '-oStrictHostKeyChecking=no', '-oUpdateHostKeys=no', '-oServerAliveInterval=300', '-oServerAliveCountMax=5',
                         '-i', self.sshkey, '{}@{}'.format(self.remoteuser, self.IPv4), command]
        output = []
        result = -1
        if verbose:
            print('{}Running remotely: {}'.format('{}: '.format(prefix) if prefix else '', command))
        proc = subprocess.Popen(sshcmd, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True)
        for line in proc.stdout:
            line = line.rstrip()
            if showoutput:
                print('{}{}'.format('{}: '.format(prefix) if prefix else '', line))
            if returnoutput:
                output.append(line)
        proc.wait()
        result = proc.returncode
        if verbose:
            print('{}Command {}'.format('{}: '.format(prefix) if prefix else '', 'succeeded' if result == 0 else 'failed {}'.format(result)))
        return (result, output) if returnoutput else result

    def terminate(self):
        if self.instance and not self.keepinstance:
            command = self.builder.ec2cmd() + ['terminate-instances', '--instance-ids', self.instance]
            subprocess.check_output(command)
            self.sshkey = None
            self.IPv4 = None
            self.instance = None
        for sig in self.signals:
            signal.signal(sig, self.original_handlers[sig])

    def abandon(self):
        self.sshkey = None
        self.IPv4 = None
        self.instance = None
