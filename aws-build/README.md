# How to use aws-build

## Configure your build controller
*  The build controller is the machine that controls the running AWS builds

   This is usually your dev box or jenkins server
*  Install the aws command-line
```
   sudo pip install aws-shell
```
* Connect to the AWS console (t1?) and create an access key

  Go to Services => IAM => Users => <me> => Security credentials => Create access key
* Run this to set those creds up on your build controller
```
  aws --profile AWS-t1 configure
```

  If you set up a default profile by omitting `--profile` above, you don't need to use the aws-build -p switch

## Set up your key, storing it in your repo ('myrepo')
* Create a key with
```
  ssh-keygen -t rsa -f myrepo-builder -P '' -C myrepo-builder -q
```
* Check the key into your repo
* Push it to AWS

  NETWORK & SECURITY => Key Pairs => Import Key Pair, using 'myrepo-builder' as the name
* If you want to use the aws-build `-b` switch, push it to github

  OpenDNS/myrepo => Settings => Deploy keys

# Add this repo as a git submodule to your own repo:
```
  git submodule init
  git submodule add git@github.office.OpenDNS.com:OpenDNS/aws-build.git
```

# Create the build controller job
* Run this as the command on the build controller
```
  aws-build/aws-build -i myrepo-builder -n myrepo -p AWS-t1 -a debian-8 -a debian-9 -a ubuntu-12.04::STATIC=1 -- make packages
```

  This runs three asynchronous jobs on debian-8, debian-9 and ubuntu-12.04
  The ubuntu build has an additional STATIC=1 command-line argument

# Debug time
* You can create an on-the-fly build box if investigating stuff from somewhere with a 'myrepo' checkout:
* Do a DEBUG build of the forwarder (OpenDNS/opendnscache.git) and of dnscrypt-tool and keep the box around
```
  aws-build/aws-build -a ubuntu-12.04-32bit:c3.large -b SRE-3255 -K -- ./autobuild -fdD
```

  The `command` part can be something as simple as `true` if you just want the environment immediately.
  We created a c3.large box because we need the extra CPU.
  See `lib/AWSBuilder.py` for a list of available resources.

* Log into the temporary build box:

  Looking at line 2 of the output for the IP number, you can
```
  ssh -i odc-builder ubuntu@IP.IP.IP.IP     # use admin@ for debian builds
```
* Throw it all away:

  Finally when we're done with the machine, just run `poweroff` - it'll self-terminate
