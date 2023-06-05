# libuup example application

This example application makes use of `libuup` and `libcrl`

## Features

* Configures the config loader
* Sets up a config loading loop
* Provides a key-value `options` file to configure a running service
* Loads per-organization CRL formatted `rules` files
* Creates regular md5 digests of loaded files that can be used to validate against
the Brain API.
* Creates a TCP server that listens for JSON formatted messages and uses 
those messages to load and apply an organization's policy.
* Builds a debian package that installs the application as a daemontools
`supervise` service.

## To build this application

This will only build under Linux (specifically tested on Debian), it does not build
under any BSD variant (including MacOS).  It has been tested within the DPT team's
Vagrant image, instructions for that are included below.

* Clone the UUP builder repo (https://github.office.opendns.com/SRE/uup)

```
$ cd ~/Source/
$ git clone git@github.office.opendns.com:SRE/uup.git
$ git submodule init
$ git submodule update
```

* Build the application

```
$ make release test
```

For more debugging output use `debug` instead of `release`

* To build the application and create the debian package

```
$ MAKE_DEBS=1 make release test 
```

## To use the application

* Application usage
```
$ ./libuup/exe-uup-example/build-linux-64-release/uup-example -h
usage: uup-example [options]
       start the example application

options:
  -f <dir>  directory that contains config (default .)
  -h        display this usage text
  -a <ip>   IP address for rules server (default 127.0.0.1)
  -p <port> port for rules server (default 1234)
  -s <dir>  save known-good configuration files here for emergency use on startup
  -G <path> Graphite stats log file
```

* Run the application against the example config files

```
$ ./libuup/exe-uup-example/build-linux-64-release/uup-example -f ./libuup/exe-uup-example/etc/config
$ ./libuup/exe-uup-example/build-linux-64-debug/uup-example -f ./libuup/exe-uup-example/etc/config
```

* Send data to the application to evaluate rules.

The example rules file is for organization `1234` and has rules that act on a `value` fact:
```json
rules 2
count 4
[rules:4]
rule_id:=1, data:="Just one"
(value = 1): (one)
rule_id:=2, data:="Positive"
(value > 1): (lots)
rule_id:=3, data:="Zero"
(value = 0): (nothing)
rule_id:=4
(value < 0): (negative)
```

The TCP server is listening for a single new-line terminated JSON message which
must contain a numeric "org" field with the organization ID, other fields will
be used as facts by the rules engine.  It will generate a new-line terminated
JSON response.

To send data to the application via netcat (could also use telnet):
```
$ echo 'junk' | nc 127.0.0.1 1234
{"error":"Received invalid json"}

$ echo '{ "org": 5678 }' | nc 127.0.0.1 1234
{"org":5678,"error":"Unable to find a policy for org 5678"}

$ echo '{ "org": 1234 }' | nc 127.0.0.1 1234
{"org":1234,"error":"Rules execution resulted in no action: Internal error testing org 1234 rule 0"}
--> The rules engine expected there to be a "value" fueld

$ echo '{ "org": 1234, "value": 1 }' | nc 127.0.0.1 1234
{"org":1234,"rule_id":1,"rule_data":"Just one","action":"one"}

$ echo '{ "org": 1234, "value": 2 }' | nc 127.0.0.1 1234
{"org":1234,"rule_id":2,"rule_data":"Positive","action":"lots"}

$ echo '{ "org": 1234, "value": 0 }' | nc 127.0.0.1 1234
{"org":1234,"rule_id":3,"rule_data":"Zero","action":"nothing"}

$ echo '{ "org": 1234, "value": -123 }' | nc 127.0.0.1 1234
{"org":1234,"rule_id":4,"action":"negative"}
```

## To install and use the service from the debian package

* Build and locate the debian package
```
$ MAKE_DEBS=1 make release test
$ find $(pwd) -name "*.deb"
/home/vagrant/Source/uup/libuup/exe-uup-example/build-linux-64-release/uup-example-service_0.1-dev_amd64.deb
```

* Install the debian package
```
$ sudo dpkg -i /home/vagrant/Source/uup/libuup/exe-uup-example/build-linux-64-release/uup-example-service_0.1-dev_amd64.deb
```

* The service will be installed and will immediately begin to run and accept requests as shown above
```
$ cd /service/uup-example
$ tail -f log/current
18033 UUP Example Application started
18033   config directory: /service/uup-example/config
18033   graphitelog path: /service/uup-example/graphitelog
20220303 200402.733 T     18033 ------ 5 - loading options
20220303 200402.733 T     18033 ------ 4 - key-value:: // parsing file: /service/uup-example/config/options
20220303 200402.733 T     18033 ------ 5 - options::digest_store_dir=digests
20220303 200402.733 T     18033 ------ 5 - options::example_option=123
20220303 200402.733 T     18033 ------ 3 - /service/uup-example/config/options:8: 'unimplemented_option': Unrecognised key (ignored; marked as optional)
20220303 200402.733 T     18033 ------ 5 - loaded options (delivery 76389, latency 143, loadtime 0)
20220303 200402.733 T     18033 ------ 5 - loading rules
20220303 200402.733 T     18033 ------ 5 - rules: queued 1 segments
20220303 200402.733 T     18033 ------ 5 - added rules segment 1234 from file /service/uup-example/config/rules/rules.1234.org.gz (delivery 76389, latency 143, loadtime 0)
20220303 200402.733 T     18033 ------ 5 - loaded rules (loadtime 0)
18033 Example option has been set to 123
20220303 200446.054 T     18034 ------ 3 - Received 28/28 bytes: { "org": 1234, "value": 2 }\n
```

* The service's configuration files will be within `/service/uup-example/config/rules/`. 
  New rules files can be placed here, with the naming format of `rules.[orgid].org.gz`
  (while the `.gz` suffix is required the file does not have to be compressed).
  New files and and modification of existing files should be picked up immediately 
  and the service's log will indicate if they parsed correctly.

## To build within a vagrant image

If a build environment for this is needed, the DPT team has a Vagrant image that
we use for development on which this example can be built.  To use this you will
need to install Vagrant and a VM environment as appropriate for your local OS.

You can then clone our Vagrant repo: https://github.office.opendns.com/SRE/vagrant-resolver

This repo expects the code to be built to exist in `~/Source`, however this can
be modified via the Vagrantfile.  It will perform an initial synchronization of
that directory to the VM, if resynchronization is needed it can be accomplished
either by running `vangrant rsync` each time or by leaving a process running
`vangrant rsync-auto`.

To setup the vagrant VM from MacOS:

```
$ mkdir -p ~/Source
$ cd ~/Source
$ git clone git@github.office.opendns.com:SRE/uup.git
$ git submodule init
$ git submodule update
$ mkdir -p ~/Vagrant
$ cd ~/Vagrant
$ git@github.office.opendns.com:SRE/vagrant-resolver.git vagrant-uup-example
$ vagrant up
$ vagrant ssh
$ cd Source/uup
```

From here follow the instructions above for building and installing the service.
Once the service is up and running you should be able to query it from outside the
VM, however you'll need the local IP the VM is running on:

```
$ vagrant ssh
$ ifconfig eth1
...
eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.33  netmask 255.255.255.0  broadcast 192.168.1.255
...
```

Now that you have the local IP you can query from outside the VM, using netcat (`nc`)
or telnet

```
$ echo '{ "org": 1234, "value": 1 }' | nc 192.168.1.33 1234
{"org":1234,"rule_id":1,"rule_data":"Just one","action":"one"}
$ telnet 192.168.1.33 1234
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
{ "org": 1234, "value": -123 }
{"org":1234,"rule_id":4,"action":"negative"}
Connection closed by foreign host.
```
As a note, local routing can potentially override the ability to connect to the
VM in this manner (this has been observed on the `umbrella-eng` office networks).