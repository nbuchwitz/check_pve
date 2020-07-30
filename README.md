# check_pve
Icinga check command for Proxmox VE via API

## Setup

### Requirements

This check command depends on **Python 3** and the following modules:
 * enum
 * requests
 * argparse

**Installation on Debian / Ubuntu**
```
apt install python3 python3-requests
```

**Installation on Redhat 7 / CentOS 7**
```
yum install python36 python36-requests
```

**Installation on FreeBSD**
```
pkg install python3 py37-requests
```


### Create a API user in Proxmox VE

Create a role named ``Monitoring`` and assign necessary privileges:

```
pveum roleadd Monitoring
pveum rolemod Monitoring --privs Sys.Modify,VM.Monitor,Sys.Audit,Datastore.Audit,VM.Audit
```

Create a user named ``monitoring`` and set password:

```
pveum useradd monitoring@pve --comment "The ICINGA 2 monitoring user"
pveum passwd monitoring@pve
```

Assign ``monitoring`` role to user ``monitoring``

```
pveum aclmod / -user monitoring@pve -role Monitoring
```

For further information about the Proxmox VE privilege system have a look into the [documentation](https://pve.proxmox.com/pve-docs/pve-admin-guide.html#_strong_pveum_strong_proxmox_ve_user_manager).


## Usage

The ``icinga2`` folder contains the command definition and service examples for use with Icinga2.

```
usage: check_pve.py [-h] -e API_ENDPOINT [--api-port API_PORT] -u API_USER -p API_PASSWORD [-k] -m
                    {cluster,version,cpu,memory,storage,io_wait,updates,services,subscription,vm,vm_status,replication,disk-health,ceph-health}
                    [-n NODE] [--name NAME] [--vmid VMID]
                    [--expected-vm-status {running,stopped,paused}]
                    [--ignore-vm-status] [--ignore-service NAME]
                    [--ignore-disk NAME] [-w TRESHOLD_WARNING]
                    [-c TRESHOLD_CRITICAL] [-M] [-V MIN_VERSION]

Check command for PVE hosts via API

optional arguments:
  -h, --help            show this help message and exit

API Options:
  -e API_ENDPOINT, --api-endpoint API_ENDPOINT
                        PVE api endpoint hostname
  --api-port API_PORT   PVE api endpoint port
  -u API_USER, --username API_USER
                        PVE api user (e.g. icinga2@pve or icinga2@pam,
                        depending on which backend you have chosen in proxmox)
  -p API_PASSWORD, --password API_PASSWORD
                        PVE api user password
  -k, --insecure        Don't verify HTTPS certificate

Check Options:
  -m {cluster,version,cpu,memory,storage,io_wait,updates,services,subscription,vm,vm_status,replication,disk-health}, --mode {cluster,version,cpu,memory,storage,io_wait,updates,services,subscription,vm,vm_status,replication,disk-health}
                        Mode to use.
  -n NODE, --node NODE  Node to check (necessary for all modes except cluster
                        and version)
  --name NAME           Name of storage, vm, or container
  --vmid VMID           ID of virtual machine or container
  --expected-vm-status {running,stopped,paused}
                        Expected VM status
  --ignore-vm-status    Ignore VM status in checks
  --ignore-service NAME
                        Ignore service NAME in checks
  --ignore-disk NAME    Ignore disk NAME in health check
  -w TRESHOLD_WARNING, --warning TRESHOLD_WARNING
                        Warning treshold for check value
  -c TRESHOLD_CRITICAL, --critical TRESHOLD_CRITICAL
                        Critical treshold for check value
  -M                    Values are shown in MB (if available). Tresholds are
                        also treated as MB values
  -V MIN_VERSION, --min-version MIN_VERSION
                        The minimal pve version to check for. Any version
                        lower than this will return CRITICAL.
```

## Examples

**Check cluster health**
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m cluster
OK - Cluster 'proxmox1' is healthy'
```

**Check PVE version**
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m version -V 5.0.0
OK - Your pve instance version '5.2' (0fcd7879) is up to date
```

**Check CPU load**
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m cpu -n node1
OK - CPU usage is 2.4%|usage=2.4%;;
```

**Check memory usage**
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m memory -n node1
OK - Memory usage is 37.44%|usage=37.44%;; used=96544.72MB;;;257867.91
```

**Check disk-health**
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m disk-health -n node1
OK - All disks are healthy|wearout_sdb=96%;; wearout_sdc=96%;; wearout_sdd=96%;; wearout_sde=96%;;
```

**Check storage usage**
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m storage -n node1 --name local
OK - Storage usage is 54.23%|usage=54.23%;; used=128513.11MB;;;236980.36

./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m storage -n node1 --name vms-disx
CRITICAL - Storage 'vms-disx' doesn't exist on node 'node01'
```

**Check subscription status**
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m subscription -n node1 -w 50 -c 10
OK - Subscription of level 'Community' is valid until 2019-01-09
```

**Check VM status**

Without specifying a node name:
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m vm --name test-vm
OK - VM 'test-vm' is running on 'node1'|cpu=1.85%;; memory=8.33%;;
```

You can also pass a container name for the VM check:
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m vm --name test-lxc
OK - LXC 'test-lxc' on node 'node1' is running|cpu=0.11%;; memory=13.99%;;
```

With memory thresholds:
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m vm --name test-vm -w 50 -c 80
OK - VM 'test-vm' is running on 'node1'|cpu=1.85%;; memory=40.33%;50.0;80.0
```

With a specified node name, the check plugin verifies on which node the VM runs.
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m vm -n node1 --name test-vm
OK - VM 'test-vm' is running on node 'node1'|cpu=1.85%;; memory=8.33%;;

./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m vm -n node1 --name test-vm
WARNING - VM 'test-vm' is running on node 'node2' instead of 'node1'|cpu=1.85%;; memory=8.33%;;
```

If you only want to gather metrics and don't care about the vm status add the ``--ignore-vm-status`` flag:
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m vm --name test-vm --ignore-vm-status
OK - VM 'test-vm' is not running
```

Specify the expected VM status:
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m vm --name test-vm --expected-vm-status stopped
OK - VM 'test-vm' is not running

```

For hostalive checks without gathering performance data use ``vm_status`` instead of ``vm``. The parameters are the same as with ``vm``.

**Check storage replication status**
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m replication -n node1
OK - No failed replication jobs on node1
```

**Check ceph cluster health**
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -m ceph-health
WARNING - Ceph Cluster is in warning state
```

## FAQ

### Could not connect to PVE API: Failed to resolve hostname

Verify that your DNS server is working and can resolve your hostname. If everything is fine check for proxyserver environment variables (HTTP_PROXY,HTTPS_PROXY), which maybe not allow communication to port 8006.

## Contributors

* Alexey Kukushkin ([meshok0](https://github.com/meshok0))
