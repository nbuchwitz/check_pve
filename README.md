# check_pve
Icinga check command for Proxmox VE via API

## installation / dependencies
### Debian / Ubuntu
```
apt install python-enum34 python-requests
```

### Redhat / CentOS
```
yum install python-enum34 python-requests
```

## usage
```
usage: check_pve.py [-h] -e API_ENDPOINT -u API_USER -p API_PASSWORD [-k] -m
                    {cluster,cpu,memory,storage,io_wait,updates,services,subscription,vm}
                    [-n NODE] [--name NAME] [--ignore-service NAME]
                    [-w TRESHOLD_WARNING] [-c TRESHOLD_CRITICAL] [-M]

Check command for PVE hosts via API

optional arguments:
  -h, --help            show this help message and exit

API Options:
  -e API_ENDPOINT, --api-endpoint API_ENDPOINT
                        PVE api endpoint hostname
  -u API_USER, --username API_USER
                        PVE api user (e.g. icinga2@pve or icinga2@pam, depending on which backend you have chosen in proxmox)
  -p API_PASSWORD, --password API_PASSWORD
                        PVE api user password
  -k, --insecure        Don't verify HTTPS certificate

Check Options:
  -m {cluster,cpu,memory,storage,io_wait,updates,services,subscription,vm}, --mode {cluster,cpu,memory,storage,io_wait,updates,services,subscription,vm}
                        Mode to use.
  -n NODE, --node NODE  Node to check (necessary for all modes except cluster)
  --name NAME           Name of storage or vm
  --ignore-service NAME
                        Ignore service NAME in checks
  -w TRESHOLD_WARNING, --warning TRESHOLD_WARNING
                        Warning treshold for check value
  -c TRESHOLD_CRITICAL, --critical TRESHOLD_CRITICAL
                        Critical treshold for check value
  -M                    Values are shown in MB (if available). Tresholds are
                        also treated as MB values
```

# hints

Try something like that first ...

```
./check_pve.py -u icinga2@pve -p uoXei8fee9shia4tah4voobe -e proxmox.localdomain.local -k -m cluster
```

## Get cluster health
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -k -m cluster
OK - Cluster 'proxmox1' is healthy'
```

## Get CPU load
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -k -m cpu -n node1
OK - CPU usage is 2.4%|usage=2.4%;;
```

## Get storage usage
```
./check_pve.py -u <API_USER> -p <API_PASSWORD> -e <API_ENDPOINT> -k -m storage -n server914sx --name local
OK - Storage usage is 54.23%|usage=54.23%;; used=128513.11MB;;;236980.36
```

# faq
## AttributeError: 'int' object has no attribute 'name'
### Problem
```
Traceback (most recent call last):
  File "/usr/lib/nagios/plugins/check_pve.py", line 419, in <module>
    pve.check()
  File "/usr/lib/nagios/plugins/check_pve.py", line 359, in check
    self.checkOutput()
  File "/usr/lib/nagios/plugins/check_pve.py", line 59, in checkOutput
    self.output(self.checkResult, message)
  File "/usr/lib/nagios/plugins/check_pve.py", line 62, in output
    prefix = returnCode.name
AttributeError: 'int' object has no attribute 'name'
```

### Solution
Be sure, python-enum34 (enum34) is installed.
https://docs.python.org/3/library/enum.html#creating-an-enum

## 
### Problem
```
Traceback (most recent call last):
  File "/usr/lib/nagios/plugins/check_pve.py", line 418, in <module>
    pve = CheckPVE()
  File "/usr/lib/nagios/plugins/check_pve.py", line 415, in __init__
    self.getTicket()
  File "/usr/lib/nagios/plugins/check_pve.py", line 115, in getTicket
    result = self.request(url, "post", data=data)
  File "/usr/lib/nagios/plugins/check_pve.py", line 96, in request
    self.output(NagiosState.UNKNOWN, "Could not connect to PVE API: Failed to resolve hostname")
  File "/usr/lib/nagios/plugins/check_pve.py", line 62, in output
    prefix = returnCode.name
AttributeError: 'int' object has no attribute 'name'
```
### Solution
Check the connection with curl
```
curl -k -d "username=<API_USER>&password=<API_PASSWORD>"  https://<API_ENDPOINT>:8006/api2/json/access/ticket
``` 
Maybee a proxy (http_proxy, https_proxy) env variable blocks the connection to your proxmox host



