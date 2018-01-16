# check_pve
Icinga check command for Proxmox VE via API

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
                        PVE api user
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
