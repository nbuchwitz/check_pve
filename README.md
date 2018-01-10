# check_pve
Icinga check command for Proxmox VE via API

## usage
```

usage: check_pve.py [-h] -e API_ENDPOINT -u API_USER -p API_PASSWORD [-k] -m
                    {cluster,cpu,memory,storage,io_wait,updates,subscription}
                    [-n NODE] [-s STORAGE] [-w TRESHOLD_WARNING]
                    [-c TRESHOLD_CRITICAL] [-U {GB,MB,%}]

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
  -m {cluster,cpu,memory,storage,io_wait,updates,subscription}, --mode {cluster,cpu,memory,storage,io_wait,updates,subscription}
                        Mode to use.
  -n NODE, --node NODE  Node to check (necessary for all modes except cluster)
  -s STORAGE, --storage STORAGE
                        Name of storage
  -w TRESHOLD_WARNING, --warning TRESHOLD_WARNING
                        Warning treshold for check value
  -c TRESHOLD_CRITICAL, --critical TRESHOLD_CRITICAL
                        Critical treshold for check value
  -U {GB,MB,%}, --unit {GB,MB,%}
                        Return numerical values in GB, MB or %
```
