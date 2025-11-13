# ARP, Traffic sniffing and DNS spoofing project in the course ethical hacking dat505
In this assignment we were going to implement `arp_spoof.py`, `traffic_interceptor.py`and `dns_spoof.py`, each to server there own purpose in the pipeline.

### Requirements
The only requirements for this project is `scapy`, and version `2.6.1` was used and can be installed via pip using the requirements file

### Running experiements
Each experiment have several required or optional flags which is explained here including an example run.

**NOTE: Each python script has to be run with sudo privileges**
#### ARP spoofing
Example command: sudo python3 arp_spoof.py -t 10.10.0.20 -g 10.10.0.1 -i eth0

**Flags:**
- -t, --target, Target IP, **Required**
- -g, --gateway, Gateway IP, **Required**
- -i, --interface, Interface, Optional (Defaults to `eth0`)
- -f, --forwarding, Forwarding of IP, default=0, accepted values 0/1, Optional (Defaults to `0`)
- -v, --verbose, Verbose flag, default=0, accepted values 0/1, Optional (Defaults to `0`)

#### Traffic interceptor
Example command: sudo python3 traffic_interceptor.py -i eth0 -o traffic_sniffing -d 20

**Flags**
- -i, --interface, Interface, **Required**
- -o, --output, Output filename/destination, **Required**
- -d, --duration, Duration of packet sniffing, Optional

#### DNS spoofing
DNS spoofing has to be run alongside ARP spoofing to get desired results

Example command: sudo python3 dns_spoof.py -i eth0 -c dns_configs.json

**Flags**
- -i, --interface, Interface, **Required**
- -c, --config, Configuration file, **Required**

## Ethical reminder
**THIS IS DONE STRICTLY AS A TEACHING EXPERIENCE WITHIN A CONTROLLED LAB ENVIROMENT WITHOUT INTERNET EXPOSURE, DO NOT USE ANY METHODS IN AN ENVIRONMENT EXPOSED TO THE INTERNET**