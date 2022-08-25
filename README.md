# CertScan

Certificate Scanner. Find certificates on your network.

## Run modes

### Single Scan mode

Run a single scan by passing one of the following scan types:

`-s` or `--single` expects a single IPv4 address or domain name

`-c` or `--cidr` expects an IPv4 subnet in CIDR notation

`-r` or `--range` expects the start and end IPv4 addresses of a range of IPv4 addresses separated by `-`

`-d` or `--domains` expects a list of domains separated by `,`

and optionally (if not specified, it defaults to `--ports 443`) one of these port scan types:

`-p` or `--ports` to specify ports to scan in the form separated by `,`

`-n` or `--nmap` to scan for open ports with nmap, then scan for certificates on those open ports

Set `-q` or `--quiet` to prevent certificates from printing to std

Set `--csv` to have the certificates printed to the default output location `output/certificates.csv`

Examples:

`certscan --single 10.10.10.10 --ports 443`

`certscan --cidr 10.10.10.0/24 --ports 443,636`

`certscan --range 10.10.10.0-10.10.10.255 --nmap`

`certscan --domains [example.com,subdomain.example.com, ... ,moredomains.example.com] --nmap`

### Scheduled mode

Modify the `config.ini` configuration and run `certscan` without any arguments.

## Build

`python setup.py py2exe`