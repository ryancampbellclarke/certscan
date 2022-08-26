# CertScan

Certificate Scanner. Find certificates on your network.

## Run modes

### Single Scan mode

Run a single scan by passing one of the following scan types:

`-s` or `--single` expects a single IPv4 address or domain name

`-c` or `--cidr` expects an IPv4 subnet in CIDR notation

`-r` or `--range` expects the start and end IPv4 addresses of a range of IPv4
addresses separated by `-`

`-d` or `--domains` expects a list of domains separated by `,`

and optionally (if not specified, it defaults to `--ports 443`):

`-p` or `--ports` to specify ports to scan in the form separated by `,`

Optional parameters:

Set `-q` or `--quiet` to prevent certificates from printing to std

Set `-j` or `--json` to print certificates to stdout as json

Set `-o` or `--output` to have the certificates printed to a CSV. If no path is
passed the file will be created at `output/certificates.csv`

Examples:



Scan only 10.10.10.10 port 443: `certscan --single 10.10.10.10`

Scan the entire 10.10.10.0/24 network on ports 443 and 636: `certscan --cidr 10.10.10.0/24 --ports 443,636`

Scan the list of domains on port 123: `certscan --domains [example.com,subdomain.example.com,,moredomains.example.com] -p 123`

### Scheduled mode

#### Config

set `-i` or `--ini`: Modifies the `config.ini` configuration and
run `certscan -i` without any arguments.

#### Database

set `-db` or `--database`: Connects to `database.ini` to discover scanner
information.

## Build

`python setup.py py2exe`