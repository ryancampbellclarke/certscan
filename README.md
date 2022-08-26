# CertScan

Certificate Scanner. Find certificates on your network.

## Installation

### Python interpreter

1. Download source
2. In source directory run as `python main.py`

### Windows

#### Binary
1. Download binary from Releases page on Github.
2. Extract archive to installation folder
3. [OPTIONAL] [Add the extracted folder to PATH](https://www.architectryan.com/2018/03/17/add-to-the-path-on-windows-10/)
4. If you added to path, run with `certscan`. Otherwise, run `certscan.exe` from the installation folder or with the absolute path.

#### Build from source
1. Follow build instructions in [Build section](#build)
2. Copy the generated `dist/` folder to where you'd like to install it
3. [OPTIONAL] [Add the extracted folder to PATH](https://www.architectryan.com/2018/03/17/add-to-the-path-on-windows-10/)
4. If you added to path, run with `certscan`. Otherwise, run `certscan.exe` from the installation folder or with the absolute path.

## Run modes

### Single Scan

Run a scan by `-s` or `--scan` with one of the following strings:

Single IP: `-s 10.10.10.10`

Range of IPs: `-s 10.10.10.0-10.10.10.5`

Range of IPs in CIDR notation: `-s 10.10.10.0/24`

A domain: `-s example.com` 

A list of domains: `-s example.com,example.org,example.edu`



and optionally (if not specified, it defaults to `--ports 443`):

`-p` or `--ports` to specify ports to scan in the form separated by `,`

Optional parameters:

Set `-q` or `--quiet` to prevent certificates from printing to std

Set `-j` or `--json` to print certificates to stdout as json

Set `-o` or `--output` to have the certificates printed to a CSV. If no path is
passed the file will be created at `output/certificates.csv`

Set `-a` or `--all` to include certificates not found in scan

Examples:

Scan only 10.10.10.10 port 443: `certscan --single 10.10.10.10`

Scan the entire 10.10.10.0/24 network on ports 443 and
636: `certscan --cidr 10.10.10.0/24 --ports 443,636`

Scan the list of domains on port
123: `certscan --domains [example.com,subdomain.example.com,,moredomains.example.com] -p 123`

### Scheduled

#### Config

set `-c` or `--config`: Modifies the `config.ini` configuration and
run `certscan -i` without any arguments.

#### Database

set `-db` or `--database`: Connects to `database.ini` to discover scanner
information.

## Build

`python setup.py py2exe`