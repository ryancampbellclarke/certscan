# certscan

Certificate Scanner. Find certificates on your network.

## Contents

* [Usage](#usage)
  * [Single Scan](#single-scan)
  * [Scheduled](#scheduled)
* [Installation](#Installation)
  * [Python interpreter](#python-interpreter)
  * [Windows](#windows)
* [Build](#build)

## Usage

`usage: certscan.exe [-h] [-s SCAN | -d | -c] [-p PORTS] [-q | -j] [-o [OUTPUT]] [-a] [-v]`

### Single Scan

Run a scan by `-s` or `--scan` with one of the following strings:

Single IP: `-s 10.10.10.10`

List of IPs: `-s 10.10.10.10,10.10.10.20,10.10.10.30`

Range of IPs: `-s 10.10.10.0-10.10.10.5`

Range of IPs in CIDR notation: `-s 10.10.10.0/24`

A domain: `-s example.com` 

A list of domains: `-s example.com,example.org,example.edu`

and optionally (if not specified, it defaults to `--ports 443`):

`-p` or `--ports` to specify ports to scan in the form separated by `,`

#### Optional parameters:

`-q` or `--quiet` to prevent certificates from printing to std

`-j` or `--json` to print certificates to stdout as json

`-o` or `--output` to have the certificates printed to a CSV. If no path is
passed the file will be created at `output/certificates.csv`

`-a` or `--all` to include certificates not found in scan

Examples:

Scan only 10.10.10.10 port 443: `certscan --single 10.10.10.10`

Scan the entire 10.10.10.0/24 network on ports 443 and
636: `certscan --cidr 10.10.10.0/24 --ports 443,636`

Scan the list of domains on port
123: `certscan --domains [example.com,subdomain.example.com,,moredomains.example.com] -p 123`

### Scheduled

#### Config

**NOTE:** On roadmap, not yet implemented. Issue #22

set `-c` or `--config`: Creates scanners defined in `conf/config.ini`

#### Database

**NOTE:** On roadmap, not yet implemented. Issue #23

set `-d` or `--database`: Connects to `conf/database.ini` to discover scanner
information.

## Installation

### Python interpreter

```
# clone certscan repo
git clone git@github.com:ryancampbellclarke/certscan.git

# change directory to cloned directory
cd certscan

# run through python interperter with one of these depending on your installation
python certscan.py
```

### Binary
1. Download binary from [Releases page on Github](https://github.com/ryancampbellclarke/certscan/releases).
2. Extract archive to installation folder
3. Optional: [Add the extracted folder to PATH](https://www.architectryan.com/2018/03/17/add-to-the-path-on-windows-10/)
4. If you added to path, run with `certscan`. Otherwise, run `certscan.exe` from the installation folder or with the absolute path to `certscan.exe`.

## Build binary

Use nuitka to build binary:

```
# clone certscan repo
git clone git@github.com:ryancampbellclarke/certscan.git

# change directory to cloned directory
cd certscan

# install requirements
pip install -r requirements.txt

# build with nuitka
python -m nuitka certscan.py --standalone
```
