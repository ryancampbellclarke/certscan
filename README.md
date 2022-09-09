# certscan

Certificate Scanner. Find certificates on your network.

## Contents

* [Usage](#usage)
* [Installation](#installation)
* [Tests](#tests)
* [Build Binary](#build-binary)

## Usage

```commandline
usage: certscan.py [-h] [-p PORTS] [-q | -j] [-o [OUTPUT]] [-a] [-v] [scan_target]

positional arguments:
  scan_target           Target of discovery scan. Formats: Single IP: '10.10.10.10', Single domain: 'example.com', List of IPs: '10.10.10.10,10.10.10.20,10.10.10.30', Range of IPs: '10.10.10.10-10.10.10.20', Range of IPs by CIDR    
                        notation: '10.10.10.0/24', List of domains: 'example.com,example.org,example.edu'

options:
  -h, --help            show this help message and exit
  -p PORTS, --ports PORTS
                        List of ports to scan on each host
  -q, --quiet           Turn off printing discovered certificates to stdout
  -j, --json            Output discovered certificates to std as json
  -o [OUTPUT], --output [OUTPUT]
                        Output discovered certificates to output/certificates.csv or (optional) specified path
  -a, --all             Print all certificate scans to stdout, found and not-found certificates. Prints in json if -j option set
  -v, --version         Software version
```

### Examples

```commandline
# Get certificate from example.com:443
python certscan.py -s example.com

# Get certificates from mixed list of IPs and domains on multiple ports
python certscan.py -s example.com,10.10.10.10,example.edu -p 443,636,1337

# Dump to file, silence output
python certscan.py -s example.com -o /path/to/dir/ -q

# Dump output as json
python certscan.py -s example.com -j
```

## Installation

### Python interpreter

```commandline
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
3. Optional: Add the extracted folder to PATH
4. If you added to path, run with `certscan`. Otherwise, run the `certscan` binary from the installation folder.

## Tests

Run tests with `pytest`

## Build binary

Use nuitka to build binary:

```commandline
# clone certscan repo
git clone git@github.com:ryancampbellclarke/certscan.git

# change directory to cloned directory
cd certscan

# install requirements
pip install -r requirements.txt

# build with nuitka
python -m nuitka certscan.py --standalone
```
