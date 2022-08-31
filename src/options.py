import ipaddress

from src import scanner

"""
Helper functions to implement command line options and to organize them for further parsing.
"""


def scan_type_group(parser):
    """
    Sets up Scan Type arguments related to configuring a certscan run
    """
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-s", "--scan", type=str,
                       help="Scan a single IP: 10.10.10.10, a single domain:"
                            " example.com,a list of IPs: 10.10.10.10,"
                            "10.10.10.20,10.10.10.30, a range of IPs: "
                            "10.10.10.10-10.10.10.20, a range of IPs by CIDR "
                            "notation: 10.10.10.0/24, or a list of domains: "
                            "example.com,example.org,example.edu"
                            "`,`")
    return parser


def port_scan_group(parser):
    """
    Sets up Port Scan Type arguments related to configuring a certscan run
    """
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--ports", type=str,
                       help="List of ports to scan on each host")
    return parser


def print_group(parser):
    """
    Sets up arguments related to managing printing to stdout
    """
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-q", "--quiet", action='store_true',
                       help="Turn off printing discovered certificates to"
                            " stdout")
    group.add_argument("-j", "--json", action='store_true',
                       help=f"Output discovered certificates to std as json")
    return parser


def parse_scan_input(args):
    """
    Parses the arguments passed to determine which one was selected and returns
    the data associated.
    """
    # Determine if it is an IP address
    try:
        ipaddress.ip_address(args.scan)
        isIpAddress = True
    except ValueError:
        isIpAddress = False

    if isIpAddress:
        return (scanner.ScanMethod.single, args.scan)
    elif "/" in args.scan:
        # Only CIDR should have "/"
        return (scanner.ScanMethod.cidr, args.scan)
    elif "-" in args.scan:
        return (scanner.ScanMethod.range, args.scan)
    else:
        return (scanner.ScanMethod.domains, args.scan)


def parse_port_scan_input(args):
    """
    Parses the arguments passed to determine which one was selected and returns
    the data associated.
    """
    if args.ports:
        return (scanner.PortScanMethod.specific_ports, args.ports)
    else:
        return (
            scanner.PortScanMethod.specific_ports, scanner.DEFAULT_PORT_TARGET)


def parse_inputs(args):
    """

    """
    (scan_method, scan_target) = parse_scan_input(args)
    (port_scan_method, port_scan_target) = parse_port_scan_input(args)
    return (scan_method, scan_target, port_scan_method,
            port_scan_target)
