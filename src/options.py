from src import scanner

"""
Helper functions to implement command line options and to organize them for further parsing.
"""


def scan_type_group(parser):
    """
    Sets up Scan Type arguments related to configuring a certscan run
    """
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-s", "--single", type=str,
                       help="Scan the given domain name or IPv4 address")
    group.add_argument("-c", "--cidr", type=str,
                       help="Scan the given CIDR notated (e.g. 10.10.10.0/24) "
                            "subnet")
    group.add_argument("-r", "--range", type=str,
                       help="Scan inclusively the range of two IP addresses "
                            "delimited by '-'")
    group.add_argument("-d", "--domains", type=str,
                       help="Scan inclusively a list of domains separated by "
                            "`,`")
    group.add_argument("-db", "--database", action='store_true',
                       help="Read scanner configuration from database defined "
                            "in database.ini")
    group.add_argument("-i", "--ini", action='store_true',
                       help="Read scanner configuration from config.ini")
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
    if args.single:
        return (scanner.ScanMethod.single, args.single)
    elif args.cidr:
        return (scanner.ScanMethod.cidr, args.cidr)
    elif args.range:
        return (scanner.ScanMethod.range, args.range)
    elif args.domains:
        return (scanner.ScanMethod.domains, args.domains)


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
