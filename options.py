import scanner

"""
Helper functions to implement command line options and to organize them for further parsing.
"""


def no_scan_type(args):
    """
    Checks if all scan_type args are None
    :param args: Parsed args from an ArgumentParser
    :return: False if no scan type was passed
    """
    if all(arg is None for arg in args):
        return True
    else:
        return False


def scan_type_group(parser):
    """
    Sets up Scan Type arguments related to configuring a certscan run
    :param parser: ArgumentParser instance that these options will be added to.
    :return: ArgumentParser instance with new Scan Type options
    """
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-s", "--single", type=str, help="Scan the given domain name or IPv4 address")
    group.add_argument("-c", "--cidr", type=str,
                       help="Scan the given CIDR notated (e.g. 10.10.10.0/24) subnet")
    group.add_argument("-r", "--range", type=str,
                       help="Scan inclusively the range of two IP addresses delimited by '-'")
    group.add_argument("-d", "--domains", type=str,
                       help="Scan inclusively a list of domains separated by `,`")
    group.add_argument("-db", "--database", action='store_true',
                       help="Read scanner configuration from database defined in config.ini")
    return parser


def port_scan_group(parser):
    """
    Sets up Port Scan Type arguments related to configuring a certscan run
    :param parser: ArgumentParser instance that these options will be added to.
    :return: ArgumentParser instance with new Port Scan options
    """
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--ports", type=str,
                       help="List of ports to scan on each host")
    group.add_argument("-n", "--nmap", action='store_true',
                       help="Use nmap to scan for ports that are open on each host")
    return parser


def parse_scan_input(args):
    """
    Parses the arguments passed to determine which one was selected and returns the data associated.
    :param args: Parsed args from an ArgumentParser
    :return: tuple with the ScanMethod and the details of the scan method
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
    Parses the arguments passed to determine which one was selected and returns the data associated.
    :param args: Parsed args from an ArgumentParser
    :return:
    """
    if args.nmap:
        return (scanner.PortScanMethod.nmap, None)
    elif args.ports:
        return (scanner.PortScanMethod.specific_ports, args.ports)
