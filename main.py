import argparse

from scan import Scan

if __name__ == '__main__':
    # Read
    parser = argparse.ArgumentParser()
    scan_type_group = parser.add_mutually_exclusive_group()
    scan_type_group.add_argument("-s", "--single", type=str, help="Scan the given domain name or IPv4 address")
    scan_type_group.add_argument("-c", "--cidr", type=str,
                                 help="Scan the given CIDR notated (e.g. 10.10.10.0/24) subnet")
    scan_type_group.add_argument("-r", "--range", type=str,
                                 help="Scan inclusively the range of two IP addresses delimited by '-'")
    scan_type_group.add_argument("-d", "--domains", type=str,
                                 help="Scan inclusively a list of domains separated by `,`")
    port_scan_type_group = parser.add_mutually_exclusive_group()
    port_scan_type_group.add_argument("-p", "--ports", type=str,
                                      help="List of ports to scan on each host")
    port_scan_type_group.add_argument("-n", "--nmap",
                                      help="Use nmap to scan for ports that are open on each host")
    args = parser.parse_args()

    # TODO If no arguments, read config.ini

    # Set port scan method
    scan = Scan()
    # Parse scan targets
    if args.single:
        # TODO Implement single scan
        print(args.single)
        pass
    elif args.cidr:
        # TODO Implement cidr scan
        print(args.cidr)
        pass
    elif args.range:
        # TODO Implement range scan
        print(args.range)
        pass
    elif args.domains:
        # TODO Implement domains scan
        print(args.domains)
        pass
