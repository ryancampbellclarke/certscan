import argparse

from scan import Scan
import options


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser = options.scan_type_group(parser)
    parser = options.port_scan_group(parser)
    args = parser.parse_args()
    # TODO If no arguments, read config.ini

    (scan_method, scan_target) = options.parse_scan_input(args)
    (port_scan_method, port_scan_target) = options.parse_port_scan_input(args)

    scan = Scan(scan_method,scan_target,port_scan_method,port_scan_target)

    print(scan.scan_target)
    print(scan.scan_method)
    print(scan.port_scan_target)
    print(scan.port_scan_method)
