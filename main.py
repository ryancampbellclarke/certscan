import argparse

from scanner import Scanner
import options


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser = options.scan_type_group(parser)
    parser = options.port_scan_group(parser)
    args = parser.parse_args()
    # TODO If no arguments, read config.ini

    (scan_method, scan_target) = options.parse_scan_input(args)
    (port_scan_method, port_scan_target) = options.parse_port_scan_input(args)

    scanner = Scanner(scan_method, scan_target, port_scan_method, port_scan_target)

    print(scanner.scan_target)
    print(scanner.scan_method)
    print(scanner.port_scan_target)
    print(scanner.port_scan_method)
