import argparse
import csv
import os
import sys
from os.path import dirname

from src.helpers import write_list_of_certs_to_file, DEFAULT_FILE_OUT
from src.scanner import Scanner
from src import options


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser = options.scan_type_group(parser)
    parser = options.port_scan_group(parser)
    parser.add_argument("-q", "--quiet", action='store_true',
                        help="Turn off printing discovered certificates to"
                             " stdout")
    parser.add_argument("-o", "--output", nargs='?', const=DEFAULT_FILE_OUT,
                        help=f"Output discovered certificates to "
                             f"{DEFAULT_FILE_OUT}"
                             f" or specified path")
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.database:
        # TODO read database (defined in config.ini) for scanner configuration
        raise NotImplementedError(
            "Will read database (defined in config.ini) for scanner "
            "configuration")
    elif args.ini:
        # TODO read config.ini for scanner configuration
        raise NotImplementedError(
            "Will read config.ini for scanner configuration")
    else:
        # Command line usage, output to stdout or csv
        (scan_method, scan_target) = options.parse_scan_input(args)
        (port_scan_method, port_scan_target) = options.parse_port_scan_input(
            args)

        scanner = Scanner(scan_method, scan_target, port_scan_method,
                          port_scan_target, quiet=args.quiet)

        discovered_certs = scanner.start_scan()

        if args.output:
            write_list_of_certs_to_file(discovered_certs, args.output)