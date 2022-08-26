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
    parser = options.print_group(parser)
    parser.add_argument("-o", "--output", nargs='?', const=DEFAULT_FILE_OUT,
                        help=f"Output discovered certificates to "
                             f"{DEFAULT_FILE_OUT}"
                             f" or specified path")
    parser.add_argument("-a", "--all", action='store_true',
                        help="Print all certificate scans to stdout, found and "
                             "not-found certificates. Prints in json if -j "
                             "option set")

    args = parser.parse_args()

    # Check if no args, print help
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.database:
        # TODO read database (defined in database.ini) for scanner configuration
        raise NotImplementedError(
            "Will read database (defined in config.ini) for scanner "
            "configuration")
    elif args.ini:
        # Command line usage from .ini file
        # TODO read config.ini for scanner configuration
        raise NotImplementedError(
            "Will read config.ini for scanner configuration")
    else:
        # Command line usage, output to stdout or csv
        (scan_method, scan_target, port_scan_method,
         port_scan_target) = options.parse_inputs(args)
        # (scan_method, scan_target) = options.parse_scan_input(args)
        # (port_scan_method, port_scan_target) = options.parse_port_scan_input(args)
        scanner = Scanner(scan_method, scan_target, port_scan_method,
                          port_scan_target, quiet=args.quiet,
                          print_as_json=args.json, show_all_certs=args.all)
        discovered_certs = scanner.start_scan()

        # output to csv if flag set
        if args.output:
            write_list_of_certs_to_file(discovered_certs, args.output)
