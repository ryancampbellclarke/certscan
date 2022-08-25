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
            # # write to csv
            # try:
            #     os.mkdir(dirname(args.output))
            # except:
            #     # Dir already exists
            #     pass
            # with open(args.output, "w", newline="") as csvfile:
            #     writer = csv.writer(csvfile)
            #     writer.writerow(
            #         ['subject', 'common_name', 'issuer', 'issuer_common_name',
            #          'not_valid_after', 'not_valid_before', 'serial_number',
            #          'signature_hash_algorithm', 'version',
            #          'subject_alternative_names', 'port'])
            #     for cert in discovered_certs:
            #         writer.writerow(
            #             [cert.subject, cert.common_name, cert.issuer,
            #              cert.issuer_common_name,
            #              cert.not_valid_after, cert.not_valid_before,
            #              cert.serial_number,
            #              cert.signature_hash_algorithm, cert.version,
            #              cert.subject_alternative_names, cert.port])
