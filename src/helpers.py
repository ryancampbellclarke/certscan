# write to csv
import argparse
import csv
import os
from os.path import dirname
from typing import List

from src import options
from src.certificate import ScannedCertificate
from src.scanner import Scanner

DEFAULT_OUTPUT_FOLDER = "output/"
DEFAULT_FILE_OUT = f"{DEFAULT_OUTPUT_FOLDER}certificates.csv"


def get_args(parser):
    """
    Use scanners configured in database configured in database.ini file
    """
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

    return parser.parse_args()


def certscan_config(args):
    """
    Use scanners configured in config.ini file
    """
    # TODO read config.ini for scanner configuration
    raise NotImplementedError(
        "Will read config.ini for scanner configuration")


def certscan_database(args):
    # TODO read database (defined in database.ini) for scanner configuration
    raise NotImplementedError(
        "Will read database (defined in database.ini) for scanner "
        "configuration")


def certscan_direct(args):
    """
    Use scanner requested from arguments, output to stdout and/or csv
    """
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


def write_list_of_certs_to_file(discovered_certs: List[ScannedCertificate],
                                filename):
    """
    Takes list of discovered certificates and a filename and write these
    certificates to that file
    """
    try:
        os.mkdir(dirname(filename))
    except:
        # Dir already exists, that's fine.
        pass
    with open(file=filename, mode="w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            ['subject', 'target', 'common_name', 'issuer', 'issuer_common_name',
             'not_valid_after', 'not_valid_before', 'serial_number',
             'signature_hash_algorithm', 'version',
             'subject_alternative_names', 'port'])
        for cert in discovered_certs:
            writer.writerow(
                [cert.subject, cert.target, cert.common_name, cert.issuer,
                 cert.issuer_common_name,
                 cert.not_valid_after, cert.not_valid_before,
                 cert.serial_number,
                 cert.signature_hash_algorithm, cert.version,
                 cert.subject_alternative_names, cert.port])
