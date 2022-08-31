# write to csv
import argparse
import csv
import json
import os
import sys
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
    parser = options.port_scan_group(parser)
    parser = options.print_group(parser)
    parser.add_argument("scan_target", type=str,
                       help="Target of discovery scan. "
                            "Formats: Single IP: '10.10.10.10', "
                            "Single domain: 'example.com', "
                            "List of IPs: '10.10.10.10,10.10.10.20,10.10.10.30', "
                            "Range of IPs: '10.10.10.10-10.10.10.20', "
                            "Range of IPs by CIDR notation: '10.10.10.0/24', "
                            "List of domains: 'example.com,example.org,example.edu'")
    parser.add_argument("-o", "--output", nargs='?', const=DEFAULT_FILE_OUT,
                        help=f"Output discovered certificates to "
                             f"{DEFAULT_FILE_OUT}"
                             f" or (optional) specified path")
    parser.add_argument("-a", "--all", action='store_true',
                        help="Print all certificate scans to stdout, found and "
                             "not-found certificates. Prints in json if -j "
                             "option set")
    parser.add_argument("-v", "--version", action='store_true',
                        help="Software version")

    return parser.parse_args()


def dump_all_discovered_certs_in_json(discovered_certs):
    return json.dumps(
        [disc_cert.__dict__ for disc_cert in discovered_certs], indent=4,
        sort_keys=True, default=str)

def certscan_direct(args):
    """
    Use scanner requested from arguments, output to stdout and/or csv
    """
    (scan_method, scan_target, port_scan_method,
     port_scan_target) = options.parse_inputs(args)
    scanner = Scanner(scan_method, scan_target, port_scan_method,
                      port_scan_target, quiet=args.quiet,
                      print_as_json=args.json, show_all_certs=args.all)
    discovered_certs = scanner.start_scan()

    if args.json:
        print(dump_all_discovered_certs_in_json(discovered_certs))

    # output to csv if flag set
    if args.output:
        write_list_of_certs_to_file(discovered_certs, args.output)


def print_args_help(parser):
    parser.print_help(sys.stderr)
    sys.exit(1)


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
