import argparse
import csv
import os

from scanner import Scanner
import options

DEFAULT_OUTPUT_FOLDER = "output/"
DEFAULT_FILE_OUT = "output/certificates.csv"

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--quiet", action='store_true',
                        help="Turn off printing discovered certificates to stdout")
    parser = options.scan_type_group(parser)
    parser = options.port_scan_group(parser)
    args = parser.parse_args()

    if options.no_scan_type([args.cidr, args.single, args.domains, args.range]):
        # TODO read config.ini for scanner configuration
        raise NotImplementedError(
            "Will read config.ini for scanner configuration")
    elif args.database:
        # TODO read database (defined in config.ini) for scanner configuration
        raise NotImplementedError(
            "Will read database (defined in config.ini) for scanner "
            "configuration")
    else:
        # Command line usage, output to stdout or csv
        (scan_method, scan_target) = options.parse_scan_input(args)
        (port_scan_method, port_scan_target) = options.parse_port_scan_input(
            args)

        scanner = Scanner(scan_method, scan_target, port_scan_method,
                          port_scan_target, quiet=args.quiet)

        discovered_certs = scanner.start_scan()

        # TODO implement different output path
        # TODO implement option flag
        # write to csv
        try:
            os.mkdir(DEFAULT_OUTPUT_FOLDER)
        except:
            # Dir already exists
            pass
        with open(DEFAULT_FILE_OUT, "w",newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(
                ['subject', 'common_name', 'issuer', 'issuer_common_name',
                 'not_valid_after', 'not_valid_before', 'serial_number',
                 'signature_hash_algorithm', 'version',
                 'subject_alternative_names', 'port'])
            for cert in discovered_certs:
                writer.writerow(
                    [cert.subject, cert.common_name, cert.issuer, cert.issuer_common_name,
                     cert.not_valid_after, cert.not_valid_before, cert.serial_number,
                     cert.signature_hash_algorithm, cert.version,
                     cert.subject_alternative_names, cert.port])

