# write to csv
import csv
import os
from os.path import dirname
from typing import List

from src.certificate import ScannedCertificate

DEFAULT_OUTPUT_FOLDER = "output/"
DEFAULT_FILE_OUT = f"{DEFAULT_OUTPUT_FOLDER}certificates.csv"


def write_list_of_certs_to_file(discovered_certs: List[ScannedCertificate],
                                filename):
    try:
        os.mkdir(dirname(filename))
    except:
        # Dir already exists, that's fine.
        pass
    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            ['subject', 'common_name', 'issuer', 'issuer_common_name',
             'not_valid_after', 'not_valid_before', 'serial_number',
             'signature_hash_algorithm', 'version',
             'subject_alternative_names', 'port'])
        for cert in discovered_certs:
            writer.writerow(
                [cert.subject, cert.common_name, cert.issuer,
                 cert.issuer_common_name,
                 cert.not_valid_after, cert.not_valid_before,
                 cert.serial_number,
                 cert.signature_hash_algorithm, cert.version,
                 cert.subject_alternative_names, cert.port])
