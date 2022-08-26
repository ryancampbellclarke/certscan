import json
from datetime import datetime
from typing import List

from cryptography.hazmat._oid import ExtensionOID
from cryptography.x509 import Certificate, ExtensionNotFound


class ScannedCertificate:
    target: str
    subject: str
    common_name: str
    issuer: str
    issuer_common_name: str
    not_valid_after: datetime
    not_valid_before: datetime
    serial_number: str
    signature_hash_algorithm: str
    version: str
    subject_alternative_names: List[str] = []
    port: int = 443

    def __common_name_from_cert(self, cert):
        """
        Pulls common name from rfc4514 formatted string found in cert.subject.rdns
        """
        for item in cert.subject.rdns:
            str_item = item.rfc4514_string()
            if str_item.startswith("CN="):
                return str_item.replace("CN=", "")


    def to_string(self):
        """
        Converts object to string with fields of common interest
        """
        san_string = ', '.join(map(str, self.subject_alternative_names))
        return f"Common name:                   {self.common_name} \n" \
               f"Issuer common name:            {self.issuer_common_name} \n" \
               f"Port:                          {self.port} \n" \
               f"Subject Alternative Names:     {san_string} \n" \
               f"Not Valid Before:              {self.not_valid_before} \n" \
               f"Not Valid After:               {self.not_valid_after} \n"

    def __read_sans_from_cert(self, cert):
        """
        Parses extensions for SAN extension OID and converts to list
        """
        try:
            SANs = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            subject_alternative_names = []
            for san in SANs.value:
                subject_alternative_names.append(san.value)
            return subject_alternative_names
        except ExtensionNotFound:
            # This is normal when there are no SANs
            return []


    def __issuer_common_name_from_cert(self, cert):
        """
        Pulls issuer common name from rfc4514 formatted string found in cert.issuer.rdns
        """
        for item in cert.issuer.rdns:
            str_item = item.rfc4514_string()
            if str_item.startswith("CN="):
                return str_item.replace("CN=", "")

    def to_json(self):
        """
        Dumps object's json representation
        """
        return json.dumps(self.__dict__, indent=4, sort_keys=True, default=str)

    def __init__(self, cert: Certificate, target: str, port: int = 443):
        self.target = target
        self.subject = cert.subject.rfc4514_string()
        self.common_name = self.__common_name_from_cert(cert)
        self.issuer = cert.issuer.rfc4514_string()
        self.issuer_common_name = self.__issuer_common_name_from_cert(cert)
        self.not_valid_after = cert.not_valid_after
        self.not_valid_before = cert.not_valid_before
        self.serial_number = str(cert.serial_number)
        self.signature_hash_algorithm = cert.signature_hash_algorithm.name
        self.version = cert.version.name
        self.subject_alternative_names = self.__read_sans_from_cert(cert)
        self.port = port
