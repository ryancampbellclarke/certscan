from cryptography import x509
import socket
import ssl
from cryptography.x509.oid import ExtensionOID
import sys

#target = "yukon.ca"
target = "expired.badssl.com"
port = 443
# create default context
context = ssl.create_default_context()
# set context so it can receive valid certificate
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

with socket.create_connection((target, port)) as sock:
    with context.wrap_socket(sock, server_hostname=target) as wrapped_sock:
        der_cert = wrapped_sock.getpeercert(True)
        cert = x509.load_der_x509_certificate(der_cert)
        # show cert expiry date
        #print(cert)

        # Get SANs

        subject = cert.subject.rfc4514_string()
        issuer=cert.issuer.rfc4514_string()
        not_valid_after=cert.not_valid_after
        not_valid_before=cert.not_valid_before
        serial_number=cert.serial_number
        signature_hash_algorithm=cert.signature_hash_algorithm.name
        version=cert.version.name
        subject_alternative_names = []
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for san in san.value:
            subject_alternative_names.append(san.value)