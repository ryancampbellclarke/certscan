from cryptography import x509
import socket
import ssl
from cryptography.x509.oid import ExtensionOID
import sys

from certificate import ScannedCertificate

#target = "yukon.ca"
target = "example.com"
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

        scanned_cert = ScannedCertificate(cert)


        print(scanned_cert.__dict__)