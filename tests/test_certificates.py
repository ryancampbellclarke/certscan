from cryptography import x509

from src.certificate import ScannedCertificateStub, ScannedCertificate
from tests.test_helpers import EXAMPLE_COM_PEM_TEST_CERT


class TestScannedCertificateStub:
    def test_to_string(self):
        target = "10.10.10.10"
        port = 443
        cert_stub = ScannedCertificateStub(target, port)
        assert cert_stub.to_string() == f"Target:                        {target} \n" \
                                        f"Port:                          {port} \n" \
                                        f"Status:                        {cert_stub.NOT_FOUND} \n"

    def test_to_json(self):
        target = "10.10.10.10"
        port = 443
        cert_stub = ScannedCertificateStub(target, port)
        assert cert_stub.to_json() == '{\n    "port": 443,\n    "status": "Not found",\n    "target": "10.10.10.10"\n}'


class TestScannedCertificate:
    def test_to_string(self):
        raw_cert = x509.load_pem_x509_certificate(EXAMPLE_COM_PEM_TEST_CERT)
        target = "10.10.10.10"
        port = 443
        new_cert = ScannedCertificate(raw_cert, target, port)
        assert new_cert.to_string() == f"Target:                        {target} \n" \
                                       f"Port:                          {port} \n" \
                                       f"Common name:                   www.example.org \n" \
                                       f"Issuer common name:            DigiCert TLS RSA SHA256 2020 CA1 \n" \
                                       f"Subject Alternative Names:     www.example.org, example.net, example.edu, example.com, example.org, www.example.com, www.example.edu, www.example.net \n" \
                                       f"Not Valid Before:              2022-03-14 00:00:00 \n" \
                                       f"Not Valid After:               2023-03-14 23:59:59 \n"

    def test_to_json(self):
        raw_cert = x509.load_pem_x509_certificate(EXAMPLE_COM_PEM_TEST_CERT)
        target = "example.com"
        port = 443
        new_cert = ScannedCertificate(raw_cert, target, port)
        assert new_cert.to_json() == '{\n    "common_name": "www.example.org",\n    "issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US",\n    "issuer_common_name": "DigiCert TLS RSA SHA256 2020 CA1",\n    "not_valid_after": "2023-03-14 23:59:59",\n    "not_valid_before": "2022-03-14 00:00:00",\n    "port": 443,\n    "serial_number": "20823119674429668393338028820299337114",\n    "signature_hash_algorithm": "sha256",\n    "subject": "CN=www.example.org,O=Internet\\u00a0Corporation\\u00a0for\\u00a0Assigned\\u00a0Names\\u00a0and\\u00a0Numbers,L=Los Angeles,ST=California,C=US",\n    "subject_alternative_names": [\n        "www.example.org",\n        "example.net",\n        "example.edu",\n        "example.com",\n        "example.org",\n        "www.example.com",\n        "www.example.edu",\n        "www.example.net"\n    ],\n    "target": "example.com",\n    "version": "v3"\n}'
