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

    # def test_to_json(self):
    #     target = "10.10.10.10"
    #     port = 443
    #     cert_stub = ScannedCertificateStub(target, port)
    #     assert cert_stub.to_json() == '{\n    "port": 443,\n    "status": "Not found",\n    "target": "10.10.10.10"\n}'
    #
    # def test_constructor(self):
    #     # TODO test_constructor
    #     raw_cert = x509.load_pem_x509_certificate(EXAMPLE_COM_PEM_TEST_CERT)
    #     target = "10.10.10.10"
    #     port = 443
    #     new_cert = ScannedCertificate(raw_cert, target, port)
    #     print(new_cert.__dict__)
    #     # assert new_cert.__dict__ == {'target': '10.10.10.10', 'subject': 'CN=www.example.org,O=Internet\xa0Corporation\xa0for\xa0Assigned\xa0Names\xa0and\xa0Numbers,L=Los Angeles,ST=California,C=US', 'common_name': 'www.example.org', 'issuer': 'CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US', 'issuer_common_name': 'DigiCert TLS RSA SHA256 2020 CA1', 'not_valid_after': datetime.datetime(2023, 3, 14, 23, 59, 59), 'not_valid_before': datetime.datetime(2022, 3, 14, 0, 0), 'serial_number': '20823119674429668393338028820299337114', 'signature_hash_algorithm': 'sha256', 'version': 'v3', 'subject_alternative_names': ['www.example.org', 'example.net', 'example.edu', 'example.com', 'example.org', 'www.example.com', 'www.example.edu', 'www.example.net'], 'port': 443}
