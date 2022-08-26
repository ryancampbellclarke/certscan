from src.certificate import ScannedCertificateStub


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

