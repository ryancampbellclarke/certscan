import ipaddress
from enum import Enum
from typing import List
from cryptography import x509
import socket
import ssl

from cryptography.hazmat._oid import ExtensionOID


class PortScanMethod(int, Enum):
    nmap = 0,
    specific_ports = 1


class ScanMethod(int, Enum):
    single = 0,
    cidr = 1,
    range = 2,
    domains = 3


DEFAULT_PORT_TARGET = "443"


class Scanner:
    scan_method: ScanMethod
    scan_target: List[ipaddress.ip_address]
    port_scan_method: PortScanMethod
    port_scan_target: List[int] = []

    def __scan(self, target, port):
        context = ssl.create_default_context()
        # set context so it can receive valid certificate
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target, port)) as sock:
            with context.wrap_socket(sock, server_hostname=target) as wrapped_sock:
                der_cert = wrapped_sock.getpeercert(True)
                cert = x509.load_der_x509_certificate(der_cert)

                subject = cert.subject.rfc4514_string()
                common_name = ""
                for item in cert.subject.rdns:
                    str_item = item.rfc4514_string()
                    if str_item.startswith("CN="):
                        common_name = str_item.replace("CN=", "")
                        break;
                issuer = cert.issuer.rfc4514_string()
                not_valid_after = cert.not_valid_after
                not_valid_before = cert.not_valid_before
                serial_number = cert.serial_number
                signature_hash_algorithm = cert.signature_hash_algorithm.name
                version = cert.version.name
                subject_alternative_names = []
                san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for san in san.value:
                    subject_alternative_names.append(san.value)

    def start_scan(self):
        if not self.scan_target:
            raise ValueError("No scan targets specified")
        targets = self.scan_target
        if self.port_scan_method == PortScanMethod.nmap:
            raise NotImplementedError("Will use nmap function to find ports to scan")
        elif self.port_scan_method == PortScanMethod.specific_ports:
            ports = self.scan_target
        else:
            ports = [int(DEFAULT_PORT_TARGET)]

    def __convert_scan_target_str_to_list(self, scan_target: str, scan_method: ScanMethod):
        targets: List[ipaddress.ip_address] = []
        if scan_method == ScanMethod.single:
            # Append single IP to list
            targets.append(str(ipaddress.ip_address(scan_target)))
            return targets
        elif scan_method == ScanMethod.cidr:
            return [str(ip) for ip in ipaddress.IPv4Network(scan_target)]
        elif scan_method == ScanMethod.range:
            try:
                ip_range = [ipaddress.IPv4Address(ip) for ip in scan_target.split('-')]
                start_ip = ip_range[0]
                end_ip = ip_range[1]
                for ip_int in range(int(start_ip), int(end_ip) + 1):
                    targets.append(str(ipaddress.IPv4Address(ip_int)))
                return targets
            except ValueError as e:
                print(e)
        elif scan_method == ScanMethod.domains:
            return [domain for domain in scan_target.split(',')]
        return targets

    def __convert_port_scan_target_str_to_list(self, port_scan_target):
        if port_scan_target:
            try:
                return [int(port) for port in port_scan_target.split(',')]
            except ValueError as e:
                print(e)
        else:
            return [int(DEFAULT_PORT_TARGET)]

    def __init__(self, scan_method: ScanMethod, scan_target: str, port_scan_method: PortScanMethod,
                 port_scan_target: str):
        self.scan_method = scan_method
        self.port_scan_method = port_scan_method
        self.scan_target = self.__convert_scan_target_str_to_list(scan_target, scan_method)
        self.port_scan_target = self.__convert_port_scan_target_str_to_list(port_scan_target)
