import ipaddress
from enum import Enum
from typing import List
from cryptography import x509
import socket
import ssl

from cryptography.hazmat._oid import ExtensionOID

from src.certificate import ScannedCertificate


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
    quiet: bool = False
    print_as_json: bool = False

    @staticmethod
    def scan(target, port):
        context = ssl.create_default_context()
        # set context so it can receive valid certificate
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(address=(target, port)) as sock:
            with context.wrap_socket(sock=sock,
                                     server_hostname=target) as wrapped_sock:
                der_cert = wrapped_sock.getpeercert(True)
                cert = x509.load_der_x509_certificate(der_cert)
                return ScannedCertificate(cert=cert, target=target, port=port)

    def __nmap_port_discovery(self):
        # TODO Implement NMAP port discovery
        raise NotImplementedError(
            "Will use nmap function to find ports to scan")

    def start_scan(self):
        # Set scan targets
        if not self.scan_target:
            raise ValueError("No scan targets specified")
        targets = self.scan_target

        # Set scan ports
        if self.port_scan_method == PortScanMethod.nmap:
            ports = self.__nmap_port_discovery()
        elif self.port_scan_method == PortScanMethod.specific_ports:
            ports = self.port_scan_target
        else:
            ports = [int(DEFAULT_PORT_TARGET)]

        discovered_certs = []
        for target in targets:
            for port in ports:
                discovered_cert = Scanner.scan(target, port)
                discovered_certs.append(discovered_cert)
                if not self.quiet:
                    print(discovered_cert.to_string())
                if self.print_as_json:
                    print(discovered_cert.to_json())

        return discovered_certs

    def __convert_scan_target_str_to_list(self, scan_target: str,
                                          scan_method: ScanMethod):
        targets: List[ipaddress.ip_address] = []
        if scan_method == ScanMethod.single:
            # Append single IP to list
            targets.append(str(ipaddress.ip_address(scan_target)))
            return targets
        elif scan_method == ScanMethod.cidr:
            return [str(ip) for ip in ipaddress.IPv4Network(scan_target)]
        elif scan_method == ScanMethod.range:
            try:
                ip_range = [ipaddress.IPv4Address(ip) for ip in
                            scan_target.split('-')]
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

    def __init__(self, scan_method: ScanMethod, scan_target: str,
                 port_scan_method: PortScanMethod,
                 port_scan_target: str,
                 quiet: bool = False, print_as_json=False):
        self.scan_method = scan_method
        self.port_scan_method = port_scan_method
        self.scan_target = self.__convert_scan_target_str_to_list(scan_target,
                                                                  scan_method)
        self.port_scan_target = self.__convert_port_scan_target_str_to_list(
            port_scan_target)
        self.quiet = quiet

        if print_as_json:
            # Set quiet automatically if json selected
            self.print_as_json = print_as_json
            self.quiet = True
