import ipaddress
import string
from enum import Enum
from typing import List, Any


class PortScanMethod(int, Enum):
    nmap = 0,
    specific_ports = 1


class ScanMethod(int, Enum):
    single = 0,
    cidr = 1,
    range = 2,
    domains = 3


class Scanner():
    scan_method: ScanMethod
    scan_target: List[ipaddress.ip_address]
    port_scan_method: PortScanMethod
    port_scan_target: List[int] = []

    def __convert_scan_target_str_to_list(self, scan_target: str, scan_method: ScanMethod):
        targets: List[ipaddress.ip_address] = []
        if scan_method == ScanMethod.single:
            # Append single IP to list
            return targets.append(str(ipaddress.ip_address(scan_target)))
        elif scan_method == ScanMethod.cidr:
            return [str(ip) for ip in ipaddress.IPv4Network(scan_target)]
        elif scan_method == ScanMethod.range:
            try:
                ip_range = [ipaddress.IPv4Address(ip) for ip in scan_target.split('-')]
                start_ip = ip_range[0]
                end_ip = ip_range[1]
                for ip_int in range(int(start_ip), int(end_ip)):
                    targets.append(str(ipaddress.IPv4Address(ip_int)))
                return targets
            except:
                ValueError("The string expected should be IPv4 addresses of the form x.x.x.x-x.x.x.x")
        elif scan_method == ScanMethod.domains:
            return [domain for domain in scan_target.split(',')]
        return targets

    def __convert_port_scan_target_str_to_list(self, port_scan_target):
        try:
            target = [int(port) for port in port_scan_target.split(',')]
        except:
            raise ValueError("Non-integer in list of ports")
        return target

    def __init__(self, scan_method: ScanMethod, scan_target: str, port_scan_method: PortScanMethod,
                 port_scan_target: str):
        self.scan_method = scan_method
        self.port_scan_method = port_scan_method
        self.scan_target = self.__convert_scan_target_str_to_list(scan_target, scan_method)
        if port_scan_target is not None:
            self.port_scan_target = self.__convert_port_scan_target_str_to_list(port_scan_target)
