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

    def __convert_scan_target_string_to_list(self, scan_target: str, scan_method: ScanMethod):
        targets: List[ipaddress.ip_address] = []
        if scan_method == ScanMethod.single:
            # Append single IP to list
            targets.append(ipaddress.ip_address(scan_target))
        elif scan_method == ScanMethod.cidr:
            # TODO implement CIDR conversion
            targets = [str(ip) for ip in ipaddress.IPv4Network(scan_target)]
        elif scan_method == ScanMethod.range:
            # TODO implement range conversion
            pass
        elif scan_method == ScanMethod.domains:
            # TODO implement domains conversion
            pass
        return targets

    def __convert_port_scan_target_string_to_list(self, port_scan_target):
        try:
            target = [int(port) for port in port_scan_target.split(',')]
        except:
            raise ValueError("Non-integer in list of ports")
        return target

    def __init__(self, scan_method: ScanMethod, scan_target: str, port_scan_method: PortScanMethod,
                 port_scan_target: str):
        self.scan_method = scan_method
        self.port_scan_method = port_scan_method
        self.scan_target = self.__convert_scan_target_string_to_list(scan_target, scan_method)
        if port_scan_target is not None:
            self.port_scan_target = self.__convert_port_scan_target_string_to_list(port_scan_target)