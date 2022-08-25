import ipaddress
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


class Scan():
    scan_method: ScanMethod
    scan_target: List[Any]
    port_scan_method: PortScanMethod
    port_scan_target: List[int]

    def __convert_scan_target_string_to_list(self, scan_target: str, scan_method: ScanMethod):
        # TODO implement string to list for each use case
        targets: List[ipaddress] = []
        if scan_method == ScanMethod.single:
            targets.append(ipaddress.ip_address(scan_target))
        elif scan_method == ScanMethod.cidr:
            pass
        elif scan_method == ScanMethod.range:
            pass
        elif scan_method == ScanMethod.domains:
            pass
        return targets

    def __init__(self, scan_method: ScanMethod, scan_target: str, port_scan_method: PortScanMethod, port_scan_target: str):
        self.scan_method = scan_method
        self.port_scan_method = port_scan_method
        self.scan_target = self.__convert_scan_target_string_to_list(scan_target, scan_method)
        self.port_scan_target = port_scan_target
