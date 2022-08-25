import ipaddress
from enum import Enum
from typing import List


class PortScanMethod(int, Enum):
    nmap = 0,
    specific_ports = 1


class ScanMethod(int, Enum):
    single = 0,
    cidr = 1,
    range = 2,
    domains = 3


class Scan():
    port_scan_method: PortScanMethod
    ports: List[int]
    scan_method: ScanMethod
    scan_detail: str
    enumerated_hosts: List[ipaddress]

    def __init__(self, ):
        pass
