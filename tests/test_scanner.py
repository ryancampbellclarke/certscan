from src.scanner import Scanner, PortScanMethod, ScanMethod

# This test suite scans a set of sites outside this project's control. The tests
# will fail if they are no longer available. These tests will also fail if your
# computer cannot connect to the network.
# Please suggest a better way of doing this if you can think of it.

def test_domain_scan():
    # Targets github.com
    scan_method = ScanMethod.domains
    scan_target="github.com"
    port_scan_method=PortScanMethod.specific_ports
    port_scan_target="443"
    scanner = Scanner(scan_method, scan_target, port_scan_method,
                      port_scan_target)
    discovered_certs = scanner.start_scan()
    assert len(discovered_certs) == 1
    assert discovered_certs[0].common_name == scan_target

def test_ip_scan():
    # Targets 140.82.112.3 (2022-08-30) this resolves to github.com
    scan_method = ScanMethod.single
    scan_target = "140.82.112.3"
    port_scan_method = PortScanMethod.specific_ports
    port_scan_target = "443"
    scanner = Scanner(scan_method, scan_target, port_scan_method,
                      port_scan_target)
    discovered_certs = scanner.start_scan()
    assert len(discovered_certs) == 1
    assert discovered_certs[0].common_name == "github.com"

def test_cidr_scan():
    # Targets 140.82.112.3/32 which represents a single IP that resolves to github.com
    scan_method = ScanMethod.cidr
    scan_target = "140.82.112.3/32"
    port_scan_method = PortScanMethod.specific_ports
    port_scan_target = "443"
    scanner = Scanner(scan_method, scan_target, port_scan_method,
                      port_scan_target)
    discovered_certs = scanner.start_scan()
    assert len(discovered_certs) == 1
    assert discovered_certs[0].common_name == "github.com"

def test_range_scan():
    # Targets 140.82.112.3-140.82.112.3 which represents a single IP that resolves to github.com
    scan_method = ScanMethod.range
    scan_target = "140.82.112.3-140.82.112.3"
    port_scan_method = PortScanMethod.specific_ports
    port_scan_target = "443"
    scanner = Scanner(scan_method, scan_target, port_scan_method,
                      port_scan_target)
    discovered_certs = scanner.start_scan()
    assert len(discovered_certs) == 1
    assert discovered_certs[0].common_name == "github.com"



