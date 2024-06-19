# Code program for “Port Scanning, -- Ahmed, Suraesh, Reduan”

# Written by Ahmed Salahudin:

import socket

# function to check a defined list of ports to see if they are open
def tcp_connect_scan(target, ports):

    results = {}

    # Dictionary mapping commonly exploited ports to their associated services:
    service_map = {
        20: "FTP",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        137: "NetBIOS",
        139: "NetBIOS",
        445: "SMB",
        8080: "HTTP",
        8443: "HTTPS",
        1433: "SQL Server",
        1434: "SQL Server",
        3306: "MySQL",
        3389: "Remote Desktop"
    }


    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout for the connection attempt

        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                results[port] = service_map.get(port, "Unknown Service")
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    if not results:
        print("No open vulnerable ports found.")

    return results


def port_scan(Target):
    target = Target
    vulnerable_ports = [20, 21, 22, 23, 25, 53, 137, 139, 445, 80, 443, 8080, 8443, 1433, 1434, 3306, 3389]
    
    results = tcp_connect_scan(target, vulnerable_ports)
    return results
