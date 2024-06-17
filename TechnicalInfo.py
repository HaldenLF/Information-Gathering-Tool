# Code program for technical information -- Liam, Johnny, Maryam

# Written by Maryam and Liam

import socket
import dns.resolver
import ping3

def check_ip_and_domain(target):
    try:
        ip_address = socket.gethostbyname(target)
        domain_name = socket.gethostbyaddr(ip_address)[0]
        return ip_address, domain_name
    except socket.gaierror:
        return "Invalid target", None


def is_online(target):
  # checks if target site is online
  try:
    ping3.ping(target)
    return True
  except Exception:
    return False


def get_tech_info(target):
    ip_address, server_name = check_ip_and_domain(target)

    results = []
    if server_name:
        IP = (f"IP Address of {target}: {ip_address}")
        results.append(IP)
        server = f"{target} server: {server_name}"
        results.append(server)

        # Check online status using ping3
        if is_online(target):
            results.append(f"{target} is online")
        else:
            results.append(f"{target} is offline")

    else:
        results.append("Invalid target entered.")

    return results
