import requests
import ipaddress
import sys
from configparser import ConfigParser
from pprint import pprint
import urllib3
import subprocess

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
config = ConfigParser()
config.read('cachedbindupdate.ini')
api_key = config['API']['Key']
secret_key = config['API']['Secret']
base_url = config['API']['URL']
forward_zone = config['Config']['ForwardZone']

VERIFY_SSL = False  # Set True in production

# ----------------------------------------

session = requests.Session()
session.auth = (api_key, secret_key)
session.verify = VERIFY_SSL
# session.headers.update({"Content-Type": "application/json"})

def PrintException():
    exc_type, exc_obj, exc_tb = sys.exc_info()
    f = exc_tb.tb_frame
    lineno = exc_tb.tb_lineno
    filename = f.f_code.co_filename

    with open(filename, 'r') as file:
        lines = file.readlines()
        code_line = lines[lineno - 1].strip()

    print(f"An error occurred in {filename} at line {lineno}:")
    print(f"  Type: {exc_type.__name__}")
    print(f"  Message: {exc_obj}")
    print(f"  Code Causing Error: {code_line}")

def api_get(endpoint):
    url = f"{base_url}{endpoint}"
    r = session.get(url)
    r.raise_for_status()
    return r.json()


def api_post(endpoint, payload):
    url = f"{base_url}{endpoint}"
    r = session.post(url, json=payload)
    r.raise_for_status()
    return r.json()


def normalize_mac(mac):
    return mac.lower().replace("-", ":").strip()


def is_global_ipv6(addr):
    try:
        ip = ipaddress.IPv6Address(addr)
        return not (ip.is_link_local or ip.is_multicast or ip.is_private)
    except Exception:
        return False

def is_keasubnet_ipv6(addr):
    def is_ipv6_in_range(ipv6_address: str, start_range: str, end_range: str) -> bool:
        """
        Checks if a given IPv6 address is within a specified range of IPv6 addresses.

        Args:
            ipv6_address: The IPv6 address to check (as a string).
            start_range: The starting IPv6 address of the range (as a string).
            end_range: The ending IPv6 address of the range (as a string).

        Returns:
            True if the IPv6 address is within the range (inclusive), False otherwise.
        """
        try:
            ip_to_check = ipaddress.IPv6Address(ipv6_address)
            range_start = ipaddress.IPv6Address(start_range)
            range_end = ipaddress.IPv6Address(end_range)

            return range_start <= ip_to_check <= range_end
        except ipaddress.AddressValueError as e:
            print(f"Error: Invalid IPv6 address provided: {e}")
            return False
    try:
        ip = ipaddress.IPv6Address(addr)
        subnet = ip[0:19]
        if is_ipv6_in_range(ip, f"{subnet}::1000", f"{subnet}::2000"):
            return True
        else:
            return False
    except:
        return True

def ping_ipv6_local(ipv6, count=2, timeout=1):
    try:
        result = subprocess.run(
            ["ping", "-6", "-c", str(count), "-W", str(timeout), ipv6],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return result.returncode == 0
    except Exception:
        PrintException()
        return False

def ping_ipv6_via_opnsense(ipv6, interface=None, count=2, timeout=1):
    """
    Uses OPNsense diagnostics API to ping an IPv6 address.
    Returns True if at least one reply is received.
    """

    payload = {
        "host": ipv6,
        "count": str(count),
        "timeout": str(timeout),
        "inet": "inet6"
    }

    if interface:
        payload["interface"] = interface

    try:
        result = api_post("/diagnostics/interface/ping", payload)

        # OPNsense typically returns packet_loss as string percentage
        packet_loss = result.get("packet_loss", "100").replace("%", "").strip()

        if packet_loss.isdigit():
            return int(packet_loss) < 100

        # fallback if format changes
        output = result.get("output", "")
        return "0.0% packet loss" in output

    except Exception:
        PrintException()
        return False

def main():
    print("Fetching ARP table...")
    arp_data = api_get("/diagnostics/interface/get_arp")

    print("Fetching NDP table...")
    ndp_data = api_get("/diagnostics/interface/get_ndp")

    print("Fetching KEA DHCPv4 reservations...")
    dhcp4_data = api_get("/kea/dhcpv4/search_reservation")

    print("Fetching KEA DHCPv6 reservations...")
    dhcp6_data = api_get("/kea/dhcpv6/search_reservation")

    payload = {
        "current": 1,
        "rowCount": -1,
        "sort": {
            "if_descr": "asc"
        },
        "selected_interfaces": []
    }
    print("Fetching KEA DHCPv6 leases...")
    dhcp6_leases = api_post("/kea/leases6/search", payload)
    print("Fetching KEA DHCPv6 subnets...")
    dhcp6_subnets = api_get("/kea/dhcpv6/search_subnet")
    try:
        dhcp4_reservations = dhcp4_data.get("rows", [])
        dhcp6_reservations = dhcp6_data.get("rows", [])
        dhcp6_leases = dhcp6_leases.get("rows", [])
    except:
        PrintException()
    existing_dhcp6_macs = {
        normalize_mac(r.get("hw_address", ""))
        for r in dhcp6_reservations
    }
    existing_dhcp6_duids = {
        normalize_mac(r.get("duid", ""))
        for r in dhcp6_reservations
    }
    existing_dhcp6_ipres = {
        normalize_mac(r.get("ip_address", ""))
        for r in dhcp6_reservations
    }
    dhcp4_map = {}
    for res4 in dhcp4_reservations:
        hostname = res4.get("hostname")
        mac = normalize_mac(res4.get("hw_address", ""))
        dhcp4_map.setdefault(mac, hostname)
    # ---------------- Parse Data ----------------
    ndp_map = {}
    try:
        for entry in ndp_data:
            mac = normalize_mac(entry.get("mac", ""))
            ipv6 = entry.get("ip", "")

            if not mac or mac in existing_dhcp6_macs or ipv6 in existing_dhcp6_ipres or not is_global_ipv6(ipv6):
                continue

            if not ping_ipv6_local(ipv6):
                print(f"[UNREACHABLE] Host {dhcp4_map[mac]} NDP {ipv6} on {mac} did not respond to ping")
                continue

            if not is_keasubnet_ipv6(ipv6):
                ndp_map[mac] = ipv6
            else:
                ndp_map.setdefault(mac, ipv6)
    except:
        PrintException()
    # lease_dhcp6_macs = {
    #     normalize_mac(r.get("hwaddr", ""))
    #     for r in dhcp6_leases if r["is_reserved"] != "hwaddr" and r['hwtype'] == "135" and r['hwaddr_source'] == "4"
    # }

    # ---------------- Parse Data ----------------
    lease_map = {}
    try:
        for entry in dhcp6_leases:
            mac = normalize_mac(entry.get("hwaddr", ""))
            ipv6 = entry.get("address", "")
            if not mac or mac in existing_dhcp6_macs or not is_global_ipv6(ipv6):
                continue
            if not ping_ipv6_local(ipv6):
                if mac not in dhcp4_map:
                    print(f"[UNREACHABLE] Host {entry['hostname']} Lease {ipv6} on {mac} did not respond to ping")
                else:
                    print(f"[UNREACHABLE] Host {dhcp4_map[mac]} Lease {ipv6} on {mac} did not respond to ping")
                continue
            if not is_keasubnet_ipv6(ipv6):
                lease_map[mac] = ipv6
            else:
                lease_map.setdefault(mac, ipv6)
    except:
        PrintException()
    created_count = 0
    for res4 in dhcp4_reservations:
        try:
            hostname = res4.get("hostname")
            mac = normalize_mac(res4.get("hw_address", ""))
            duid = ""
            if mac in existing_dhcp6_macs:
                # print(f"[SKIP] {hostname} already has DHCPv6 reservation")
                continue
            if 'elastic' in hostname:
                continue
            if not hostname or not mac:
                continue
            if mac not in ndp_map and mac not in lease_map:
                # print(f"[OOPS] {hostname} MAC {mac} not found in NDP data...")
                ipv6_address = None
                for ipv6host in dhcp6_leases:
                    if ipv6host.get('hwaddr', '') != '':
                        if hostname+"." == ipv6host.get('hostname', '') or hostname+"."+forward_zone == ipv6host.get('hostname', ''):
                            if ipv6host['hwaddr'] not in existing_dhcp6_macs:
                                # print(f"[HUH] Found {hostname} in DHCPv6 Leases with {ipv6host['address']} on {ipv6host['hwaddr']} MAC")
                                ipv6_address = ipv6host.get('address', '')
                                mac = ipv6host['hwaddr']
                                print(f"Found {hostname} MAC {mac} in KEA DHCPv6 Lease data {ipv6_address}...")
                            else:
                                continue
                        else:
                            continue
                    elif hostname+"." == ipv6host.get('hostname', '') or hostname+"."+forward_zone == ipv6host.get('hostname', ''):
                        if ipv6host['duid'] not in existing_dhcp6_duids:
                            # print(f"[HUH] Found {hostname} in DHCPv6 Leases with {ipv6host['address']} with {ipv6host['duid']} DUID")
                            duid = ipv6host['duid']
                            mac = ""
                            ipv6_address = ipv6host.get('address', '')
                            print(f"Found {hostname} DUID {duid} in KEA DHCPv6 Lease data {ipv6_address}...")
                        else:
                            continue
                if ipv6_address is None:
                    # print(f"[HUH] {hostname} not found in Lease data")
                    continue
            elif mac in ndp_map:
                ipv6_address = ndp_map[mac]
                print(f"Found {hostname} MAC {mac} in NDP data {ipv6_address}...")
            elif mac in lease_map:
                ipv6_address = lease_map[mac]
                print(f"Found {hostname} MAC {mac} in KEA DHCPv6 Lease data {ipv6_address}...")
            else:
                print(f"[YIKES] {hostname} MAC {mac} not found...")
                continue
            ipv6_description = res4.get("description", "")
            print(f"[CREATE] Adding DHCPv6 reservation for {hostname} ({mac}/{duid}) -> {ipv6_address}")
            ipv6_subnet_uuid = [ dhcpv6_pool['uuid'] for dhcpv6_pool in dhcp6_subnets['rows'] if ipaddress.IPv6Address(ipv6_address) in ipaddress.ip_network(dhcpv6_pool['subnet'], strict=False) ][0]
            payload = {
                "reservation": {
                    "description": ipv6_description,
                    "domain_search": "",
                    "duid": duid,
                    "hostname": hostname+"."+forward_zone,
                    "hw_address": mac,
                    "ip_address": ipv6_address,
                    "subnet": ipv6_subnet_uuid
                }
            }
            api_post("/kea/dhcpv6/add_reservation", payload)
            #print('would post:')
            #pprint(payload)
            created_count += 1
        except:
            PrintException()
    print(f"\nCompleted. Created {created_count} new DHCPv6 reservations.")

if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        print("HTTP error:", e.response.text)
        PrintException()
        sys.exit(1)
    except Exception as e:
        print("Error:", str(e))
        PrintException()
        sys.exit(1)
