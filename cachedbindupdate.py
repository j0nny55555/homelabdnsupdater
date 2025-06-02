import redis
import requests
import json
import urllib3
import dns.resolver
import dns.tsig
import ipaddress
import socket
import sys
from dns.update import Update
from dns.message import make_query
from dns.query import tcp
import dns.rdata
from configparser import ConfigParser
from datetime import datetime, timedelta
from pprint import pprint
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

config = ConfigParser()
config.read('cachedbindupdate.ini')
seccache_redis_host = config['Redis']['Host']
seccache_redis_port = config['Redis']['Port']
seccache_redis_db = config['Redis']['DB']
seccache_redis_password = config['Redis']['Password']
api_key = config['OPNSense']['Key']
secret_key = config['OPNSense']['Secret']
base_url = config['OPNSense']['URL']
dns_server = config['DNS']['DNSServer']
key_name_update = config['DNS']['KeyNameUpdates']
key_secret_update = config['DNS']['KeySecretUpdate']
portainer_url = config['Portainer']['URL']
portainer_username = config['Portainer']['Username']
portainer_password = config['Portainer']['Password']
forward_zone = config['Config']['ForwardZone']
dns_domain = config['Config']['DNSDomain']
ipv4_resolver = config['Config']['IPv4Resolver']
ipv6_resolver = config['Config']['IPv6Resolver']
ipv4_subnetfilter = config['Config']['IPv4SubnetFilter']
ipv6_subnetfilter = config['Config']['IPv6SubnetFilter']
ipv4_only_hosts = config['Config']['IPv4OnlyHosts'].split('\n')
dns_subnets = config['Config']['Subnets'].split('\n')
dns_reversezones = config['Config']['ReverseZones'].split('\n')

# Make reverse_zones lookup table
reverse_zones = {}
for entrynum in range(len(dns_subnets)):
    reverse_zones.setdefault(dns_subnets[entrynum], dns_reversezones[entrynum])

# Initialize the TSIG key for DNS updates
key_update = dns.tsig.Key(
    key_name_update,
    key_secret_update,
    algorithm=dns.tsig.HMAC_MD5,
)

manual_hostname_to_mac = {
    'hostname': ['mac','ip'],
}

fwd_update = Update(forward_zone)
fwd_update.keyring = key_update
ptr_updates = {}
for ip_subnet, reverse_zone in reverse_zones.items():
    ptr_updates[ip_subnet] = Update(reverse_zone)
    ptr_updates[ip_subnet].keyring = key_update

pending_changes = {
    'add': {
        'A': [],
        'AAAA': [],
        'PTRIPv4': [],
        'PTRIPv6': []
    },
    'delete': {
        'A': [],
        'AAAA': [],
        'PTRIPv4': [],
        'PTRIPv6': []
    }
}

# Initialize the request with authentication details using Basic auth
routerAPI = requests.session()
routerAPI.auth = (api_key, secret_key)
routerAPI.verify = False

debug = False
report_findings = False

# Initialize resolvers
resolverObj4 = dns.resolver.Resolver()
resolverObj4.nameservers = [ipv4_resolver]
resolverObj4.timeout = 2
resolverObj4.retry = 3

resolverObj6 = dns.resolver.Resolver()
resolverObj6.nameservers = [ipv6_resolver]
resolverObj6.timeout = 2
resolverObj6.retry = 3

# Redis Key Patterns
KEY_PATTERNS = [
    'arp:mac:*',
    'arp:address:*',
    'ndp:mac:*',
    'ndp:address:*',
    'dhcpv4:mac:*',
    'dhcpv4:address:*',
    'dhcpv4:hostname:*',
    'dhcpv6:mac:*',
    'dhcpv6:address:*',
    'dhcpv6:hostname:*',
    'interface:mac:*',
    'interface:address:*',
    'interface:hostname:*',
    'docker:mac:*',
    'docker:address:*',
    'docker:hostname:*',
]

########################################################################
# Note: 'manual_hostname_to_mac' dictionary
# Once we added the Portainer collection this did not become necessary
# It is left here so you can use that if you need to in the meantime
########################################################################
# manual_hostname_to_mac = {
#     'hostname': ['macaddress','ipaddress']
# }

def connect_to_redis():
    """Connects to the Redis database."""
    try:
        # Initialize Redis connection
        r = redis.Redis(
            host=seccache_redis_host,
            port=6379,
            db=6,
            password=seccache_redis_password,
            decode_responses=True
        )
        r.ping()  # Check connection
        return r
    except redis.exceptions.ConnectionError as e:
        print(f"Could not connect to Redis: {e}")
        return None

def get_opnsense_data(endpoint):
    """Fetches data from the OPNsense API."""
    try:
        response = routerAPI.get(f"{base_url}{endpoint}")
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from {endpoint}: {e}")
        return None

def get_data_from_redis(redis_client, pattern):
    """Retrieves data from Redis matching the given key pattern."""
    keys = redis_client.keys(pattern)
    data = {}
    for key in keys:
        try:
            value = redis_client.get(key)
            if value:
                data[key] = json.loads(value)
            # Filter out older data from cache - limit is currently 2 hours old
            if datetime.strptime(data[key]['last_seen'],"%Y-%m-%d %H:%M:%S") + timedelta(hours=2) > datetime.now():
                pass
            else:
                print(f"Not using aged {data[key]['last_seen']} Redis data... {key}")
                #pprint(data[key])
                del data[key]
        except (json.JSONDecodeError, TypeError) as e:
            print(f"Error decoding JSON for key {key}: {e}")
    return data

def update_redis_entry(redis_client, key, new_data):
    """Updates an existing Redis entry with new data."""
    new_data["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ########################################################################
    # There used to be a 'manual_hostname_to_mac' dictionary
    # Once we added the Portainer collection this did not become necessary
    # It is left here so you can use that if you need to in the meantime
    ########################################################################
    # for manual_hostname, manual_mac_ip in manual_hostname_to_mac.items():
    #     manual_mac = manual_mac_ip[0]
    #     manual_address = manual_mac_ip[1]
    #     if manual_mac in new_data['mac']:
    #         new_data['hostname'] = list(set(new_data['hostname'] + [manual_hostname]))
    #         new_data['address'] = list(set(new_data['address'] + [manual_address]))
    #         print(f"Manual Hostname to Mac update... {manual_hostname} - {manual_mac} - {manual_address}")
    entryRaw = redis_client.get(key)
    entry = json.loads(entryRaw) if entryRaw else {}
    if entry:
        # Update existing entry with new data
        for k, v in new_data.items():
            if isinstance(entry.get(k), list):
                entry[k] = list(set(entry[k] + v)) if v else entry[k]
            else:
                entry[k] = v
        redis_client.set(key, json.dumps(entry))
    else:
        # Create new entry
        redis_client.set(key, json.dumps(new_data))

def resolve_hostname(r, hostname):
    """Resolves a hostname to IP addresses using DNS."""
    try:
        resolver = dns.resolver.Resolver()
        fqdn = f"{hostname}.{dns_domain}"
        a_records = resolver.resolve(fqdn, 'A')
        aaaa_records = resolver.resolve(fqdn, 'AAAA')

        ip_addresses = []
        for rdata in a_records:
            ip_addresses.append(rdata.address)
        for rdata in aaaa_records:
            ip_addresses.append(rdata.address)

        return ip_addresses
    except dns.resolver.NXDOMAIN:
        print(f"Hostname {hostname} not found in DNS.")
        return []
    except dns.resolver.NoAnswer:
        print(f"No A or AAAA records found for {hostname}.")
        return []
    except Exception as e:
        print(f"Error resolving hostname {hostname}: {e}")
        return []

def resolve_ip(r, ip_address):
    """Resolves an IP address to a hostname using DNS (PTR record)."""
    try:
        resolver = dns.resolver.Resolver()
        if ":" in ip_address: #IPv6
            # Parse the IPv6 address
            ipv6_obj = ipaddress.IPv6Address(ip_address)
            # Convert to bytes in network order (big-endian)
            bytes_value = ipv6_obj._ip.to_bytes(16, 'big')
            # Split each byte into two nibbles and collect them all
            nibbles = []
            for byte in bytes_value:
                # Convert the byte to its hexadecimal representation
                hex_byte = '{:02x}'.format(byte)
                # Split each hex character into individual nibble strings
                for c in hex_byte:
                    nibbles.append(c)
            # Reverse all nibbles to create PTR domain name
            reversed_nibbles = list(reversed(nibbles))
            ptr_domain = ".".join(reversed_nibbles) + ".ip6.arpa."
            ptr_record = resolver.resolve(f"{ptr_domain}", 'PTR')
            hostname = ptr_record[0].target.to_string()
        else:  # IPv4
            # Split the IP address into octets and reverse_them
            octets = ip_address.split('.')
            reversed_octets = list(reversed(octets))
            ptr_domain = ".".join(reversed_octets) + ".in-addr.arpa."
            ptr_record = resolver.resolve(f"{ptr_domain}", 'PTR')
            hostname = ptr_record[0].target.to_string()
        return hostname
    except dns.resolver.NXDOMAIN:
        print(f"No PTR record found for IP address {ip_address}.")
        return None
    except dns.resolver.NoAnswer:
        print(f"No PTR record found for IP address {ip_address}.")
        return None
    except Exception as e:
        print(f"Error resolving IP address {ip_address}: {e}")
        return None

def process_arp(redis_client):
    """Collects and stores ARP data in Redis."""
    data = get_opnsense_data("/diagnostics/interface/get_arp")
    if data:
        if debug:
            pprint(data[0:5])
        for arp_entry in data:
            address = arp_entry.get("ip") # actually stored as "ip" we rename to address as used elsewhere
            if address.startswith(ipv4_subnetfilter):
                mac = arp_entry.get("mac")
                mac = mac.lower()
                hostname = arp_entry.get("hostname")
                hostname = hostname.lower() if hostname else None
                redis_key_mac = f"arp:mac:{mac}"
                redis_key_address = f"arp:address:{address}"
                redis_key_address = f"arp:hostname:{hostname}"
                arp_entry["mac"] = [mac] if mac else []
                arp_entry["address"] = [address] if address else []
                arp_entry["address"] = [ address for address in arp_entry["address"] if address.startswith(ipv4_subnetfilter) ]
                arp_entry["hostname"] = [hostname] if hostname else []
                if mac:
                    update_redis_entry(redis_client, redis_key_mac, arp_entry)
                if address:
                    update_redis_entry(redis_client, redis_key_address, arp_entry)
                if hostname:
                    update_redis_entry(redis_client, redis_key_address, arp_entry)
            else:
                if debug:
                    print(f"Skipped...")
                    pprint(arp_entry)
        print(f"ARP entries pulled: {len(data)}")
    list_of_arp_keys = redis_client.keys("arp:*")
    print(f"ARP keys in Redis: {len(list_of_arp_keys)}")

def process_ndp(redis_client):
    """Collects and stores NDP data in Redis."""
    data = get_opnsense_data("/diagnostics/interface/get_ndp")
    if data:
        if debug:
            pprint(data[0:5])
        for ndp_entry in data:
            address = ndp_entry.get("ip") # actually stored as "ip" we rename to address as used elsewhere
            if address.startswith(ipv6_subnetfilter):
                mac = ndp_entry.get("mac")
                mac = mac.lower()
                hostname = ndp_entry.get("hostname")
                hostname = hostname.lower() if hostname else None
                redis_key_mac = f"ndp:mac:{mac}"
                redis_key_address = f"ndp:address:{address}"
                redis_key_address = f"ndp:hostname:{hostname}"
                ndp_entry["mac"] = [mac] if mac else []
                ndp_entry["address"] = [address] if address else []
                ndp_entry["address"] = [ address for address in ndp_entry["address"] if address.startswith(ipv6_subnetfilter) ]
                ndp_entry["hostname"] = [hostname] if hostname else []
                if mac:
                    update_redis_entry(redis_client, redis_key_mac, ndp_entry)
                if address:
                    update_redis_entry(redis_client, redis_key_address, ndp_entry)
                if hostname:
                    update_redis_entry(redis_client, redis_key_address, ndp_entry)
            else:
                if debug:
                    print(f"Skipped...")
                    pprint(ndp_entry)
        print(f"NDP entries pulled: {len(data)}")
    list_of_ndp_keys = redis_client.keys("ndp:*")
    print(f"NDP keys in Redis: {len(list_of_ndp_keys)}")

def process_dhcpv4(redis_client):
    """Collects and stores DHCPv4 data in Redis."""
    data = get_opnsense_data("/dhcpv4/leases/searchLease")  # Changed endpoint to static leases
    if data:
        if debug:
            pprint(data['rows'][0:5])
        for dhcpv4_entry in data['rows']:
            address = dhcpv4_entry.get("address")
            mac = dhcpv4_entry.get("mac")
            mac = mac.lower()
            hostname = dhcpv4_entry.get("hostname")
            hostname = hostname.lower() if hostname else None
            redis_key_mac = f"dhcpv4:mac:{mac}"
            redis_key_address = f"dhcpv4:address:{address}"
            redis_key_hostname = f"dhcpv4:hostname:{hostname}"
            dhcpv4_entry["mac"] = [mac] if mac else []
            dhcpv4_entry["address"] = [address] if address else []
            dhcpv4_entry["hostname"] = [hostname] if hostname else []
            if mac:
                update_redis_entry(redis_client, redis_key_mac, dhcpv4_entry)
            if address:
                update_redis_entry(redis_client, redis_key_address, dhcpv4_entry)
            if hostname:
                update_redis_entry(redis_client, redis_key_hostname, dhcpv4_entry)
        print(f"DHCPv4 entrys pulled: {len(data['rows'])}")
    list_of_dhcpv4_keys = redis_client.keys("dhcpv4:*")
    print(f"DHCPv4 keys in Redis: {len(list_of_dhcpv4_keys)}")

def process_dhcpv6(redis_client):
    """Collects and stores DHCPv6 data in Redis."""
    data = get_opnsense_data("/dhcpv6/leases/searchLease") # Changed endpoint to static leases
    if data:
        if debug:
            pprint(data['rows'][0:5])
        for dhcpv6_entry in data['rows']:
            address = dhcpv6_entry.get("address")
            mac = dhcpv6_entry.get("mac")
            mac = mac.lower()
            hostname = dhcpv6_entry.get("hostname")
            hostname = hostname.lower() if hostname else None
            redis_key_mac = f"dhcpv6:mac:{mac}"
            redis_key_address = f"dhcpv6:address:{address}"
            redis_key_hostname = f"dhcpv6:hostname:{hostname}"
            dhcpv6_entry["mac"] = [mac] if mac else []
            dhcpv6_entry["address"] = [address] if address else []
            dhcpv6_entry["hostname"] = [hostname] if hostname else []
            if mac:
                update_redis_entry(redis_client, redis_key_mac, dhcpv6_entry)
            if address:
                update_redis_entry(redis_client, redis_key_address, dhcpv6_entry)
            if hostname:
                update_redis_entry(redis_client, redis_key_hostname, dhcpv6_entry)
        print(f"DHCPv6 entrys pulled: {len(data['rows'])}")
    list_of_dhcpv6_keys = redis_client.keys("dhcpv6:*")
    print(f"DHCPv6 keys in Redis: {len(list_of_dhcpv6_keys)}")

def process_interfaces(redis_client):
    """Collects and stores OPNSense Interface data in Redis."""
    data = get_opnsense_data("/diagnostics/interface/getInterfaceConfig") # Changed endpoint to static leases
    if data:
        if debug:
            pprint(data)
        for interface_name, interface_entry in data.items():
            cleaned_entry = {}
            hostname = 'opnsense'
            ipv4addresses = [ ipv4address['ipaddr'] for ipv4address in interface_entry['ipv4'] ]
            ipv4addresses = [ ipv4address for ipv4address in ipv4addresses if ipv4address.startswith(ipv4_subnetfilter) ]
            ipv6addresses = [ ipv6address['ipaddr'] for ipv6address in interface_entry['ipv6'] ]
            ipv6addresses = [ ipv6address for ipv6address in ipv6addresses if ipv6address.startswith(ipv6_subnetfilter) ]
            alladdresses = list(set(ipv4addresses + ipv6addresses))
            mac = interface_entry['macaddr']
            redis_key_mac = f"interface:mac:{mac}"
            redis_key_hostname = f"interface:hostname:{hostname}"
            cleaned_entry["mac"] = [mac] if mac else []
            cleaned_entry["address"] = alladdresses
            cleaned_entry["hostname"] = [hostname] if hostname else []
            for k, v in interface_entry.items():
                if type(v) == type(str):
                    cleaned_entry[k] = v
            if mac:
                update_redis_entry(redis_client, redis_key_mac, cleaned_entry)
            if hostname:
                update_redis_entry(redis_client, redis_key_hostname, cleaned_entry)
            for address in alladdresses:
                if address:
                    redis_key_address = f"interface:address:{address}"
                    update_redis_entry(redis_client, redis_key_address, cleaned_entry)
        #print(f"DHCPv6 entrys pulled: {len(data['rows'])}")
    #list_of_dhcpv6_keys = redis_client.keys("dhcpv6:*")
    #print(f"DHCPv6 keys in Redis: {len(list_of_dhcpv6_keys)}")

def process_docker_containers(redis_client):
    # Step 1: Authenticate with Portainer
    auth_url = f"{portainer_url}/api/auth"
    auth_data = {'username': portainer_username, 'password': portainer_password}
    response = requests.post(auth_url, json=auth_data)
    if response.status_code != 200:
        print("Authentication failed")
        exit()

    cookies = response.cookies

    # Step 2: Retrieve List of Endpoints (Docker Hosts)
    endpoints_url = f"{portainer_url}/api/endpoints"
    headers = {'Content-Type': 'application/json'}
    response = requests.get(endpoints_url, headers=headers, cookies=cookies)

    if response.status_code != 200:
        print("Failed to retrieve endpoints")
        exit()

    endpoints = response.json()
    print(f"Found {len(endpoints)} endpoint(s)")

    container_list = []

    # Step 3: Iterate Over Endpoints and Containers
    for endpoint in endpoints:
        endpoint_id = endpoint['Id']
        endpoint_status = endpoint['Status']
        if endpoint['Name'] in ['SOC']:
            continue
        print(f"Looking into {endpoint['Name']} with status {endpoint_status}...")
        print(f"Which has {len(endpoint['Snapshots'][0]['DockerSnapshotRaw']['Containers'])} Docker Snapshots Container Definitions")
        
        if endpoint_status != 1:
            print(f"Skipping inactive endpoint...")
            continue

        containers_url = f"{portainer_url}/api/endpoints/{endpoint_id}/docker/containers/json"
        response = requests.get(containers_url, headers=headers, cookies=cookies)
        
        if response.status_code != 200:
            print(f"Failed to retrieve containers from endpoint {endpoint_id}")
            #pprint(response.text)
            continue

        containers = response.json()
        for container in containers:
            if 'Id' in container:
                pass
            else:
                continue

            container_id = container['Id']
            
            # Step 4: Retrieve Detailed Container Info
            container_info_url = f"{portainer_url}/api/endpoints/{endpoint_id}/docker/containers/{container_id}/json"
            response = requests.get(container_info_url, headers=headers, cookies=cookies)
            
            if response.status_code != 200:
                print(f"Failed to get details for container {container_id}")
                continue

            container_details = response.json()
            
            # Step 5: Extract Hostname
            hostname = container_details.get('Config', {}).get('Hostname', 'N/A')
            
            # Step 6: Extract IP and MAC Address from NetworkSettings
            network_settings = container_details.get('NetworkSettings', {})
            networks = network_settings.get('Networks', {})
            
            ipv4_address = []
            ipv6_address = []
            addresses = []
            mac_address = []
            
            if networks:
                for net_name, data in networks.items():
                    goodNetwork = False
                    if 'IPAMConfig' in data and data['IPAMConfig'] is not None:
                        if 'IPv4Address' in data['IPAMConfig']:
                            if data['IPAMConfig']['IPv4Address'].startswith(ipv4_subnetfilter):
                                goodNetwork = True
                                ipv4_address.append(data['IPAMConfig']['IPv4Address'])
                        else:
                            if data['IPAddress'].startswith(ipv4_subnetfilter):
                                goodNetwork = True
                                ipv4_address.append(data.get('IPAddress'))
                        if 'IPv6Address' in data['IPAMConfig']:
                            if data['IPAMConfig']['IPv6Address'].startswith(ipv6_subnetfilter):
                                goodNetwork = True
                                ipv6_address.append(data['IPAMConfig']['IPv6Address'])
                    if goodNetwork:
                        mac_address.append(data.get('MacAddress'))
                ipv4_address = list(set([ip for ip in ipv4_address if ip.startswith(ipv4_subnetfilter)]))
                ipv6_address = list(set([ip for ip in ipv6_address if ip.startswith(ipv6_subnetfilter)]))
            addresses = list(set(ipv4_address + ipv6_address))
            #print(f"Container ID: {container_id}")
            #print(f"Hostname:       {hostname}")
            #print(f"IPv4 Address:     {ipv4_address or 'N/A'}")
            #print(f"IPv6 Address:     {ipv6_address or 'N/A'}")
            #print(f"MAC Address:    {mac_address or 'N/A'}")
            #print("-" * 50)
            if len(ipv4_address) > 0:
                container_list.append({'hostname': hostname, 'macaddr': mac_address[0], 'address': addresses})
    #pprint(container_list)
    for container_entry in container_list:
            mac = container_entry['macaddr']
            hostname = container_entry['hostname']
            alladdresses = container_entry["address"]
            redis_key_mac = f"docker:mac:{mac}"
            redis_key_hostname = f"docker:hostname:{hostname}"
            container_entry["mac"] = [mac] if mac else []
            container_entry["hostname"] = [hostname] if hostname else []
            if mac:
                update_redis_entry(redis_client, redis_key_mac, container_entry)
            if hostname:
                update_redis_entry(redis_client, redis_key_hostname, container_entry)
            for address in alladdresses:
                if address:
                    redis_key_address = f"docker:address:{address}"
                    update_redis_entry(redis_client, redis_key_address, container_entry)

def create_dns_updates(hosts_data):
    print_existing = False  # For debugging purposes only
    
    # First pass: Add new records
    for hostname, ips in hosts_data.items():
        if not ips:
            continue

        for ip_address in ips:
            try:
                # Determine IP version and resolver
                ip_obj = ipaddress.ip_address(ip_address)
                is_ipv6 = ip_obj.version == 6
                resolver = resolverObj6 if is_ipv6 else resolverObj4
                address_family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
                record_type = 'AAAA' if is_ipv6 else 'A'
                # Skip and Remove IPv6 if it exists for IPv4-only hosts
                if hostname in ipv4_only_hosts and is_ipv6:
                    fqdn = f"{hostname}.{dns_domain}"
                    existing_ips = []
                    try:
                        response = resolver.resolve(fqdn, record_type)
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                        continue
                    existing_ips.extend([rdata.address for rdata in response])
                    if ip_address in existing_ips:
                        print(f"Removing AAAA record for {fqdn}: {ip_address}")
                        fwd_update.delete(hostname, 'AAAA', ip_address)
                    continue
            except ValueError as e:
                print(f"Invalid IP format: {ip_address}")
                continue

            # Process A/AAAA records
            try:
                fqdn = f"{hostname}.{dns_domain}"
                existing_ips = []
                response = resolver.resolve(fqdn, record_type)
                existing_ips.extend([rdata.address for rdata in response])
                
                if ip_address not in existing_ips:
                    print(f"Adding {record_type} record: {fqdn} -> {ip_address}")
                    fwd_update.add(hostname, 3600, record_type, ip_address)
                    pending_changes['add'][record_type].append((hostname, ip_address))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                print(f"Adding {record_type} record: {fqdn} -> {ip_address} - NoAnswer/NXDOMAIN/NoNameservers")
                fwd_update.add(hostname, 3600, record_type, ip_address)
                pending_changes['add'][record_type].append((hostname, ip_address))
            except Exception as e:
                print(f"Skipping {record_type} record for {fqdn} -> {ip_address}")
                print(f"Error resolving {record_type} records: {e}")

            # Process PTR records
            try:
                fqdn = f"{hostname}.{dns_domain}."
                if is_ipv6:
                    subnet = ip_address[0:19]
                    ipv6_obj = ipaddress.IPv6Address(ip_address)
                    bytes_value = ipv6_obj._ip.to_bytes(16, 'big')
                    nibbles = []
                    for byte in bytes_value:
                        hex_byte = '{:02x}'.format(byte)
                        for c in hex_byte:
                            nibbles.append(c)
                    reversed_nibbles = list(reversed(nibbles))
                    ptr_domain = '.'.join(reversed_nibbles) + '.ip6.arpa.'
                else:
                    octets = ip_address.split('.')
                    subnet = '.'.join(octets[0:3])
                    ptr_domain = '.'.join(reversed(octets)) + '.in-addr.arpa.'

                response = resolver.resolve(ptr_domain, 'PTR', 'IN')
                existing_hostnames = [rdata.target.to_text() for rdata in response]
                existing_hostnames = [hostname.lower() for hostname in existing_hostnames]
                if f"{fqdn}" not in existing_hostnames:
                    print(f"Adding PTR record: {ptr_domain} -> {fqdn} - FQDN not in existing hostnames")
                    ptr_updates[subnet].add(ptr_domain, 3600, 'PTR', fqdn)
                    pending_changes['add'][f'PTR{"IPv6" if is_ipv6 else "IPv4"}'].append((ptr_domain, ip_address))
                else:
                    if print_existing:
                        print(f"Found PTR record: {','.join(existing_hostnames)} for {fqdn} - No action needed")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                print(f"Adding PTR record: {ptr_domain} -> {fqdn} - NoAnswer/NXDOMAIN/NoNameservers")
                ptr_updates[subnet].add(ptr_domain, 3600, 'PTR', fqdn)
                pending_changes['add'][f'PTR{"IPv6" if is_ipv6 else "IPv4"}'].append((ptr_domain, ip_address))
            except Exception as e:
                print(f"Skipping {record_type} record for {ip_address} -> {fqdn}")
                print(f"Error resolving {ptr_domain} for {fqdn} records: {e}")

        do_cleanup = True
        if do_cleanup:
            # Second pass: Remove records not present in reference data
            def get_current_records(fqdn, record_type, resolver):
                """Get all current DNS records of a given type."""
                current_records = set()
                try:
                    response = resolver.resolve(fqdn, record_type)
                    for rdata in response:
                        if record_type == 'A':
                            current_records.add((rdata.address, rdata.rdtype))
                        elif record_type == 'AAAA':
                            current_records.add((rdata.address, rdata.rdtype))
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    pass
                except Exception as e:
                    print(f"Error resolving {record_type} records: {e}")
                return current_records

            def get_current_ptr_records(ptr_domain):
                """Get all current PTR records."""
                current_ptr_records = set()
                for subnet, reverse_zone in reverse_zones.items():
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.nameservers = [dns_server]
                        response = resolver.resolve(ptr_domain, 'PTR', 'IN')
                        for rdata in response:
                            #ptr_domain = f"{rdata.domain}."
                            rdatafqdn = rdata.target.to_text()
                            current_ptr_records.add((ptr_domain, rdatafqdn.lower()))
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                        pass
                    except Exception as e:
                        print(f"Error resolving PTR records for {reverse_zone}: {e}")
                
                return current_ptr_records

            # Set FQDN for A and AAAA record lookup
            fqdn = f"{hostname}.{dns_domain}"
            # Get all current A records
            current_a_records = get_current_records(fqdn, 'A', resolverObj4)
            # Get all current AAAA records
            current_aaaa_records = get_current_records(fqdn, 'AAAA', resolverObj6)

            #pprint(current_aaaa_records)

            # Get all current PTR records
            fqdn = f"{hostname}.{dns_domain}"
            if is_ipv6:
                subnet = ip_address[0:19]
                ipv6_obj = ipaddress.IPv6Address(ip_address)
                bytes_value = ipv6_obj._ip.to_bytes(16, 'big')
                nibbles = []
                for byte in bytes_value:
                    hex_byte = '{:02x}'.format(byte)
                    for c in hex_byte:
                        nibbles.append(c)
                reversed_nibbles = list(reversed(nibbles))
                ptr_domain = '.'.join(reversed_nibbles) + '.ip6.arpa.'
            else:
                octets = ip_address.split('.')
                subnet = '.'.join(octets[0:3])
                ptr_domain = '.'.join(reversed(octets)) + '.in-addr.arpa.'
            current_ptr_records = get_current_ptr_records(ptr_domain)  # Modify to handle IPv4 and IPv6 properly
            #print(f"Found {len(current_a_records)} current A records.")
            #print(f"Found {len(current_aaaa_records)} current AAAA records.")
            #print(f"Found {len(current_ptr_records)} current PTR records.")

            # Remove A records not in reference data
            for (ip_address, rtype) in current_a_records:
                if ip_address not in [ip for ips in hosts_data.values() for ip in ips]:
                    hostname_find = None
                    for hn, ips in hosts_data.items():
                        if ip_address in ips:
                            hostname_find = hn
                            break
                    
                    if hostname_find:
                        fqdn = f"{hostname_find}.{dns_domain}"
                        print(f"Removing A record: {ip_address} from {fqdn}")
                        fwd_update.delete(hostname_find, 'A', ip_address)
                        pending_changes['delete']['A'].append((hostname_find, ip_address))
                    else:
                        fqdn = f"{hostname}.{dns_domain}"
                        print(f"Removing A record: {ip_address} from {fqdn}")
                        fwd_update.delete(hostname, 'A', ip_address)
                        pending_changes['delete']['A'].append((hostname, ip_address))

            # Remove AAAA records not in reference data
            for (ip_address, rtype) in current_aaaa_records:
                if ip_address not in [ip for ips in hosts_data.values() for ip in ips]:
                    hostname_find = None
                    for hn, ips in hosts_data.items():
                        if ip_address in ips:
                            hostname_find = hn
                            break

                    if hostname_find:
                        fqdn = f"{hostname_find}.{dns_domain}"
                        print(f"Removing AAAA record: {ip_address} from {fqdn}")
                        fwd_update.delete(hostname_find, 'AAAA', ip_address)
                        pending_changes['delete']['AAAA'].append((hostname_find, ip_address))
                    else:
                        fqdn = f"{hostname}.{dns_domain}"
                        print(f"Removing AAAA record: {ip_address} from {fqdn}")
                        fwd_update.delete(hostname, 'AAAA', ip_address)
                        pending_changes['delete']['AAAA'].append((hostname, ip_address))

            doing_ptr_cleanup = False
            if doing_ptr_cleanup:
                # Remove PTR records not in reference data
                for (ptr_domain, target) in current_ptr_records:
                    matching_ip = None
                    hostname_find = None
                    for hn, ips in hosts_data.items():
                        for ip in ips:
                            if ":" in ip:  # IPv6
                                ipv6_obj = ipaddress.IPv6Address(ip)
                                subnet = ip[0:19]
                                bytes_value = ipv6_obj._ip.to_bytes(16, 'big')
                                nibbles = []
                                for byte in bytes_value:
                                    hex_byte = '{:02x}'.format(byte)
                                    for c in hex_byte:
                                        nibbles.append(c)
                                reversed_nibbles = list(reversed(nibbles))
                                ptr_domain_to_check = '.'.join(reversed_nibbles) + '.ip6.arpa.'
                            else:  # IPv4
                                octets = ip.split('.')
                                subnet = '.'.join(octets[0:3])
                                ptr_domain_to_check = '.'.join(reversed(octets)) + '.in-addr.arpa.'
                            
                            if ptr_domain == ptr_domain_to_check:
                                matching_ip = ip
                                hostname_find = hn
                                break
                    fqdn = f"{hostname_find}.{dns_domain}."
                    if not matching_ip:
                        print(f"Removing PTR record: {ptr_domain} -> {target}")
                        # Remove the PTR record from the appropriate reverse zone
                        for subnet, reverse_zone in reverse_zones.items():
                            try:
                                ptr_update_resolver = dns.resolver.Resolver()
                                ptr_update_resolver.nameservers = [dns_server]
                                response = ptr_update_resolver.resolve(ptr_domain, 'PTR')
                                if len(response) == 0 or response[0].target != target:
                                    print(f"Skipping PTR record removal - no matching record found")
                                    continue
                            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                                pass
                            try:
                                # Remove the PTR record
                                print(f"Removing PTR record: {ip_address} from {fqdn}")
                                ptr_updates[subnet].delete(ptr_domain, 'PTR', fqdn)
                                pending_changes['delete'][f'PTR{"IPv6" if ":" in ip else "IPv4"}'].append((ptr_domain, fqdn))
                        
                            except Exception as e:
                                print(f"Error removing PTR record {ptr_domain}: {e}")

    return pending_changes

def main():
    """Main function to collect and store data."""

    # Initialize Redis connection
    redis_client = connect_to_redis()
    if not redis_client:
        print("Failed to connect to Redis. Exiting...")
        return
    print("Connected to Redis.")

    #list_of_arp_keys = redis_client.keys("*")
    #for key in list_of_arp_keys:
    #   redis_client.delete(key)

    # Collect and process data
    print("Collecting ARP data...")
    process_arp(redis_client)

    print("Collecting NDP data...")
    process_ndp(redis_client)

    print("Collecting DHCPv4 data...")
    process_dhcpv4(redis_client)

    print("Collecting DHCPv6 data...")
    process_dhcpv6(redis_client)

    print("Collecting Interface data...")
    process_interfaces(redis_client)

    print("Collecting Docker Container data...")
    process_docker_containers(redis_client)

    print("Data collection complete.")

    debug = False
    check_data = False
    if check_data:
        slimmed_cached_data = {}
        for pattern in KEY_PATTERNS:
            cached_data = get_data_from_redis(redis_client, pattern)
            output_count = 0
            
            for k, v in cached_data.items():
                while output_count < 5:
                    slimmed_cached_data.setdefault(k, v)
                    output_count+=1

        pprint(slimmed_cached_data)

    # Assuming get_data_from_redis is already defined and available
    all_data = []
    for pattern in KEY_PATTERNS:
        cached_data = get_data_from_redis(redis_client, pattern)
        for k, v in cached_data.items():
            skipdata = False
            # for key, value in v.items():
            #     if type(value) == type(list()):
            #         if 'c14d51c61e4b' in value:
            #             redis_client.delete(k)
            #             skipdata = True
            #             break
            if not skipdata:
                all_data.append(v)
    #pprint(all_data)
    #sys.exit(0)
    mac_to_ips = {}
    hostname_to_ips = {}
    mac_to_ips_with_no_hostname = {}
    # Get Hostname to IP list setup
    for value_dict in all_data:
        addresses = value_dict.get('address', [])
        macs = value_dict.get('mac', [])
        hostnames = value_dict.get('hostname', [])
        
        for address in addresses:
            # We query for the reverse PTR to get an additional hostnames
            existing_hostnames = []
            try:
                # Determine IP version and resolver
                ip_obj = ipaddress.ip_address(address)
                is_ipv6 = ip_obj.version == 6
                resolver = resolverObj6 if is_ipv6 else resolverObj4
                address_family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
                record_type = 'AAAA' if is_ipv6 else 'A'
            except ValueError as e:
                print(f"Invalid IP format: {address}")
                continue
            try:
                if is_ipv6:
                    subnet = address[0:19]
                    ipv6_obj = ipaddress.IPv6Address(address)
                    bytes_value = ipv6_obj._ip.to_bytes(16, 'big')
                    nibbles = []
                    for byte in bytes_value:
                        hex_byte = '{:02x}'.format(byte)
                        for c in hex_byte:
                            nibbles.append(c)
                    reversed_nibbles = list(reversed(nibbles))
                    ptr_domain = '.'.join(reversed_nibbles) + '.ip6.arpa.'
                else:
                    octets = address.split('.')
                    subnet = '.'.join(octets[0:3])
                    ptr_domain = '.'.join(reversed(octets)) + '.in-addr.arpa.'

                response = resolver.resolve(ptr_domain, 'PTR', 'IN')
                existing_fqdns = [rdata.target.to_text() for rdata in response]
                existing_fqdns = [hostname.lower() for hostname in existing_fqdns if hostname.endswith(forward_zone)]
                
                for fqdn in existing_fqdns:
                    fqdnsplit = fqdn.split('.')
                    hostname = '.'.join(fqdnsplit[:-3])
                    existing_hostnames.append(hostname)
                if report_findings:
                    print(f"Found {len(existing_hostnames)}: {', '.join(existing_hostnames)}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                if debug:
                    print(f"Skipping {record_type} record for {address}")
                    print(f"Error resolving {ptr_domain} PTR records: {e}")
            except Exception as e:
                if debug:
                    print(f"Skipping {record_type} record for {address}")
                    print(f"Error resolving {ptr_domain} PTR records: {e}")
            # If we found any hostname in DNS, we add it here
            if len(existing_hostnames) > 0:
                existing_hostnames = list(set(existing_hostnames))
                for existing_hostname in existing_hostnames:
                    hostnames.append(existing_hostname)
            hostnames = list(set(hostnames))
            # Make Hostname to IP dictionary of lists
            for hn in hostnames:
                if hn in hostname_to_ips:
                    hostname_to_ips[hn] = list(set(hostname_to_ips[hn] + [address]))
                else:
                    hostname_to_ips.setdefault(hn, [address])
            # Make MAC to IP dictionary of lists
            for mac in macs:
                if mac in mac_to_ips:
                    mac_to_ips[mac] = list(set(mac_to_ips[mac] + [address]))
                else:
                    mac_to_ips.setdefault(mac, [address])
            # Find macs with ips with no hostname
            for mac in macs:
                if len(existing_hostnames) > 0:
                    if len(hostnames) == 0:
                        mac_to_ips_with_no_hostname.setdefault(mac, [address])
                        mac_to_ips_with_no_hostname[mac] = list(set(mac_to_ips_with_no_hostname[mac] + [address]))

    
    for hostname, host_ips in hostname_to_ips.items():
        for host_ip in host_ips:
            for mac, mac_ips in mac_to_ips.items():
                if host_ip in mac_ips:
                    hostname_to_ips[hostname] = list(set(host_ips + mac_ips))

    try:
        pending_changes = create_dns_updates(hostname_to_ips)
        debug = True
        if debug:
            print("DNS Updates:")
            print(pending_changes)

        number_of_changes = 0
        for change_type, record_type in pending_changes.items():
            for record, items in record_type.items():
                number_of_changes += len(items)

        if number_of_changes > 0:
            # Send updates - UNCOMMENT TO EXECUTE
            if not debug:
                response = tcp(fwd_update, dns_server)
                print(f"Forward update response: {response.rcode()}")

            if not debug:
                for subnet, ptr_update in ptr_updates.items():
                    response = tcp(ptr_update, dns_server)
                    print(f"Reverse update response for {subnet}: {response.rcode()}")
        else:
            print("No DNS updates needed.")
    except Exception as e:
        print(f"Error during DNS update: {e}")

    pprint(hostname_to_ips)

    for mac, ipaddresses in mac_to_ips_with_no_hostname.items():
        print(f"MAC: {mac} has no hostname at all - {','.join(ipaddresses)}")

if __name__ == "__main__":
    main()
