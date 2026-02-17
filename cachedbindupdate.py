import redis
import requests
import json
import urllib3
import dns.resolver
import dns.tsig
import ipaddress
import socket
import sys
import time
import pickle
from dns.update import Update
from dns.message import make_query
from dns.query import tcp
import dns.name
import dns.query
import dns.rdata
import dns.reversename
import dns.zone
import dns.rdatatype
from configparser import ConfigParser
from datetime import datetime, timedelta
from pprint import pprint
import ipaddress
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
dns_ttl = int(config.get('DNS', 'TTL', fallback=300))  # Default to 300 if not set
key_name_update = config['DNS']['KeyNameUpdates']
key_secret_update = config['DNS']['KeySecretUpdate']
portainer_url = config['Portainer']['URL']
portainer_username = config['Portainer']['Username']
portainer_password = config['Portainer']['Password']
keep_cache = config['Config']['KeepCache']
debug = config['Config']['Debug']
debugLog = config['Config']['DebugLog']
report_findings = config['Config']['ReportFindings']
forward_zone = config['Config']['ForwardZone']
dns_domain = config['Config']['DNSDomain']
ipv4_resolver = config['Config']['IPv4Resolver']
ipv6_resolver = config['Config']['IPv6Resolver']
ipv4_subnetfilter = config['Config']['IPv4SubnetFilter']
ipv6_subnetfilter = config['Config']['IPv6SubnetFilter']
ipv4_only_hosts = config['Config']['IPv4OnlyHosts'].split('\n')
multihost_list = config['Config']['MultiHostList'].split('\n')
statichosts = config['Config']['StaticHosts'].split('\n')
dns_subnets = config['Config']['Subnets'].split('\n')
dns_reversezones = config['Config']['ReverseZones'].split('\n')
bad_hostnames = config['Config']['BadHostnames'].split('\n')
bad_addresses = config['Config']['BadAddresses'].split('\n')
token_file = "portainer_token.pkl"

if keep_cache == 'False':
    keep_cache = False
else:
    keep_cache = True
if debug == 'False':
    debug = False
else:
    debug = True
if debugLog == 'False':
    debugLog = False
else:
    debugLog = True
if report_findings == 'False':
    report_findings = False
else:
    report_findings = True

starttime = datetime.now()
log_data = []

# Holds the key of the main host w/mac and the value is the list of hosted hosts
sharedhosts_primary_dict = {}
# Holds the key each hosted host with the value being the main host that hosts it
sharedhosts_secondary_dict = {}
for hosts_line in multihost_list:
    hosts_split = hosts_line.split('/')
    sharedhosts_primary_dict.setdefault(hosts_split[0], hosts_split[1:])
    for secondary_host in sharedhosts_primary_dict[hosts_split[0]]:
        sharedhosts_secondary_dict.setdefault(secondary_host, hosts_split[0])

# Portainer Cookie
portainer_jwt_token = None

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
    'arp:hostname:*',
    'ndp:mac:*',
    'ndp:address:*',
    'ndp:hostname:*',
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
    'static:mac:*',
    'static:address:*',
    'static:hostname:*',
]

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

def logdatamessage(message):
    if debugLog:
        print(message)
    log_data.append(message)

def connect_to_redis(rdb):
    """Connects to the Redis database."""
    try:
        # Initialize Redis connection
        r = redis.Redis(
            host=seccache_redis_host,
            port=6379,
            db=rdb,
            password=seccache_redis_password,
            decode_responses=True,
            socket_connect_timeout=5
        )
        r.ping()  # Check connection
        return r
    except redis.exceptions.ConnectionError as e:
        print(f"Could not connect to Redis: {e}")
        return None

def portainer_authenticate(username, password):
    """Authenticates with Portainer and returns the JWT."""
    auth_url = f"{portainer_url}/api/auth"
    payload = {"Username": username, "Password": password}
    response = requests.post(auth_url, json=payload)
    response.raise_for_status()
    return response.json()["jwt"]

def portainer_save_token(token, filename):
    """Saves the token and timestamp to a file."""
    token_data = {"token": token, "timestamp": time.time()}
    with open(filename, "wb") as f:
        pickle.dump(token_data, f)

def portainer_load_token(filename):
    """Loads the token and timestamp from a file."""
    try:
        with open(filename, "rb") as f:
            return pickle.load(f)
    except FileNotFoundError:
        return None

def portainer_is_token_expired(timestamp, token_lifetime_seconds=8 * 3600):
    """Checks if the token has expired."""
    return time.time() - timestamp >= token_lifetime_seconds

def all_systems_up(redis_client):
    """
    Checks if Redis, DNS server, OPNsense, and Portainer are all up and responding.
    
    Returns:
        bool: True if all systems are responsive, False otherwise.
    """
    try:
        # Check Redis connection
        if not redis_client.ping():
            return False
        
        # Check DNS server
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            resolver.timeout = 2
            resolver.retry = 3
            # Try to resolve a known domain
            resolver.resolve('ns01.homelab.home', 'A')
        except Exception as e:
            print(f"DNS server not responding: {e}")
            return False
        
        # Check OPNsense web interface
        try:
            get_opnsense_data("/diagnostics/interface/get_arp")
        except requests.exceptions.RequestException as e:
            print(f"OPNsense not responding: {e}")
            return False
        
        # Check Portainer web interface
        try:
            global portainer_jwt_token
            token_data = portainer_load_token(token_file)
            if token_data and not portainer_is_token_expired(token_data["timestamp"]):
                portainer_jwt_token = token_data["token"]
                endpoints_url = f"{portainer_url}/api/endpoints?provisioned=true"
                headers = {
                    "Authorization": f"Bearer {portainer_jwt_token}",
                    "Content-Type": "application/json"
                }
                response = requests.get(endpoints_url, headers=headers)
                if response.status_code != 200:
                    print("Authentication failed - token failed or expired")
                    token_data = None
                    portainer_jwt_token = None
                else:
                    pass
                    #print("Using saved token.")
            if not portainer_jwt_token:
                logdatamessage("Authenticating to get a new token.")
                try:
                    portainer_jwt_token = portainer_authenticate(portainer_username, portainer_password)
                    portainer_save_token(portainer_jwt_token, token_file)
                    logdatamessage("New token obtained and saved.")
                except requests.exceptions.RequestException as e:
                    print(f"Authentication failed: {e}")
                    exit()
            endpoints_url = f"{portainer_url}/api/endpoints?provisioned=true"
            headers = {
                "Authorization": f"Bearer {portainer_jwt_token}",
                "Content-Type": "application/json"
            }
            response = requests.get(endpoints_url, headers=headers)
            if response.status_code != 200:
                print("Failed to retrieve endpoints")
                exit()
            endpoints = response.json()
            container_list = []
            # Step 3: Iterate Over Endpoints and Containers
            for endpoint in endpoints:
                endpoint_id = endpoint['Id']
                endpoint_status = endpoint['Status']
                #print(f"Looking into {endpoint['Name']} with status {endpoint_status}...")
                if endpoint_status != 1:
                    #print(f"Skipping inactive endpoint...")
                    continue
                containers_url = f"{portainer_url}/api/endpoints/{endpoint_id}/docker/containers/json?all=true"
                headers = {
                    "Authorization": f"Bearer {portainer_jwt_token}",
                    "Content-Type": "application/json"
                }
                response = requests.get(containers_url, headers=headers)
                if response.status_code != 200:
                    print(f"Failed to retrieve endpoints - {containers_url}")
                    #pprint(response.json())
                    #pprint(container_list)
                    #exit()
                containers = response.json()
                if len(containers) == 0:
                    print(f"Endpoint {endpoint_id} has 0 containers...")
                    continue
                else:
                    container_list.append(containers)
                # if 'Snapshots' not in endpoint or not endpoint['Snapshots']:
                #     logdatamessage(f"No Docker Snapshots found for endpoint {endpoint_id}")
                #     logdatamessage("Exiting...")
                #     return False
                # #if 'ContainerCount' in endpoint['Snapshots'][0] and endpoint['Snapshots'][0]['ContainerCount'] > 0:
                # #    return True
                # if 'DockerSnapshotRaw' not in endpoint['Snapshots'][0]:
                #     logdatamessage(f"No DockerSnapshotRaw found in endpoint {endpoint_id}")
                #     logdatamessage("Exiting...")
                #     return False
                # if not endpoint['Snapshots'][0]['DockerSnapshotRaw'].get('Containers'):
                #     logdatamessage(f"No Docker Containers found in endpoint {endpoint_id}")
                #     pprint(endpoint)
                #     logdatamessage("Exiting...")
                #     return False
            if len(container_list) == 0:
                return False
        except requests.exceptions.RequestException as e:
            print(f"Portainer not responding: {e}")
            return False
        
        return True
    
    except Exception as e:
        print(f"Unexpected error during system checks: {e}")
        return False


def get_opnsense_data(endpoint):
    """Fetches data from the OPNsense API."""
    try:
        response = routerAPI.get(f"{base_url}{endpoint}")
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"{base_url}{endpoint}")
        print(f"Error fetching data from {endpoint}: {e}")
        return None

def get_data_from_redis(redis_client, pattern):
    """Retrieves data from Redis matching the given key pattern."""
    keys = redis_client.keys(pattern)
    data = {}
    for key in keys:
        try:
            valueraw = redis_client.get(key)
            if valueraw:
                value = json.loads(valueraw)
                if datetime.strptime(value['last_seen'],"%Y-%m-%d %H:%M:%S") + timedelta(hours=1) > datetime.now():
                    data[key] = value
                else:
                    if debug:
                        print(f"Not using aged {value['last_seen']} Redis data... {key}")
        except (json.JSONDecodeError, TypeError) as e:
            print(f"Error decoding JSON for key {key}: {e}")
    return data

def get_all_data_from_redis(redis_client, pattern):
    """Retrieves data from Redis matching the given key pattern."""
    keys = redis_client.keys(pattern)
    data = {}
    for key in keys:
        try:
            valueraw = redis_client.get(key)
            if valueraw:
                value = json.loads(valueraw)
                data[key] = value
        except (json.JSONDecodeError, TypeError) as e:
            print(f"Error decoding JSON for key {key}: {e}")
    return data

def update_redis_entryv2(redis_client, key, new_data, keep_cache, cache_list):
    """Updates an existing Redis entry with new data."""
    new_data["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if keep_cache:
        entryRaw = redis_client.get(key)
        entry = json.loads(entryRaw) if entryRaw else {}
    else:
        entry = {}
    if entry:
        # Update existing entry with new data
        for k, v in new_data.items():
            if isinstance(entry.get(k), list) and k in cache_list:
                # addresses can only have one mac, but a mac can have more than one address
                entry[k] = list(set(entry[k] + v)) if v else list(set(entry[k]))
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
                # Unreliable hostname retrieval from ARP, so we set it to None
                hostname = None
                #hostname = arp_entry.get("hostname")
                #hostname = hostname.lower() if hostname else None
                redis_key_mac = f"arp:mac:{mac}"
                redis_key_address = f"arp:address:{ipaddress.IPv4Address(address)}"
                #redis_key_hostname = f"arp:hostname:{hostname}"
                arp_entry["mac"] = [mac] if mac else []
                arp_entry["address"] = [address] if address else []
                arp_entry["address"] = [ f"{ipaddress.IPv4Address(address)}" for address in arp_entry["address"] if address.startswith(ipv4_subnetfilter) ]
                arp_entry["hostname"] = [hostname] if hostname else []
                if mac:
                    update_redis_entryv2(redis_client, redis_key_mac, arp_entry, keep_cache, ['address','hostname'])
                if address:
                    update_redis_entryv2(redis_client, redis_key_address, arp_entry, keep_cache, ['hostname'])
                #if hostname:
                #    update_redis_entryv2(redis_client, redis_key_hostname, arp_entry, keep_cache, ['mac', 'address'])
            else:
                if debug:
                    print(f"Skipped...")
                    pprint(arp_entry)
        logdatamessage(f"ARP entries pulled: {len(data)}")
    list_of_arp_keys = redis_client.keys("arp:*")
    logdatamessage(f"ARP keys in Redis: {len(list_of_arp_keys)}")

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
                # Unreliable hostname retrieval from NDP, so we set it to None
                hostname = None
                #hostname = ndp_entry.get("hostname")
                #hostname = hostname.lower() if hostname else None
                redis_key_mac = f"ndp:mac:{mac}"
                redis_key_address = f"ndp:address:{ipaddress.IPv6Address(address)}"
                #redis_key_hostname = f"ndp:hostname:{hostname}"
                ndp_entry["mac"] = [mac] if mac else []
                ndp_entry["address"] = [address] if address else []
                ndp_entry["address"] = [ f"{ipaddress.IPv6Address(address)}" for address in ndp_entry["address"] if address.startswith(ipv6_subnetfilter) ]
                ndp_entry["hostname"] = [hostname] if hostname else []
                if mac:
                    update_redis_entryv2(redis_client, redis_key_mac, ndp_entry, keep_cache, ['address','hostname'])
                if address:
                    update_redis_entryv2(redis_client, redis_key_address, ndp_entry, keep_cache, ['hostname'])
                #if hostname:
                #    update_redis_entryv2(redis_client, redis_key_hostname, ndp_entry, keep_cache, ['mac', 'address'])
            else:
                if debug:
                    print(f"Skipped...")
                    pprint(ndp_entry)
        logdatamessage(f"NDP entries pulled: {len(data)}")
    list_of_ndp_keys = redis_client.keys("ndp:*")
    logdatamessage(f"NDP keys in Redis: {len(list_of_ndp_keys)}")

def process_dhcpv4(redis_client):
    """Collects and stores DHCPv4 data in Redis."""
    data = get_opnsense_data("/dhcpv4/leases/searchLease")
    if data:
        if debug:
            pprint(data['rows'][0:5])
        for dhcpv4_entry in data['rows']:
            address = f"{ipaddress.IPv4Address(dhcpv4_entry.get('address'))}"
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
                update_redis_entryv2(redis_client, redis_key_mac, dhcpv4_entry, keep_cache, ['address','hostname'])
            if address:
                update_redis_entryv2(redis_client, redis_key_address, dhcpv4_entry, keep_cache, ['hostname'])
            if hostname:
                update_redis_entryv2(redis_client, redis_key_hostname, dhcpv4_entry, keep_cache, ['mac', 'address'])
        logdatamessage(f"ISC DHCPv4 entrys pulled: {len(data['rows'])}")
    list_of_dhcpv4_keys = redis_client.keys("dhcpv4:*")
    logdatamessage(f"ISC DHCPv4 keys in Redis: {len(list_of_dhcpv4_keys)}")

def process_dhcpv6(redis_client):
    """Collects and stores DHCPv6 data in Redis."""
    data = get_opnsense_data("/dhcpv6/leases/searchLease")
    if data:
        if debug:
            pprint(data['rows'][0:5])
        for dhcpv6_entry in data['rows']:
            address = f"{ipaddress.IPv6Address(dhcpv6_entry.get('address'))}"
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
                update_redis_entryv2(redis_client, redis_key_mac, dhcpv6_entry, keep_cache, ['address','hostname'])
            if address:
                update_redis_entryv2(redis_client, redis_key_address, dhcpv6_entry, keep_cache, ['hostname'])
            if hostname:
                update_redis_entryv2(redis_client, redis_key_hostname, dhcpv6_entry, keep_cache, ['mac', 'address'])
        logdatamessage(f"ISC DHCPv6 entrys pulled: {len(data['rows'])}")
    list_of_dhcpv6_keys = redis_client.keys("dhcpv6:*")
    logdatamessage(f"ISC DHCPv6 keys in Redis: {len(list_of_dhcpv6_keys)}")

def process_keadhcpv4(redis_client):
    """Collects and stores DHCPv4 data in Redis."""
    data = get_opnsense_data("/kea/dhcpv4/search_reservation")
    if data:
        if debug:
            pprint(data['rows'][0:5])
        for dhcpv4_entry in data['rows']:
            address = f"{ipaddress.IPv4Address(dhcpv4_entry.get('ip_address'))}"
            mac = dhcpv4_entry.get("hw_address")
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
                update_redis_entryv2(redis_client, redis_key_mac, dhcpv4_entry, keep_cache, ['address','hostname'])
            if address:
                update_redis_entryv2(redis_client, redis_key_address, dhcpv4_entry, keep_cache, ['hostname'])
            if hostname:
                update_redis_entryv2(redis_client, redis_key_hostname, dhcpv4_entry, keep_cache, ['mac', 'address'])
        logdatamessage(f"KEA DHCPv4 entrys pulled: {len(data['rows'])}")
    list_of_dhcpv4_keys = redis_client.keys("dhcpv4:*")
    logdatamessage(f"KEA DHCPv4 keys in Redis: {len(list_of_dhcpv4_keys)}")

def process_keadhcpv6(redis_client):
    """Collects and stores DHCPv6 data in Redis."""
    data = get_opnsense_data("/kea/dhcpv6/search_subnet")
    if data:
        if debug:
            pprint(data)
            # ['rows'][0:5])
        for dhcpv6_subnet in data['rows']:
            subnet_data = get_opnsense_data(f"/kea/dhcpv6/get_subnet?$uuid={dhcpv6_subnet['uuid']}")
            if subnet_data:
                if debug:
                    pprint(subnet_data)
                if 'rows' in subnet_data:
                    for dhcpv6_entry in subnet_data['rows']:
                        address = f"{ipaddress.IPv6Address(dhcpv6_entry.get('ip_address'))}"
                        mac = dhcpv6_entry.get("hw_address")
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
                            update_redis_entryv2(redis_client, redis_key_mac, dhcpv6_entry, keep_cache, ['address','hostname'])
                        if address:
                            update_redis_entryv2(redis_client, redis_key_address, dhcpv6_entry, keep_cache, ['hostname'])
                        if hostname:
                            update_redis_entryv2(redis_client, redis_key_hostname, dhcpv6_entry, keep_cache, ['mac', 'address'])
                    logdatamessage(f"KEA DHCPv6 entrys pulled: {len(subnet_data['rows'])}")
        logdatamessage(f"KEA DHCPv6 subnets pulled: {len(data['rows'])}")
    list_of_dhcpv6_keys = redis_client.keys("dhcpv6:*")
    logdatamessage(f"KEA DHCPv6 keys in Redis: {len(list_of_dhcpv6_keys)}")

def process_interfaces(redis_client):
    """Collects and stores OPNSense Interface data in Redis."""
    data = get_opnsense_data("/diagnostics/interface/getInterfaceConfig")
    if data:
        if debug:
            pprint(data)
        for interface_name, interface_entry in data.items():
            cleaned_entry = {}
            hostname = 'opnsense'
            ipv4addresses = [ ipv4address['ipaddr'] for ipv4address in interface_entry['ipv4'] ]
            ipv4addresses = [ f"{ipaddress.IPv4Address(ipv4address)}" for ipv4address in ipv4addresses if ipv4address.startswith(ipv4_subnetfilter) ]
            ipv6addresses = [ ipv6address['ipaddr'] for ipv6address in interface_entry['ipv6'] ]
            ipv6addresses = [ f"{ipaddress.IPv6Address(ipv6address)}" for ipv6address in ipv6addresses if ipv6address.startswith(ipv6_subnetfilter) ]
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
                update_redis_entryv2(redis_client, redis_key_mac, cleaned_entry, keep_cache, ['address','hostname'])
            for address in alladdresses:
                if address:
                    redis_key_address = f"interface:address:{address}"
                    update_redis_entryv2(redis_client, redis_key_address, cleaned_entry, keep_cache, ['hostname'])
            if hostname:
                update_redis_entryv2(redis_client, redis_key_hostname, cleaned_entry, keep_cache, ['mac', 'address'])
        logdatamessage(f"Interface entrys pulled: {len(data)}")
    list_of_interface_keys = redis_client.keys("interface:*")
    logdatamessage(f"Interface keys in Redis: {len(list_of_interface_keys)}")

def process_docker_containers(redis_client):
    # Step 1: Authenticate with Portainer
    global portainer_jwt_token
    token_data = portainer_load_token(token_file)
    if token_data and not portainer_is_token_expired(token_data["timestamp"]):
        portainer_jwt_token = token_data["token"]
        endpoints_url = f"{portainer_url}/api/endpoints?provisioned=true"
        headers = {
            "Authorization": f"Bearer {portainer_jwt_token}",
            "Content-Type": "application/json"
        }
        response = requests.get(endpoints_url, headers=headers)
        if response.status_code != 200:
            logdatamessage("Authentication failed - token failed or expired")
            token_data = None
            portainer_jwt_token = None
        else:
            logdatamessage("Using saved token.")
    if not portainer_jwt_token:
        logdatamessage("Authenticating to get a new token.")
        try:
            portainer_jwt_token = portainer_authenticate(portainer_username, portainer_password)
            portainer_save_token(portainer_jwt_token, token_file)
            logdatamessage("New token obtained and saved.")
        except requests.exceptions.RequestException as e:
            print(f"Authentication failed: {e}")
            exit()
    # Step 2: Retrieve List of Endpoints (Docker Hosts)
    endpoints_url = f"{portainer_url}/api/endpoints?provisioned=true"
    headers = {
        "Authorization": f"Bearer {portainer_jwt_token}",
        "Content-Type": "application/json"
    }
    response = requests.get(endpoints_url, headers=headers)
    if response.status_code != 200:
        print("Failed to retrieve endpoints")
        exit()
    endpoints = response.json()
    logdatamessage(f"Found {len(endpoints)} endpoint(s)")
    container_list = []
    # Step 3: Iterate Over Endpoints and Containers
    for endpoint in endpoints:
        endpoint_id = endpoint['Id']
        endpoint_status = endpoint['Status']
        logdatamessage(f"Looking into {endpoint['Name']} with status {endpoint_status}...")
        if endpoint_status != 1:
            logdatamessage(f"Skipping inactive endpoint...")
            continue
        # if 'Snapshots' not in endpoint or not endpoint['Snapshots']:
        #     logdatamessage(f"No Docker Snapshots found for endpoint {endpoint_id}")
        #     continue
        # if 'DockerSnapshotRaw' not in endpoint['Snapshots'][0]:
        #     logdatamessage(f"No DockerSnapshotRaw found in endpoint {endpoint_id}")
        #     continue
        # if not endpoint['Snapshots'][0]['DockerSnapshotRaw'].get('Containers'):
        #     logdatamessage(f"No Docker Containers found in endpoint {endpoint_id}")
        #     pprint(endpoint['Snapshots'])
        #     logdatamessage("Exiting...")
        #     sys.exit(0)
        containers_url = f"{portainer_url}/api/endpoints/{endpoint_id}/docker/containers/json?all=true"
        response = requests.get(containers_url, headers=headers)
        if response.status_code != 200:
            logdatamessage(f"Failed to retrieve containers from endpoint {endpoint_id}")
            #pprint(response.text)
            continue
        containers = response.json()
        logdatamessage(f"Which has {len(containers)} Docker Snapshots Container Definitions")
        for container in containers:
            if 'Id' in container:
                pass
            else:
                continue
            container_id = container['Id']
            # Step 4: Retrieve Detailed Container Info
            container_info_url = f"{portainer_url}/api/endpoints/{endpoint_id}/docker/containers/{container_id}/json"
            response = requests.get(container_info_url, headers=headers)
            if response.status_code != 200:
                logdatamessage(f"Failed to get details for container {container_id}")
                continue
            container_details = response.json()
            # Step 5: Extract Hostname
            hostname = container_details.get('Config', {}).get('Hostname', 'N/A')
            # check if the container is running
            if container_details.get('State', {}).get('Running') is not True:
                logdatamessage(f"Container {container_id} - {hostname} is not running, skipping...")
                continue
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
                    else:
                        if debug:
                            print(f"Network {net_name} has no IPAMConfig, skipping...")
                    if goodNetwork:
                        mac_address.append(data.get('MacAddress'))
                ipv4_address = list(set([f"{ipaddress.IPv4Address(ip)}" for ip in ipv4_address if ip.startswith(ipv4_subnetfilter)]))
                ipv6_address = list(set([f"{ipaddress.IPv6Address(ip)}" for ip in ipv6_address if ip.startswith(ipv6_subnetfilter)]))
            addresses = list(set(ipv4_address + ipv6_address))
            if len(mac_address) > 0:
                container_list.append({'hostname': [hostname], 'mac': list(set(mac_address)), 'address': list(set(addresses))})
    for container_entry in container_list:
            macs = container_entry['mac']
            hostnames = container_entry['hostname']
            alladdresses = container_entry["address"]
            for mac in macs:
                redis_key_mac = f"docker:mac:{mac}"
                update_redis_entryv2(redis_client, redis_key_mac, container_entry, keep_cache, ['address','hostname'])
            for address in alladdresses:
                if address:
                    redis_key_address = f"docker:address:{address}"
                    update_redis_entryv2(redis_client, redis_key_address, container_entry, keep_cache, ['hostname'])
            for hostname in hostnames:
                redis_key_hostname = f"docker:hostname:{hostname}"
                update_redis_entryv2(redis_client, redis_key_hostname, container_entry, keep_cache, ['mac', 'address'])

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

def get_ipv6_subnet(ip_address):
    if ':' in ip_address:  # IPv6
        ipv6_obj = ipaddress.IPv6Address(ip_address)
        subnet = ip_address[0:19]
        bytes_value = ipv6_obj._ip.to_bytes(16, 'big')
        nibbles = []
        for byte in bytes_value:
            hex_byte = '{:02x}'.format(byte)
            for c in hex_byte:
                nibbles.append(c)
        reversed_nibbles = list(reversed(nibbles))
        ptr_domain = '.'.join(reversed_nibbles) + '.ip6.arpa.'
    else:  # IPv4
        octets = ip_address.split('.')
        subnet = '.'.join(octets[0:3])
        ptr_domain = '.'.join(reversed(octets)) + '.in-addr.arpa.'
    return subnet, ptr_domain

def create_dns_updatesv2(hosts_data):
    print_existing = False  # For debugging purposes only

    def get_ptr_domain(ip_address):
        if ':' in ip_address:  # IPv6
            ipv6_obj = ipaddress.IPv6Address(ip_address)
            subnet = ip_address[0:19]
            bytes_value = ipv6_obj._ip.to_bytes(16, 'big')
            nibbles = []
            for byte in bytes_value:
                hex_byte = '{:02x}'.format(byte)
                for c in hex_byte:
                    nibbles.append(c)
            reversed_nibbles = list(reversed(nibbles))
            ptr_domain = '.'.join(reversed_nibbles) + '.ip6.arpa.'
        else:  # IPv4
            octets = ip_address.split('.')
            subnet = '.'.join(octets[0:3])
            ptr_domain = '.'.join(reversed(octets)) + '.in-addr.arpa.'
        return subnet, ptr_domain

    def get_forward_records_for_zone(nameserver, zone_name):
        """Performs a zone transfer and returns A/AAAA records with TTL."""
        try:
            # Initialize the zone transfer
            xfr = dns.query.xfr(nameserver, zone_name)
            zone = dns.zone.from_xfr(xfr)
            records = {}
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    if rdataset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                        rdtype_text = dns.rdatatype.to_text(rdataset.rdtype)

                        ips = [rdata.address for rdata in rdataset]

                        records.setdefault(str(name), {})
                        records[str(name)][rdtype_text] = {
                            "ips": ips,
                            "ttl": rdataset.ttl
                        }
            for domain in records.keys():
                for record_type in ['A', 'AAAA']:
                    if record_type not in records[domain]:
                        records[domain].setdefault(record_type, {'ips':[], 'ttl': dns_ttl})
            return records
        except Exception as e:
            print(f"Error performing zone transfer: {e}")
            return {}

    def get_reverse_records_for_zone(nameserver, reverse_zone):
        """Performs a zone transfer for the reverse DNS zone corresponding to a subnet
        and extracts the PTR records."""
        try:
            # Initiate the zone transfer
            axfr = dns.query.xfr(nameserver, zone=reverse_zone)
            zone = dns.zone.from_xfr(axfr)
            # Extract PTR records, as IP (reversed from PTR) and hostnames (targets)
            ptr_records = {}
            for name, node in zone.nodes.items():
                rdatasets = node.rdatasets
                for rdataset in rdatasets:
                    if rdataset.rdtype == dns.rdatatype.PTR:
                        for rdata in rdataset:
                            ptr_address = f"{name}.{reverse_zone}"
                            text = ""
                            if ptr_address.endswith('.in-addr.arpa.'):
                                conversion = ptr_address[:-14]
                                text = ".".join(reversed(conversion.split('.')))
                            elif ptr_address.endswith('.ip6.arpa.'):
                                conversion = ptr_address[:-10]
                                conversion = "".join(reversed(conversion.split('.')))
                                parts = []
                                for i in range(0, len(conversion), 4):
                                    parts.append("".join(conversion[i : i + 4]))
                                text = ":".join(parts)
                            ip_address = f"{text}"
                            if ':' in ip_address:
                                ip_address = f"{ipaddress.IPv6Address(ip_address)}"
                            else:
                                ip_address = f"{ipaddress.IPv4Address(ip_address)}"
                            if ip_address in ptr_records:
                                if str(rdata.target) not in ptr_records[ip_address]:
                                    ptr_records[ip_address].append(str(rdata.target))
                            else:
                                ptr_records[ip_address] = [str(rdata.target)]
            return ptr_records

        except Exception as e:
            print(f"Error performing zone transfer for {reverse_zone}: {e}")
            return {}

    # Update A and AAAA IN Forward Records
    forward_records = get_forward_records_for_zone(dns_server, dns_domain)
    #debug = False
    if debug:
        print("host data:")
        pprint(hosts_data)
        print("forward records:")
        pprint(forward_records)
    logdatamessage(f"IN - checking the updates list for add/delete to existing...")
    # First pass: Add new records
    print_existing = False
    for hostname, ips in hosts_data.items():
        try:
            if not ips:
                # skip
                continue
            fqdn = f"{hostname}.{dns_domain}"
            if hostname in forward_records.keys():
                for ip_address in ips:
                    ip_type = 'AAAA' if ':' in ip_address else 'A'
                    if ip_address in forward_records[hostname][ip_type]['ips']:
                        if print_existing:
                            logdatamessage(f"Found existing {ip_type} record: {fqdn} -> {ip_address}")
                        continue
                    else:
                        logdatamessage(f"Adding {ip_type} record: {fqdn} -> {ip_address}")
                        fwd_update.add(hostname, dns_ttl, ip_type, ip_address)
                        pending_changes['add'][ip_type].append((hostname, ip_address))
                for ip_address in forward_records[hostname][ip_type]['ips']:
                    ip_type = 'AAAA' if ':' in ip_address else 'A'
                    if ip_address in ips:
                        if print_existing:
                            logdatamessage(f"Found existing {ip_type} record: {fqdn} -> {ip_address}")
                        continue
                    else:
                        logdatamessage(f"Removing {ip_type} record: {ip_address} from {fqdn}")
                        fwd_update.delete(hostname, ip_type, ip_address)
                        pending_changes['delete'][ip_type].append((fqdn, ip_address))
            else:
                for ip_address in ips:
                    ip_type = 'AAAA' if ':' in ip_address else 'A'
                    logdatamessage(f"Adding {ip_type} record: {fqdn} -> {ip_address}")
                    fwd_update.add(hostname, dns_ttl, ip_type, ip_address)
                    pending_changes['add'][ip_type].append((hostname, ip_address))
        except Exception as e:
            print(f"Error during DNS Forward 1st pass: {e}")
            PrintException()
    for hostname, answerData in forward_records.items():
        try:
            fqdn = f"{hostname}.{dns_domain}"
            for record_type in ['A', 'AAAA']:
                if hostname in hosts_data.keys():
                    for ip_address in answerData[record_type]['ips']:
                        if ip_address not in hosts_data[hostname]:
                            logdatamessage(f"Removing {record_type} record: {ip_address} from {fqdn}")
                            fwd_update.delete(hostname, record_type, ip_address)
                            pending_changes['delete'][record_type].append((fqdn, ip_address))
                        else:
                            if print_existing:
                                logdatamessage(f"Found existing {record_type} record: {fqdn} -> {ip_address}")
                            continue
                elif hostname in bad_hostnames:
                    for ip_address in answerData[record_type]['ips']:
                        logdatamessage(f"Removing {record_type} record: {ip_address} from {fqdn}")
                        fwd_update.delete(hostname, record_type, ip_address)
                        pending_changes['delete'][record_type].append((fqdn, ip_address))
                else:
                    for ip_address in answerData[record_type]['ips']:
                        logdatamessage(f"Removing {record_type} record: {ip_address} from {fqdn}")
                        fwd_update.delete(hostname, record_type, ip_address)
                        pending_changes['delete'][record_type].append((fqdn, ip_address))
        except Exception as e:
            print(f"Error during DNS Forward 2nd pass: {e}")
            PrintException()
    logdatamessage(f"PTR - checking the updates list for add/delete to existing...")
    # Update Reverse PTR Records
    for subnet_update in ptr_updates.keys():
        if subnet_update not in reverse_zones:
            logdatamessage(f"Skipping PTR cleanup for unknown subnet: {subnet_update}")
        reverse_zone = reverse_zones[subnet_update]
        if report_findings:
            logdatamessage(f"Checking PTR records for subnet {subnet_update} in zone {reverse_zone}...")
        ptr_records = get_reverse_records_for_zone(dns_server, reverse_zone)
        if '.' in subnet_update:
            subnet = f"{subnet_update}0/24"
        else:
            subnet = f"{subnet_update}:/64"
        logdatamessage(f"Found {len(ptr_records)} PTR records in subnet {subnet}.")
        if debug:
            pprint(ptr_records)
        # Check host_data entries
        for hostname, ips in hosts_data.items():
            # report_findings = True
            if not ips:
                # skip
                continue
            subnet_ips = [ ip for ip in ips if ip.startswith(subnet_update) ]
            if len(subnet_ips) == 0:
                # skip
                continue
            fqdn = f"{hostname}.{dns_domain}."
            # Check each IP and add if missing
            for ip_address in subnet_ips:
                ptr_subnet, ptr_domain = get_ptr_domain(ip_address)
                if ip_address in ptr_records.keys():
                    if fqdn in ptr_records[ip_address]:
                        # Keep
                        continue
                    else:
                        # Add
                        if report_findings:
                            logdatamessage(f"Adding PTR record: {ptr_domain} -> {fqdn} - missing FQDN")
                        ptr_updates[subnet_update].add(ptr_domain, dns_ttl, 'PTR', fqdn)
                        pending_changes['add'][f'PTR{"IPv6" if ":" in ip_address else "IPv4"}'].append((ptr_domain, fqdn))
                else:
                    # Add
                    if report_findings:
                        logdatamessage(f"Adding PTR record: {ptr_domain} -> {fqdn} - missing IP + FQDN")
                    ptr_updates[subnet_update].add(ptr_domain, 3600, 'PTR', fqdn)
                    pending_changes['add'][f'PTR{"IPv6" if ":" in ip_address else "IPv4"}'].append((ptr_domain, fqdn))
            for ptr_ip_address, ptr_fqdns in ptr_records.items():
                if fqdn in ptr_fqdns:
                    if ptr_ip_address in subnet_ips:
                        # Keep
                        continue
                    else:
                        ptr_subnet, ptr_domain = get_ptr_domain(ptr_ip_address)
                        # Delete
                        #if report_findings:
                        logdatamessage(f"Removing PTR record: {ptr_ip_address} -> {fqdn} - IP for Hostname {hostname} not found in hosts_data")
                        ptr_updates[subnet_update].delete(ptr_domain, 'PTR', fqdn)
                        pending_changes['delete'][f'PTR{"IPv6" if ":" in ptr_ip_address else "IPv4"}'].append((ptr_domain, fqdn))
        # Check all PTR Entries
        for ptr_ip_address, ptr_fqdns in ptr_records.items():
            ptr_subnet, ptr_domain = get_ptr_domain(ptr_ip_address)
            for ptr_fqdn in ptr_fqdns:
                ptr_fqdn_parts = ptr_fqdn.split('.')
                ptr_hostname = '.'.join(ptr_fqdn_parts[:-3])
                if report_findings:
                    logdatamessage(f"Checking PTR record {ptr_hostname} ({ptr_fqdn}) for {ptr_ip_address}...")
                if ptr_hostname in bad_hostnames:
                    if (ptr_domain, ptr_fqdn) not in pending_changes['delete'][f'PTR{"IPv6" if ":" in ptr_ip_address else "IPv4"}']:
                        logdatamessage(f"Removing PTR record: {ptr_ip_address} -> {ptr_hostname} found in bad_hostnames")
                        ptr_updates[subnet_update].delete(ptr_domain, 'PTR', ptr_fqdn)
                        pending_changes['delete'][f'PTR{"IPv6" if ":" in ptr_ip_address else "IPv4"}'].append((ptr_domain, ptr_fqdn))
                elif ptr_hostname not in hosts_data:
                    logdatamessage(f"Removing PTR record: {ptr_hostname} not found in hosts_data")
                    ptr_updates[subnet_update].delete(ptr_domain, 'PTR', ptr_fqdn)
                    pending_changes['delete'][f'PTR{"IPv6" if ":" in ptr_ip_address else "IPv4"}'].append((ptr_domain, ptr_fqdn))
                elif ptr_hostname in hosts_data:
                    if ptr_ip_address not in hosts_data[ptr_hostname]:
                        logdatamessage(f"Removing PTR record: {ptr_hostname} ({ptr_ip_address}) not found in hosts_data")
                        ptr_updates[subnet_update].delete(ptr_domain, 'PTR', ptr_fqdn)
                        pending_changes['delete'][f'PTR{"IPv6" if ":" in ptr_ip_address else "IPv4"}'].append((ptr_domain, ptr_fqdn))
                # elif ptr_hostname not in hosts_data:
                #     ptr_subnet, ptr_domain = get_ptr_domain(ptr_ip_address)
                #     if (ptr_domain, ptr_fqdn) not in pending_changes['delete'][f'PTR{"IPv6" if ":" in ptr_ip_address else "IPv4"}']:
                #         logdatamessage(f"Removing PTR record: {ptr_ip_address} -> {ptr_hostname} not in hostnames")
                #         ptr_updates[subnet_update].delete(ptr_domain, 'PTR', ptr_fqdn)
                #         pending_changes['delete'][f'PTR{"IPv6" if ":" in ptr_ip_address else "IPv4"}'].append((ptr_domain, ptr_fqdn))
                else:
                    # Skip - fqdn is not in this record set
                    continue
    # Check and update TTL for each record type
    for hostname, record_data in forward_records.items():
        if hostname not in hosts_data:
            continue
        for record_type in ['A', 'AAAA']:
            if record_type not in record_data:
                continue
            if report_findings:
                logdatamessage(f"Checking TTL on domains - {hostname} - {record_type}")
            current_ttl = record_data[record_type]["ttl"]
            current_ips = record_data[record_type]["ips"]
            if current_ttl == dns_ttl:
                continue
            fqdn = f"{hostname}.{dns_domain}"
            logdatamessage(
                f"Updating TTL for {record_type} {fqdn}: {current_ttl} -> {dns_ttl}"
            )
            # Delete entire RRset
            fwd_update.delete(hostname, record_type)
            # Re-add all records with correct TTL
            for ip_address in current_ips:
                fwd_update.add(hostname, dns_ttl, record_type, ip_address)
            pending_changes['add'][record_type].append(
                (hostname, f"TTL {current_ttl} -> {dns_ttl}")
            )
    return pending_changes

def main():
    """Main function to collect and store data."""

    # Setup Redis logging connection
    redis_logging_client = connect_to_redis(5)

    # Initialize Redis connection
    redis_client = connect_to_redis(6)
    if not redis_client:
        print("Failed to connect to Redis. Exiting...")
        return
    logdatamessage("Connected to Redis.")

    logdatamessage("Cleaning up problematic records...")
    for pattern in KEY_PATTERNS:
        cached_data = get_all_data_from_redis(redis_client, pattern)
        for k, v in cached_data.items():
            for key, value in v.items():
                if key == 'hostname':
                    for badhostname in bad_hostnames:
                        if badhostname in value:
                            logdatamessage(f"Cleaning up problematic hostname '{badhostname}' in {k}")
                            v['hostname'] = [h for h in value if h != badhostname]
                            if len(v['hostname']) == 0:
                                logdatamessage(f"Removing {k} as no hostnames remain")
                                redis_client.delete(k)
                                continue
                            else:
                                # Update the record with cleaned hostname
                                logdatamessage(f"Updating {k} with cleaned hostname")
                                redis_client.set(k, json.dumps(v))
                            # to_delete_macs = v['macs']
                            # to_delete_ips = v['addresses']
                            # for delete_mac in to_delete_macs:
                            #     redis_client.delete
                    if key == 'hostname' and len(value) > 0 and v['hostname'][0] in multihost_list:
                        continue
                    elif len(v['mac']) > 1:
                        logdatamessage(f"found multiple MAC on {k} - {v['hostname'][0] if 'hostname' in v.keys() and len(v['hostname']) > 0 else 'N/A'}")
                        #pprint(v)
    redis_client.save()
    logdatamessage("Checking if all systems are up...")
    if not all_systems_up(redis_client):
        print("One or more systems are not responding. Exiting...")
        return
    logdatamessage("All systems are up and running.")

    if keep_cache:
        logdatamessage("Keeping DNS cache from Redis")
    else:
        logdatamessage("Ignoring DNS cache from Redis")

    #list_of_keys = redis_client.keys("*")
    #for key in list_of_keys:
    #   redis_client.delete(key)

    # Collect and process data
    logdatamessage("Collecting ARP data...")
    process_arp(redis_client)

    logdatamessage("Collecting NDP data...")
    process_ndp(redis_client)

    # logdatamessage("Collecting ISC DHCPv4 data...")
    # process_dhcpv4(redis_client)

    # logdatamessage("Collecting ISC DHCPv6 data...")
    # process_dhcpv6(redis_client)

    logdatamessage("Collecting KEA DHCPv4 data...")
    process_keadhcpv4(redis_client)

    logdatamessage("Collecting KEA DHCPv6 data...")
    process_keadhcpv6(redis_client)

    logdatamessage("Collecting Interface data...")
    process_interfaces(redis_client)
    if not all_systems_up(redis_client):
        print("One or more systems are not responding. Exiting...")
        return
    logdatamessage("Collecting Docker Container data...")
    process_docker_containers(redis_client)

    logdatamessage("Collecting Static Host data...")
    staticrecords = {}
    for statichost in statichosts:
        staticrecord = {
            'hostname': [],
            'mac': [],
            'address': []
        }
        statichostsplit = statichost.split('/')
        # print(f"working: {statichost}")
        for element in range(len(statichostsplit)):
            if statichostsplit[element] == 'mac':
                staticrecord['mac'].append(statichostsplit[element + 1].lower())
                if staticrecord['mac'][0] not in staticrecords:
                    staticrecords[staticrecord['mac'][0]] = {}
            if statichostsplit[element] == 'hostname':
                staticrecord['hostname'].append(statichostsplit[element + 1].lower())
            if statichostsplit[element] == 'address':
                staticrecord['address'].append(statichostsplit[element + 1].lower())
        staticrecords[staticrecord['mac'][0]]['hostname'] = list(set(staticrecord['hostname'] + staticrecords[staticrecord['mac'][0]].get('hostname', [])))
        staticrecords[staticrecord['mac'][0]]['mac'] = list(set(staticrecord['mac'] + staticrecords[staticrecord['mac'][0]].get('mac', [])))
        staticrecords[staticrecord['mac'][0]]['address'] = list(set(staticrecord['address'] + staticrecords[staticrecord['mac'][0]].get('address', [])))
        # pprint(staticrecords[staticrecord['mac'][0]])
    for mac, record in staticrecords.items():
        redis_key_mac = f"static:mac:{mac}"
        update_redis_entryv2(redis_client, redis_key_mac, record, keep_cache, ['address','hostname'])
        for hostname in record['hostname']:
            redis_key_hostname = f"static:hostname:{hostname}"
            update_redis_entryv2(redis_client, redis_key_hostname, record, keep_cache, ['mac', 'address'])
        for address in record['address']:
            redis_key_address = f"static:address:{address}"
            update_redis_entryv2(redis_client, redis_key_address, record, keep_cache, ['hostname'])
    redis_client.save()
    time.sleep(2)
    logdatamessage("Data collection complete.")
    if not all_systems_up(redis_client):
        print("One or more systems are not responding. Exiting...")
        return
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
    if not all_systems_up(redis_client):
        print("One or more systems are not responding. Exiting...")
        return
    # Clean up stale records by IP
    logdatamessage("Cleaning up stale records...")
    for pattern in KEY_PATTERNS:
        logdatamessage(f"working pattern: {pattern}")
        cached_data = get_all_data_from_redis(redis_client, pattern)
        for k, v in cached_data.items():
            ips_to_remove = []
            hostname = v.get('hostname', [None])
            hostname = hostname[0] if hostname else None
            if datetime.strptime(v['last_seen'],"%Y-%m-%d %H:%M:%S") + timedelta(minutes=5) <= datetime.now():
                logdatamessage(f"Removing {k} as last_seen is older than 5 minutes")
                redis_client.delete(k)
                continue
            for key, value in v.items():
                if key == 'address':
                    if len(value) == 0:
                        logdatamessage(f"Removing {k} as no addresses remain")
                        redis_client.delete(k)
                        continue
                    for address in value:
                        addressgood = False
                        # Skip IPv6 for IPv4-only hosts
                        ipv6_subnet, ipv6_domain = get_ipv6_subnet(address)
                        if hostname in ipv4_only_hosts and ':' in address:
                            logdatamessage(f"Cleaning up IPv6 record for {address} in {k} IPv4 only host {hostname}")
                        #elif ':' in address and is_ipv6_in_range(address, f"{ipv6_subnet}::1000", f"{ipv6_subnet}::2000"):
                        #    logdatamessage(f"Cleaning up IPv6 record for {address} in {k} Bad Range {hostname}")
                        elif address in bad_addresses:
                            logdatamessage(f"Cleaning up IPv6 record for {address} in {k} Bad Address {hostname}")
                        else:
                            address_pattern = f"*:address:{address}"
                            check_data = get_data_from_redis(redis_client, address_pattern)
                            if check_data:
                                for check_key, check_value in check_data.items():
                                    if check_value:
                                        if 'last_seen' in check_value:
                                            if datetime.strptime(check_value['last_seen'],"%Y-%m-%d %H:%M:%S") + timedelta(hours=1) <= datetime.now():
                                                logdatamessage(f"Cleaning up stale record for {address} in {k} with 'last_seen' of {check_value['last_seen']}")
                                            else:
                                                if debug:
                                                    print(f"Keeping record for {address} in {k}")
                                                addressgood = True
                                                break
                                        else:
                                            logdatamessage(f"Cleaning up stale record for {address} in {k} no last_seen value")
                                    else:
                                        if debug:
                                            print(f"Cleaning up stale record for {address} in {k} no check value")
                            else:
                                if debug:
                                    print(f"Cleaning up stale record for {address} in {k} no check data")
                        if not addressgood:
                            ips_to_remove.append(address)
            if len(ips_to_remove) > 0:
                ips_to_remove = list(set(ips_to_remove))
                cached_data_cleanup = get_data_from_redis(redis_client, '*')
                for k_cleanup, v_cleanup in cached_data_cleanup.items():
                    if v_cleanup and 'address' in v_cleanup:
                        before = len(v_cleanup.get('address', []))
                        v_cleanup['address'] = list(set(v_cleanup.get('address', [])) - set(ips_to_remove))
                        after = len(v_cleanup.get('address', []))
                        if before != after and after > 0:
                            redis_client.set(k_cleanup, json.dumps(v_cleanup))
                            logdatamessage(f"Updated {k_cleanup} with {before} -> {after} addresses after cleanup")
                        elif after == 0:
                            redis_client.delete(k_cleanup)
                            logdatamessage(f"Deleted {k_cleanup} after cleanup as no addresses remain")
                redis_client.save()
                time.sleep(2)
        # Clean up stale records by MAC
        cached_data = get_all_data_from_redis(redis_client, pattern)
        for k, v in cached_data.items():
            macs_to_remove = []
            hostname = v.get('hostname', [None])
            hostname = hostname[0] if hostname else None
            if datetime.strptime(v['last_seen'],"%Y-%m-%d %H:%M:%S") + timedelta(hours=1) <= datetime.now():
                logdatamessage(f"Removing {k} as last_seen is older than 1 hours")
                redis_client.delete(k)
                continue
            for key, value in v.items():
                if key == 'mac':
                    if len(value) == 0:
                        logdatamessage(f"Removing {k} as no macs remain")
                        redis_client.delete(k)
                        continue
                    for mac in value:
                        macgood = False
                        mac_pattern = f"*:mac:{mac}"
                        check_data = get_data_from_redis(redis_client, mac_pattern)
                        if check_data:
                            for check_key, check_value in check_data.items():
                                if check_value:
                                    if 'last_seen' in check_value:
                                        if datetime.strptime(check_value['last_seen'],"%Y-%m-%d %H:%M:%S") + timedelta(hours=1) <= datetime.now():
                                            logdatamessage(f"Cleaning up stale record for {mac} in {k} with 'last_seen' of {check_value['last_seen']}")
                                        else:
                                            if debug:
                                                print(f"Keeping record for {mac} in {k}")
                                            macgood = True
                                            break
                                    else:
                                        logdatamessage(f"Cleaning up stale record for {mac} in {k} no last_seen value")
                                else:
                                    if debug:
                                        print(f"Cleaning up stale record for {mac} in {k} no check value")
                        else:
                            if debug:
                                print(f"Cleaning up stale record for {mac} in {k} no check data")
                        if not macgood:
                            macs_to_remove.append(mac)
            if len(macs_to_remove) > 0:
                macs_to_remove = list(set(macs_to_remove))
                cached_data_cleanup = get_data_from_redis(redis_client, '*')
                for k_cleanup, v_cleanup in cached_data_cleanup.items():
                    if v_cleanup and 'mac' in v_cleanup:
                        before = len(v_cleanup.get('mac', []))
                        v_cleanup['mac'] = list(set(v_cleanup.get('mac', [])) - set(macs_to_remove))
                        after = len(v_cleanup.get('mac', []))
                        if before != after and after > 0:
                            redis_client.set(k_cleanup, json.dumps(v_cleanup))
                            logdatamessage(f"Updated {k_cleanup} with {before} -> {after} macs after cleanup")
                        elif after == 0:
                            redis_client.delete(k_cleanup)
                            logdatamessage(f"Deleted {k_cleanup} after cleanup as no macs remain")
                redis_client.save()
                time.sleep(2)
    #sys.exit(0)
    if not all_systems_up(redis_client):
        print("One or more systems are not responding. Exiting...")
        return
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

    cleaned_data = []
    for value_dict in all_data:
        if 'address' in value_dict and 'mac' in value_dict:
            if len(value_dict['address']) > 0 and len(value_dict['mac']) > 0:
                cleaned_data.append(value_dict)
    logdatamessage("Data cleanup complete.")
    #pprint(all_data)
    #sys.exit(0)
    do_fill_in = False
    
    logdatamessage("Creating hostname to IP and MAC to IP from Redis data and DNS lookups...")
    mac_to_ips = {}
    hostname_to_ips = {}
    mac_to_ips_with_no_hostname = {}
    # Get Hostname to IP list setup
    for value_dict in cleaned_data:
        addresses = value_dict.get('address', [])
        macs = value_dict.get('mac', [])
        hostnames = value_dict.get('hostname', [])
        # Get the host name if it is known or in DNS already
        # If we have the hostname, we can skip the DNS lookup
        if len(hostnames) == 0 or hostnames[0] in sharedhosts_secondary_dict.keys():
            for address in addresses:
                # We query for the reverse PTR to get an additional hostnames
                existing_hostnames = []
                if do_fill_in:
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
                        # First attempt to not propigate bad hostnames
                        for badhostname in bad_hostnames:
                            existing_fqdns = [hostname for hostname in existing_fqdns if not hostname.startswith(badhostname)]
                        for fqdn in existing_fqdns:
                            fqdnsplit = fqdn.split('.')
                            hostname = '.'.join(fqdnsplit[:-3])
                            existing_hostnames.append(hostname)
                        if report_findings or len(existing_hostnames) > 1:
                            logdatamessage(f"{address} found {len(existing_hostnames)}: {', '.join(existing_hostnames)}")
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
                if len(hostnames) > 0 and hostnames[0] in sharedhosts_secondary_dict.keys():
                    hostnames = list(set(hostnames + sharedhosts_primary_dict[sharedhosts_secondary_dict[hostnames[0]]]))
                else:
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
        else:
            for hostname in hostnames:
                for address in addresses:
                    if hostname in hostname_to_ips:
                        hostname_to_ips[hostname] = list(set(hostname_to_ips[hostname] + [address]))
                    else:
                        hostname_to_ips.setdefault(hostname, [address])
                    for mac in macs:
                        if mac in mac_to_ips:
                            mac_to_ips[mac] = list(set(mac_to_ips[mac] + [address]))
                        else:
                            mac_to_ips.setdefault(mac, [address])

    for hostname, host_ips in hostname_to_ips.items():
        for host_ip in host_ips:
            for mac, mac_ips in mac_to_ips.items():
                if host_ip in mac_ips:
                    hostname_to_ips[hostname] = list(set(host_ips + mac_ips))
                    if hostname in ipv4_only_hosts:
                        hostname_to_ips[hostname] = [ ip for ip in hostname_to_ips[hostname] if ':' not in ip ]
    if not all_systems_up(redis_client):
        print("One or more systems are not responding. Exiting...")
        return
    logdatamessage(f"Processing DNS updates for {len(hostname_to_ips)} hostnames...")
    try:
        pending_changes = create_dns_updatesv2(hostname_to_ips)
        debug = False
        if debug:
            print("DNS Updates:")
            print(pending_changes)

        number_of_changes = 0
        for change_type, record_type in pending_changes.items():
            for record, items in record_type.items():
                number_of_changes += len(items)

        if number_of_changes > 0:
            logdatamessage("DNS updates created successfully...")
            # Send updates - UNCOMMENT TO EXECUTE
            if not debug:
                if not all_systems_up(redis_client):
                    print("One or more systems are not responding. Exiting...")
                    return
                response = tcp(fwd_update, dns_server)
                logdatamessage(f"Forward update response: {response.rcode()}")

            if not debug:
                for subnet, ptr_update in ptr_updates.items():
                    if not all_systems_up(redis_client):
                        print("One or more systems are not responding. Exiting...")
                        return
                    response = tcp(ptr_update, dns_server)
                    logdatamessage(f"Reverse update response for {subnet}: {response.rcode()}")
            
            redis_logging_client.set(f"hostlistdns:datetimecheck", starttime.strftime("%Y-%m-%dT%H:%M:%S.%f"))
        else:
            logdatamessage("No DNS updates needed.")
    except Exception as e:
        print(f"Error during DNS update: {e}")
        PrintException()

    stoptime = datetime.now()

    if debug:
        pprint(hostname_to_ips)

    for mac, ipaddresses in mac_to_ips_with_no_hostname.items():
        logdatamessage(f"MAC: {mac} has no hostname at all - {','.join(ipaddresses)}")
    
    logdatamessage(f"Done.")

    logmessage = ""
    for line in log_data:
        logmessage+=f"{line}\n"
        #print(line)
    starttimestr = starttime.strftime("%Y-%m-%d:%H-%M-%S.%f")
    redis_logging_client.set(f"hostlistdns:log:{starttimestr}", logmessage)
    redis_logging_client.expire(f"hostlistdns:log:{starttimestr}", 3600)
    redis_logging_client.set(f"hostlistdns:datetimelast", starttimestr)
    redis_logging_client.set(f"hostlistdns:durationseconds", str((stoptime - starttime).total_seconds()))

    redis_client.save()
    redis_client.close()
    redis_logging_client.save()
    redis_logging_client.close()

if __name__ == "__main__":
    main()
