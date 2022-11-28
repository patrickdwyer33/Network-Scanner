import sys
import time
import json
import subprocess
from subprocess import TimeoutExpired
import socket
import http.client as http_client

assert(len(sys.argv) == 3)

input_file_name = sys.argv[1]
output_file_name = sys.argv[2]

input_file = open(input_file_name, "r")
dns_servers_file = open(r"public_dns_servers.txt", "r")

dns_servers_list = dns_servers_file.readlines()
website_list = input_file.readlines()

output_data = {}

def get_addresses(website_name, type):
    result = []
    for dns_server in dns_servers_list:
        for i in range(0, 3):
            dns_server = dns_server.split('\n')[0]
            output = None
            try:
                output = subprocess.check_output(["nslookup", "-type="+type, website_name, dns_server], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            except TimeoutExpired:
                print('Timeout Error during nslookup', file=sys.stderr)
                break
            except:
                print('Exception during nslookup routine. Args: ' + type + ', ' + website_name + ', ' + dns_server, file=sys.stderr)
            if output is not None:
                output = output.splitlines()
                output = output[3:]
                for line in output:
                    if line[:8] == "Address:":
                        address = line[9:]
                        address = address.split('\n')[0]
                        result.append(address)
    result = list(set(result))
    return result

def get_insecure_http_bool(website_name):
    http_server = None
    insecure_http = False
    redirect_to_https = False
    try:
        host_info = socket.getaddrinfo(host=website_name, port=80, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
        connection = host_info[0][4]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.setblocking(True)
        sock.connect(connection)
        return True
    except TimeoutError:
        return False
    except Exception as e:
        print(e)
        print('Non TimeoutError exception during get_insecure_http_bool routing. Args: ' + website_name, file=sys.stderr)
        return False
    
def get_hsts(website_name):
    try:
        conn = http_client.HTTPSConnection(website_name, port=443)
        conn.request("GET", "/", body=None, headers={})
        response = conn.getresponse()
        hsts_val = response.getheader('strict-transport-security', default=None)
        if hsts_val is not None:
            return True
        else:
            return False
    except Exception as e:
        print(e)
        print("Exception during get_hsts. Args: " + website_name)
    return False


def get_server_info(website_name, idx):
    http_server = None
    insecure_http = False
    redirect_to_https = False
    hsts = False
    if idx >= 10:
        return (http_server, insecure_http, redirect_to_https, hsts)
    conn = None
    try:
        conn = http_client.HTTPConnection(website_name, 80, timeout=2)
        insecure_http = True
    except Exception as e:
        print(e)
        print('Exception during server info routine. Args: ' + website_name, file=sys.stderr)
        return (http_server, insecure_http, redirect_to_https)
    try:
        if conn is not None:
            conn.request("GET", "/", body=None, headers={})
            response = conn.getresponse()
            status_code = int(response.status)
            http_server = response.getheader("Server", default=None)
            if status_code >= 400:
                return (http_server, insecure_http, redirect_to_https, hsts)
            if status_code >= 300:
                idx = idx + 1
                next_loc = response.getheader("Location", default=None)
                if next_loc is None:
                    return (http_server, insecure_http, redirect_to_https, hsts)
                elif next_loc.split(':')[0] == "https":
                    redirect_to_https = True
                    hsts = get_hsts(next_loc)
                    return (http_server, insecure_http, redirect_to_https, hsts)
                else:
                    redirect_to_https = get_server_info(next_loc, idx+1)[2]
    except Exception as e:
        print(e)
        print('Exception during server info routine. Args: ' + website_name, file=sys.stderr)
    return (http_server, insecure_http, redirect_to_https, hsts)

for website_name in website_list:
    website_name = website_name.split('\n')[0]
    if website_name:
        print(website_name)
        website_data = {}
        website_data["scan_time"] = time.time()
        website_data["ipv4_addresses"] = get_addresses(website_name, "A")
        website_data["ipv6_addresses"] = get_addresses(website_name, "AAAA")
        server_info = get_server_info(website_name, 0)
        website_data["http_server"] = server_info[0]
        website_data["insecure_http"] = get_insecure_http_bool(website_name)
        website_data["redirect_to_https"] = server_info[2]
        output_data[website_name] = website_data

with open(output_file_name, "w") as f:
    json.dump(output_data, f, sort_keys=True, indent=4)
