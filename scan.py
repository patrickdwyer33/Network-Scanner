import sys
import time
import json
import subprocess
import requests

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
    for i in range(0, 3):
        for dns_server in dns_servers_list:
            dns_server = dns_server.split('\n')[0]
            try:
                output = subprocess.check_output(["nslookup", "-type="+type, website_name, dns_server], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                output = output.splitlines()
                output = output[3:]
                for line in output:
                    if line[:8] == "Address:":
                        address = line[9:]
                        address = address.split('\n')[0]
                        result.append(address)
            except TimeoutError:
                print('Timeout Error during nslookup', file=sys.stderr)
            except:
                print('Exception during nslookup routine. Args: ' + type + ', ' + website_name + ', ' + dns_server, file=sys.stderr)
    result = list(set(result))
    return result

def get_server_info(website_name):
    http_server = None
    insecure_http = False
    redirect_to_https = False
    try:
        r = requests.get("http://"+website_name+":80", timeout=2)
        status_code = int(r.status_code)
        http_server = r.headers.get('Server', None)
        if status_code < 400:
            insecure_http = True
        idx = 0
        print(status_code)
        while status_code < 400 and status_code >= 300 and idx < 10:
            idx = idx + 1
            next_loc = r.headers['Location']
            print(next_loc)
            if next_loc[:5] == "https":
                redirect_to_https = True
                break
            r = requests.get(next_loc, timeout=5)
            status_code = int(r.status_code)
    except TimeoutError:
        print('Timeout Error during nslookup', file=sys.stderr)
    except Exception as e:
        print(e)
        print('Exception during server info routine. Args: ' + website_name, file=sys.stderr)
    return (http_server, insecure_http, redirect_to_https)

for website_name in website_list:
    website_name = website_name.split('\n')[0]
    if website_name:
        print(website_name)
        website_data = {}
        website_data["scan_time"] = time.time()
        website_data["ipv4_addresses"] = get_addresses(website_name, "A")
        website_data["ipv6_addresses"] = get_addresses(website_name, "AAAA")
        server_info = get_server_info(website_name)
        website_data["http_server"] = server_info[0]
        website_data["insecure_http"] = server_info[1]
        website_data["redirect_to_https"] = server_info[2]
        output_data[website_name] = website_data

with open(output_file_name, "w") as f:
    json.dump(output_data, f, sort_keys=True, indent=4)
