import sys
import time
import json
import subprocess
from subprocess import TimeoutExpired
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
                print(dns_server)
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
    
def get_hsts(website_name):
    hsts = False
    website_name = website_name[8:]
    len_name = len(website_name)
    if website_name[-1] == "/":
        if len_name > 1:
            website_name = website_name[:len_name-1]
            len_name = len_name - 1
    website_name = website_name.split(':')[0]
    try:
        output = subprocess.check_output(["openssl", "s_client", "-crlf", "-connect", website_name+":443"], 
            input=b'GET / HTTP1.0\r\nHost: "+website_name+"\r\n\r\n',timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        output_sections = output.split('---')
        response = output_sections[-1]
        for line in response.splitlines():
            line2 = line.split(':')[0].strip()
            if line2 == 'strict-transport-security':
                hsts = True
    except Exception as e:
        print(e)
        print("Exception during get_hsts. Args: " + website_name, file=sys.stderr)
    return hsts


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

possible_tls_versions = set(["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2"])

def get_tls_versions_info(website_name):
    tls_versions = []
    try:
        output = subprocess.check_output(["nmap", "--script", "ssl-enum-ciphers", "-p", "443", website_name], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        output_lines = output.splitlines()
        for line in output_lines:
            line2 = line.split(':')[0]
            bar_split = line2.split('|')
            if len(bar_split) <= 1:
                continue
            line2 = bar_split[1]
            line2 = line2.strip()
            if line2 in possible_tls_versions:
                tls_versions.append(line2)
    except Exception as e:
        print(e)
        print('Exception during tls versions info routine. Args: ' + website_name, file=sys.stderr)
        print('first exception')
    try:
        output = subprocess.check_output(["openssl", "s_client", "-tls1_3", "-connect", website_name+":443"], input=b'', timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        output_sections = output.split('---')
        server_certificate_section = output_sections[2]
        for line in server_certificate_section.splitlines():
            line2 = line.strip()
            if line2 == "Server certificate":
                tls_versions.append("TLSv1.3")
                break
    except Exception as e:
        print(e)
        print('Exception during tls versions info routine. Args: ' + website_name, file=sys.stderr)
        print('second exception')
    return tls_versions

def get_root_ca(website_name):
    root_ca = None
    try:
        output = subprocess.check_output(["openssl", "s_client", "-connect", website_name+":443"], input=b'', timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        output_sections = output.split('---')
        certificate_chain_section = output_sections[1].splitlines()
        assert(certificate_chain_section != '')
        last_idx = -1
        last_line = certificate_chain_section[-1]
        while last_line == '' or last_line == '\n':
            last_idx = last_idx - 1
            last_line = certificate_chain_section[last_idx]
        values = last_line.split(',')
        for val in values:
            val = val.strip()
            if len(val.split(':')) > 1:
                val = val.split(':')[1]
            if len(val) == 0:
                continue
            if val[0] == "O" and val[1] == " ":
                root_ca = val[4:]
    except Exception as e:
        print(e)
        print('Exception during get_root_ca routine. Args: ' + website_name, file=sys.stderr)
    return root_ca

def get_rdns_names(ipaddr):
    result = []
    try:
        output = subprocess.check_output(["nslookup", ipaddr], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        for line in output.splitlines():
            splitted = line.split(' ')[-1]
            try:
                if splitted[-3] == "name":
                    name = splitted[-1]
                    name = name[:len(name)-1]
                    result.append(name)
            except:
                pass
    except TimeoutExpired:
        print('Timeout Error during reverse nslookup', file=sys.stderr)
    except:
        print('Exception during reverse nslookup routine. Args: ' + ipaddr, file=sys.stderr)
    return result

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
        website_data["insecure_http"] = server_info[1]
        website_data["redirect_to_https"] = server_info[2]
        website_data["hsts"] = server_info[3]
        website_data["tls_versions"] = get_tls_versions_info(website_name)
        website_data["root_ca"] = get_root_ca(website_name)
        rdns_names = []
        for ipaddr in website_data["ipv4_addresses"]:
            rdns_names = rdns_names + get_rdns_names(ipaddr)
        website_data["rdns_names"] = rdns_names
        output_data[website_name] = website_data

with open(output_file_name, "w") as f:
    json.dump(output_data, f, sort_keys=True, indent=4)
