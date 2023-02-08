import json
import texttable
import sys

assert(len(sys.argv) == 3)

input_file_name = sys.argv[1]
output_file_name = sys.argv[2]

json_file = open(input_file_name)

output_text = ''

data = json.load(json_file)

table1 = texttable.Texttable()

rows1 = []
first_row1 = ["Website", "scan_time", "insecure_http", "http_server", "ipv4_addresses", "ipv6_addresses", "redirect_to_https", "hsts", "tls_versions", "root_ca", "rdns_names", "rtt_range", "geo_locations"]
rows1.append(first_row1)
rtts_data = []
root_list = []
root_count = {}
server_list = []
server_count = {}
tls_versions_count = {}
insecure_http_count = 0
redirect_to_https_count = 0
hsts_count = 0
ipv6_count = 0
for website in data.keys():
    website_info = data[website]
    row = [website]
    for data_key in ["scan_time", "insecure_http", "http_server", "ipv4_addresses", "ipv6_addresses", "redirect_to_https", "hsts", "tls_versions", "root_ca", "rdns_names", "rtt_range", "geo_locations"]:
        info = website_info[data_key]
        if data_key == "rtt_range":
            rtts_data.append([website, info[0], info[1]])
        if data_key == "root_ca":
            info = info.replace('"', '')
            root_list.append(info)
            root_count[info] = root_count.get(info, 0) + 1
        if data_key == "http_server":
            server_list.append(info)
            server_count[info] = server_count.get(info, 0) + 1
        if data_key == "tls_versions":
            for tls in info:
                tls_versions_count[tls] = tls_versions_count.get(tls, 0) + 1
        if data_key == "insecure_http":
            if info:
                insecure_http_count = insecure_http_count + 1
        if data_key == "redirect_to_https":
            if info:
                redirect_to_https_count = redirect_to_https_count + 1
        if data_key == "hsts":
            if info:
                hsts_count = hsts_count + 1
        if data_key == "ipv6_addresses":
            if info:
                ipv6_count = ipv6_count + 1
        row.append(info)
        

        
    rows1.append(row)

table1.add_rows(rows1)

output_text = output_text + table1.draw()

rtts_data.sort(key=lambda x: x[1])
print(rtts_data)

table2 = texttable.Texttable()

first_row2 = ["Website", "min RTT", "max RTT"]

rows2 = [first_row2] + rtts_data

table2.add_rows(rows2)

output_text = output_text + '\n' + table2.draw()

root_list = list(set(root_list))
root_list.sort(key=lambda x: root_count[x], reverse=True)

table3 = texttable.Texttable()

first_row3 = ["Root CA", "Count"]

rows3 = [first_row3]

for root in root_list:
    row = [root, root_count[root]]
    rows3.append(row)

table3.add_rows(rows3)

output_test = output_text + '\n' + table3.draw()

server_list = list(set(server_list))
server_list.sort(key=lambda x: server_count[x], reverse=True)

table4 = texttable.Texttable()

first_row4 = ["Web Server", "Count"]

rows4 = [first_row4]

for server in server_list:
    row = [server, server_count[server]]
    rows4.append(row)

table4.add_rows(rows4)

output_test = output_text + '\n' + table4.draw()

table5 = texttable.Texttable()

first_row5 = ["Attribute", "Percent Supported"]

num_websites = len(data.keys())

rows5 = [first_row5, 
["SSLv2", tls_versions_count.get("SSLv2", 0)/num_websites], 
["SSLv3", tls_versions_count.get("SSLv3", 0)/num_websites], 
["TLSv1.0", tls_versions_count.get("TLSv1.0", 0)/num_websites], 
["TLSv1.1", tls_versions_count.get("TLSv1.1", 0)/num_websites], 
["TLSv1.2", tls_versions_count.get("TLSv1.2", 0)/num_websites], 
["TLSv1.3", tls_versions_count.get("TLSv1.3", 0)/num_websites], 
["plain http", insecure_http_count/num_websites], 
["https redirect", redirect_to_https_count/num_websites], 
["hsts", hsts_count/num_websites],
["ipv6", ipv6_count/num_websites]]

table5.add_rows(rows5)

output_text = output_text + '\n' + table5.draw()

with open(output_file_name, "w") as f:
    f.write(output_text)






