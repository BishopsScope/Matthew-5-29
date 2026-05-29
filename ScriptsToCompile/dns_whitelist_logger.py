# This script is to be run through the Control Panel IPv4 127.0.0.1 and IPv6 set to ::1
# The point of this script is to create a log file that contains all of the whitelisted websites
# that I want to be able to visit simply by me visiting them and this script logging which
# domains and subdomains were visited. This is to automate having to look for domains and
# subdomains manually.

### Script 2: dns_whitelist_logger.py ("test mode")
import os, json, socket, time, threading, sys
from dnslib.server import DNSServer, BaseResolver, DNSLogger
from dnslib import DNSRecord

# Determine base directory (folder containing the .exe or .py)
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_FILE = os.path.join(BASE_DIR, 'new_whitelisted_domains.json')
UPSTREAM_DNS = '8.8.8.8'
UPSTREAM_PORT = 53

domains = set()
lock = threading.Lock()

class LoggerResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.').lower()
        with lock:
            domains.add(qname)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(4)
            sock.sendto(request.pack(), (UPSTREAM_DNS, UPSTREAM_PORT))
            data, _ = sock.recvfrom(512)
            return DNSRecord.parse(data)
        except:
            return request.reply()

def persist_loop():
    while True:
        time.sleep(30)
        with lock:
            with open(LOG_FILE, 'w') as f:
                json.dump(sorted(domains), f, indent=2)

if __name__ == '__main__':
    # Clear any previous logs
    with open(LOG_FILE, 'w') as f:
        json.dump([], f)
    domains.clear()

    resolver = LoggerResolver()
    logger = DNSLogger(prefix=True)
    server_udp = DNSServer(resolver, port=53, address='0.0.0.0', tcp=False, logger=logger)
    server_tcp = DNSServer(resolver, port=53, address='0.0.0.0', tcp=True, logger=logger)
    server_udp.start_thread()
    server_tcp.start_thread()
    threading.Thread(target=persist_loop, daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        with lock:
            with open(LOG_FILE, 'w') as f:
                json.dump(sorted(domains), f, indent=2)