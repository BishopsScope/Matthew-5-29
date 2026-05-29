# This script is to be run through the Control Panel IPv4 127.0.0.1 and IPv6 set to ::1
# The point of this script is to create a log file that contains all of the whitelisted websites
# that I want to be able to visit simply by me visiting them and this script logging which
# domains and subdomains were visited. This is to automate having to look for domains and
# subdomains manually.

### Script 2: dns_whitelist_logger.py ("test mode")
import atexit
import ctypes
import json
import os
import signal
import socket
import sys
import threading
import time
from dnslib.server import DNSServer, BaseResolver, DNSLogger
from dnslib import DNSRecord

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_FILE     = os.path.join(BASE_DIR, 'new_whitelisted_domains.json')
UPSTREAM_DNS = '8.8.8.8'
UPSTREAM_PORT = 53

# ─────────────────────────────────────────────────────────────────────────────
# Shared state
# ─────────────────────────────────────────────────────────────────────────────

domains: set[str] = set()
lock    = threading.Lock()

# Event set by the resolver whenever a domain that wasn't seen before arrives.
# The persist thread wakes on this event and writes within ~150 ms.
_dirty  = threading.Event()

# ─────────────────────────────────────────────────────────────────────────────
# Persistence helpers
# ─────────────────────────────────────────────────────────────────────────────

def _save() -> None:
    """Write the current domain snapshot to LOG_FILE.

    Uses a write-to-temp-then-replace strategy so the file is never left in a
    partially-written (corrupt) state if the process is killed mid-write.
    """
    with lock:
        snapshot = sorted(domains)
    tmp = LOG_FILE + ".tmp"
    try:
        with open(tmp, 'w') as f:
            json.dump(snapshot, f, indent=2)
        os.replace(tmp, LOG_FILE)
    except Exception:
        pass   # never let a write error crash the DNS server


def persist_loop() -> None:
    """Background thread: wakes immediately when a new domain is logged and
    writes within ~150 ms (short debounce to batch an entire page-load worth
    of DNS queries into a single write rather than one write per query).

    Previous behaviour: sleep(30) — meaning up to 30 s of data could be lost
    if the process was closed before the next scheduled write.
    New behaviour: write within 150 ms of the first new domain.
    """
    while True:
        _dirty.wait()          # block until the resolver sees a new domain
        _dirty.clear()
        time.sleep(0.15)       # brief debounce — gather the rest of this page load
        _dirty.clear()         # discard events that fired during the debounce
        _save()

# ─────────────────────────────────────────────────────────────────────────────
# Exit-path coverage
#
# Ctrl+C  →  SIGINT  →  KeyboardInterrupt  →  caught below in __main__
# sys.exit / end of script  →  atexit handlers
# kill / task-manager End Process  →  SIGTERM  →  signal handler below
# Console X-button (Windows)  →  CTRL_CLOSE_EVENT  →  SetConsoleCtrlHandler
# ─────────────────────────────────────────────────────────────────────────────

atexit.register(_save)

def _signal_handler(sig, frame):
    _save()
    sys.exit(0)

signal.signal(signal.SIGINT,  _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)

if sys.platform == "win32":
    # Register a Windows console-control handler so that clicking the X button
    # (which sends CTRL_CLOSE_EVENT = 2) triggers a final save before the
    # process is terminated.
    #
    # Python's own signal machinery only handles SIGINT (Ctrl+C) and, on some
    # builds, SIGBREAK (Ctrl+Break).  The CTRL_CLOSE_EVENT fired by the X
    # button is invisible to Python's signal module, which is why Ctrl+C saved
    # the file but the X button did not.
    _HandlerType = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)

    def _win_ctrl_handler(event: int) -> bool:
        # event values: 0=CTRL_C, 1=CTRL_BREAK, 2=CTRL_CLOSE,
        #               5=CTRL_LOGOFF, 6=CTRL_SHUTDOWN
        _save()
        return False  # False = let the default handler run (terminates the process)

    _win_handler_ref = _HandlerType(_win_ctrl_handler)   # keep reference alive
    ctypes.windll.kernel32.SetConsoleCtrlHandler(_win_handler_ref, True)

# ─────────────────────────────────────────────────────────────────────────────
# DNS resolver
# ─────────────────────────────────────────────────────────────────────────────

class LoggerResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.').lower()

        is_new = False
        with lock:
            if qname not in domains:
                domains.add(qname)
                is_new = True

        if is_new:
            # Wake the persist thread so it writes within ~150 ms.
            # This replaces the old 30-second polling interval.
            _dirty.set()

        # Forward the query upstream regardless of whether it was new
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(4)
            sock.sendto(request.pack(), (UPSTREAM_DNS, UPSTREAM_PORT))
            data, _ = sock.recvfrom(512)
            return DNSRecord.parse(data)
        except Exception:
            return request.reply()

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    # Clear any previous session
    with open(LOG_FILE, 'w') as f:
        json.dump([], f)
    domains.clear()

    # Start the immediate-persist background thread
    threading.Thread(target=persist_loop, daemon=True).start()

    resolver = LoggerResolver()
    logger   = DNSLogger(prefix=True)
    server_udp = DNSServer(resolver, port=53, address='0.0.0.0', tcp=False, logger=logger)
    server_tcp = DNSServer(resolver, port=53, address='0.0.0.0', tcp=True,  logger=logger)
    server_udp.start_thread()
    server_tcp.start_thread()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _save()
