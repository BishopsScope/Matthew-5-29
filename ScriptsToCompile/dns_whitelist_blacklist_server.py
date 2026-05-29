# To compile, run: pyinstaller --clean --onedir dns_whitelist_blacklist_server__vXX.py

import os, json, socket, time, sys, threading
from datetime import datetime, timedelta, timezone
from dnslib.server import DNSServer, BaseResolver, DNSLogger
from dnslib import RR, QTYPE, A, AAAA, DNSRecord

# ── Base directory (folder containing the .exe or .py) ───────────────────────
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── File paths ────────────────────────────────────────────────────────────────
WHITELIST_FILE      = os.path.join(BASE_DIR, 'whitelisted_domains.json')
BLACKLIST_FILE      = os.path.join(BASE_DIR, 'blacklisted_domains.json')
METRICS_FILE        = os.path.join(BASE_DIR, 'domain_access_log.json')
DELETION_FILE       = os.path.join(BASE_DIR, 'domains_to_be_deleted.json')
UPSTREAM_DNS_FILE   = os.path.join(BASE_DIR, 'UPSTREAM_DNS.txt')
THRESHOLD_DAYS_FILE = os.path.join(BASE_DIR, 'THRESHOLD_DAYS.txt')

# ── Hard-coded defaults (written to disk on first run if files are absent) ────
_DEFAULT_UPSTREAM_DNS   = '8.8.8.8'
_DEFAULT_THRESHOLD_DAYS = 7

# ── Read or create UPSTREAM_DNS.txt ──────────────────────────────────────────
if not os.path.exists(UPSTREAM_DNS_FILE):
    with open(UPSTREAM_DNS_FILE, 'w') as _f:
        _f.write(_DEFAULT_UPSTREAM_DNS)
    UPSTREAM_DNS = _DEFAULT_UPSTREAM_DNS
else:
    _val = open(UPSTREAM_DNS_FILE).read().strip()
    UPSTREAM_DNS = _val if _val else _DEFAULT_UPSTREAM_DNS

# ── Read or create THRESHOLD_DAYS.txt ────────────────────────────────────────
if not os.path.exists(THRESHOLD_DAYS_FILE):
    with open(THRESHOLD_DAYS_FILE, 'w') as _f:
        _f.write(str(_DEFAULT_THRESHOLD_DAYS))
    THRESHOLD_DAYS = _DEFAULT_THRESHOLD_DAYS
else:
    try:
        THRESHOLD_DAYS = int(open(THRESHOLD_DAYS_FILE).read().strip())
    except Exception:
        THRESHOLD_DAYS = _DEFAULT_THRESHOLD_DAYS

UPSTREAM_PORT  = 53
CUSTOM_ENTRIES = {}

# ── Ensure blacklisted_domains.json exists ────────────────────────────────────
if not os.path.exists(BLACKLIST_FILE):
    with open(BLACKLIST_FILE, 'w') as _f:
        json.dump([], _f)

# ── Thread lock protecting all access to the metrics dict and its file ────────
# Both the TCP and UDP DNS servers call resolve() from separate threads.
# Without this lock, two simultaneous requests can interleave their dict writes
# and their file writes, causing corruption.  All code that reads OR writes
# `metrics` at runtime must hold this lock.
_metrics_lock = threading.Lock()

# ── Atomic metrics file writer ────────────────────────────────────────────────
# The old save_metrics() opened the file with 'w' (which truncates immediately)
# and then wrote the JSON.  If the process was killed mid-write — which happens
# every time the Task Scheduler restarts the server — the file was left as a
# partial or empty blob.  On the next startup json.load() would throw, metrics
# would reset to {}, and every domain would get a fresh timestamp.
#
# os.replace() is an atomic rename on both Windows and POSIX: the destination
# file switches from old→new in a single OS call with no window where a reader
# can see a half-written file.  A kill signal between the temp-write and the
# replace leaves the original file fully intact.
def save_metrics():
    """Write metrics to disk atomically (temp file → os.replace).

    Must be called while _metrics_lock is held so the snapshot is consistent.
    """
    tmp = METRICS_FILE + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(metrics, f, indent=2)
        os.replace(tmp, METRICS_FILE)
    except Exception:
        # Best-effort cleanup of the temp file; don't crash the server
        try:
            os.remove(tmp)
        except Exception:
            pass

# ── Load whitelist ────────────────────────────────────────────────────────────
try:
    with open(WHITELIST_FILE) as f:
        raw_whitelist = json.load(f)
        WHITELIST = set(raw_whitelist)
except Exception:
    WHITELIST = set()

# ── Load blacklist ────────────────────────────────────────────────────────────
try:
    with open(BLACKLIST_FILE) as f:
        raw_blacklist = json.load(f)
        BLACKLIST = set(raw_blacklist)
except Exception:
    BLACKLIST = set()

# ── Load or initialize metrics ────────────────────────────────────────────────
# First try to load from the primary file, then fall back to the temp file left
# by a previous atomic write that was interrupted before os.replace() ran.
def _load_metrics_from_disk() -> dict:
    for path in (METRICS_FILE, METRICS_FILE + '.tmp'):
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception:
            continue
    return {}

metrics = _load_metrics_from_disk()

# Clean metrics: only keep entries that match current whitelist exactly
metrics = {dom: ts for dom, ts in metrics.items() if dom in WHITELIST}

# Ensure every whitelisted domain has an initial timestamp.
# Each missing domain gets its own datetime.now() so no two domains share the
# same startup timestamp (sharing a timestamp made it look like the whole file
# updated whenever any single domain was resolved).
for dom in WHITELIST:
    if dom not in metrics:
        metrics[dom] = datetime.now(timezone.utc).isoformat()

# Startup save: no threads are running yet so no lock is needed here.
save_metrics()

# ── Compute deletion list at startup ──────────────────────────────────────────
def compute_deletions(current_metrics):
    deletions = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=THRESHOLD_DAYS)
    for dom, ts in current_metrics.items():
        try:
            last = datetime.fromisoformat(ts)
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            if last < cutoff:
                deletions.append(dom)
        except ValueError:
            deletions.append(dom)
    tmp = DELETION_FILE + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(sorted(deletions), f, indent=2)
        os.replace(tmp, DELETION_FILE)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass

compute_deletions(metrics)


class WhitelistResolver(BaseResolver):
    def resolve(self, request, _handler):
        qname = str(request.q.qname).rstrip('.').lower()
        reply = request.reply()

        # Custom entries (read-only at runtime, no lock needed)
        if qname in CUSTOM_ENTRIES:
            ip = CUSTOM_ENTRIES[qname]
            if ':' in ip:
                reply.add_answer(RR(qname + '.', QTYPE.AAAA, rdata=AAAA(ip), ttl=60))
            else:
                reply.add_answer(RR(qname + '.', QTYPE.A,    rdata=A(ip),    ttl=60))
            return reply

        # Blacklisted: deny immediately (BLACKLIST is read-only at runtime)
        if self.match_list(qname, BLACKLIST):
            reply.header.rcode = 3
            return reply

        # Whitelisted: forward upstream and log the access timestamp
        matched = self.match_list(qname, WHITELIST)
        if matched:
            # Hold the lock for the dict write + atomic file save together.
            # This prevents two simultaneous requests from interleaving their
            # writes and ensures the file on disk is always a consistent snapshot.
            with _metrics_lock:
                metrics[matched] = datetime.now(timezone.utc).isoformat()
                save_metrics()

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(4)
                sock.sendto(request.pack(), (UPSTREAM_DNS, UPSTREAM_PORT))
                data, _ = sock.recvfrom(512)
                return DNSRecord.parse(data)
            except Exception:
                reply.header.rcode = 2
                return reply

        # Block everything else
        reply.header.rcode = 3
        return reply

    def match_list(self, domain, domain_list):
        """Return the matching entry (exact or wildcard) from domain_list, or None."""
        d = domain
        if d.startswith('www.'):
            d = d[4:]
        if d in domain_list:
            return d
        for entry in domain_list:
            if entry.startswith('*.'):
                base = entry[2:]
                if d.endswith(base) and d != base:
                    return entry
        return None


if __name__ == '__main__':
    resolver   = WhitelistResolver()
    logger     = DNSLogger(prefix=True)
    server_tcp = DNSServer(resolver, port=53, address='0.0.0.0', tcp=True,  logger=logger)
    server_udp = DNSServer(resolver, port=53, address='0.0.0.0', tcp=False, logger=logger)
    server_tcp.start_thread()
    server_udp.start_thread()
    print(f"DNS server running — upstream: {UPSTREAM_DNS}  threshold: {THRESHOLD_DAYS} days")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        with _metrics_lock:
            save_metrics()
