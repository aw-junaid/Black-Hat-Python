"""
Threaded TCP SYN Scanner
------------------------
Faster version of the basic SYN scan — uses a thread pool so many ports
are probed concurrently instead of one sr1() call at a time.

Run as root/sudo (raw sockets required):
    sudo python3 syn_scan.py 192.168.1.1 --ports 1-1000
    sudo python3 syn_scan.py 192.168.1.1 --ports 22,80,443,8080
"""

import argparse
import threading
from queue import Queue
from scapy.all import IP, TCP, sr1, conf

conf.verb = 0  # silence Scapy's own logging globally

results = {}
results_lock = threading.Lock()


def parse_ports(port_str):
    """Accepts '1-1000' or '22,80,443' or a mix like '22,80,1000-1010'."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def syn_probe(target_ip, port, timeout):
    pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None:
        return "filtered"
    if resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        if flags == 0x12:  # SYN-ACK -> open
            rst = IP(dst=target_ip) / TCP(dport=port, flags="R", seq=resp[TCP].ack)
            sr1(rst, timeout=1, verbose=0)
            return "open"
        elif flags == 0x14:  # RST-ACK -> closed
            return "closed"
    elif resp.haslayer(__import__("scapy.all", fromlist=["ICMP"]).ICMP):
        return "filtered"
    return "unknown"


def worker(target_ip, timeout, q):
    while True:
        try:
            port = q.get_nowait()
        except Exception:
            return
        state = syn_probe(target_ip, port, timeout)
        with results_lock:
            results[port] = state
        q.task_done()


def threaded_scan(target_ip, ports, threads=50, timeout=2):
    q = Queue()
    for p in ports:
        q.put(p)

    workers = []
    for _ in range(min(threads, len(ports)) or 1):
        t = threading.Thread(target=worker, args=(target_ip, timeout, q), daemon=True)
        t.start()
        workers.append(t)

    q.join()
    return results


def main():
    parser = argparse.ArgumentParser(description="Threaded TCP SYN scanner")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--ports", default="1-1024", help="Port range/list, e.g. 1-1000 or 22,80,443")
    parser.add_argument("--threads", type=int, default=50, help="Concurrent worker threads")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-probe timeout in seconds")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    print(f"Scanning {args.target} — {len(ports)} ports, {args.threads} threads\n")

    res = threaded_scan(args.target, ports, threads=args.threads, timeout=args.timeout)

    for port in sorted(res):
        state = res[port]
        if state == "open":
            print(f"{port:>6}/tcp  OPEN")
    print()
    open_count = sum(1 for s in res.values() if s == "open")
    closed_count = sum(1 for s in res.values() if s == "closed")
    filtered_count = sum(1 for s in res.values() if s == "filtered")
    print(f"Summary: {open_count} open, {closed_count} closed, {filtered_count} filtered")


if __name__ == "__main__":
    main()
