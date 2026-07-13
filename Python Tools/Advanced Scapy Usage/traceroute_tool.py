"""
Traceroute with Scapy
-----------------------
Two ways to trace a route:
  1. custom_traceroute() — manual TTL-increment loop, shows the mechanics
  2. builtin_traceroute() — Scapy's own traceroute() helper, faster and
     also builds a result object you can graph

Run as root/sudo:
    sudo python3 traceroute_tool.py 8.8.8.8
    sudo python3 traceroute_tool.py 8.8.8.8 --builtin
"""

import argparse
from scapy.all import IP, ICMP, UDP, sr1, traceroute


def custom_traceroute(target_ip, max_hops=30, timeout=2):
    print(f"Tracing route to {target_ip} (manual, max {max_hops} hops)\n")
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target_ip, ttl=ttl) / UDP(dport=33434)
        reply = sr1(pkt, timeout=timeout, verbose=0)

        if reply is None:
            print(f"{ttl:>3}\t*\t\trequest timed out")
            continue

        hop_ip = reply.src

        if reply.haslayer(ICMP):
            icmp_type = reply.getlayer(ICMP).type
            if icmp_type == 11:  # Time Exceeded -> intermediate hop
                print(f"{ttl:>3}\t{hop_ip}")
            elif icmp_type == 3:  # Destination Unreachable -> arrived
                print(f"{ttl:>3}\t{hop_ip}\t(destination reached)")
                break
        elif reply.src == target_ip:
            print(f"{ttl:>3}\t{hop_ip}\t(destination reached)")
            break


def builtin_traceroute(target_ip, max_hops=20):
    print(f"Tracing route to {target_ip} (Scapy built-in, max {max_hops} hops)\n")
    result, unanswered = traceroute(target_ip, maxttl=max_hops, verbose=0)
    result.show()
    print(f"\n{len(unanswered)} unanswered probe(s)")
    return result


def main():
    parser = argparse.ArgumentParser(description="Traceroute using Scapy")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("--max-hops", type=int, default=30)
    parser.add_argument("--builtin", action="store_true", help="Use Scapy's built-in traceroute() instead")
    args = parser.parse_args()

    if args.builtin:
        builtin_traceroute(args.target, max_hops=args.max_hops)
    else:
        custom_traceroute(args.target, max_hops=args.max_hops)


if __name__ == "__main__":
    main()
