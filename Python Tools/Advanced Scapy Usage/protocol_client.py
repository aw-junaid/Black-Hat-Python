"""
Custom Protocol Client
------------------------
Sends a PING or DATA packet using MyProto and waits for the server's reply.

Run as root/sudo:
    sudo python3 protocol_client.py 127.0.0.1 --type ping
    sudo python3 protocol_client.py 127.0.0.1 --type data --payload "hello world"
"""

import argparse
import random
from scapy.all import IP, UDP, sr1
from custom_protocol import MyProto, MYPROTO_PORT, MSG_PING, MSG_DATA, MSG_TYPE_NAMES


def send_message(target_ip, msg_type, payload=b"", session_id=None, timeout=3):
    if session_id is None:
        session_id = random.randint(1, 0xFFFFFFFF)

    pkt = (
        IP(dst=target_ip)
        / UDP(dport=MYPROTO_PORT)
        / MyProto(
            version=1,
            msg_type=msg_type,
            payload_len=len(payload),
            session_id=session_id,
            payload=payload,
        )
    )

    print(f"[send] -> {target_ip}:{MYPROTO_PORT} session={session_id} "
          f"type={MSG_TYPE_NAMES[msg_type]} payload={payload!r}")

    reply = sr1(pkt, timeout=timeout, verbose=0)

    if reply is None:
        print("[recv] no reply (timeout)")
        return None

    if reply.haslayer(MyProto):
        rmp = reply[MyProto]
        rtype = MSG_TYPE_NAMES.get(rmp.msg_type, "UNKNOWN")
        print(f"[recv] <- session={rmp.session_id} type={rtype} payload={rmp.payload!r}")
        return rmp
    else:
        print("[recv] reply received but not a MyProto packet")
        return None


def main():
    parser = argparse.ArgumentParser(description="MyProto UDP client")
    parser.add_argument("target", help="Server IP address")
    parser.add_argument("--type", choices=["ping", "data"], default="ping")
    parser.add_argument("--payload", default="hello", help="Payload text for --type data")
    args = parser.parse_args()

    if args.type == "ping":
        send_message(args.target, MSG_PING)
    else:
        send_message(args.target, MSG_DATA, payload=args.payload.encode())


if __name__ == "__main__":
    main()
