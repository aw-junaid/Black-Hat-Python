"""
Custom Protocol Server
-----------------------
Listens for MyProto packets over UDP and replies:
    PING -> PONG
    DATA -> ACK

Run as root/sudo (Scapy sniff needs raw socket access):
    sudo python3 protocol_server.py --iface lo
"""

import argparse
from scapy.all import sniff, send, IP, UDP
from custom_protocol import MyProto, MYPROTO_PORT, MSG_PING, MSG_PONG, MSG_DATA, MSG_ACK, MSG_TYPE_NAMES


def handle_packet(pkt):
    if not pkt.haslayer(MyProto):
        return

    mp = pkt[MyProto]
    src_ip = pkt[IP].src
    src_port = pkt[UDP].sport
    msg_name = MSG_TYPE_NAMES.get(mp.msg_type, "UNKNOWN")

    print(f"[recv] {src_ip}:{src_port} session={mp.session_id} type={msg_name} payload={mp.payload!r}")

    if mp.msg_type == MSG_PING:
        reply_payload = b"pong"
        reply_type = MSG_PONG
    elif mp.msg_type == MSG_DATA:
        reply_payload = b"received " + str(len(mp.payload)).encode() + b" bytes"
        reply_type = MSG_ACK
    else:
        return  # nothing to reply to

    reply = (
        IP(dst=src_ip)
        / UDP(sport=MYPROTO_PORT, dport=src_port)
        / MyProto(
            version=1,
            msg_type=reply_type,
            payload_len=len(reply_payload),
            session_id=mp.session_id,
            payload=reply_payload,
        )
    )
    send(reply, verbose=0)
    print(f"[sent] -> {src_ip}:{src_port} type={MSG_TYPE_NAMES[reply_type]} payload={reply_payload!r}")


def main():
    parser = argparse.ArgumentParser(description="MyProto UDP server")
    parser.add_argument("--iface", default=None, help="Interface to listen on (default: Scapy's default)")
    args = parser.parse_args()

    print(f"Listening for MyProto traffic on UDP/{MYPROTO_PORT} (Ctrl+C to stop)...")
    sniff(
        filter=f"udp port {MYPROTO_PORT}",
        prn=handle_packet,
        iface=args.iface,
        store=False,
    )


if __name__ == "__main__":
    main()
