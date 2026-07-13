"""
Custom Protocol Definition
---------------------------
Defines MyProto, a toy binary protocol layered on top of UDP port 9999.
Import this module from both the server and client so they share one
definition of the wire format.

Wire format:
    version      : 1 byte
    msg_type     : 1 byte   (0=PING, 1=PONG, 2=DATA, 3=ACK)
    payload_len  : 2 bytes  (big-endian, auto length of payload)
    session_id   : 4 bytes  (big-endian)
    payload      : variable, length = payload_len
"""

from scapy.all import Packet, ByteField, ShortField, IntField, StrLenField, bind_layers, UDP

MYPROTO_PORT = 9999

MSG_PING = 0
MSG_PONG = 1
MSG_DATA = 2
MSG_ACK = 3

MSG_TYPE_NAMES = {MSG_PING: "PING", MSG_PONG: "PONG", MSG_DATA: "DATA", MSG_ACK: "ACK"}


class MyProto(Packet):
    name = "MyProto"
    fields_desc = [
        ByteField("version", 1),
        ByteField("msg_type", MSG_PING),
        ShortField("payload_len", 0),
        IntField("session_id", 0),
        StrLenField("payload", b"", length_from=lambda pkt: pkt.payload_len),
    ]

    def pre_dissect(self, s):
        return s

    def post_build(self, pkt, pay):
        # auto-fill payload_len if the caller didn't set it explicitly
        if self.payload_len == 0 and self.payload:
            length = len(self.payload)
            pkt = pkt[:2] + length.to_bytes(2, "big") + pkt[4:]
        return pkt + pay


# Bind the custom layer on top of UDP whenever either port matches 9999,
# so Scapy auto-dissects it for both directions of traffic.
bind_layers(UDP, MyProto, dport=MYPROTO_PORT)
bind_layers(UDP, MyProto, sport=MYPROTO_PORT)
