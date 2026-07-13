# Scapy Networking Toolkit

A small collection of Scapy-based scripts covering four core low-level networking techniques:

| File | Purpose |
|---|---|
| `syn_scan.py` | Threaded TCP SYN (half-open) port scanner |
| `os_fingerprint.py` | Heuristic OS guessing from TTL / window size / TCP options |
| `custom_protocol.py` | Shared definition of a custom binary protocol (`MyProto`) over UDP |
| `protocol_server.py` | Server that listens for and replies to `MyProto` packets |
| `protocol_client.py` | Client that sends `MyProto` packets (PING / DATA) |
| `traceroute_tool.py` | Manual and Scapy-built-in traceroute implementations |

---

## Requirements

```bash
pip install scapy --break-system-packages
```

All scripts need **raw socket access**, so run everything with `sudo` (Linux/macOS) or an Administrator shell (Windows, with Npcap installed).

Tested with Python 3.10+ and Scapy 2.5+.

---

## 1. TCP SYN Scan — `syn_scan.py`

Sends a SYN to each target port and inspects the response, without completing the TCP handshake ("half-open" scan). Uses a thread pool so many ports can be probed concurrently.

**Usage:**
```bash
sudo python3 syn_scan.py 192.168.1.1 --ports 1-1024
sudo python3 syn_scan.py 192.168.1.1 --ports 22,80,443,8080 --threads 100
```

**Flags:**
- `--ports` — range (`1-1000`), list (`22,80,443`), or mix (`22,80,1000-1010`). Default `1-1024`.
- `--threads` — concurrent worker threads. Default `50`.
- `--timeout` — seconds to wait per probe. Default `2.0`.

**How it interprets responses:**
| Response | Port state |
|---|---|
| SYN-ACK (flags `0x12`) | open (Scapy sends a RST afterward to close cleanly) |
| RST-ACK (flags `0x14`) | closed |
| ICMP error / no reply | filtered |

---

## 2. OS Fingerprinting — `os_fingerprint.py`

Sends one crafted SYN probe with common TCP options (MSS, Window Scale, Timestamp, SACK) and guesses the target OS family from the reply's TTL, window size, and option set.

**Usage:**
```bash
sudo python3 os_fingerprint.py 192.168.1.1
sudo python3 os_fingerprint.py 192.168.1.1 --port 443
```

**What it looks at:**
- **TTL** — rounded up to the nearest common initial value (64 = Linux/Unix/macOS, 128 = Windows, 255 = network gear/older Unix). The observed TTL is `initial_TTL - hops`, so this is a rough estimate, not an exact match.
- **Window size** and **TCP option ordering** — secondary signal on stack type.

This is a teaching tool, not a replacement for `nmap -O` or `p0f`, which match against databases of thousands of real-world stack signatures.

---

## 3. Custom Protocol Crafting — `custom_protocol.py` + client/server

Defines a toy binary protocol (`MyProto`) layered on UDP port 9999, then demonstrates it with a working client and server.

**Wire format:**
```
version      1 byte
msg_type     1 byte    (0=PING, 1=PONG, 2=DATA, 3=ACK)
payload_len  2 bytes   big-endian
session_id   4 bytes   big-endian
payload      variable  (length = payload_len)
```

**Try it locally (two terminals):**

Terminal 1 — start the server:
```bash
sudo python3 protocol_server.py --iface lo
```

Terminal 2 — send messages:
```bash
sudo python3 protocol_client.py 127.0.0.1 --type ping
sudo python3 protocol_client.py 127.0.0.1 --type data --payload "hello world"
```

Expected exchange:
```
client: PING  -> server
server: PONG  -> client

client: DATA "hello world" -> server
server: ACK "received 11 bytes" -> client
```

To adapt this for your own protocol: edit `fields_desc` in `custom_protocol.py` (add/remove `ByteField`, `ShortField`, `IntField`, `StrLenField`, `BitField`, etc.), then both client and server automatically pick up the new format since they import from the same module.

---

## 4. Traceroute — `traceroute_tool.py`

Two implementations:
- **Manual** (`custom_traceroute`) — increments TTL from 1 upward, sends a UDP probe, and reads back ICMP Time Exceeded / Destination Unreachable messages. Shows exactly what a traceroute does under the hood.
- **Built-in** (`builtin_traceroute`) — wraps Scapy's own `traceroute()`, which is faster (sends all TTLs concurrently) and returns a result object you can call `.graph()` on if `graphviz` is installed.

**Usage:**
```bash
sudo python3 traceroute_tool.py 8.8.8.8
sudo python3 traceroute_tool.py 8.8.8.8 --builtin
sudo python3 traceroute_tool.py 8.8.8.8 --max-hops 15
```

---

## Common Scapy Flag Reference

Useful when reading raw TCP responses in any of these scripts:

| Hex | Flags | Meaning |
|---|---|---|
| `0x02` | SYN | Connection request |
| `0x12` | SYN-ACK | Port open, handshake offered |
| `0x14` | RST-ACK | Port closed |
| `0x04` | RST | Connection reset |
| `0x18` | PSH-ACK | Data push |

---

## Legal / Scope Notice

Only run these scripts against:
- Hosts and networks you own, **or**
- Systems you have explicit written authorization to test.

SYN scans and OS fingerprinting can violate computer misuse laws even on shared infrastructure (university networks, ISP-managed equipment, cloud provider ranges without permission). Keep testing to your own lab, local VMs, or an authorized scope.

---

## Troubleshooting

- **"Operation not permitted" / no packets sent** — you're not running as root/Administrator.
- **All ports show "filtered"** — a firewall (local or on the target) is dropping probes; try a longer `--timeout`, or test against a host you know is reachable (e.g., your router at `192.168.1.1`).
- **`protocol_client.py` gets no reply** — confirm `protocol_server.py` is running first and both are using the same `--iface` (use `lo` for same-machine testing).
- **Windows users** — install [Npcap](https://npcap.com/) in WinPcap-compatible mode; Scapy needs it for raw packet I/O.
