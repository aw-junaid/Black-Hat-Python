This Python script demonstrates how to set up a **reverse SSH tunnel** using the `paramiko` library. A reverse SSH tunnel allows you to forward a port on a remote SSH server back to a local machine, enabling access to services on the local machine from the remote server. This is similar to the `-R` option in OpenSSH.

---

### Code

#### Imports and Constants
```python
import getpass  # For securely reading passwords
import os  # For OS-related functions
import socket  # For creating and managing network sockets
import select  # For I/O multiplexing
import sys  # For system-specific parameters and functions
import threading  # For handling threading
from optparse import OptionParser  # For parsing command-line options

import paramiko  # For implementing SSH functionality

SSH_PORT = 22  # Default SSH port
DEFAULT_PORT = 4000  # Default port for remote forwarding

g_verbose = True  # Global variable to control verbose output
```

#### Helper Functions
1. **`handler(chan, host, port)`**:
   - Handles data transfer between the SSH channel and the remote host.
   - Establishes a connection to the remote host and forwards data bidirectionally.

   ```python
   def handler(chan, host, port):
       sock = socket.socket()
       try:
           sock.connect((host, port))  # Connect to the remote host
       except Exception as e:
           verbose("Forwarding request to %s:%d failed: %r" % (host, port, e))
           return

       verbose(
           "Connected!  Tunnel open %r -> %r -> %r"
           % (chan.origin_addr, chan.getpeername(), (host, port))
       )
       while True:
           r, w, x = select.select([sock, chan], [], [])  # Wait for data
           if sock in r:
               data = sock.recv(1024)  # Receive data from the remote host
               if len(data) == 0:
                   break
               chan.send(data)  # Send data to the SSH channel
           if chan in r:
               data = chan.recv(1024)  # Receive data from the SSH channel
               if len(data) == 0:
                   break
               sock.send(data)  # Send data to the remote host
       chan.close()
       sock.close()
       verbose("Tunnel closed from %r" % (chan.origin_addr,))
   ```

2. **`reverse_forward_tunnel(server_port, remote_host, remote_port, transport)`**:
   - Sets up a reverse port forwarding tunnel.
   - Listens for incoming connections on the specified server port and forwards them to the remote host.

   ```python
   def reverse_forward_tunnel(server_port, remote_host, remote_port, transport):
       transport.request_port_forward("", server_port)  # Request port forwarding
       while True:
           chan = transport.accept(1000)  # Accept incoming connections
           if chan is None:
               continue
           thr = threading.Thread(
               target=handler, args=(chan, remote_host, remote_port)
           )  # Start a new thread to handle the connection
           thr.setDaemon(True)
           thr.start()
   ```

3. **`verbose(s)`**:
   - Prints verbose output if `g_verbose` is `True`.

   ```python
   def verbose(s):
       if g_verbose:
           print(s)
   ```

4. **`get_host_port(spec, default_port)`**:
   - Parses a string in the format `host:port` into a host and port.

   ```python
   def get_host_port(spec, default_port):
       args = (spec.split(":", 1) + [default_port])[:2]
       args[1] = int(args[1])
       return args[0], args[1]
   ```

#### Command-Line Options
The script uses `OptionParser` to parse command-line arguments.

```python
def parse_options():
    global g_verbose

    parser = OptionParser(
        usage="usage: %prog [options] <ssh-server>[:<server-port>]",
        version="%prog 1.0",
        description=HELP,
    )
    parser.add_option(
        "-q",
        "--quiet",
        action="store_false",
        dest="verbose",
        default=True,
        help="squelch all informational output",
    )
    parser.add_option(
        "-p",
        "--remote-port",
        action="store",
        type="int",
        dest="port",
        default=DEFAULT_PORT,
        help="port on server to forward (default: %d)" % DEFAULT_PORT,
    )
    parser.add_option(
        "-u",
        "--user",
        action="store",
        type="string",
        dest="user",
        default=getpass.getuser(),
        help="username for SSH authentication (default: %s)"
        % getpass.getuser(),
    )
    parser.add_option(
        "-K",
        "--key",
        action="store",
        type="string",
        dest="keyfile",
        default=None,
        help="private key file to use for SSH authentication",
    )
    parser.add_option(
        "",
        "--no-key",
        action="store_false",
        dest="look_for_keys",
        default=True,
        help="don't look for or use a private key file",
    )
    parser.add_option(
        "-P",
        "--password",
        action="store_true",
        dest="readpass",
        default=False,
        help="read password (for key or password auth) from stdin",
    )
    parser.add_option(
        "-r",
        "--remote",
        action="store",
        type="string",
        dest="remote",
        default=None,
        metavar="host:port",
        help="remote host and port to forward to",
    )
    options, args = parser.parse_args()

    if len(args) != 1:
        parser.error("Incorrect number of arguments.")
    if options.remote is None:
        parser.error("Remote address required (-r).")

    g_verbose = options.verbose
    server_host, server_port = get_host_port(args[0], SSH_PORT)
    remote_host, remote_port = get_host_port(options.remote, SSH_PORT)
    return options, (server_host, server_port), (remote_host, remote_port)
```

#### Main Function
The `main()` function sets up the SSH connection and starts the reverse tunnel.

```python
def main():
    options, server, remote = parse_options()

    password = None
    if options.readpass:
        password = getpass.getpass("Enter SSH password: ")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    verbose("Connecting to ssh host %s:%d ..." % (server[0], server[1]))
    try:
        client.connect(
            server[0],
            server[1],
            username=options.user,
            key_filename=options.keyfile,
            look_for_keys=options.look_for_keys,
            password=password,
        )
    except Exception as e:
        print("*** Failed to connect to %s:%d: %r" % (server[0], server[1], e))
        sys.exit(1)

    verbose(
        "Now forwarding remote port %d to %s:%d ..."
        % (options.port, remote[0], remote[1])
    )

    try:
        reverse_forward_tunnel(
            options.port, remote[0], remote[1], client.get_transport()
        )
    except KeyboardInterrupt:
        print("C-c: Port forwarding stopped.")
        sys.exit(0)
```

---

### How to Run the Code

1. **Install Dependencies**:
   - Install the `paramiko` library using pip:
     ```bash
     pip install paramiko
     ```

2. **Run the Script**:
   - Save the script to a file, e.g., `reverse_ssh_tunnel.py`.
   - Run the script with the required arguments:
     ```bash
     python reverse_ssh_tunnel.py -p <remote_port> -r <remote_host:remote_port> <ssh_server>
     ```
   - Example:
     ```bash
     python reverse_ssh_tunnel.py -p 4000 -r localhost:8080 user@ssh.example.com
     ```

3. **Connect to the Tunnel**:
   - The script will forward traffic from `ssh.example.com:4000` to `localhost:8080`.

---

### Notes
- This script is for educational purposes and should not be used in production environments without proper security measures.
- Ensure the SSH server allows remote port forwarding.
- Use strong passwords or key-based authentication for SSH connections.
- The script handles keyboard interrupts (`Ctrl+C`) gracefully.


```python
#!/usr/bin/env python

# Copyright (C) 2008  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Sample script showing how to do remote port forwarding over paramiko.

This script connects to the requested SSH server and sets up remote port
forwarding (the openssh -R option) from a remote port through a tunneled
connection to a destination reachable from the local machine.
"""

import getpass
import os
import socket
import select
import sys
import threading
from optparse import OptionParser

import paramiko

SSH_PORT = 22
DEFAULT_PORT = 4000

g_verbose = True


def handler(chan, host, port):
    sock = socket.socket()
    try:
        sock.connect((host, port))
    except Exception as e:
        verbose("Forwarding request to %s:%d failed: %r" % (host, port, e))
        return

    verbose(
        "Connected!  Tunnel open %r -> %r -> %r"
        % (chan.origin_addr, chan.getpeername(), (host, port))
    )
    while True:
        r, w, x = select.select([sock, chan], [], [])
        if sock in r:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            chan.send(data)
        if chan in r:
            data = chan.recv(1024)
            if len(data) == 0:
                break
            sock.send(data)
    chan.close()
    sock.close()
    verbose("Tunnel closed from %r" % (chan.origin_addr,))


def reverse_forward_tunnel(server_port, remote_host, remote_port, transport):
    transport.request_port_forward("", server_port)
    while True:
        chan = transport.accept(1000)
        if chan is None:
            continue
        thr = threading.Thread(
            target=handler, args=(chan, remote_host, remote_port)
        )
        thr.setDaemon(True)
        thr.start()


def verbose(s):
    if g_verbose:
        print(s)


HELP = """\
Set up a reverse forwarding tunnel across an SSH server, using paramiko. A
port on the SSH server (given with -p) is forwarded across an SSH session
back to the local machine, and out to a remote site reachable from this
network. This is similar to the openssh -R option.
"""


def get_host_port(spec, default_port):
    "parse 'hostname:22' into a host and port, with the port optional"
    args = (spec.split(":", 1) + [default_port])[:2]
    args[1] = int(args[1])
    return args[0], args[1]


def parse_options():
    global g_verbose

    parser = OptionParser(
        usage="usage: %prog [options] <ssh-server>[:<server-port>]",
        version="%prog 1.0",
        description=HELP,
    )
    parser.add_option(
        "-q",
        "--quiet",
        action="store_false",
        dest="verbose",
        default=True,
        help="squelch all informational output",
    )
    parser.add_option(
        "-p",
        "--remote-port",
        action="store",
        type="int",
        dest="port",
        default=DEFAULT_PORT,
        help="port on server to forward (default: %d)" % DEFAULT_PORT,
    )
    parser.add_option(
        "-u",
        "--user",
        action="store",
        type="string",
        dest="user",
        default=getpass.getuser(),
        help="username for SSH authentication (default: %s)"
        % getpass.getuser(),
    )
    parser.add_option(
        "-K",
        "--key",
        action="store",
        type="string",
        dest="keyfile",
        default=None,
        help="private key file to use for SSH authentication",
    )
    parser.add_option(
        "",
        "--no-key",
        action="store_false",
        dest="look_for_keys",
        default=True,
        help="don't look for or use a private key file",
    )
    parser.add_option(
        "-P",
        "--password",
        action="store_true",
        dest="readpass",
        default=False,
        help="read password (for key or password auth) from stdin",
    )
    parser.add_option(
        "-r",
        "--remote",
        action="store",
        type="string",
        dest="remote",
        default=None,
        metavar="host:port",
        help="remote host and port to forward to",
    )
    options, args = parser.parse_args()

    if len(args) != 1:
        parser.error("Incorrect number of arguments.")
    if options.remote is None:
        parser.error("Remote address required (-r).")

    g_verbose = options.verbose
    server_host, server_port = get_host_port(args[0], SSH_PORT)
    remote_host, remote_port = get_host_port(options.remote, SSH_PORT)
    return options, (server_host, server_port), (remote_host, remote_port)


def main():
    options, server, remote = parse_options()

    password = None
    if options.readpass:
        password = getpass.getpass("Enter SSH password: ")

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())

    verbose("Connecting to ssh host %s:%d ..." % (server[0], server[1]))
    try:
        client.connect(
            server[0],
            server[1],
            username=options.user,
            key_filename=options.keyfile,
            look_for_keys=options.look_for_keys,
            password=password,
        )
    except Exception as e:
        print("*** Failed to connect to %s:%d: %r" % (server[0], server[1], e))
        sys.exit(1)

    verbose(
        "Now forwarding remote port %d to %s:%d ..."
        % (options.port, remote[0], remote[1])
    )

    try:
        reverse_forward_tunnel(
            options.port, remote[0], remote[1], client.get_transport()
        )
    except KeyboardInterrupt:
        print("C-c: Port forwarding stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()

```
