"""SOCKS5 TCP/UDP requests through the actual pinned Xray core."""
import ipaddress
import json
import socket
import struct
import sys

policy = sys.argv[1]
assert policy in ("auto", "ipv4_only", "ipv6_only")
proxy = ("192.168.241.2", 1080)
timeout = 1.5
evidence = []


def receive(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("proxy closed the connection")
        data += chunk
    return data


def address(host, port=9000):
    try:
        ip = ipaddress.ip_address(host)
        value = bytes([1 if ip.version == 4 else 4]) + ip.packed
    except ValueError:
        value = bytes([3, len(host)]) + host.encode("ascii")
    return value + struct.pack("!H", port)


def open_socks(command, destination):
    sock = socket.create_connection(proxy, timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        assert receive(sock, 2) == b"\x05\x00"
        sock.sendall(b"\x05" + bytes([command]) + b"\x00" + destination)
        head = receive(sock, 4)
        if head[1] != 0:
            raise ConnectionError("SOCKS request rejected")
        size = {1: 4, 4: 16}.get(head[3])
        if size is None:
            size = receive(sock, 1)[0]
        packed = receive(sock, size)
        port = struct.unpack("!H", receive(sock, 2))[0]
        return sock, (str(ipaddress.ip_address(packed)), port)
    except BaseException:
        sock.close()
        raise


def result(network, host, expected, query):
    nonce = (policy + "-" + network + "-" + host).encode()
    try:
        response = query(nonce)
    except (TimeoutError, OSError, EOFError):
        response = None
    if expected:
        assert response == expected.encode() + b":" + nonce, (network, host, expected, response)
    else:
        assert response is None, ("forbidden family replied", network, host, response)
    evidence.append({"network": network, "host": host, "expected": expected or "blocked",
                     "nonce": nonce.decode()})


cases = [("192.168.241.4", "ipv4"), ("fd00:397::4", "ipv6"),
         ("::ffff:192.168.241.4", "ipv4")]
# AsIs uses the OS resolver rather than Xray's static DNS hosts.
if policy != "auto":
    cases += [("v4.example.test", "ipv4"), ("v6.example.test", "ipv6"),
              ("dual.example.test", policy[:4])]

for host, family in cases:
    expected = family if policy == "auto" or policy == family + "_only" else None

    def tcp(nonce):
        conn, _ = open_socks(1, address(host))
        with conn:
            conn.sendall(nonce)
            return conn.recv(512)

    result("tcp", host, expected, tcp)

# One association deliberately mixes families. This catches restrictions that
# apply only to its first destination and miss later XUDP-style destinations.
control, relay = open_socks(3, address("0.0.0.0", 0))
with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
    udp.settimeout(timeout)
    # Establish a permitted association, then change its destinations. If its
    # very first target is denied, Xray closes that dispatched flow entirely.
    # That separate fail-closed case is exercised below with a fresh socket.
    first = next(i for i, (_, f) in enumerate(cases)
                 if policy == "auto" or policy == f + "_only")
    mixed_cases = [cases[first]] + cases[:first] + cases[first + 1:]
    for host, family in mixed_cases:
        expected = family if policy == "auto" or policy == family + "_only" else None

        def send(nonce):
            udp.sendto(b"\x00\x00\x00" + address(host) + nonce, relay)
            packet, _ = udp.recvfrom(1024)
            size = {1: 4, 4: 16}.get(packet[3])
            start = 4
            if size is None:
                size, start = packet[4], 5
            return packet[start + size + 2:]

        result("udp", host, expected, send)

if policy != "auto":
    forbidden = next(host for host, f in cases if policy != f + "_only")
    control, relay = open_socks(3, address("0.0.0.0", 0))
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(timeout)

        def denied_first(nonce):
            udp.sendto(b"\x00\x00\x00" + address(forbidden) + nonce, relay)
            return udp.recvfrom(1024)[0]

        result("udp-first", forbidden, None, denied_first)

print(json.dumps({"policy": policy, "passed": True, "evidence": evidence}), flush=True)
