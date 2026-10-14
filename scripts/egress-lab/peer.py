"""Isolated dual-stack echo peer. Records every received test nonce."""
import json
import socket
import threading
import time


def record(family, network, data):
    print(json.dumps({"family": family, "network": network,
                      "nonce": data.decode("ascii")}), flush=True)
    return (family + ":").encode() + data


def echo(family, network, address):
    af = socket.AF_INET if family == "ipv4" else socket.AF_INET6
    sock = socket.socket(af, socket.SOCK_STREAM if network == "tcp" else socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if af == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((address, 9000))
    if network == "tcp":
        sock.listen(16)
        while True:
            conn, _ = sock.accept()
            print(json.dumps({"family": family, "network": "tcp_accept", "nonce": ""}), flush=True)
            with conn:
                conn.settimeout(3)
                try:
                    data = conn.recv(256)
                    if data:
                        conn.sendall(record(family, network, data))
                except (TimeoutError, OSError):
                    pass
    else:
        while True:
            data, addr = sock.recvfrom(256)
            sock.sendto(record(family, network, data), addr)


for family, address in [("ipv4", "192.168.241.4"), ("ipv6", "fd00:397::4")]:
    for network in ["tcp", "udp"]:
        threading.Thread(target=echo, args=(family, network, address), daemon=True).start()
time.sleep(180)
