#!/usr/bin/env python3
"""Deterministic DNS truth server for tests/test_dns_ring.mojo.

Serves a fixed zone over UDP and TCP on 127.0.0.1:PORT (default
19553), exercising every resolver path:

  a.test      -> two A records (1.2.3.4, 5.6.7.8)
  aaaa.test   -> one AAAA record (2001:db8::42)
  cname.test  -> CNAME -> a.test (answer uses compression pointers)
  big.test    -> UDP answers with TC=1 and no records; TCP serves
                 one A record (9.9.9.9) — forces the TCP fallback
  retry.test  -> the FIRST UDP query for each txid is ignored — forces
                 the retry path
  nx.test     -> RCODE=3 (NXDOMAIN)

Stays up until killed; handles many queries (unlike echo_server.py).
"""

import socket
import struct
import sys
import threading


def parse_qname(msg: bytes, off: int):
    labels = []
    while True:
        n = msg[off]
        if n == 0:
            return ".".join(labels), off + 1
        labels.append(msg[off + 1 : off + 1 + n].decode())
        off += 1 + n


def enc_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def build_response(query: bytes, tcp: bool) -> bytes:
    txid = query[:2]
    qname, qend = parse_qname(query, 12)
    qtype, qclass = struct.unpack(">HH", query[qend : qend + 4])
    question = query[12 : qend + 4]

    flags = 0x8180  # QR=1, RD=1, RA=1
    answers = []
    rcode = 0
    qname_ptr = 0xC00C  # compression pointer to the question name

    def rr(name_ptr: int, rtype: int, rdata: bytes) -> bytes:
        return struct.pack(">HHHIH", name_ptr, rtype, 1, 60, len(rdata)) + rdata

    if qname == "a.test" and qtype == 1:
        answers.append(rr(qname_ptr, 1, bytes([1, 2, 3, 4])))
        answers.append(rr(qname_ptr, 1, bytes([5, 6, 7, 8])))
    elif qname == "aaaa.test" and qtype == 28:
        addr = socket.inet_pton(socket.AF_INET6, "2001:db8::42")
        answers.append(rr(qname_ptr, 28, addr))
    elif qname == "cname.test" and qtype == 1:
        target = enc_name("a.test")
        answers.append(rr(qname_ptr, 5, target))
        # the A record's owner is a compression pointer into the CNAME
        # rdata (12 + len(question) + 12 bytes into the message)
        a_owner = 0xC000 | (12 + len(question) + 12)
        answers.append(rr(a_owner, 1, bytes([1, 2, 3, 4])))
    elif qname == "big.test" and qtype == 1:
        if not tcp:
            flags |= 0x0200  # TC
        else:
            answers.append(rr(qname_ptr, 1, bytes([9, 9, 9, 9])))
    elif qname == "nx.test":
        rcode = 3
    flags |= rcode

    header = txid + struct.pack(">HHHHH", flags, 1, len(answers), 0, 0)
    return header + question + b"".join(answers)


def udp_loop(port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    drop_counter = 0
    while True:
        query, peer = s.recvfrom(2048)
        qname, _ = parse_qname(query, 12)
        if qname == "retry.test":
            drop_counter += 1
            print(f"retry query #{drop_counter}", flush=True)
            if drop_counter % 2 == 1:
                continue  # drop odd-numbered queries: forces a retry
        s.sendto(build_response(query, tcp=False), peer)


def tcp_loop(port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(8)
    while True:
        conn, _ = s.accept()
        try:
            ln = struct.unpack(">H", conn.recv(2, socket.MSG_WAITALL))[0]
            query = conn.recv(ln, socket.MSG_WAITALL)
            resp = build_response(query, tcp=True)
            conn.sendall(struct.pack(">H", len(resp)) + resp)
        finally:
            conn.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19553
    threading.Thread(target=tcp_loop, args=(port,), daemon=True).start()
    print(f"dns truth server v2 on 127.0.0.1:{port} (udp+tcp)", flush=True)
    udp_loop(port)


if __name__ == "__main__":
    main()
