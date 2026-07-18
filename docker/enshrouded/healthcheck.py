#!/usr/bin/env python3
import os
import socket
import sys

port = int(os.environ.get("QUERY_PORT", "15637"))
payload = b"\xff\xff\xff\xffTSource Engine Query\x00"

try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2.0)
        sock.sendto(payload, ("127.0.0.1", port))
        response, _ = sock.recvfrom(2048)
        if len(response) < 5 or response[:4] != b"\xff\xff\xff\xff":
            raise RuntimeError("invalid A2S response")
except Exception as exc:
    print(f"A2S readiness failed: {exc}", file=sys.stderr)
    sys.exit(1)
