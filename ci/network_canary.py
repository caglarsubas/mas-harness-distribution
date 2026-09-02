#!/usr/bin/env python3
"""Prove that both IPv4 and IPv6 outbound socket connects are OS-denied."""

from __future__ import annotations

import errno
import socket


def denied(family: int, address: tuple[object, ...]) -> bool:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as candidate:
            candidate.settimeout(0.2)
            candidate.connect(address)
    except OSError as exc:
        return exc.errno in {errno.EPERM, errno.EACCES}
    return False


if not denied(socket.AF_INET, ("192.0.2.1", 9)) or not denied(socket.AF_INET6, ("2001:db8::1", 9, 0, 0)):
    raise SystemExit("offline network canary: outbound denial was not enforced")
print("offline network canary: OS denied IPv4 and IPv6 outbound egress")
