"""Minimal canonical CBOR encoder (RFC 8949 / CTAP2 canonical form) for the types WebAuthn needs."""

import struct


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for info, fmt in ((24, '>B'), (25, '>H'), (26, '>I'), (27, '>Q')):
        if n < 1 << (8 * struct.calcsize(fmt)):
            return bytes([major << 5 | info]) + struct.pack(fmt, n)
    raise ValueError('integer too large for CBOR')


def encode(value) -> bytes:
    if isinstance(value, bool):
        return b'\xf5' if value else b'\xf4'
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return _head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b''.join(encode(v) for v in value)
    if isinstance(value, dict):
        items = sorted(((encode(k), encode(v)) for k, v in value.items()), key=lambda kv: (len(kv[0]), kv[0]))
        return _head(5, len(items)) + b''.join(k + v for k, v in items)
    raise TypeError(f'cannot CBOR-encode {type(value).__name__}')
