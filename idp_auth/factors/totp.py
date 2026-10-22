"""HOTP (RFC 4226) / TOTP (RFC 6238) software authenticator."""

import base64
import hashlib
import hmac
import struct
import time
from collections.abc import Callable
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

_ALGORITHMS = {'SHA1': hashlib.sha1, 'SHA256': hashlib.sha256, 'SHA512': hashlib.sha512}


def hotp(key: bytes, counter: int, digits: int = 6, algorithm: str = 'SHA1') -> str:
    digest = hmac.new(key, struct.pack('>Q', counter), _ALGORITHMS[algorithm.upper()]).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack('>I', digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10**digits).zfill(digits)


def decode_secret(secret: str) -> bytes:
    cleaned = secret.replace(' ', '').replace('-', '').upper().rstrip('=')
    return base64.b32decode(cleaned + '=' * (-len(cleaned) % 8))


class Totp:
    def __init__(
        self,
        secret: str,
        digits: int = 6,
        period: int = 30,
        algorithm: str = 'SHA1',
        issuer: str | None = None,
        account: str | None = None,
        clock: Callable[[], float] = time.time,
    ):
        if algorithm.upper() not in _ALGORITHMS:
            raise ValueError(f'unsupported TOTP algorithm: {algorithm}')
        self._key = decode_secret(secret)
        self.digits, self.period, self.algorithm = digits, period, algorithm.upper()
        self.issuer, self.account = issuer, account
        self._clock = clock

    @classmethod
    def from_uri(cls, uri: str, clock: Callable[[], float] = time.time) -> 'Totp':
        parsed = urlparse(uri)
        if parsed.scheme != 'otpauth' or parsed.netloc.lower() != 'totp':
            raise ValueError('not an otpauth://totp URI')
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        label = unquote(parsed.path.lstrip('/'))
        issuer, _, account = label.rpartition(':')
        return cls(
            params['secret'],
            digits=int(params.get('digits', 6)),
            period=int(params.get('period', 30)),
            algorithm=params.get('algorithm', 'SHA1'),
            issuer=params.get('issuer') or issuer or None,
            account=account or None,
            clock=clock,
        )

    def to_uri(self) -> str:
        label = quote(':'.join(p for p in (self.issuer, self.account) if p) or 'idp-auth')
        params = {
            'secret': base64.b32encode(self._key).decode().rstrip('='),
            'algorithm': self.algorithm,
            'digits': self.digits,
            'period': self.period,
        }
        if self.issuer:
            params['issuer'] = self.issuer
        return f'otpauth://totp/{label}?{urlencode(params)}'

    def at(self, t: float) -> str:
        return hotp(self._key, int(t) // self.period, self.digits, self.algorithm)

    def now(self) -> str:
        return self.at(self._clock())

    def verify(self, code: str, t: float | None = None, window: int = 1) -> bool:
        t = self._clock() if t is None else t
        return any(hmac.compare_digest(self.at(t + step * self.period), code) for step in range(-window, window + 1))
