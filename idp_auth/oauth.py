"""OAuth client authentication helpers (RFC 7523 / RFC 6749 section 2.3)."""

import base64
import hashlib
import json
import secrets
import time
from collections.abc import Callable
from urllib.parse import quote_plus

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
DEFAULT_LIFETIME = 300


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def client_assertion(
    client_id: str,
    audience: str,
    private_key: str,
    key_id: str | None = None,
    certificate: str | None = None,
    lifetime: int = DEFAULT_LIFETIME,
    clock: Callable[[], float] = time.time,
) -> str:
    """Signed JWT for ``private_key_jwt``: iss = sub = client_id, aud = the token endpoint.

    RSA keys sign RS256, P-256 keys sign ES256. With ``certificate`` (PEM), the header carries ``x5t`` and
    ``x5t#S256`` thumbprints, which Entra ID uses to find the registered certificate.
    """
    key = serialization.load_pem_private_key(private_key.encode(), password=None)
    if isinstance(key, rsa.RSAPrivateKey):
        alg = 'RS256'
    elif isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1):
        alg = 'ES256'
    else:
        raise ValueError('private_key must be RSA or EC P-256')

    header = {'alg': alg, 'typ': 'JWT'}
    if key_id:
        header['kid'] = key_id
    if certificate:
        der = x509.load_pem_x509_certificate(certificate.encode()).public_bytes(serialization.Encoding.DER)
        header['x5t'] = _b64url(hashlib.sha1(der).digest())  # a certificate thumbprint, not a security hash
        header['x5t#S256'] = _b64url(hashlib.sha256(der).digest())

    now = int(clock())
    claims = {
        'iss': client_id,
        'sub': client_id,
        'aud': audience,
        'jti': secrets.token_urlsafe(16),
        'iat': now,
        'nbf': now,
        'exp': now + int(lifetime),
    }
    signing_input = '.'.join(_b64url(json.dumps(part, separators=(',', ':')).encode()) for part in (header, claims))
    if alg == 'RS256':
        signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    else:
        r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
        signature = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')  # JWS wants raw r || s, not DER
    return f'{signing_input}.{_b64url(signature)}'


def basic_auth_header(username: str, password: str) -> str:
    """``Authorization`` value for client_secret_basic: both parts form-urlencoded first, per RFC 6749 2.3.1."""
    raw = f'{quote_plus(username)}:{quote_plus(password)}'.encode()
    return 'Basic ' + base64.b64encode(raw).decode()
