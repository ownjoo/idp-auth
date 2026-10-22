"""Software FIDO2/WebAuthn authenticator.

A browser's only job in WebAuthn is to build ``clientDataJSON`` (type, challenge, origin) and hand its hash to the
authenticator. We do both halves: build clientDataJSON, then sign ``authenticatorData || sha256(clientDataJSON)``
with an ES256 key we hold. Output is the ``PublicKeyCredential.toJSON()`` shape relying parties accept.

The origin must still sit under the credential's RP ID, so the credential keeps its phishing resistance.
"""

import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass, field
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from idp_auth.factors import cbor

FLAG_UP = 0x01  # user present
FLAG_UV = 0x04  # user verified
FLAG_AT = 0x40  # attested credential data included
COSE_ES256 = -7


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def _challenge_bytes(challenge: bytes | str) -> bytes:
    return challenge if isinstance(challenge, bytes) else b64url_decode(challenge)


@dataclass
class Credential:
    credential_id: bytes
    rp_id: str
    private_key: ec.EllipticCurvePrivateKey
    user_handle: bytes | None = None
    sign_count: int = 0
    aaguid: bytes = field(default=bytes(16))

    @classmethod
    def create(cls, rp_id: str, user_handle: bytes | None = None) -> 'Credential':
        return cls(
            credential_id=os.urandom(32),
            rp_id=rp_id,
            private_key=ec.generate_private_key(ec.SECP256R1()),
            user_handle=user_handle,
        )

    # -- persistence -------------------------------------------------------------------------------------------

    def to_dict(self) -> dict:
        pem = self.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        return {
            'credential_id': b64url_encode(self.credential_id),
            'rp_id': self.rp_id,
            'user_handle': b64url_encode(self.user_handle) if self.user_handle is not None else None,
            'private_key': pem.decode(),
            'sign_count': self.sign_count,
            'aaguid': self.aaguid.hex(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Credential':
        return cls(
            credential_id=b64url_decode(data['credential_id']),
            rp_id=data['rp_id'],
            private_key=serialization.load_pem_private_key(data['private_key'].encode(), password=None),
            user_handle=b64url_decode(data['user_handle']) if data.get('user_handle') is not None else None,
            sign_count=int(data.get('sign_count', 0)),
            aaguid=bytes.fromhex(data.get('aaguid', '00' * 16)),
        )

    # -- ceremonies --------------------------------------------------------------------------------------------

    def registration(self, challenge: bytes | str, origin: str, rp_id: str | None = None) -> dict:
        """Response to ``navigator.credentials.create()``, with ``none`` attestation."""
        client_data = self._client_data('webauthn.create', challenge, origin, rp_id)
        attested = self.aaguid + struct.pack('>H', len(self.credential_id)) + self.credential_id + self._cose_key()
        auth_data = self._auth_data(FLAG_UP | FLAG_UV | FLAG_AT, self.sign_count) + attested
        attestation = cbor.encode({'fmt': 'none', 'attStmt': {}, 'authData': auth_data})
        return {
            'id': b64url_encode(self.credential_id),
            'rawId': b64url_encode(self.credential_id),
            'type': 'public-key',
            'response': {
                'clientDataJSON': b64url_encode(client_data),
                'attestationObject': b64url_encode(attestation),
                'transports': ['internal'],
            },
            'clientExtensionResults': {},
            'authenticatorAttachment': 'platform',
        }

    def assertion(self, challenge: bytes | str, origin: str, rp_id: str | None = None) -> dict:
        """Response to ``navigator.credentials.get()``. Increments and stores ``sign_count``."""
        client_data = self._client_data('webauthn.get', challenge, origin, rp_id)
        self.sign_count += 1
        auth_data = self._auth_data(FLAG_UP | FLAG_UV, self.sign_count)
        signature = self.private_key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            'id': b64url_encode(self.credential_id),
            'rawId': b64url_encode(self.credential_id),
            'type': 'public-key',
            'response': {
                'clientDataJSON': b64url_encode(client_data),
                'authenticatorData': b64url_encode(auth_data),
                'signature': b64url_encode(signature),
                'userHandle': b64url_encode(self.user_handle) if self.user_handle is not None else None,
            },
            'clientExtensionResults': {},
            'authenticatorAttachment': 'platform',
        }

    # -- internals ---------------------------------------------------------------------------------------------

    def _client_data(self, kind: str, challenge: bytes | str, origin: str, rp_id: str | None) -> bytes:
        if rp_id is not None and rp_id != self.rp_id:
            raise ValueError(f'credential is bound to RP {self.rp_id!r}, not {rp_id!r}')
        host = urlparse(origin).hostname or ''
        if host != self.rp_id and not host.endswith('.' + self.rp_id):
            raise ValueError(f'origin {origin!r} is not within RP ID {self.rp_id!r}')
        return json.dumps(
            {
                'type': kind,
                'challenge': b64url_encode(_challenge_bytes(challenge)),
                'origin': origin,
                'crossOrigin': False,
            },
            separators=(',', ':'),
        ).encode()

    def _auth_data(self, flags: int, counter: int) -> bytes:
        return hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags]) + struct.pack('>I', counter)

    def _cose_key(self) -> bytes:
        numbers = self.private_key.public_key().public_numbers()
        return cbor.encode(
            {1: 2, 3: COSE_ES256, -1: 1, -2: numbers.x.to_bytes(32, 'big'), -3: numbers.y.to_bytes(32, 'big')}
        )
