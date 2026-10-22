import hashlib
import json
import struct
import unittest

from fido2 import cbor
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestedCredentialData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
)

from idp_auth.factors.webauthn import Credential, b64url_decode, b64url_encode

RP_ID = 'login.example.com'
ORIGIN = 'https://login.example.com'


def make_server() -> Fido2Server:
    return Fido2Server(PublicKeyCredentialRpEntity(name='Example', id=RP_ID), verify_origin=lambda o: o == ORIGIN)


class TestCredentialFormat(unittest.TestCase):
    def setUp(self):
        self.cred = Credential.create(rp_id=RP_ID, user_handle=b'user-1')

    def test_registration_shape(self):
        reg = self.cred.registration(challenge=b'c' * 32, origin=ORIGIN)
        self.assertEqual(reg['type'], 'public-key')
        self.assertEqual(b64url_decode(reg['rawId']), self.cred.credential_id)
        client_data = json.loads(b64url_decode(reg['response']['clientDataJSON']))
        self.assertEqual(client_data['type'], 'webauthn.create')
        self.assertEqual(client_data['origin'], ORIGIN)
        self.assertEqual(b64url_decode(client_data['challenge']), b'c' * 32)

        att = cbor.decode(b64url_decode(reg['response']['attestationObject']))
        self.assertEqual(att['fmt'], 'none')
        auth_data = att['authData']
        self.assertEqual(auth_data[:32], hashlib.sha256(RP_ID.encode()).digest())
        flags = auth_data[32]
        self.assertTrue(flags & 0x01, 'UP')
        self.assertTrue(flags & 0x04, 'UV')
        self.assertTrue(flags & 0x40, 'AT')

    def test_assertion_counter_increments(self):
        first = self.cred.assertion(challenge=b'a' * 32, origin=ORIGIN)
        second = self.cred.assertion(challenge=b'b' * 32, origin=ORIGIN)
        count = lambda a: struct.unpack('>I', b64url_decode(a['response']['authenticatorData'])[33:37])[0]  # noqa: E731
        self.assertEqual(count(second), count(first) + 1)
        self.assertEqual(self.cred.sign_count, count(second))

    def test_challenge_accepts_base64url_string(self):
        a = self.cred.assertion(challenge=b64url_encode(b'z' * 16), origin=ORIGIN)
        client_data = json.loads(b64url_decode(a['response']['clientDataJSON']))
        self.assertEqual(b64url_decode(client_data['challenge']), b'z' * 16)

    def test_persistence_round_trip(self):
        self.cred.assertion(challenge=b'x', origin=ORIGIN)
        restored = Credential.from_dict(json.loads(json.dumps(self.cred.to_dict())))
        self.assertEqual(restored.credential_id, self.cred.credential_id)
        self.assertEqual(restored.sign_count, self.cred.sign_count)
        self.assertEqual(restored.user_handle, b'user-1')

    def test_wrong_rp_rejected_locally(self):
        with self.assertRaises(ValueError):
            self.cred.assertion(challenge=b'x', origin=ORIGIN, rp_id='evil.example.net')


class TestAgainstRelyingParty(unittest.TestCase):
    """Round-trip through Yubico's reference RP implementation."""

    def test_register_then_authenticate(self):
        server = make_server()
        user = PublicKeyCredentialUserEntity(id=b'user-1', name='svc', display_name='svc')
        options, state = server.register_begin(user, user_verification=UserVerificationRequirement.PREFERRED)

        cred = Credential.create(rp_id=RP_ID, user_handle=b'user-1')
        reg = cred.registration(challenge=options.public_key.challenge, origin=ORIGIN)
        auth_data = server.register_complete(state, reg)
        stored: AttestedCredentialData = auth_data.credential_data
        self.assertEqual(stored.credential_id, cred.credential_id)

        options, state = server.authenticate_begin([stored])
        assertion = cred.assertion(challenge=options.public_key.challenge, origin=ORIGIN)
        server.authenticate_complete(state, [stored], assertion)

    def test_tampered_signature_fails(self):
        server = make_server()
        user = PublicKeyCredentialUserEntity(id=b'u', name='svc', display_name='svc')
        options, state = server.register_begin(user)
        cred = Credential.create(rp_id=RP_ID, user_handle=b'u')
        stored = server.register_complete(
            state, cred.registration(options.public_key.challenge, ORIGIN)
        ).credential_data

        options, state = server.authenticate_begin([stored])
        assertion = cred.assertion(challenge=options.public_key.challenge, origin=ORIGIN)
        sig = bytearray(b64url_decode(assertion['response']['signature']))
        sig[-1] ^= 0xFF
        assertion['response']['signature'] = b64url_encode(bytes(sig))
        with self.assertRaises(Exception):  # noqa: B017 - fido2 raises InvalidSignature
            server.authenticate_complete(state, [stored], assertion)


if __name__ == '__main__':
    unittest.main()
