"""client_credentials recipe: client_secret_post, client_secret_basic and private_key_jwt (RS256 / ES256)."""

import base64
import datetime
import hashlib
import json
import unittest
from typing import ClassVar
from urllib.parse import parse_qsl, unquote_plus

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from idp_auth import LoginError, Recipe, RecipeError, login, login_sync

ISSUER = 'https://op.example.com'
TOKEN_URL = f'{ISSUER}/oauth2/token'
NOW = 1_700_000_000.0
CLOCK = lambda: NOW  # noqa: E731


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def self_signed(key) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'svc-client')])
    start = datetime.datetime(2023, 1, 1, tzinfo=datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )


RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())
CERT = self_signed(RSA_KEY)


def verify_jwt(token: str, public_key) -> tuple[dict, dict]:
    header_b64, claims_b64, sig_b64 = token.split('.')
    header, claims = json.loads(b64url_decode(header_b64)), json.loads(b64url_decode(claims_b64))
    signed, sig = f'{header_b64}.{claims_b64}'.encode(), b64url_decode(sig_b64)
    if header['alg'] == 'RS256':
        public_key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
    elif header['alg'] == 'ES256':
        r, s = int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')
        public_key.verify(encode_dss_signature(r, s), signed, ec.ECDSA(hashes.SHA256()))
    else:
        raise AssertionError(f'unexpected alg {header["alg"]}')
    return header, claims


class FakeTokenEndpoint:
    def __init__(self, secret: str | None = None, public_key=None, require_audience: str | None = None):
        self.secret, self.public_key, self.require_audience = secret, public_key, require_audience
        self.requests: list[dict] = []
        self.assertions: list[tuple[dict, dict]] = []

    def deny(self, description: str) -> httpx.Response:
        return httpx.Response(401, json={'error': 'invalid_client', 'error_description': description})

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == '/.well-known/openid-configuration':
            return httpx.Response(200, json={'issuer': ISSUER, 'token_endpoint': TOKEN_URL})
        if request.url.path != '/oauth2/token' or request.method != 'POST':
            return httpx.Response(404)
        data = dict(parse_qsl(request.content.decode(), keep_blank_values=True))
        self.requests.append({'data': data, 'authorization': request.headers.get('authorization')})
        if data.get('grant_type') != 'client_credentials':
            return httpx.Response(400, json={'error': 'unsupported_grant_type'})
        if self.require_audience and data.get('audience') != self.require_audience:
            return httpx.Response(400, json={'error': 'invalid_request', 'error_description': 'audience required'})

        client_id = None
        if auth := request.headers.get('authorization'):
            user, _, password = base64.b64decode(auth.removeprefix('Basic ')).decode().partition(':')
            client_id, secret = unquote_plus(user), unquote_plus(password)
            if secret != self.secret:
                return self.deny('bad client secret')
        elif 'client_assertion' in data:
            if data.get('client_assertion_type') != 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer':
                return self.deny('bad assertion type')
            try:
                header, claims = verify_jwt(data['client_assertion'], self.public_key)
            except Exception:
                return self.deny('assertion signature invalid')
            self.assertions.append((header, claims))
            if (
                claims['aud'] != TOKEN_URL
                or claims['iss'] != claims['sub']
                or not (claims['iat'] <= NOW < claims['exp'])
            ):
                return self.deny('assertion claims invalid')
            client_id = claims['sub']
        elif 'client_secret' in data:
            client_id = data.get('client_id')
            if data['client_secret'] != self.secret:
                return self.deny('bad client secret')
        else:
            return self.deny('no client authentication')
        if client_id != 'svc-client':
            return self.deny('unknown client')
        return httpx.Response(
            200,
            json={'access_token': 'at-cc', 'token_type': 'Bearer', 'expires_in': 3599, 'scope': data.get('scope', '')},
        )

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


class TestClientCredentials(unittest.IsolatedAsyncioTestCase):
    BASE: ClassVar = {'token_url': TOKEN_URL, 'client_id': 'svc-client'}

    async def run_cc(self, endpoint: FakeTokenEndpoint, **inputs):
        async with httpx.AsyncClient(transport=endpoint.transport()) as client:
            return await login('client_credentials', {**self.BASE, **inputs}, client=client, clock=CLOCK)

    async def test_client_secret_post_is_the_default_for_secrets(self):
        endpoint = FakeTokenEndpoint(secret='s3cret')
        result = await self.run_cc(endpoint, client_secret='s3cret', scope='api.read')
        self.assertEqual(result.outputs['access_token'], 'at-cc')
        self.assertEqual(result.outputs['scope'], 'api.read')
        sent = endpoint.requests[0]
        self.assertEqual(sent['data']['client_secret'], 's3cret')
        self.assertIsNone(sent['authorization'])

    async def test_client_secret_basic(self):
        endpoint = FakeTokenEndpoint(secret='s3:cr&t')
        result = await self.run_cc(endpoint, client_secret='s3:cr&t', auth_method='client_secret_basic')
        self.assertEqual(result.outputs['access_token'], 'at-cc')
        sent = endpoint.requests[0]
        self.assertTrue(sent['authorization'].startswith('Basic '))
        self.assertNotIn('client_secret', sent['data'])

    async def test_private_key_jwt_rsa_with_certificate_thumbprints(self):
        endpoint = FakeTokenEndpoint(public_key=RSA_KEY.public_key())
        cert_pem = CERT.public_bytes(serialization.Encoding.PEM).decode()
        result = await self.run_cc(endpoint, private_key=pem(RSA_KEY), certificate=cert_pem, key_id='k-1')
        self.assertEqual(result.outputs['access_token'], 'at-cc')
        header, claims = endpoint.assertions[0]
        der = CERT.public_bytes(serialization.Encoding.DER)
        self.assertEqual(header['alg'], 'RS256')
        self.assertEqual(header['kid'], 'k-1')
        self.assertEqual(header['x5t'], b64url(hashlib.sha1(der).digest()))
        self.assertEqual(header['x5t#S256'], b64url(hashlib.sha256(der).digest()))
        self.assertEqual((claims['iss'], claims['sub'], claims['aud']), ('svc-client', 'svc-client', TOKEN_URL))
        self.assertEqual(claims['exp'] - claims['iat'], 300)
        self.assertTrue(claims['jti'])
        self.assertNotIn('client_secret', endpoint.requests[0]['data'])

    async def test_private_key_jwt_ec(self):
        endpoint = FakeTokenEndpoint(public_key=EC_KEY.public_key())
        result = await self.run_cc(endpoint, private_key=pem(EC_KEY))
        self.assertEqual(result.outputs['access_token'], 'at-cc')
        header, _ = endpoint.assertions[0]
        self.assertEqual(header['alg'], 'ES256')
        self.assertNotIn('kid', header)

    async def test_fresh_jti_each_run(self):
        endpoint = FakeTokenEndpoint(public_key=EC_KEY.public_key())
        await self.run_cc(endpoint, private_key=pem(EC_KEY))
        await self.run_cc(endpoint, private_key=pem(EC_KEY))
        self.assertNotEqual(endpoint.assertions[0][1]['jti'], endpoint.assertions[1][1]['jti'])

    async def test_wrong_key_is_rejected(self):
        endpoint = FakeTokenEndpoint(public_key=RSA_KEY.public_key())
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(LoginError) as ctx:
            await self.run_cc(endpoint, private_key=pem(other))
        err = ctx.exception
        self.assertEqual((err.reason, err.status_code), ('rejected', 401))
        self.assertIn('invalid_client', str(err))

    async def test_discovery(self):
        endpoint = FakeTokenEndpoint(secret='s3cret')
        result = await self.run_cc(endpoint, token_url=None, issuer=ISSUER, client_secret='s3cret')
        self.assertEqual(result.outputs['access_token'], 'at-cc')

    async def test_audience_and_resource_passed_through(self):
        endpoint = FakeTokenEndpoint(secret='s3cret', require_audience='https://api.example.com')
        result = await self.run_cc(
            endpoint, client_secret='s3cret', audience='https://api.example.com', resource='https://api.example.com'
        )
        self.assertEqual(result.outputs['access_token'], 'at-cc')
        self.assertEqual(endpoint.requests[0]['data']['resource'], 'https://api.example.com')

    async def test_other_errors_are_flow_errors(self):
        endpoint = FakeTokenEndpoint(secret='s3cret', require_audience='https://api.example.com')
        with self.assertRaises(LoginError) as ctx:
            await self.run_cc(endpoint, client_secret='s3cret')
        self.assertEqual((ctx.exception.reason, ctx.exception.status_code), ('flow', 400))
        self.assertIn('audience required', str(ctx.exception))

    async def test_needs_credentials(self):
        with self.assertRaises(LoginError) as ctx:
            await self.run_cc(FakeTokenEndpoint())
        self.assertIn('client_secret or private_key', str(ctx.exception))

    async def test_needs_token_endpoint(self):
        with self.assertRaises(LoginError):
            await self.run_cc(FakeTokenEndpoint(secret='s'), token_url=None, client_secret='s')

    async def test_unknown_auth_method(self):
        with self.assertRaises(LoginError) as ctx:
            await self.run_cc(FakeTokenEndpoint(secret='s'), client_secret='s', auth_method='tls_client_auth')
        self.assertIn('auth_method', str(ctx.exception))

    async def test_secrets_scrubbed(self):
        endpoint = FakeTokenEndpoint(public_key=RSA_KEY.public_key())
        result = await self.run_cc(endpoint, private_key=pem(RSA_KEY))
        dumped = json.dumps(result.vars, default=str)
        self.assertNotIn('PRIVATE KEY', dumped)

    def test_sync(self):
        endpoint = FakeTokenEndpoint(secret='s3cret')
        with httpx.Client(transport=endpoint.transport()) as client:
            result = login_sync('client_credentials', {**self.BASE, 'client_secret': 's3cret'}, client=client)
        self.assertEqual(result.outputs['access_token'], 'at-cc')


class TestClientAssertionAction(unittest.TestCase):
    def test_validation(self):
        with self.assertRaises(RecipeError):
            Recipe.from_dict({'name': 'x', 'steps': [{'client_assertion': {'client_id': 'c'}}]})

    def test_basic_auth_validation(self):
        with self.assertRaises(RecipeError):
            Recipe.from_dict({'name': 'x', 'steps': [{'request': {'url': 'https://x/', 'basic_auth': 'nope'}}]})


if __name__ == '__main__':
    unittest.main()
