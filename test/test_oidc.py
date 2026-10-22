"""generic_oidc: authorization code + PKCE through an HTML login, stopping at redirect_uri, then the token exchange."""

import base64
import hashlib
import json
import secrets
import unittest
from typing import ClassVar
from urllib.parse import parse_qsl, urlencode

import httpx

from idp_auth import LoginError, login, login_sync
from idp_auth.factors.totp import Totp
from test.mock_idp import html

ISSUER = 'https://op.example.com'
REDIRECT_URI = 'http://localhost:8765/callback'
TOTP_SECRET = base64.b32encode(b'12345678901234567890').decode()
CLOCK = lambda: 1_700_000_000.0  # noqa: E731


def form_data(request: httpx.Request) -> dict:
    return dict(parse_qsl(request.content.decode(), keep_blank_values=True))


class FakeOpenIdProvider:
    """Discovery, /authorize (HTML login, optional TOTP), /token with PKCE verification."""

    def __init__(
        self,
        totp_secret: str | None = None,
        response_mode: str = 'query',
        deny: bool = False,
        tamper_state: bool = False,
        existing_session: bool = False,
        client_secret: str | None = None,
    ):
        self.totp = Totp(totp_secret, clock=CLOCK) if totp_secret else None
        self.response_mode, self.deny, self.tamper_state = response_mode, deny, tamper_state
        self.existing_session, self.client_secret = existing_session, client_secret
        self.pending: dict = {}
        self.codes: dict = {}
        self.callback_hits = 0
        self.login_posts = 0

    def finish(self) -> httpx.Response:
        state = 'forged' if self.tamper_state else self.pending['state']
        if self.deny:
            params = {'error': 'access_denied', 'error_description': 'User is not assigned to this app', 'state': state}
        else:
            code = secrets.token_urlsafe(8)
            self.codes[code] = dict(self.pending)
            params = {'code': code, 'state': state}
        if self.response_mode == 'form_post':
            fields = ''.join(f'<input type="hidden" name="{k}" value="{v}">' for k, v in params.items())
            return html(
                f'<body onload="document.forms[0].submit()"><form method="post" action="{REDIRECT_URI}">{fields}</form>'
            )
        return httpx.Response(302, headers={'location': f'{REDIRECT_URI}?{urlencode(params)}'})

    def login_page(self, error: str = '') -> httpx.Response:
        return html(
            (f'<div class="alert alert-danger">{error}</div>' if error else '')
            + '<form method="post" action="/login"><input type="hidden" name="txn" value="t-1">'
            '<input name="username" autocomplete="username"><input type="password" name="password">'
            '<button type="submit">Sign in</button></form>'
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.host == 'localhost':
            self.callback_hits += 1
            return httpx.Response(502)
        if url.path == '/.well-known/openid-configuration':
            return httpx.Response(
                200,
                json={
                    'issuer': ISSUER,
                    'authorization_endpoint': f'{ISSUER}/authorize',
                    'token_endpoint': f'{ISSUER}/token',
                },
            )
        if url.path == '/authorize':
            q = dict(url.params)
            assert q['response_type'] == 'code' and q['code_challenge_method'] == 'S256', q
            assert q['redirect_uri'] == REDIRECT_URI and q['client_id'] == 'cli-1', q
            assert 'openid' in q['scope'].split(), q
            self.pending = q
            if self.existing_session:
                return self.finish()
            return httpx.Response(302, headers={'location': '/login?txn=t-1', 'set-cookie': 'op_txn=t-1; Path=/'})
        if url.path == '/login' and request.method == 'GET':
            return self.login_page()
        if url.path == '/login':
            self.login_posts += 1
            data = form_data(request)
            if 'op_txn=t-1' not in request.headers.get('cookie', ''):
                return httpx.Response(400, text='no transaction')
            if (data.get('username'), data.get('password')) != ('svc', 'pw'):
                return self.login_page('Invalid username or password.')
            if self.totp:
                return httpx.Response(303, headers={'location': '/mfa'})
            return self.finish()
        if url.path == '/mfa' and request.method == 'GET':
            return html(
                '<form method="post" action="/mfa"><input name="otp" autocomplete="one-time-code">'
                '<button>Verify</button></form>'
            )
        if url.path == '/mfa':
            if not self.totp.verify(form_data(request).get('otp', '')):
                return html(
                    '<p role="alert">Wrong code.</p>'
                    '<form method="post" action="/mfa"><input name="otp"><button>Verify</button></form>'
                )
            return self.finish()
        if url.path == '/token':
            return self.token(form_data(request))
        return httpx.Response(404)

    def token(self, data: dict) -> httpx.Response:
        grant = self.codes.pop(data.get('code'), None)
        if (
            grant is None
            or data.get('grant_type') != 'authorization_code'
            or data.get('redirect_uri') != REDIRECT_URI
            or data.get('client_id') != 'cli-1'
            or (self.client_secret and data.get('client_secret') != self.client_secret)
        ):
            return httpx.Response(400, json={'error': 'invalid_grant', 'error_description': 'bad code'})
        digest = base64.urlsafe_b64encode(hashlib.sha256(data.get('code_verifier', '').encode()).digest())
        if digest.rstrip(b'=').decode() != grant['code_challenge']:
            return httpx.Response(400, json={'error': 'invalid_grant', 'error_description': 'PKCE verification failed'})
        id_token = '.'.join(
            base64.urlsafe_b64encode(json.dumps(part).encode()).rstrip(b'=').decode()
            for part in ({'alg': 'none'}, {'sub': 'svc', 'nonce': grant['nonce']})
        )
        return httpx.Response(
            200,
            json={
                'access_token': 'at-1',
                'id_token': id_token + '.',
                'refresh_token': 'rt-1',
                'token_type': 'Bearer',
                'expires_in': 3600,
                'scope': grant['scope'],
            },
        )

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


class TestGenericOidc(unittest.IsolatedAsyncioTestCase):
    BASE: ClassVar = {
        'issuer': ISSUER,
        'client_id': 'cli-1',
        'redirect_uri': REDIRECT_URI,
        'username': 'svc',
        'password': 'pw',
    }

    async def run_oidc(self, op: FakeOpenIdProvider, **overrides):
        async with httpx.AsyncClient(transport=op.transport()) as client:
            return await login('generic_oidc', {**self.BASE, **overrides}, client=client, clock=CLOCK)

    async def test_discovery_login_and_token_exchange(self):
        op = FakeOpenIdProvider()
        result = await self.run_oidc(op)
        self.assertEqual(result.outputs['access_token'], 'at-1')
        self.assertEqual(result.outputs['refresh_token'], 'rt-1')
        self.assertEqual(result.outputs['token_type'], 'Bearer')
        self.assertTrue(result.outputs['id_token'])
        self.assertEqual(op.callback_hits, 0)

    async def test_explicit_endpoints_without_discovery(self):
        op = FakeOpenIdProvider()
        result = await self.run_oidc(
            op, issuer=None, authorize_url=f'{ISSUER}/authorize', token_url=f'{ISSUER}/token', scope='openid profile'
        )
        self.assertEqual(result.outputs['scope'], 'openid profile')

    async def test_totp(self):
        result = await self.run_oidc(FakeOpenIdProvider(totp_secret=TOTP_SECRET), totp_secret=TOTP_SECRET)
        self.assertEqual(result.outputs['access_token'], 'at-1')

    async def test_form_post_response_mode(self):
        op = FakeOpenIdProvider(response_mode='form_post')
        result = await self.run_oidc(op)
        self.assertEqual(result.outputs['access_token'], 'at-1')
        self.assertEqual(op.callback_hits, 0)

    async def test_existing_session_skips_the_login_page(self):
        op = FakeOpenIdProvider(existing_session=True)
        result = await self.run_oidc(op)
        self.assertEqual(result.outputs['access_token'], 'at-1')
        self.assertEqual(op.login_posts, 0)

    async def test_confidential_client(self):
        op = FakeOpenIdProvider(client_secret='cs-1')
        result = await self.run_oidc(op, client_secret='cs-1')
        self.assertEqual(result.outputs['access_token'], 'at-1')
        self.assertNotIn('cs-1', json.dumps(result.vars, default=str))

    async def test_wrong_password(self):
        op = FakeOpenIdProvider()
        with self.assertRaises(LoginError) as ctx:
            await self.run_oidc(op, password='nope')
        self.assertEqual(ctx.exception.reason, 'rejected')
        self.assertIn('Invalid username or password.', str(ctx.exception))
        self.assertEqual(op.login_posts, 1)

    async def test_access_denied(self):
        with self.assertRaises(LoginError) as ctx:
            await self.run_oidc(FakeOpenIdProvider(deny=True))
        self.assertEqual(ctx.exception.reason, 'rejected')
        self.assertIn('access_denied', str(ctx.exception))
        self.assertIn('not assigned', str(ctx.exception))

    async def test_state_mismatch(self):
        with self.assertRaises(LoginError) as ctx:
            await self.run_oidc(FakeOpenIdProvider(tamper_state=True))
        self.assertEqual(ctx.exception.reason, 'flow')
        self.assertIn('state', str(ctx.exception))

    async def test_token_exchange_failure(self):
        op = FakeOpenIdProvider(client_secret='cs-1')
        with self.assertRaises(LoginError) as ctx:
            await self.run_oidc(op, client_secret='wrong')
        self.assertIn('invalid_grant', str(ctx.exception))
        self.assertEqual(ctx.exception.status_code, 400)

    async def test_needs_issuer_or_endpoints(self):
        with self.assertRaises(LoginError):
            await self.run_oidc(FakeOpenIdProvider(), issuer=None)

    def test_sync(self):
        op = FakeOpenIdProvider()
        with httpx.Client(transport=op.transport()) as client:
            result = login_sync('generic_oidc', self.BASE, client=client)
        self.assertEqual(result.outputs['access_token'], 'at-1')


if __name__ == '__main__':
    unittest.main()
