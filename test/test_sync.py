"""The sync driver must behave exactly like the async one; these mirror the async engine/recipe tests."""

import json
import unittest

import httpx
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

from idp_auth import LoginError, Recipe, SyncEngine, login_sync
from idp_auth.factors.webauthn import Credential, b64url_encode
from test.mock_idp import EntraLikeIdp, GenericIdp, JsonMfaIdp
from test.test_engine import AUTHN_RECIPE, CLOCK, TOTP_SECRET

SP_APP = 'https://sp.example.com/app'


def client_for(transport: httpx.BaseTransport) -> httpx.Client:
    return httpx.Client(transport=transport, follow_redirects=True)


class TestSyncHtmlFlows(unittest.TestCase):
    def test_generic_saml_into_sp(self):
        idp = GenericIdp()
        with client_for(idp.transport()) as client:
            result = login_sync(
                'generic_saml', {'start_url': SP_APP, 'username': 'svc', 'password': 'pw'}, client=client
            )
        self.assertEqual(result.saml.relay_state, 'rs-1')
        self.assertIn('Welcome svc', result.response.text)
        self.assertEqual(result.cookies.get('sp_session', domain='sp.example.com'), 'ok')

    def test_assertion_only(self):
        idp = GenericIdp()
        with client_for(idp.transport()) as client:
            result = login_sync(
                'generic_saml',
                {'start_url': SP_APP, 'username': 'svc', 'password': 'pw', 'deliver_assertion': False},
                client=client,
            )
        self.assertTrue(result.saml.response)
        self.assertEqual(idp.sp.acs_hits, 0)

    def test_entra(self):
        idp = EntraLikeIdp()
        with client_for(idp.transport()) as client:
            result = login_sync(
                'entra_saml', {'start_url': SP_APP, 'username': 'svc@example.com', 'password': 'pw'}, client=client
            )
        self.assertIn('Welcome svc', result.response.text)

    def test_entra_error_code(self):
        idp = EntraLikeIdp()
        with client_for(idp.transport()) as client, self.assertRaises(LoginError) as ctx:
            login_sync(
                'entra_saml', {'start_url': SP_APP, 'username': 'svc@example.com', 'password': 'x'}, client=client
            )
        self.assertIn('50126', str(ctx.exception))


class TestSyncJsonAndMfa(unittest.TestCase):
    def test_totp(self):
        idp = JsonMfaIdp(TOTP_SECRET, clock=CLOCK)
        inputs = {'base': 'https://idp.example.com', 'username': 'svc', 'password': 'pw', 'totp_secret': TOTP_SECRET}
        with client_for(idp.transport()) as client:
            result = SyncEngine(client, clock=CLOCK).run(Recipe.from_dict(AUTHN_RECIPE), inputs)
        self.assertEqual(result.outputs, {'session_token': 'sess-tok'})

    def test_bad_password_redacted(self):
        idp = JsonMfaIdp(TOTP_SECRET, clock=CLOCK)
        inputs = {'base': 'https://idp.example.com', 'username': 'svc', 'password': 'hunter2-x', 'totp_secret': None}
        with client_for(idp.transport()) as client, self.assertRaises(LoginError) as ctx:
            SyncEngine(client, clock=CLOCK).run(Recipe.from_dict(AUTHN_RECIPE), inputs)
        self.assertNotIn('hunter2-x', str(ctx.exception))

    def test_push_poll_uses_sync_sleep(self):
        idp = JsonMfaIdp(TOTP_SECRET, clock=CLOCK, push_pending_polls=2)
        slept = []
        recipe = Recipe.from_dict(
            {
                'name': 'push',
                'steps': [
                    {
                        'loop': {
                            'max': 5,
                            'until': {'equals': ['${authn.status}', 'SUCCESS']},
                            'steps': [
                                {'sleep': 2},
                                {
                                    'request': {
                                        'method': 'POST',
                                        'url': 'https://idp.example.com/api/authn/factors/push/verify',
                                        'json': {},
                                    },
                                    'extract': [{'name': 'authn', 'from': 'json'}],
                                },
                            ],
                        }
                    }
                ],
                'outputs': {'token': '${authn.sessionToken}'},
            }
        )
        with client_for(idp.transport()) as client:
            result = SyncEngine(client, sleep=slept.append).run(recipe, {})
        self.assertEqual(result.outputs['token'], 'push-tok')
        self.assertEqual(slept, [2.0, 2.0, 2.0])

    def test_webauthn(self):
        rp = Fido2Server(PublicKeyCredentialRpEntity(name='Example', id='idp.example.com'))
        cred = Credential.create(rp_id='idp.example.com', user_handle=b'u1')
        options, state = rp.register_begin(PublicKeyCredentialUserEntity(id=b'u1', name='svc', display_name='svc'))
        stored = rp.register_complete(
            state, cred.registration(options.public_key.challenge, 'https://idp.example.com')
        ).credential_data
        pending = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == '/challenge':
                opts, pending['state'] = rp.authenticate_begin([stored])
                return httpx.Response(200, json={'challenge': b64url_encode(opts.public_key.challenge)})
            rp.authenticate_complete(pending['state'], [stored], json.loads(request.content))
            return httpx.Response(200, json={'status': 'SUCCESS'})

        recipe = Recipe.from_dict(
            {
                'name': 'webauthn',
                'inputs': {'credential': {'secret': True}},
                'steps': [
                    {
                        'request': {'url': 'https://idp.example.com/challenge'},
                        'extract': [{'name': 'ch', 'from': 'json'}],
                    },
                    {
                        'mfa': {
                            'factor': 'webauthn',
                            'credential': '${credential}',
                            'challenge': '${ch.challenge}',
                            'origin': 'https://idp.example.com',
                            'into': 'assertion',
                        }
                    },
                    {
                        'request': {'method': 'POST', 'url': 'https://idp.example.com/verify', 'json': '${assertion}'},
                        'extract': [{'name': 'status', 'from': 'json', 'path': 'status'}],
                    },
                ],
                'outputs': {'status': '${status}'},
            }
        )
        stored_cred = cred.to_dict()
        with client_for(httpx.MockTransport(handler)) as client:
            result = SyncEngine(client).run(recipe, {'credential': stored_cred})
        self.assertEqual(result.outputs['status'], 'SUCCESS')
        self.assertEqual(stored_cred['sign_count'], 1)


class TestSyncTransportErrors(unittest.TestCase):
    def test_http_error_becomes_login_error_without_query(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError('refused', request=request)

        recipe = Recipe.from_dict({'name': 'x', 'steps': [{'request': {'url': 'https://down.example/p?token=abc'}}]})
        with client_for(httpx.MockTransport(handler)) as client, self.assertRaises(LoginError) as ctx:
            SyncEngine(client).run(recipe, {})
        self.assertEqual(ctx.exception.step, 1)
        self.assertIn('ConnectError', str(ctx.exception))
        self.assertIn('https://down.example/p', str(ctx.exception))
        self.assertNotIn('token=abc', str(ctx.exception))

    def test_rejects_async_client(self):
        with self.assertRaises(TypeError):
            SyncEngine(httpx.AsyncClient())


class TestSyncInsideEventLoop(unittest.IsolatedAsyncioTestCase):
    async def test_login_sync_works_while_a_loop_is_running(self):
        idp = GenericIdp()
        with client_for(idp.transport()) as client:
            result = login_sync(
                'generic_saml', {'start_url': SP_APP, 'username': 'svc', 'password': 'pw'}, client=client
            )
        self.assertTrue(result.saml.response)


if __name__ == '__main__':
    unittest.main()
