import base64
import json
import unittest
from typing import ClassVar

import httpx
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

from idp_auth import Engine, LoginError, Recipe, RecipeError
from idp_auth.factors.webauthn import Credential, b64url_encode
from test.mock_idp import GenericIdp, JsonMfaIdp

TOTP_SECRET = base64.b32encode(b'12345678901234567890').decode()
CLOCK = lambda: 1_700_000_000.0  # noqa: E731

AUTHN_RECIPE = {
    'name': 'json-authn',
    'inputs': {
        'base': {},
        'username': {},
        'password': {'secret': True},
        'totp_secret': {'secret': True, 'default': None},
    },
    'steps': [
        {
            'request': {
                'method': 'POST',
                'url': '${base}/api/authn',
                'json': {'username': '${username}', 'password': '${password}'},
            },
            'extract': [{'name': 'authn', 'from': 'json'}],
        },
        {'fail': 'authentication failed: ${authn.errorSummary}', 'when': {'not_exists': '${authn.status}'}},
        {
            'when': {'equals': ['${authn.status}', 'MFA_REQUIRED']},
            'mfa': {'factor': 'totp', 'secret': '${totp_secret}', 'into': 'code'},
        },
        {
            'when': {'equals': ['${authn.status}', 'MFA_REQUIRED']},
            'request': {
                'method': 'POST',
                'url': '${base}/api/authn/factors/totp/verify',
                'json': {'stateToken': '${authn.stateToken}', 'passCode': '${code}'},
            },
            'extract': [{'name': 'authn', 'from': 'json'}],
        },
        {'fail': 'mfa failed: ${authn.errorSummary}', 'when': {'not_equals': ['${authn.status}', 'SUCCESS']}},
    ],
    'outputs': {'session_token': '${authn.sessionToken}'},
}


def client_for(transport: httpx.BaseTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=transport, follow_redirects=True)


class TestRecipeValidation(unittest.TestCase):
    def test_unknown_action(self):
        with self.assertRaises(RecipeError):
            Recipe.from_dict({'name': 'x', 'steps': [{'teleport': {}}]})

    def test_two_actions_in_one_step(self):
        with self.assertRaises(RecipeError):
            Recipe.from_dict({'name': 'x', 'steps': [{'set': {'a': 1}, 'sleep': 1}]})

    def test_nested_loop_steps_validated(self):
        with self.assertRaises(RecipeError):
            Recipe.from_dict({'name': 'x', 'steps': [{'loop': {'until': {'exists': '${a}'}, 'steps': [{'bogus': 1}]}}]})

    def test_missing_required_input(self):
        recipe = Recipe.from_dict({'name': 'x', 'inputs': {'a': {}}, 'steps': []})
        with self.assertRaises(RecipeError):
            recipe.bind_inputs({})

    def test_unknown_input_rejected(self):
        recipe = Recipe.from_dict({'name': 'x', 'inputs': {'a': {}}, 'steps': []})
        with self.assertRaises(RecipeError):
            recipe.bind_inputs({'a': 1, 'typo': 2})

    def test_defaults_applied(self):
        recipe = Recipe.from_dict({'name': 'x', 'inputs': {'a': {'default': 5}}, 'steps': []})
        self.assertEqual(recipe.bind_inputs({}), {'a': 5})


class TestHtmlFlows(unittest.IsolatedAsyncioTestCase):
    RECIPE: ClassVar = {
        'name': 'form-login',
        'inputs': {'start_url': {}, 'username': {}, 'password': {'secret': True}},
        'steps': [
            {'request': {'url': '${start_url}'}},
            {'submit_form': {'credentials': {'username': '${username}', 'password': '${password}'}}},
        ],
    }

    async def test_follows_redirects_js_and_saml_post_into_sp(self):
        idp = GenericIdp()
        async with client_for(idp.transport()) as client:
            result = await Engine(client).run(
                Recipe.from_dict(self.RECIPE),
                {'start_url': 'https://sp.example.com/app', 'username': 'svc', 'password': 'pw'},
            )
        self.assertEqual(result.saml.response, 'PHNhbWxwOlJlc3BvbnNlLz4=')
        self.assertEqual(result.saml.relay_state, 'rs-1')
        self.assertEqual(result.saml.acs_url, 'https://sp.example.com/acs')
        self.assertIn('Welcome svc', result.response.text)
        self.assertEqual(idp.sp.acs_hits, 1)
        self.assertEqual(result.cookies.get('sp_session', domain='sp.example.com'), 'ok')

    async def test_stop_before_delivering_assertion(self):
        recipe = json.loads(json.dumps(self.RECIPE))
        recipe['steps'][1]['follow'] = {'deliver_saml': False}
        idp = GenericIdp()
        async with client_for(idp.transport()) as client:
            result = await Engine(client).run(
                Recipe.from_dict(recipe),
                {'start_url': 'https://sp.example.com/app', 'username': 'svc', 'password': 'pw'},
            )
        self.assertEqual(result.saml.response, 'PHNhbWxwOlJlc3BvbnNlLz4=')
        self.assertEqual(idp.sp.acs_hits, 0)

    async def test_submit_form_without_form_fails_cleanly(self):
        recipe = Recipe.from_dict(
            {'name': 'x', 'inputs': {'u': {}}, 'steps': [{'request': {'url': '${u}'}}, {'submit_form': {}}]}
        )
        transport = httpx.MockTransport(lambda r: httpx.Response(200, text='<p>no form</p>'))
        async with client_for(transport) as client:
            with self.assertRaises(LoginError) as ctx:
                await Engine(client).run(recipe, {'u': 'https://x.example/'})
        self.assertEqual(ctx.exception.step, 2)


class TestJsonAndMfa(unittest.IsolatedAsyncioTestCase):
    async def run_authn(self, **overrides):
        idp = JsonMfaIdp(TOTP_SECRET, clock=CLOCK)
        inputs = {'base': 'https://idp.example.com', 'username': 'svc', 'password': 'pw', 'totp_secret': TOTP_SECRET}
        inputs.update(overrides)
        async with client_for(idp.transport()) as client:
            return await Engine(client, clock=CLOCK).run(Recipe.from_dict(AUTHN_RECIPE), inputs)

    async def test_totp_factor(self):
        result = await self.run_authn()
        self.assertEqual(result.outputs, {'session_token': 'sess-tok'})

    async def test_wrong_totp_secret_fails(self):
        with self.assertRaises(LoginError) as ctx:
            await self.run_authn(totp_secret=base64.b32encode(b'x' * 20).decode())
        self.assertIn('bad code', str(ctx.exception))

    async def test_bad_password_message_and_redaction(self):
        with self.assertRaises(LoginError) as ctx:
            await self.run_authn(password='hunter2-wrong')
        self.assertIn('Authentication failed', str(ctx.exception))
        self.assertNotIn('hunter2-wrong', str(ctx.exception))

    async def test_secret_redacted_from_fail_messages(self):
        recipe = Recipe.from_dict({'name': 'x', 'inputs': {'pw': {'secret': True}}, 'steps': [{'fail': 'oops ${pw}'}]})
        async with client_for(httpx.MockTransport(lambda r: httpx.Response(200))) as client:
            with self.assertRaises(LoginError) as ctx:
                await Engine(client).run(recipe, {'pw': 'topsecret'})
        self.assertNotIn('topsecret', str(ctx.exception))

    async def test_push_poll_loop(self):
        idp = JsonMfaIdp(TOTP_SECRET, clock=CLOCK, push_pending_polls=2)
        recipe = Recipe.from_dict(
            {
                'name': 'push',
                'steps': [
                    {
                        'loop': {
                            'max': 5,
                            'until': {'equals': ['${authn.status}', 'SUCCESS']},
                            'steps': [
                                {'sleep': 0},
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
        async with client_for(idp.transport()) as client:
            result = await Engine(client).run(recipe, {})
        self.assertEqual(result.outputs['token'], 'push-tok')
        self.assertEqual(idp.polls, 3)

    async def test_loop_exhaustion(self):
        recipe = Recipe.from_dict(
            {
                'name': 'x',
                'steps': [{'loop': {'max': 2, 'until': {'exists': '${never}'}, 'steps': [{'set': {'a': 1}}]}}],
            }
        )
        async with client_for(httpx.MockTransport(lambda r: httpx.Response(200))) as client:
            with self.assertRaises(LoginError):
                await Engine(client).run(recipe, {})


class TestWebauthnFactor(unittest.IsolatedAsyncioTestCase):
    async def test_assertion_accepted_by_relying_party(self):
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
            if request.url.path == '/verify':
                rp.authenticate_complete(pending['state'], [stored], json.loads(request.content))
                return httpx.Response(200, json={'status': 'SUCCESS'})
            return httpx.Response(404)

        stored_cred = cred.to_dict()
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
        async with client_for(httpx.MockTransport(handler)) as client:
            result = await Engine(client).run(recipe, {'credential': stored_cred})
        self.assertEqual(result.outputs['status'], 'SUCCESS')
        # the caller's stored credential dict reflects the new signature counter
        self.assertEqual(stored_cred['sign_count'], 1)


if __name__ == '__main__':
    unittest.main()
