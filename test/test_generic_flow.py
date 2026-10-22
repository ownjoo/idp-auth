"""The bundled generic_saml recipe against IdPs shaped like common server-rendered products."""

import base64
import unittest
from typing import ClassVar

import httpx

from idp_auth import LoginError, login, login_sync, saml_response
from test.mock_idp import GenericIdp
from test.mock_idp_generic import AdfsLikeIdp, IdentifierFirstIdp, ShibbolethLikeIdp

SP_APP = 'https://sp.example.com/app'
TOTP_SECRET = base64.b32encode(b'12345678901234567890').decode()
CLOCK = lambda: 1_700_000_000.0  # noqa: E731


def client_for(idp) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=idp.transport(), follow_redirects=True)


class TestShibbolethShape(unittest.IsolatedAsyncioTestCase):
    async def test_login_through_consent(self):
        idp = ShibbolethLikeIdp()
        async with client_for(idp) as client:
            result = await login(
                'generic_saml', {'start_url': SP_APP, 'username': 'svc', 'password': 'pw'}, client=client
            )
        self.assertIn('Welcome svc', result.response.text)
        self.assertEqual(idp.login_posts, 1)

    async def test_wrong_password_fails_fast_with_idp_message(self):
        idp = ShibbolethLikeIdp()
        async with client_for(idp) as client:
            with self.assertRaises(LoginError) as ctx:
                await login(
                    'generic_saml', {'start_url': SP_APP, 'username': 'svc', 'password': 'wrong-pw'}, client=client
                )
        self.assertIn('The password you entered was incorrect.', str(ctx.exception))
        self.assertNotIn('wrong-pw', str(ctx.exception))
        self.assertEqual(idp.login_posts, 1)

    def test_sync(self):
        idp = ShibbolethLikeIdp()
        with httpx.Client(transport=idp.transport(), follow_redirects=True) as client:
            result = login_sync(
                'generic_saml', {'start_url': SP_APP, 'username': 'svc', 'password': 'pw'}, client=client
            )
        self.assertTrue(result.saml.response)


class TestAdfsShape(unittest.IsolatedAsyncioTestCase):
    INPUTS: ClassVar = {'start_url': SP_APP, 'username': 'svc@example.com', 'password': 'pw'}

    async def run_login(self, idp, **extra):
        async with client_for(idp) as client:
            return await login('generic_saml', {**self.INPUTS, **extra}, client=client, clock=CLOCK)

    async def test_password_then_totp(self):
        idp = AdfsLikeIdp(TOTP_SECRET, clock=CLOCK)
        result = await self.run_login(idp, totp_secret=TOTP_SECRET)
        self.assertIn('Welcome svc', result.response.text)
        self.assertEqual(idp.otp_posts, 1)

    async def test_assertion_only_with_totp(self):
        idp = AdfsLikeIdp(TOTP_SECRET, clock=CLOCK)
        async with client_for(idp) as client:
            value = await saml_response(
                'generic_saml', {**self.INPUTS, 'totp_secret': TOTP_SECRET}, client=client, clock=CLOCK
            )
        self.assertTrue(value)
        self.assertEqual(idp.sp.acs_hits, 0)

    async def test_otp_page_without_secret_fails_clearly(self):
        with self.assertRaises(LoginError) as ctx:
            await self.run_login(AdfsLikeIdp(TOTP_SECRET, clock=CLOCK))
        self.assertIn('one-time code', str(ctx.exception))

    async def test_wrong_totp_secret_fails_fast(self):
        idp = AdfsLikeIdp(TOTP_SECRET, clock=CLOCK)
        with self.assertRaises(LoginError) as ctx:
            await self.run_login(idp, totp_secret=base64.b32encode(b'y' * 20).decode())
        self.assertIn('The code you entered is not valid.', str(ctx.exception))
        self.assertEqual(idp.otp_posts, 1)

    async def test_wrong_password(self):
        with self.assertRaises(LoginError) as ctx:
            await self.run_login(AdfsLikeIdp(TOTP_SECRET, clock=CLOCK), password='nope')
        self.assertIn('Incorrect user ID or password', str(ctx.exception))


class TestOtherShapes(unittest.IsolatedAsyncioTestCase):
    async def test_identifier_first(self):
        async with client_for(IdentifierFirstIdp()) as client:
            result = await login(
                'generic_saml', {'start_url': SP_APP, 'username': 'svc@example.com', 'password': 'pw'}, client=client
            )
        self.assertIn('Welcome svc', result.response.text)

    async def test_original_generic_idp_still_works(self):
        async with client_for(GenericIdp()) as client:
            result = await login(
                'generic_saml', {'start_url': SP_APP, 'username': 'svc', 'password': 'pw'}, client=client
            )
        self.assertIn('Welcome svc', result.response.text)

    async def test_original_generic_idp_wrong_password_fails_fast(self):
        idp = GenericIdp()
        async with client_for(idp) as client:
            with self.assertRaises(LoginError) as ctx:
                await login('generic_saml', {'start_url': SP_APP, 'username': 'svc', 'password': 'x'}, client=client)
        self.assertEqual(idp.login_posts, 1)
        self.assertIn('rejected', str(ctx.exception))

    async def test_javascript_only_page_names_the_problem(self):
        transport = httpx.MockTransport(
            lambda r: httpx.Response(200, text='<div id="root"></div><script src="/app.js"></script>')
        )
        async with httpx.AsyncClient(transport=transport) as client:
            with self.assertRaises(LoginError) as ctx:
                await login(
                    'generic_saml',
                    {'start_url': 'https://spa.example/', 'username': 'u', 'password': 'p'},
                    client=client,
                )
        self.assertIn('no login form', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
