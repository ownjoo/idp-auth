"""Code-review follow-ups: drop credential headers on cross-origin redirects, scrub derived secrets,
broaden logout detection, and make cookies_for work with any cookie jar."""

import http.cookiejar
import unittest

import httpx

from idp_auth import AsyncEngine, LoginResult, Recipe, SamlCapture
from idp_auth.html import Page

URL = 'https://idp.example.com/x'


def mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestRedirectHeaderDropping(unittest.IsolatedAsyncioTestCase):
    async def seen_auth_for(self, location: str, status: int = 302, method: str = 'GET'):
        auth_on = {}

        def handler(request: httpx.Request) -> httpx.Response:
            auth_on[request.url.host] = request.headers.get('authorization')
            if request.url.host == 'idp.example.com' and request.url.path == '/start':
                return httpx.Response(status, headers={'location': location})
            return httpx.Response(200, text='done')

        recipe = Recipe.from_dict(
            {
                'name': 'x',
                'steps': [
                    {
                        'request': {
                            'method': method,
                            'url': 'https://idp.example.com/start',
                            'headers': {'Authorization': 'Bearer t-1', 'X-Trace': 'keep'},
                        }
                    }
                ],
            }
        )
        async with mock_client(handler) as client:
            await AsyncEngine(client).run(recipe, {})
        return auth_on

    async def test_authorization_dropped_crossing_origin(self):
        auth = await self.seen_auth_for('https://other.example.com/next')
        self.assertEqual(auth['idp.example.com'], 'Bearer t-1')
        self.assertIsNone(auth['other.example.com'])

    async def test_authorization_kept_same_origin(self):
        auth = await self.seen_auth_for('https://idp.example.com/next')
        self.assertEqual(auth['idp.example.com'], 'Bearer t-1')

    async def test_non_credential_headers_kept_cross_origin(self):
        traces = {}

        def handler(request: httpx.Request) -> httpx.Response:
            traces[request.url.host] = request.headers.get('x-trace')
            if request.url.host == 'idp.example.com':
                return httpx.Response(302, headers={'location': 'https://other.example.com/next'})
            return httpx.Response(200)

        recipe = Recipe.from_dict(
            {
                'name': 'x',
                'steps': [
                    {
                        'request': {
                            'url': 'https://idp.example.com/start',
                            'headers': {'Authorization': 'Bearer t', 'X-Trace': 'keep'},
                        }
                    }
                ],
            }
        )
        async with mock_client(handler) as client:
            await AsyncEngine(client).run(recipe, {})
        self.assertEqual(traces['other.example.com'], 'keep')


class TestDerivedSecretScrubbing(unittest.IsolatedAsyncioTestCase):
    async def run_recipe(self, recipe: dict, inputs: dict):
        async with mock_client(lambda r: httpx.Response(200, json={'ok': True})) as client:
            return await AsyncEngine(client).run(Recipe.from_dict(recipe), inputs)

    async def test_pkce_verifier_scrubbed(self):
        result = await self.run_recipe(
            {'name': 'x', 'steps': [{'pkce': {'into': 'p'}}, {'request': {'url': 'https://x.example/'}}]}, {}
        )
        p = result.vars['p']
        self.assertEqual(p['verifier'], '***')
        self.assertNotEqual(p['challenge'], '***')  # public value stays

    async def test_client_assertion_scrubbed(self):
        from test.test_client_credentials import RSA_KEY, pem

        recipe = {
            'name': 'x',
            'inputs': {'pk': {'secret': True}},
            'steps': [
                {
                    'client_assertion': {
                        'into': 'a',
                        'client_id': 'c',
                        'audience': 'https://x/t',
                        'private_key': '${pk}',
                    }
                },
                {'request': {'url': 'https://x.example/'}},
            ],
        }
        result = await self.run_recipe(recipe, {'pk': pem(RSA_KEY)})
        self.assertEqual(result.vars['a'], '***')


class TestLogoutDetection(unittest.TestCase):
    def auto(self, body: str):
        return Page(body, URL).auto_navigation()

    def test_action_logout_not_followed(self):
        body = (
            '<body onload="document.forms[0].submit()"><form action="/logout">'
            '<input type="hidden" name="a" value="1"></form></body>'
        )
        self.assertIsNone(self.auto(body))

    def test_wsfed_signout_field_not_followed(self):
        body = (
            '<body onload="document.forms[0].submit()"><form action="/wsfed">'
            '<input type="hidden" name="wa" value="wsignout1.0"></form></body>'
        )
        self.assertIsNone(self.auto(body))

    def test_ordinary_federation_post_still_followed(self):
        body = (
            '<body onload="document.forms[0].submit()"><form action="https://sp.example/acs">'
            '<input type="hidden" name="SAMLResponse" value="x"></form></body>'
        )
        nav = self.auto(body)
        self.assertIsNotNone(nav)
        self.assertEqual(nav.url, 'https://sp.example/acs')


class TestCookiesForAnyJar(unittest.TestCase):
    def _result(self, cookies) -> LoginResult:
        return LoginResult(outputs={}, vars={}, saml=SamlCapture(), response=None, page=None, cookies=cookies)

    def test_httpx_cookies(self):
        jar = httpx.Cookies()
        jar.set('a', '1', domain='app.example.com')
        scoped = self._result(jar).cookies_for('app.example.com')
        self.assertEqual(scoped.get('a'), '1')

    def test_stdlib_cookiejar(self):
        # hand over a raw http.cookiejar.CookieJar, as a requests session exposes
        hx = httpx.Cookies()
        hx.set('a', '1', domain='app.example.com')
        hx.set('b', '2', domain='other.example.com')
        self.assertIsInstance(hx.jar, http.cookiejar.CookieJar)
        scoped = self._result(hx.jar).cookies_for('app.example.com')
        self.assertEqual(scoped.get('a'), '1')
        self.assertEqual(list(scoped.keys()), ['a'])

    def test_unusable_cookies_raise(self):
        with self.assertRaises(TypeError):
            self._result(object()).cookies_for('app.example.com')


if __name__ == '__main__':
    unittest.main()
