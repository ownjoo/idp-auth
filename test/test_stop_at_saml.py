"""Caller-side 'stop at SAMLResponse': end the flow the moment an assertion appears and hand it back."""

import unittest

import httpx

from idp_auth import AsyncEngine, LoginError, Recipe, SyncEngine, login, login_sync, saml_response, saml_response_sync
from test.mock_idp import EntraLikeIdp, GenericIdp

SP_APP = 'https://sp.example.com/app'
CREDS = {'start_url': SP_APP, 'username': 'svc', 'password': 'pw'}
ASSERTION = 'PHNhbWxwOlJlc3BvbnNlLz4='

# Delivers the assertion (recipe default) and then keeps going; stop_at_saml must cut it short.
GREEDY_RECIPE = {
    'name': 'greedy',
    'inputs': {'start_url': {}, 'username': {}, 'password': {'secret': True}},
    'steps': [
        {'request': {'url': '${start_url}'}},
        {'submit_form': {'credentials': {'username': '${username}', 'password': '${password}'}}},
        {'request': {'url': 'https://sp.example.com/app'}},
        {'fail': 'steps after the assertion should not run'},
    ],
    'outputs': {'assertion': '${saml.response}'},
}

# SAMLResponse inside a form that also has a visible field, so it is never auto-submitted.
INTERACTIVE_PAGE = (
    '<form method="post" action="https://sp.example.com/acs">'
    f'<input type="hidden" name="SAMLResponse" value="{ASSERTION}">'
    '<input type="text" name="comment"><button>Continue</button></form>'
)


def interactive_transport() -> httpx.MockTransport:
    return httpx.MockTransport(lambda r: httpx.Response(200, text=INTERACTIVE_PAGE))


class TestStopAtSamlAsync(unittest.IsolatedAsyncioTestCase):
    async def test_engine_stops_before_delivery_and_later_steps(self):
        idp = GenericIdp()
        async with httpx.AsyncClient(transport=idp.transport(), follow_redirects=True) as client:
            result = await AsyncEngine(client, stop_at_saml=True).run(Recipe.from_dict(GREEDY_RECIPE), CREDS)
        self.assertEqual(result.saml.response, ASSERTION)
        self.assertEqual(result.saml.acs_url, 'https://sp.example.com/acs')
        self.assertEqual(result.outputs, {'assertion': ASSERTION})
        self.assertEqual(idp.sp.acs_hits, 0)

    async def test_without_flag_recipe_runs_to_the_end(self):
        idp = GenericIdp()
        async with httpx.AsyncClient(transport=idp.transport(), follow_redirects=True) as client:
            with self.assertRaises(LoginError):
                await AsyncEngine(client).run(Recipe.from_dict(GREEDY_RECIPE), CREDS)
        self.assertEqual(idp.sp.acs_hits, 1)

    async def test_login_flag_overrides_bundled_recipe_delivery(self):
        idp = EntraLikeIdp()
        async with httpx.AsyncClient(transport=idp.transport(), follow_redirects=True) as client:
            result = await login(
                'entra_saml',
                {'start_url': SP_APP, 'username': 'svc@example.com', 'password': 'pw'},
                client=client,
                stop_at_saml=True,
            )
        self.assertEqual(result.saml.response, ASSERTION)
        self.assertEqual(idp.sp.acs_hits, 0)

    async def test_saml_response_helper_returns_the_value(self):
        idp = GenericIdp()
        async with httpx.AsyncClient(transport=idp.transport(), follow_redirects=True) as client:
            self.assertEqual(await saml_response('generic_saml', CREDS, client=client), ASSERTION)
        self.assertEqual(idp.sp.acs_hits, 0)

    async def test_saml_found_on_a_non_auto_submitting_page(self):
        recipe = Recipe.from_dict(
            {'name': 'x', 'steps': [{'request': {'url': 'https://idp.example/'}}, {'fail': 'should have stopped'}]}
        )
        async with httpx.AsyncClient(transport=interactive_transport()) as client:
            self.assertEqual(await saml_response(recipe, {}, client=client), ASSERTION)

    async def test_saml_response_helper_raises_when_none_found(self):
        recipe = Recipe.from_dict({'name': 'x', 'steps': [{'request': {'url': 'https://idp.example/'}}]})
        transport = httpx.MockTransport(lambda r: httpx.Response(200, text='<p>no assertion</p>'))
        async with httpx.AsyncClient(transport=transport) as client:
            with self.assertRaises(LoginError):
                await saml_response(recipe, {}, client=client)


class TestStopAtSamlSync(unittest.TestCase):
    def test_engine_stops_before_delivery_and_later_steps(self):
        idp = GenericIdp()
        with httpx.Client(transport=idp.transport(), follow_redirects=True) as client:
            result = SyncEngine(client, stop_at_saml=True).run(Recipe.from_dict(GREEDY_RECIPE), CREDS)
        self.assertEqual(result.outputs, {'assertion': ASSERTION})
        self.assertEqual(idp.sp.acs_hits, 0)

    def test_login_sync_flag(self):
        idp = GenericIdp()
        with httpx.Client(transport=idp.transport(), follow_redirects=True) as client:
            result = login_sync('generic_saml', CREDS, client=client, stop_at_saml=True)
        self.assertEqual(result.saml.response, ASSERTION)
        self.assertEqual(idp.sp.acs_hits, 0)

    def test_saml_response_sync_helper(self):
        idp = EntraLikeIdp()
        with httpx.Client(transport=idp.transport(), follow_redirects=True) as client:
            value = saml_response_sync(
                'entra_saml', {'start_url': SP_APP, 'username': 'svc@example.com', 'password': 'pw'}, client=client
            )
        self.assertEqual(value, ASSERTION)
        self.assertEqual(idp.sp.acs_hits, 0)

    def test_saml_found_on_a_non_auto_submitting_page(self):
        recipe = Recipe.from_dict({'name': 'x', 'steps': [{'request': {'url': 'https://idp.example/'}}]})
        with httpx.Client(transport=interactive_transport()) as client:
            self.assertEqual(saml_response_sync(recipe, {}, client=client), ASSERTION)

    def test_saml_response_sync_raises_when_none_found(self):
        recipe = Recipe.from_dict({'name': 'x', 'steps': [{'request': {'url': 'https://idp.example/'}}]})
        transport = httpx.MockTransport(lambda r: httpx.Response(200, text='<p>none</p>'))
        with httpx.Client(transport=transport) as client, self.assertRaises(LoginError):
            saml_response_sync(recipe, {}, client=client)


if __name__ == '__main__':
    unittest.main()
