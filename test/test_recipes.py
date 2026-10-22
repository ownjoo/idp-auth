import unittest

import httpx

from idp_auth import LoginError, Recipe, login
from test.mock_idp import EntraLikeIdp, GenericIdp


def client_for(idp) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=idp.transport(), follow_redirects=True)


class TestBundledRecipes(unittest.TestCase):
    def test_bundled_recipes_load(self):
        for name in Recipe.bundled():
            self.assertEqual(Recipe.load(name).name, name)

    def test_unknown_bundled_recipe(self):
        with self.assertRaises(FileNotFoundError):
            Recipe.load('no-such-idp')


class TestGenericSaml(unittest.IsolatedAsyncioTestCase):
    async def test_login(self):
        idp = GenericIdp()
        async with client_for(idp) as client:
            result = await login(
                'generic_saml',
                {'start_url': 'https://sp.example.com/app', 'username': 'svc', 'password': 'pw'},
                client=client,
            )
        self.assertTrue(result.saml.response)
        self.assertIn('Welcome svc', result.response.text)

    async def test_assertion_only(self):
        idp = GenericIdp()
        async with client_for(idp) as client:
            result = await login(
                'generic_saml',
                {
                    'start_url': 'https://sp.example.com/app',
                    'username': 'svc',
                    'password': 'pw',
                    'deliver_assertion': False,
                },
                client=client,
            )
        self.assertTrue(result.saml.response)
        self.assertEqual(idp.sp.acs_hits, 0)

    async def test_bad_password(self):
        idp = GenericIdp()
        async with client_for(idp) as client:
            with self.assertRaises(LoginError):
                await login(
                    'generic_saml',
                    {'start_url': 'https://sp.example.com/app', 'username': 'svc', 'password': 'nope'},
                    client=client,
                )
        self.assertLessEqual(idp.login_posts, 3)


class TestEntraSaml(unittest.IsolatedAsyncioTestCase):
    async def test_login_through_kmsi(self):
        idp = EntraLikeIdp()
        async with client_for(idp) as client:
            result = await login(
                'entra_saml',
                {'start_url': 'https://sp.example.com/app', 'username': 'svc@example.com', 'password': 'pw'},
                client=client,
            )
        self.assertEqual(result.saml.relay_state, 'rs-1')
        self.assertIn('Welcome svc', result.response.text)

    async def test_entra_error_code_surfaces(self):
        idp = EntraLikeIdp()
        async with client_for(idp) as client:
            with self.assertRaises(LoginError) as ctx:
                await login(
                    'entra_saml',
                    {'start_url': 'https://sp.example.com/app', 'username': 'svc@example.com', 'password': 'bad'},
                    client=client,
                )
        self.assertIn('50126', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
