"""Hardening batch: URL params, meta data-url, script-submitted forms, rejection by field roles, structured
errors, pluggable drivers, redaction and cookie scoping."""

import json
import unittest
from urllib.parse import parse_qsl

import httpx

from idp_auth import AsyncEngine, Flow, HttpRequest, LoginError, Recipe, RecipeError, Sleep, SyncEngine, login
from idp_auth.html import Page
from test.mock_idp import EntraLikeIdp, html

SP_APP = 'https://sp.example.com/app'


def mock_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)


def form_data(request: httpx.Request) -> dict:
    return dict(parse_qsl(request.content.decode(), keep_blank_values=True))


class TestUrlParamExtraction(unittest.IsolatedAsyncioTestCase):
    async def run_extract(self, final_url: str, **rule):
        def handler(request):
            if request.url.path == '/start':
                return httpx.Response(302, headers={'location': final_url})
            return httpx.Response(200, text='ok')

        recipe = Recipe.from_dict(
            {
                'name': 'x',
                'steps': [{'request': {'url': 'https://idp.example/start'}, 'extract': [{'from': 'url', **rule}]}],
            }
        )
        async with mock_client(handler) as client:
            return (await AsyncEngine(client).run(recipe, {})).vars

    async def test_query_param_first_value(self):
        found = await self.run_extract('https://idp.example/x?flowId=f-1&flowId=f-2&a=1', name='flow', param='flowId')
        self.assertEqual(found['flow'], 'f-1')

    async def test_fragment_param(self):
        found = await self.run_extract('https://idp.example/cb#code=c-1&state=s', name='code', param='code')
        self.assertEqual(found['code'], 'c-1')

    async def test_missing_param_is_none(self):
        self.assertIsNone((await self.run_extract('https://idp.example/x?a=1', name='p', param='nope'))['p'])

    async def test_whole_url_without_param(self):
        found = await self.run_extract('https://idp.example/x?a=1', name='u')
        self.assertEqual(found['u'], 'https://idp.example/x?a=1')


class TestMetaDataUrl(unittest.TestCase):
    def test_data_url_wins(self):
        page = Page('<meta http-equiv="refresh" content="0" data-url="/pf/next?x=1">', 'https://pf.example/a/b')
        self.assertEqual(page.auto_navigation().url, 'https://pf.example/pf/next?x=1')


class TestScriptSubmittedHiddenForm(unittest.TestCase):
    HIDDEN = '<form method="post" action="/resume"><input type="hidden" name="state" value="s1"></form>'
    SCRIPT = '<script src="/static/autopost.js"></script>'

    def test_followed_when_it_is_all_the_page_has(self):
        nav = Page(self.HIDDEN + self.SCRIPT + '<p>Loading...</p>', 'https://idp.example/x').auto_navigation()
        self.assertEqual((nav.method, nav.url, nav.data), ('POST', 'https://idp.example/resume', {'state': 's1'}))

    def test_not_followed_without_any_script(self):
        self.assertIsNone(Page(self.HIDDEN, 'https://idp.example/x').auto_navigation())

    def test_not_followed_for_logout_forms(self):
        markup = self.HIDDEN.replace('/resume', '/logout') + self.SCRIPT
        self.assertIsNone(Page(markup, 'https://sp.example/app').auto_navigation())

    def test_not_followed_on_a_content_page(self):
        markup = self.HIDDEN + self.SCRIPT + '<main>' + 'Dashboard content. ' * 40 + '</main>'
        self.assertIsNone(Page(markup, 'https://sp.example/app').auto_navigation())

    def test_not_followed_when_other_forms_exist(self):
        markup = self.HIDDEN + self.SCRIPT + '<form action="/search"><input name="q"></form>'
        self.assertIsNone(Page(markup, 'https://idp.example/x').auto_navigation())


class TestFieldRoles(unittest.TestCase):
    def roles(self, markup: str) -> frozenset:
        return Page(f'<form>{markup}<button>Go</button></form>', 'https://x/').forms()[0].roles

    def test_roles(self):
        self.assertEqual(self.roles('<input type="email" name="e">'), {'username'})
        self.assertEqual(
            self.roles('<input name="username"><input type="password" name="p">'), {'username', 'password'}
        )
        self.assertEqual(
            self.roles('<input type="hidden" name="username" value="u"><input type="password" name="p">'), {'password'}
        )
        self.assertEqual(self.roles('<input name="otp">'), {'otp'})
        self.assertEqual(self.roles('<input type="hidden" name="a">'), frozenset())


def identifier_first_handler(known_user: str = 'svc@example.com', password: str = 'pw'):
    """Username page; unknown user re-shows it with an error. Password page keeps the username hidden."""
    posts = {'identify': 0, 'password': 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path, data = request.url.path, form_data(request)
        username_page = (
            '<form method="post" action="/identify"><input type="email" name="identifier"><button>Next</button></form>'
        )
        password_page = (
            '<form method="post" action="/password"><input type="hidden" name="identifier" value="svc@example.com">'
            '<input type="password" name="password"><button>Sign in</button></form>'
        )
        if path == '/start':
            return html(username_page)
        if path == '/identify':
            posts['identify'] += 1
            if data.get('identifier') != known_user:
                return html('<div role="alert">We couldn\'t find an account with that username.</div>' + username_page)
            return html(password_page)
        if path == '/password':
            posts['password'] += 1
            if data.get('password') != password:
                return html('<div class="error">Wrong password.</div>' + password_page)
            return html('<p>done</p>')
        return httpx.Response(404)

    return handler, posts


class TestRejectionByRoles(unittest.IsolatedAsyncioTestCase):
    async def run_generic(self, handler, username='svc@example.com', password='pw'):
        async with mock_client(handler) as client:
            return await login(
                'generic_saml',
                {'start_url': 'https://idp.example/start', 'username': username, 'password': password},
                client=client,
            )

    async def test_unknown_user_on_identifier_first_fails_fast(self):
        handler, posts = identifier_first_handler()
        with self.assertRaises(LoginError) as ctx:
            await self.run_generic(handler, username='ghost@example.com')
        self.assertEqual(posts['identify'], 1)
        self.assertEqual(ctx.exception.reason, 'rejected')
        self.assertIn("couldn't find an account", str(ctx.exception))

    async def test_wrong_password_on_password_only_page_fails_fast(self):
        handler, posts = identifier_first_handler()
        with self.assertRaises(LoginError) as ctx:
            await self.run_generic(handler, password='nope')
        self.assertEqual(posts['password'], 1)
        self.assertIn('Wrong password.', str(ctx.exception))

    async def test_progress_from_username_to_password_page_is_not_rejection(self):
        handler, posts = identifier_first_handler()
        with self.assertRaises(LoginError) as ctx:  # no SAML at the end of this fake, so the loop gives up
            await self.run_generic(handler)
        self.assertEqual(posts, {'identify': 1, 'password': 1})
        self.assertNotEqual(ctx.exception.reason, 'rejected')


class TestStructuredErrors(unittest.IsolatedAsyncioTestCase):
    async def test_transport_error(self):
        def handler(request):
            raise httpx.ConnectError('refused', request=request)

        recipe = Recipe.from_dict({'name': 'x', 'steps': [{'request': {'url': 'https://down.example/p?token=abc'}}]})
        async with mock_client(handler) as client:
            with self.assertRaises(LoginError) as ctx:
                await AsyncEngine(client).run(recipe, {})
        err = ctx.exception
        self.assertEqual(
            (err.reason, err.url, err.status_code, err.step), ('transport', 'https://down.example/p', None, 1)
        )
        self.assertIsNone(err.__cause__)  # the original error carries the full URL, query tokens included

    async def test_flow_error_carries_last_response(self):
        recipe = Recipe.from_dict(
            {'name': 'x', 'steps': [{'request': {'url': 'https://idp.example/p?sid=1'}}, {'fail': 'nope'}]}
        )
        async with mock_client(lambda r: httpx.Response(403, text='denied')) as client:
            with self.assertRaises(LoginError) as ctx:
                await AsyncEngine(client).run(recipe, {})
        err = ctx.exception
        self.assertEqual((err.reason, err.url, err.status_code, err.step), ('flow', 'https://idp.example/p', 403, 2))

    async def test_fail_step_can_declare_reason(self):
        recipe = Recipe.from_dict({'name': 'x', 'steps': [{'fail': {'message': 'bad creds', 'reason': 'rejected'}}]})
        async with mock_client(lambda r: httpx.Response(200)) as client:
            with self.assertRaises(LoginError) as ctx:
                await AsyncEngine(client).run(recipe, {})
        self.assertEqual((str(ctx.exception), ctx.exception.reason), ('bad creds', 'rejected'))

    def test_fail_reason_validated(self):
        with self.assertRaises(RecipeError):
            Recipe.from_dict({'name': 'x', 'steps': [{'fail': {'message': 'm', 'reason': 'whatever'}}]})

    async def test_mfa_required_reason(self):
        page = '<form method="post" action="/mfa"><input name="otp"><button>Verify</button></form>'
        async with mock_client(lambda r: html(page)) as client:
            with self.assertRaises(LoginError) as ctx:
                await login(
                    'generic_saml',
                    {'start_url': 'https://idp.example/', 'username': 'u', 'password': 'p'},
                    client=client,
                )
        self.assertEqual(ctx.exception.reason, 'mfa_required')


class TestEntraTolerance(unittest.IsolatedAsyncioTestCase):
    async def test_50058_on_first_page_is_tolerated(self):
        idp = EntraLikeIdp(first_page_error='50058')
        async with httpx.AsyncClient(transport=idp.transport(), follow_redirects=True) as client:
            result = await login(
                'entra_saml', {'start_url': SP_APP, 'username': 'svc@example.com', 'password': 'pw'}, client=client
            )
        self.assertTrue(result.saml.response)

    async def test_wrong_password_is_a_rejection_even_with_urlpost(self):
        idp = EntraLikeIdp(error_page_has_url_post=True)
        async with httpx.AsyncClient(transport=idp.transport(), follow_redirects=True) as client:
            with self.assertRaises(LoginError) as ctx:
                await login(
                    'entra_saml', {'start_url': SP_APP, 'username': 'svc@example.com', 'password': 'x'}, client=client
                )
        self.assertEqual(ctx.exception.reason, 'rejected')
        self.assertIn('50126', str(ctx.exception))
        self.assertEqual(idp.password_posts, 1)


class FakeResponse:
    """Just the surface Flow uses: no httpx anywhere."""

    def __init__(self, url: str, body: str = '', status: int = 200, headers: dict | None = None):
        self.url, self.text, self.status_code, self.headers = url, body, status, headers or {}

    def json(self):
        return json.loads(self.text)


class TestDriverProtocol(unittest.TestCase):
    def test_flow_driven_by_hand(self):
        recipe = Recipe.from_dict(
            {
                'name': 'x',
                'steps': [
                    {'request': {'method': 'POST', 'url': 'https://api.example/token', 'json': {'a': 1}}},
                    {'sleep': 1},
                    {'extract': [{'name': 'tok', 'from': 'json', 'path': 'access_token'}]},
                ],
                'outputs': {'token': '${tok}'},
            }
        )
        ops = Flow(recipe, {}).execute()
        op = next(ops)
        self.assertEqual(op, HttpRequest('POST', 'https://api.example/token', {'json': {'a': 1}}))
        self.assertEqual(ops.send(FakeResponse('https://api.example/token', '{"access_token": "t-1"}')), Sleep(1.0))
        with self.assertRaises(StopIteration) as done:
            ops.send(None)
        self.assertEqual(done.exception.value.outputs, {'token': 't-1'})

    def test_custom_error_types(self):
        class BoomError(Exception):
            pass

        recipe = Recipe.from_dict({'name': 'x', 'steps': [{'request': {'url': 'https://api.example/x?k=v'}}]})
        ops = Flow(recipe, {}, error_types=(BoomError,)).execute()
        next(ops)
        with self.assertRaises(LoginError) as ctx:
            ops.throw(BoomError('nope'))
        self.assertEqual((ctx.exception.reason, ctx.exception.url), ('transport', 'https://api.example/x'))

    def test_engine_error_types(self):
        class BoomError(Exception):
            pass

        def handler(request):
            raise BoomError('custom transport failure')

        recipe = Recipe.from_dict({'name': 'x', 'steps': [{'request': {'url': 'https://api.example/x'}}]})
        with httpx.Client(transport=httpx.MockTransport(handler)) as client, self.assertRaises(LoginError) as ctx:
            SyncEngine(client, error_types=(BoomError,)).run(recipe, {})
        self.assertEqual(ctx.exception.reason, 'transport')


class TestRedactionAndCookies(unittest.IsolatedAsyncioTestCase):
    async def test_secrets_scrubbed_from_vars(self):
        def handler(request):
            return httpx.Response(200, json={'echo': 's3cret-pw', 'other': 'fine'})

        recipe = Recipe.from_dict(
            {
                'name': 'x',
                'inputs': {'user': {}, 'pw': {'secret': True}},
                'steps': [
                    {
                        'request': {'url': 'https://idp.example/'},
                        'extract': [
                            {'name': 'echo', 'from': 'json', 'path': 'echo'},
                            {'name': 'other', 'from': 'json', 'path': 'other'},
                        ],
                    }
                ],
            }
        )
        async with mock_client(handler) as client:
            result = await AsyncEngine(client).run(recipe, {'user': 'svc', 'pw': 's3cret-pw'})
        self.assertEqual(result.vars['pw'], '***')
        self.assertEqual(result.vars['echo'], '***')
        self.assertEqual((result.vars['user'], result.vars['other']), ('svc', 'fine'))

    async def test_cookies_for_host(self):
        def handler(request):
            if request.url.host == 'idp.example.com':
                return httpx.Response(
                    302,
                    headers=[('location', 'https://app.sp.example.com/'), ('set-cookie', 'idp_sess=i; Path=/')],
                )
            return httpx.Response(
                200,
                headers=[
                    ('set-cookie', 'app=a; Path=/'),
                    ('set-cookie', 'shared=s; Domain=sp.example.com; Path=/'),
                ],
            )

        recipe = Recipe.from_dict({'name': 'x', 'steps': [{'request': {'url': 'https://idp.example.com/'}}]})
        async with mock_client(handler) as client:
            result = await AsyncEngine(client).run(recipe, {})
        self.assertEqual(dict(result.cookies_for('app.sp.example.com').items()), {'app': 'a', 'shared': 's'})
        self.assertEqual(dict(result.cookies_for('idp.example.com').items()), {'idp_sess': 'i'})
        self.assertEqual(dict(result.cookies_for('other.example.com').items()), {})


if __name__ == '__main__':
    unittest.main()
