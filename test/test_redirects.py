"""Redirects are followed by the flow itself (drivers send follow_redirects=False), so it can stop at a URL."""

import base64
import hashlib
import json
import unittest

import httpx

from idp_auth import AsyncEngine, Flow, HttpRequest, LoginError, Recipe, SyncEngine


def client(handler) -> httpx.AsyncClient:
    # follow_redirects=True on the client must not matter: the engine overrides it per request
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)


def one_request(url: str, method: str = 'GET', follow=True, **extra) -> Recipe:
    return Recipe.from_dict(
        {'name': 'x', 'steps': [{'request': {'method': method, 'url': url, **extra}, 'follow': follow}]}
    )


class TestRedirectSemantics(unittest.IsolatedAsyncioTestCase):
    async def test_303_turns_post_into_get_and_drops_body(self):
        seen = []

        def handler(request):
            seen.append((request.method, request.url.path, request.content))
            if request.url.path == '/submit':
                return httpx.Response(303, headers={'location': '/done'})
            return httpx.Response(200, text='ok')

        async with client(handler) as c:
            await AsyncEngine(c).run(one_request('https://x.example/submit', 'POST', data={'a': '1'}), {})
        self.assertEqual(seen, [('POST', '/submit', b'a=1'), ('GET', '/done', b'')])

    async def test_302_after_post_becomes_get(self):
        seen = []

        def handler(request):
            seen.append(request.method)
            return httpx.Response(302, headers={'location': '/next'}) if len(seen) == 1 else httpx.Response(200)

        async with client(handler) as c:
            await AsyncEngine(c).run(one_request('https://x.example/p', 'POST', data={'a': '1'}), {})
        self.assertEqual(seen, ['POST', 'GET'])

    async def test_307_keeps_method_and_body(self):
        seen = []

        def handler(request):
            seen.append((request.method, request.url.path, request.content))
            if request.url.path == '/old':
                return httpx.Response(307, headers={'location': 'https://y.example/new'})
            return httpx.Response(200)

        async with client(handler) as c:
            await AsyncEngine(c).run(one_request('https://x.example/old', 'POST', data={'a': '1'}), {})
        self.assertEqual(seen, [('POST', '/old', b'a=1'), ('POST', '/new', b'a=1')])

    async def test_cookies_from_intermediate_redirects_are_kept(self):
        def handler(request):
            if request.url.path == '/set':
                return httpx.Response(302, headers={'location': '/check', 'set-cookie': 'sid=1; Path=/'})
            return httpx.Response(200, text='has-cookie' if 'sid=1' in request.headers.get('cookie', '') else 'none')

        async with client(handler) as c:
            result = await AsyncEngine(c).run(one_request('https://x.example/set'), {})
        self.assertEqual(result.response.text, 'has-cookie')

    async def test_redirect_loop_is_an_error(self):
        async with client(lambda r: httpx.Response(302, headers={'location': r.url.path})) as c:
            with self.assertRaises(LoginError) as ctx:
                await AsyncEngine(c).run(one_request('https://x.example/loop'), {})
        self.assertIn('redirect', str(ctx.exception))

    async def test_follow_false_still_follows_http_redirects_but_not_pages(self):
        # follow: false only turns off page-level navigation (forms, meta refresh, scripts), as before
        def handler(request):
            if request.url.path == '/a':
                return httpx.Response(302, headers={'location': '/b'})
            return httpx.Response(200, text='<meta http-equiv="refresh" content="0;url=/c">')

        async with client(handler) as c:
            result = await AsyncEngine(c).run(one_request('https://x.example/a', follow=False), {})
        self.assertEqual(result.response.url.path, '/b')


class TestStopAt(unittest.IsolatedAsyncioTestCase):
    CALLBACK = 'http://localhost:8765/callback'

    def handler(self, hits):
        def handler(request):
            hits.append(str(request.url))
            if request.url.host == 'localhost':
                return httpx.Response(502, text='callback must never be fetched')
            if request.url.path == '/authorize':
                return httpx.Response(302, headers={'location': f'{self.CALLBACK}?code=c-1&state=s-1'})
            if request.url.path == '/form-post':
                return httpx.Response(
                    200,
                    text=(
                        f'<body onload="document.forms[0].submit()"><form method="post" action="{self.CALLBACK}">'
                        '<input type="hidden" name="code" value="c-2"><input type="hidden" name="state" value="s-2">'
                        '</form></body>'
                    ),
                )
            if request.url.path == '/fragment':
                return httpx.Response(302, headers={'location': f'{self.CALLBACK}#access_token=t-3&state=s-3'})
            return httpx.Response(404)

        return handler

    async def run_stop(self, path: str):
        hits = []
        recipe = one_request(f'https://idp.example{path}', follow={'stop_at': self.CALLBACK})
        async with client(self.handler(hits)) as c:
            result = await AsyncEngine(c).run(recipe, {})
        self.assertFalse(any('localhost' in h for h in hits), hits)
        return result.vars['callback']

    async def test_stop_on_http_redirect(self):
        callback = await self.run_stop('/authorize')
        self.assertEqual(callback['url'], f'{self.CALLBACK}?code=c-1&state=s-1')
        self.assertEqual(callback['params'], {'code': 'c-1', 'state': 's-1'})

    async def test_stop_on_form_post(self):
        callback = await self.run_stop('/form-post')
        self.assertEqual(callback['params'], {'code': 'c-2', 'state': 's-2'})

    async def test_stop_on_fragment(self):
        callback = await self.run_stop('/fragment')
        self.assertEqual(callback['params'], {'access_token': 't-3', 'state': 's-3'})

    async def test_other_paths_on_the_same_host_are_not_stopped(self):
        hits = []

        def handler(request):
            hits.append(request.url.path)
            if request.url.path == '/start':
                return httpx.Response(302, headers={'location': 'https://app.example/callback-other'})
            return httpx.Response(200)

        recipe = one_request('https://app.example/start', follow={'stop_at': 'https://app.example/callback'})
        async with client(handler) as c:
            result = await AsyncEngine(c).run(recipe, {})
        self.assertEqual(hits, ['/start', '/callback-other'])
        self.assertIsNone(result.vars.get('callback'))

    def test_sync_engine_stops_too(self):
        hits = []
        recipe = one_request('https://idp.example/authorize', follow={'stop_at': self.CALLBACK})
        with httpx.Client(transport=httpx.MockTransport(self.handler(hits))) as c:
            result = SyncEngine(c).run(recipe, {})
        self.assertEqual(result.vars['callback']['params']['code'], 'c-1')


class TestDriverProtocolRedirects(unittest.TestCase):
    def test_flow_asks_for_each_hop(self):
        class Resp:
            def __init__(self, url, status, headers=None, text=''):
                self.url, self.status_code, self.headers, self.text = url, status, headers or {}, text

            def json(self):
                return json.loads(self.text)

        ops = Flow(one_request('https://a.example/1'), {}).execute()
        self.assertEqual(next(ops), HttpRequest('GET', 'https://a.example/1', {}))
        second = ops.send(Resp('https://a.example/1', 302, {'location': '/2'}))
        self.assertEqual(second, HttpRequest('GET', 'https://a.example/2', {}))
        with self.assertRaises(StopIteration) as done:
            ops.send(Resp('https://a.example/2', 200, text='fine'))
        self.assertEqual(done.exception.value.response.text, 'fine')


class TestPkceAction(unittest.IsolatedAsyncioTestCase):
    async def test_values(self):
        recipe = Recipe.from_dict({'name': 'x', 'steps': [{'pkce': {'into': 'p'}}]})
        async with client(lambda r: httpx.Response(200)) as c:
            first = (await AsyncEngine(c).run(recipe, {})).vars['p']
            second = (await AsyncEngine(c).run(recipe, {})).vars['p']
        self.assertEqual(len(first['verifier']), 43)
        digest = base64.urlsafe_b64encode(hashlib.sha256(first['verifier'].encode()).digest()).rstrip(b'=').decode()
        self.assertEqual(first['challenge'], digest)
        self.assertEqual(first['method'], 'S256')
        self.assertNotEqual(first['state'], first['nonce'])
        self.assertNotEqual(first['verifier'], second['verifier'])


if __name__ == '__main__':
    unittest.main()
