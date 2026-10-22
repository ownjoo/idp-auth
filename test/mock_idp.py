"""In-process fake IdPs/SPs for engine tests, served through httpx.MockTransport."""

import json
from urllib.parse import parse_qsl

import httpx

from idp_auth.factors.totp import Totp


def form(request: httpx.Request) -> dict:
    return dict(parse_qsl(request.content.decode(), keep_blank_values=True))


def html(body: str, status: int = 200, **kwargs) -> httpx.Response:
    return httpx.Response(
        status, text=f'<html><body>{body}</body></html>', headers={'content-type': 'text/html'}, **kwargs
    )


def saml_post_page(acs: str, assertion: str = 'PHNhbWxwOlJlc3BvbnNlLz4=', relay: str = 'rs-1') -> str:
    return (
        '<html><body onload="document.forms[0].submit()">'
        f'<form method="post" action="{acs}">'
        f'<input type="hidden" name="SAMLResponse" value="{assertion}">'
        f'<input type="hidden" name="RelayState" value="{relay}">'
        '<noscript><button type="submit">Continue</button></noscript></form></body></html>'
    )


class ServiceProvider:
    """SP at sp.example.com that redirects to an IdP and accepts a POSTed SAMLResponse."""

    def __init__(self, idp_sso: str):
        self.idp_sso = idp_sso
        self.acs_hits = 0

    def handle(self, request: httpx.Request) -> httpx.Response | None:
        if request.url.host != 'sp.example.com':
            return None
        if request.url.path == '/app':
            if request.headers.get('cookie', '').find('sp_session=ok') >= 0:
                return html('<h1>Welcome svc</h1>')
            return httpx.Response(302, headers={'location': f'{self.idp_sso}?SAMLRequest=abc&RelayState=rs-1'})
        if request.url.path == '/acs' and request.method == 'POST':
            self.acs_hits += 1
            if form(request).get('SAMLResponse'):
                return httpx.Response(302, headers={'location': '/app', 'set-cookie': 'sp_session=ok; Path=/'})
            return httpx.Response(400)
        return httpx.Response(404)


class GenericIdp:
    """Plain HTML login form IdP with a CSRF token and a JS-driven redirect hop."""

    def __init__(self, username='svc', password='pw'):
        self.username, self.password = username, password
        self.login_posts = 0
        self.sp = ServiceProvider('https://idp.example.com/sso')

    def login_form(self, error: str = '') -> httpx.Response:
        return html(
            f'<p>{error}</p><form method="post" action="/login">'
            '<input type="hidden" name="csrf" value="c-1">'
            '<input type="text" name="username"><input type="password" name="password">'
            '<button type="submit">Sign in</button></form>'
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        if (sp := self.sp.handle(request)) is not None:
            return sp
        path = request.url.path
        if path == '/sso':
            # browsers would run this script; the engine has to follow it
            return html('<script>window.location.href = "/login-page";</script>')
        if path == '/login-page':
            return self.login_form()
        if path == '/login' and request.method == 'POST':
            self.login_posts += 1
            data = form(request)
            if data.get('csrf') != 'c-1':
                return httpx.Response(403)
            if (data.get('username'), data.get('password')) != (self.username, self.password):
                return self.login_form('Invalid credentials')
            return httpx.Response(200, text=saml_post_page('https://sp.example.com/acs'))
        return httpx.Response(404)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


class EntraLikeIdp:
    """Mimics Entra ID's $Config-driven login: credentials page, then 'Stay signed in?' (KMSI), then SAML POST."""

    def __init__(self, username='svc@example.com', password='pw'):
        self.username, self.password = username, password
        self.sp = ServiceProvider('https://login.example.com/saml2')

    @staticmethod
    def config_page(config: dict) -> httpx.Response:
        return html(f'<script type="text/javascript">//<![CDATA[\n$Config={json.dumps(config)};\n//]]></script>')

    def handler(self, request: httpx.Request) -> httpx.Response:
        if (sp := self.sp.handle(request)) is not None:
            return sp
        path = request.url.path
        if path == '/saml2':
            return self.config_page(
                {
                    'urlPost': '/common/login',
                    'sFT': 'ft-1',
                    'sFTName': 'flowToken',
                    'sCtx': 'ctx-1',
                    'canary': 'can-1',
                    'sCanaryTokenName': 'canary',
                    'sessionId': 'sess-1',
                }
            )
        if path == '/common/login':
            data = form(request)
            expected = {'flowToken': 'ft-1', 'ctx': 'ctx-1', 'canary': 'can-1', 'loginfmt': self.username}
            if any(data.get(k) != v for k, v in expected.items()):
                return httpx.Response(400, text='bad flow')
            if data.get('passwd') != self.password:
                return self.config_page({'sErrorCode': '50126', 'sFT': 'ft-err', 'sFTName': 'flowToken'})
            return self.config_page({'urlPost': '/kmsi', 'sFT': 'ft-2', 'sFTName': 'flowToken', 'sCtx': 'ctx-2'})
        if path == '/kmsi':
            data = form(request)
            if data.get('flowToken') != 'ft-2' or data.get('LoginOptions') != '1':
                return httpx.Response(400, text='bad kmsi')
            return httpx.Response(200, text=saml_post_page('https://sp.example.com/acs'))
        return httpx.Response(404)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


class JsonMfaIdp:
    """Okta-Authn-style JSON API: password, then a TOTP or push factor."""

    def __init__(self, totp_secret: str, clock, push_pending_polls: int = 2):
        self.totp = Totp(totp_secret, clock=clock)
        self.push_pending_polls = push_pending_polls
        self.polls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b'{}')
        path = request.url.path
        if path == '/api/authn':
            if (body.get('username'), body.get('password')) != ('svc', 'pw'):
                return httpx.Response(401, json={'errorSummary': 'Authentication failed'})
            return httpx.Response(200, json={'status': 'MFA_REQUIRED', 'stateToken': 'st-1'})
        if path == '/api/authn/factors/totp/verify':
            if body.get('stateToken') == 'st-1' and self.totp.verify(body.get('passCode', '')):
                return httpx.Response(200, json={'status': 'SUCCESS', 'sessionToken': 'sess-tok'})
            return httpx.Response(403, json={'status': 'MFA_CHALLENGE', 'errorSummary': 'bad code'})
        if path == '/api/authn/factors/push/verify':
            self.polls += 1
            if self.polls <= self.push_pending_polls:
                return httpx.Response(200, json={'status': 'MFA_CHALLENGE', 'factorResult': 'WAITING'})
            return httpx.Response(200, json={'status': 'SUCCESS', 'sessionToken': 'push-tok'})
        return httpx.Response(404)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)
