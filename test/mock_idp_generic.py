"""Fake IdPs shaped like common server-rendered products, for the generic SAML recipe."""

import httpx

from idp_auth.factors.totp import Totp
from test.mock_idp import ServiceProvider, form, html, saml_post_page


class ShibbolethLikeIdp:
    """Shibboleth-IdP-shaped: a search form and a language picker before the login form, a login button whose
    name the server requires, an attribute-release consent page, then the SAML POST."""

    def __init__(self, username='svc', password='pw'):
        self.username, self.password = username, password
        self.login_posts = 0
        self.sp = ServiceProvider('https://shib.example.com/idp/profile/SAML2/Redirect/SSO')

    def login_page(self, error: str = '') -> httpx.Response:
        error_html = f'<p class="output--error">{error}</p>' if error else ''
        return html(
            '<form action="/search"><input type="search" name="q"><button>Search</button></form>'
            '<form action="/lang"><select name="lang"><option value="en">English</option></select>'
            '<button>Change</button></form>'
            f'<section>{error_html}'
            '<form method="post" action="/idp/profile/SAML2/Redirect/SSO?execution=e1s1">'
            '<input type="hidden" name="csrf_token" value="tok-1">'
            '<input id="username" name="j_username" type="text">'
            '<input id="password" name="j_password" type="password">'
            '<button type="submit" name="_eventId_proceed">Login</button></form></section>'
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        if (sp := self.sp.handle(request)) is not None:
            return sp
        if request.method == 'GET' and request.url.path == '/idp/profile/SAML2/Redirect/SSO':
            return self.login_page()
        execution = request.url.params.get('execution')
        data = form(request)
        if execution == 'e1s1':
            self.login_posts += 1
            if '_eventId_proceed' not in data or data.get('csrf_token') != 'tok-1':
                return httpx.Response(400, text='Stale request')
            if (data.get('j_username'), data.get('j_password')) != (self.username, self.password):
                return self.login_page('The password you entered was incorrect.')
            return html(
                '<h1>Information to be provided to the service</h1>'
                '<form method="post" action="/idp/profile/SAML2/Redirect/SSO?execution=e1s2">'
                '<input type="hidden" name="csrf_token" value="tok-2">'
                '<input type="radio" name="_shib_idp_consentOptions" value="_shib_idp_rememberConsent" checked>'
                '<button type="submit" name="_eventId_proceed" value="Accept">Accept</button>'
                '<button type="submit" name="_eventId_AttributeReleaseRejected">Reject</button></form>'
            )
        if execution == 'e1s2':
            if data.get('_eventId_proceed') != 'Accept' or '_eventId_AttributeReleaseRejected' in data:
                return httpx.Response(400, text='consent not given')
            return httpx.Response(200, text=saml_post_page('https://sp.example.com/acs'))
        return httpx.Response(404)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


class AdfsLikeIdp:
    """ADFS-shaped: forms login submitted by a script (no button), then a TOTP page, then the SAML POST."""

    LOGIN_ERROR = 'Incorrect user ID or password. Type the correct user ID and password, and try again.'

    def __init__(self, totp_secret: str, clock, username='svc@example.com', password='pw'):
        self.username, self.password = username, password
        self.totp = Totp(totp_secret, clock=clock)
        self.otp_posts = 0
        self.sp = ServiceProvider('https://adfs.example.com/adfs/ls/')

    def login_page(self, error: str = '') -> httpx.Response:
        return html(
            f'<div id="error"><span id="errorText">{error}</span></div>'
            '<form method="post" id="loginForm" action="/adfs/ls/?SAMLRequest=abc&amp;client-request-id=r1">'
            '<input id="userNameInput" name="UserName" type="email">'
            '<input id="passwordInput" name="Password" type="password">'
            '<input id="kmsiInput" type="checkbox" name="Kmsi" value="true">'
            '<input type="hidden" name="AuthMethod" value="FormsAuthentication">'
            '<span id="submitButton" class="submit" onclick="return Login.submitLoginRequest();">Sign in</span>'
            '</form>'
        )

    def otp_page(self, error: str = '') -> httpx.Response:
        return html(
            f'<div id="error"><span id="errorText">{error}</span></div>'
            '<form method="post" id="options" action="/adfs/ls/?SAMLRequest=abc&amp;client-request-id=r1">'
            '<input type="hidden" name="Context" value="ctx-otp">'
            '<input type="hidden" name="AuthMethod" value="TotpAdapter">'
            '<input type="text" name="VerificationCode" autocomplete="one-time-code" inputmode="numeric">'
            '<input type="submit" id="submitButton" name="SignIn" value="Verify"></form>'
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        if (sp := self.sp.handle(request)) is not None:
            return sp
        if request.url.path != '/adfs/ls/':
            return httpx.Response(404)
        if request.method == 'GET':
            return self.login_page()
        data = form(request)
        if data.get('AuthMethod') == 'FormsAuthentication':
            if (data.get('UserName'), data.get('Password')) != (self.username, self.password):
                return self.login_page(self.LOGIN_ERROR)
            return self.otp_page()
        if data.get('AuthMethod') == 'TotpAdapter' and data.get('Context') == 'ctx-otp':
            self.otp_posts += 1
            if data.get('SignIn') != 'Verify':
                return httpx.Response(400)
            if not self.totp.verify(data.get('VerificationCode', '')):
                return self.otp_page('The code you entered is not valid.')
            return httpx.Response(200, text=saml_post_page('https://sp.example.com/acs'))
        return httpx.Response(400)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


class IdentifierFirstIdp:
    """Username on one page, password on the next (Keycloak/Auth0/Ping style)."""

    def __init__(self):
        self.sp = ServiceProvider('https://id.example.com/sso')

    def handler(self, request: httpx.Request) -> httpx.Response:
        if (sp := self.sp.handle(request)) is not None:
            return sp
        data = form(request) if request.method == 'POST' else {}
        if request.url.path == '/sso':
            return html(
                '<form method="post" action="/identify">'
                '<input type="email" name="identifier"><button>Next</button></form>'
            )
        if request.url.path == '/identify' and data.get('identifier') == 'svc@example.com':
            return html(
                '<form method="post" action="/password">'
                '<input type="hidden" name="identifier" value="svc@example.com">'
                '<input type="password" name="password"><button type="submit">Sign in</button></form>'
            )
        if request.url.path == '/password' and data == {'identifier': 'svc@example.com', 'password': 'pw'}:
            return httpx.Response(200, text=saml_post_page('https://sp.example.com/acs'))
        return httpx.Response(400, text='unexpected request')

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)
