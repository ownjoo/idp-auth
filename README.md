# idp-auth

Browserless IdP login over [httpx](https://www.python-httpx.org/). No Selenium or Playwright, and no browser at
any step, including enrolment.

Every IdP's flow is a **recipe**: declarative YAML/JSON that the engine runs. Between steps the engine does what a
browser would do: it follows redirects, auto-submitted forms (SAML POST binding), meta refresh and `location=`
script hops. It keeps cookies across domains, parses forms the way a browser serialises them, and reads JSON
config blobs embedded in pages (e.g. Entra's `$Config`). Supporting a new IdP should mean writing a new recipe,
not new code.

MFA uses a built-in software authenticator. Enrol the service account with it and the flow completes on its own:

- **TOTP / HOTP** (RFC 6238 / 4226): base32 secrets or `otpauth://` URIs.
- **FIDO2 / WebAuthn**: an ES256 virtual authenticator. It builds `clientDataJSON` itself and returns the
  `PublicKeyCredential.toJSON()` shape. Registration uses `none` attestation. Origins must sit under the
  credential's RP ID.
- **Push / phone approval**: the recipe polls with `loop` + `sleep` until someone approves.

## Usage

Sync and async are both native. Neither one wraps the other.

```python
from idp_auth import login, login_sync

inputs = {'start_url': 'https://app.example.com/sso/start', 'username': 'svc-etl@example.com', 'password': '...'}

result = await login('entra_saml', inputs)  # httpx.AsyncClient
result = login_sync('entra_saml', inputs)  # httpx.Client

result.saml.response  # base64 SAMLResponse
result.cookies  # SP session cookies (the assertion is delivered to the ACS by default)
```

Pass `client=` to use your own client (`httpx.AsyncClient` for `login`, `httpx.Client` for `login_sync`), for
proxies, HTTP/2, a custom transport and so on. Without one, a client with browser-like headers is created
(`idp_auth.DEFAULT_HEADERS`). For more control, use `AsyncEngine(client).run(recipe, inputs)` or
`SyncEngine(client).run(...)`. Both accept `clock`, `sleep` and `max_hops`.

### Stopping at the assertion

Sometimes you want the assertion itself, to exchange with AWS STS or hand to another service, and not an SP
session. `saml_response()` / `saml_response_sync()` run the flow only until a `SAMLResponse` form field appears,
never post it to the SP, and return its value. They raise `LoginError` if the flow ends without one.

```python
from idp_auth import saml_response, saml_response_sync

assertion = await saml_response('entra_saml', inputs)
assertion = saml_response_sync('entra_saml', inputs)
```

This works with any recipe, whatever its own delivery settings. It also works when the assertion sits in a form
that a browser wouldn't submit automatically. For the full `LoginResult` (RelayState, ACS URL, cookies), pass
`stop_at_saml=True` to `login()`, `login_sync()`, `AsyncEngine` or `SyncEngine`.

### How it's built

The flow logic (`idp_auth.flow.Flow`) is sans-I/O. It is a generator that yields `HttpRequest` and `Sleep`
operations and receives responses back. `SyncEngine` and `AsyncEngine` are ~20-line drivers that perform those
operations with `httpx.Client` / `time.sleep` or `httpx.AsyncClient` / `asyncio.sleep`. Recipes, HTML handling and
factors are shared, so the two modes cannot drift apart. `login_sync` never touches asyncio, so it is safe to call
from code that is already inside an event loop.

### Bundled recipes

| name | flow |
|---|---|
| `generic_saml` | SP-initiated SAML through any IdP whose login pages are HTML forms; optional TOTP |
| `entra_saml` | SP-initiated SAML through Microsoft Entra ID (password + "Stay signed in?"); error codes stop the flow rather than re-posting, except the benign 50058 |
| `generic_oidc` | OAuth 2.0 / OIDC authorization code + PKCE through an HTML-form login; returns tokens |
| `client_credentials` | OAuth 2.0 client credentials (service accounts): client secret or signed JWT, no login page |

#### `generic_oidc`

```python
result = await login(
    'generic_oidc',
    {
        'issuer': 'https://login.example.com',  # discovery; or pass authorize_url + token_url
        'client_id': 'my-app',
        'redirect_uri': 'http://localhost:8765/callback',
        'username': 'svc',
        'password': '...',
    },
)
result.outputs['access_token'], result.outputs['id_token'], result.outputs['refresh_token']
```

Optional inputs: `client_secret` (confidential clients, sent as `client_secret_post`), `scope` (default
`openid`), `totp_secret` and `max_pages`.

- The login pages are handled exactly as in `generic_saml`.
- The flow stops at `redirect_uri` without requesting it, so nothing needs to listen there. Both a redirect and a
  `form_post` response work.
- It checks `state`, reports OAuth errors (`access_denied` as `reason='rejected'`), then exchanges the code with
  the PKCE verifier.
- An existing IdP session that redirects straight back works too.
- It does **not** validate the ID token signature. The token is returned for your OIDC library to verify.

#### `generic_saml`: start here

Inputs: `start_url`, `username`, `password`. Optional: `totp_secret`, `deliver_assertion` (default true) and
`max_pages` (default 10).

On each page it does what a person would do next:

- **Picks the right form.** It skips search boxes and language pickers and uses the credentials form. If there
  isn't one, it uses a one-time-code form, then a bare continue/consent page.
- **Fills by role.** It finds the username, password and OTP fields by type, `autocomplete` and common names.
  Identifier-first flows (username on one page, password on the next) work.
- **Clicks the default button.** The first submit button's name and value are sent, as a browser does.
  Shibboleth's `_eventId_proceed` relies on this.
- **Handles MFA.** If a page asks for a one-time code, it fills a TOTP from `totp_secret`, or fails saying the
  secret is missing.
- **Fails fast.** If the next page asks again for what was just submitted, or for part of it, it stops with
  `reason='rejected'` and the IdP's own error message (from `[role=alert]`, `.error`, `#errorText`, ...) rather
  than retrying. "Part of it" covers a password page that comes back on its own. An unknown user on an
  identifier-first page counts too. Moving from a username page to a password page is progress, not a rejection.
- **Follows "please wait" pages.** That covers meta refresh (including PingFederate's `data-url`), JS
  redirects, auto-posted forms, and a lone hidden-only form whose submit lives in an external script. That last
  case is followed only when the page is otherwise near-empty and the form isn't a logout.

Tested against fake IdPs shaped like Shibboleth (consent page included), ADFS (script-submitted form, then TOTP)
and identifier-first products. IdPs whose login page is a JavaScript app (Entra, Okta, Google, ...) have no HTML
form to work with. The recipe stops with "no login form", and those IdPs need a vendor recipe such as
`entra_saml`.

#### `client_credentials`: service accounts

For machine access, this is the route the vendors support and the one to prefer. There's no login page and no
interactive MFA, just a client authenticating to the token endpoint.

```python
result = await login(
    'client_credentials',
    {
        'token_url': 'https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token',  # or issuer= for discovery
        'client_id': '<app id>',
        'private_key': open('svc.key').read(),
        'certificate': open('svc.crt').read(),  # Entra matches the cert by the x5t thumbprints
        'scope': 'https://graph.microsoft.com/.default',
    },
)
result.outputs['access_token']
```

Client authentication, picked by `auth_method` or from what you pass:

- `private_key_jwt`, the default when `private_key` is given. It sends a signed assertion: RS256 for RSA keys,
  ES256 for P-256 keys. iss and sub are the client id, aud is the token endpoint, and each run gets a fresh `jti`
  with a 5-minute lifetime. `certificate` adds `x5t` / `x5t#S256` to the header, and `key_id` adds `kid`.
- `client_secret_post`, the default when only `client_secret` is given.
- `client_secret_basic`. Both parts are form-urlencoded before base64, per RFC 6749.

`scope`, `audience` and `resource` are passed through when set. `invalid_client` and `unauthorized_client`
errors come back as `reason='rejected'`. Typical setups:

| IdP | what to register | notes |
|---|---|---|
| Entra ID | app registration with a certificate (or secret) | `scope: <resource>/.default`; pass `certificate` for `x5t` |
| Okta | API Services app, public key / private key auth | `token_url: https://<org>/oauth2/<server>/v1/token`; `key_id` if the JWKS has several keys |
| Auth0 | Machine-to-Machine app | `audience: <API identifier>` |
| Keycloak | confidential client with service accounts enabled | `issuer: https://<host>/realms/<realm>` |

## Recipe format

```yaml
name: json-authn
inputs:
  base: {}
  username: {}
  password: {secret: true}        # redacted from every error message
  totp_secret: {secret: true}
steps:
  - request: {method: POST, url: "${base}/api/authn", json: {username: "${username}", password: "${password}"}}
    extract: [{name: authn, from: json}]
  - mfa: {factor: totp, secret: "${totp_secret}", into: code}
    when: {equals: ["${authn.status}", "MFA_REQUIRED"]}
  - request: {method: POST, url: "${base}/api/authn/factors/totp/verify",
              json: {stateToken: "${authn.stateToken}", passCode: "${code}"}}
    extract: [{name: authn, from: json}]
  - fail: "MFA failed: ${authn.errorSummary}"
    when: {not_equals: ["${authn.status}", "SUCCESS"]}
outputs:
  session_token: ${authn.sessionToken}
```

**Actions** (one per step): `request`, `submit_form`, `extract`, `set`, `mfa`, `sleep`, `loop`, `fail`, `pkce`,
`client_assertion`.

- `pkce: {into: p}` sets `p.verifier`, `p.challenge`, `p.method` (`S256`), `p.state` and `p.nonce`, all freshly
  random.
- `client_assertion: {into, client_id, audience, private_key, key_id?, certificate?, lifetime?}` sets a signed
  JWT for `private_key_jwt`.
- `request` also takes `basic_auth: {username, password}`. It's skipped when either part renders to null.

**Step modifiers**:

- `when`: a condition.
- `extract`: rules run after the action.
- `follow`: `true` (the default), `false`, or `{deliver_saml: false, max_hops: 10, stop_at: <url>}`.
  - HTTP redirects are always followed, up to 20.
  - `follow` controls page-level navigation: forms, meta refresh and scripts.
  - `stop_at` ends navigation before any request to that URL (scheme, host and path compared) and sets
    `callback.url` plus `callback.params`. The params merge the query, the fragment and any form fields.

**Templates**: `${dotted.path}` over inputs, extracted variables and `saml.*`.

- A value that is exactly one expression keeps its type.
- Mapping entries whose key or value renders to null are dropped. Useful for optional tokens and dynamic field
  names like `${config.sFTName}: ${config.sFT}`.

**Conditions**: `exists`, `not_exists`, `equals`, `not_equals`, `all`, `any`, `not`.

**Extract sources**: `json` (+`path`), `js_object` (`var`, +`path`), `html` (`selector`, +`attr`), `form_field`,
`regex`, `header`, `cookie`, `url` (+`param`: the first value of that query parameter, falling back to the
fragment; useful for IdPs that keep flow state in the redirect URL), `status`.

**`fail`** takes a message, or `{message, reason}` where `reason` is one of `rejected`, `mfa_required` or `flow`.

## Errors

Every failure is a `LoginError` with these attributes:

- **`reason`**:
  - `rejected`: the IdP refused the credentials or code.
  - `transport`: a request couldn't be sent or answered.
  - `mfa_required`: a factor was asked for that the inputs can't satisfy.
  - `flow`: anything else.
- **`step`**: the 1-based index of the top-level step that failed.
- **`url`**: the URL involved, without query string or fragment.
- **`status_code`**: the last response's status.

Branch on `reason`, not on the message. Note that HTTP 401 and 403 are not errors by themselves. A rejection shows
up as `reason='rejected'` once the flow recognises it. The original exception is not chained, because transport
errors carry full URLs, query-string tokens included.

Secrets stay out of results:

- Values of inputs marked `secret: true` are replaced with `***` in every error message and in `LoginResult.vars`.
  So is any extracted value that equals one of them.
- `LoginResult.cookies` is the client's whole jar, including the IdP's session cookies. Use
  `result.cookies_for('app.example.com')` to get only the cookies a browser would send to that host.

## Writing your own driver

`Flow` does no I/O, so any HTTP stack can drive it. It yields `HttpRequest(method, url, kwargs)` and `Sleep(seconds)`.
Answer each request with an object that has `.text`, `.url`, `.status_code`, `.headers.get()` and `.json()`.
**Don't follow redirects.** The flow follows each hop itself, so that it can stop before a URL such as an OAuth
`redirect_uri`. Cookies set on intermediate redirects must still land in the jar, which `requests` and httpx both
do. If a request fails, throw the exception in. Exceptions of the types in `error_types`
become `LoginError(reason='transport')`. For example, with `requests`:

```python
import time

import requests

from idp_auth import Flow, HttpRequest, Recipe


def run(recipe: Recipe, inputs: dict, session: requests.Session):
    ops = Flow(recipe, inputs, cookies=session.cookies, error_types=(requests.RequestException,)).execute()
    reply, error = None, None
    while True:
        try:
            op = ops.throw(error) if error else ops.send(reply)
        except StopIteration as done:
            return done.value
        reply, error = None, None
        try:
            if isinstance(op, HttpRequest):
                reply = session.request(op.method, op.url, allow_redirects=False, **op.kwargs)
            else:
                time.sleep(op.seconds)
        except requests.RequestException as exc:
            error = exc
```

`op.kwargs` holds `params`, `data`, `json` and `headers`, which `requests` accepts as they are.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

The tests run every flow against in-process fake IdPs (`test/mock_idp.py`) through `httpx.MockTransport`. WebAuthn
output is checked against Yubico's reference relying party (`fido2.server`).
