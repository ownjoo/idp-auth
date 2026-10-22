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

### How it's built

The flow logic (`idp_auth.flow.Flow`) is sans-I/O. It is a generator that yields `HttpRequest` and `Sleep`
operations and receives responses back. `SyncEngine` and `AsyncEngine` are ~20-line drivers that perform those
operations with `httpx.Client` / `time.sleep` or `httpx.AsyncClient` / `asyncio.sleep`. Recipes, HTML handling and
factors are shared, so the two modes cannot drift apart. `login_sync` never touches asyncio, so it is safe to call
from code that is already inside an event loop.

### Bundled recipes

| name | flow |
|---|---|
| `generic_saml` | SP-initiated SAML, plain HTML username/password form |
| `entra_saml` | SP-initiated SAML through Microsoft Entra ID (password + "Stay signed in?") |

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

**Actions** (one per step): `request`, `submit_form`, `extract`, `set`, `mfa`, `sleep`, `loop`, `fail`.

**Step modifiers**:

- `when`: a condition.
- `extract`: rules run after the action.
- `follow`: `true` (the default), `false`, or `{deliver_saml: false, max_hops: 10}`.

**Templates**: `${dotted.path}` over inputs, extracted variables and `saml.*`.

- A value that is exactly one expression keeps its type.
- Mapping entries whose key or value renders to null are dropped. Useful for optional tokens and dynamic field
  names like `${config.sFTName}: ${config.sFT}`.

**Conditions**: `exists`, `not_exists`, `equals`, `not_equals`, `all`, `any`, `not`.

**Extract sources**: `json` (+`path`), `js_object` (`var`, +`path`), `html` (`selector`, +`attr`), `form_field`,
`regex`, `header`, `cookie`, `url`, `status`.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

The tests run every flow against in-process fake IdPs (`test/mock_idp.py`) through `httpx.MockTransport`. WebAuthn
output is checked against Yubico's reference relying party (`fido2.server`).
