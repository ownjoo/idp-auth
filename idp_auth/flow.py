"""Sans-I/O login flow: runs a Recipe, doing what a browser would between steps, without performing any I/O.

``Flow.execute()`` is a generator. It yields ``HttpRequest`` / ``Sleep`` operations, receives the
``httpx.Response`` for each request via ``send()``, and returns a ``LoginResult``. Transport errors are thrown
back into it with ``throw()``. ``idp_auth.engine`` holds the sync and async drivers that perform the I/O.
"""

import re
import time
from collections.abc import Callable, Generator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from idp_auth.errors import LoginError
from idp_auth.factors.totp import Totp
from idp_auth.factors.webauthn import Credential
from idp_auth.html import Navigation, Page
from idp_auth.recipe import Recipe, Step
from idp_auth.template import lookup, render

DEFAULT_MAX_HOPS = 10
DEFAULT_LOOP_MAX = 10


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    kwargs: dict = field(default_factory=dict)  # params / data / json / headers for httpx's request()


@dataclass(frozen=True)
class Sleep:
    seconds: float


Op = HttpRequest | Sleep
Ops = Generator[Op, Any, None]


@dataclass
class SamlCapture:
    response: str | None = None
    relay_state: str | None = None
    acs_url: str | None = None


@dataclass
class LoginResult:
    outputs: dict
    vars: dict
    saml: SamlCapture
    response: httpx.Response | None
    page: Page | None
    cookies: httpx.Cookies = field(repr=False, default_factory=httpx.Cookies)


class _AssertionCaptured(Exception):
    """Unwinds the step stack when stop_at_saml is set and an assertion has been captured."""


class _Run:
    """Mutable state of one recipe execution."""

    def __init__(self, ctx: dict):
        self.ctx = ctx
        self.saml = SamlCapture()
        self.response: httpx.Response | None = None
        self.page: Page | None = None

    @property
    def base_url(self) -> str:
        return str(self.response.url) if self.response is not None else ''


class Flow:
    def __init__(
        self,
        recipe: Recipe,
        inputs: dict,
        cookies: httpx.Cookies,
        clock: Callable[[], float] = time.time,
        max_hops: int = DEFAULT_MAX_HOPS,
        stop_at_saml: bool = False,
    ):
        self.recipe = recipe
        self.cookies = cookies  # the driver's client jar; read by `from: cookie` extraction
        self._ctx = recipe.bind_inputs(inputs)  # validate before any I/O
        self._clock = clock
        self._max_hops = max_hops
        self._stop_at_saml = stop_at_saml  # end the flow at the first SAMLResponse, never delivering it

    def execute(self) -> Generator[Op, Any, LoginResult]:
        ctx, recipe = self._ctx, self.recipe
        secrets = [v for k, v in ctx.items() if k in recipe.secret_inputs() and isinstance(v, str) and v]
        run = _Run(ctx)
        ctx['saml'] = run.saml
        for index, step in enumerate(recipe.steps, start=1):
            try:
                yield from self._step(run, step)
            except _AssertionCaptured:
                break
            except LoginError as exc:
                raise LoginError(_redact(str(exc), secrets), step=index) from None
            except httpx.HTTPError as exc:
                where = _safe_url(exc.request.url) if _has_request(exc) else 'unknown URL'
                raise LoginError(f'{exc.__class__.__name__} calling {where}', step=index) from None
        return LoginResult(
            outputs=render(recipe.outputs, ctx),
            vars=ctx,
            saml=run.saml,
            response=run.response,
            page=run.page,
            cookies=self.cookies,
        )

    # -- steps -------------------------------------------------------------------------------------------------

    def _step(self, run: _Run, step: Step) -> Ops:
        if step.when is not None and not self._condition(step.when, run.ctx):
            return
        actions = getattr(self, f'_do_{step.action}')(run, step)
        if actions is not None:  # I/O-performing actions are generators; the rest return None
            yield from actions
        if step.action != 'extract' and step.extract:
            self._extract(run, step.extract)

    def _do_request(self, run: _Run, step: Step) -> Ops:
        spec = render(step.spec or {}, run.ctx)
        if not spec.get('url'):
            raise LoginError('request step rendered without a url')
        yield from self._send(
            run,
            method=spec.get('method', 'GET').upper(),
            url=urljoin(run.base_url, spec['url']),
            params=spec.get('params'),
            data=spec.get('data'),
            json=spec.get('json'),
            headers=spec.get('headers'),
        )
        yield from self._follow(run, step.follow)

    def _do_submit_form(self, run: _Run, step: Step) -> Ops:
        spec = render(step.spec or {}, run.ctx)
        if run.page is None:
            raise LoginError('submit_form with no page loaded')
        if spec.get('selector'):
            form = run.page.form(spec['selector'])
            if form is None:
                raise LoginError(f'no form matching {spec["selector"]} on {_safe_url(run.page.url)}')
        else:
            form = run.page.login_form()
            if form is None:
                raise LoginError(
                    f'no login form on {_safe_url(run.page.url)} (if the page is built by JavaScript, '
                    'this IdP needs a vendor recipe)'
                )
        creds = spec.get('credentials') or {}
        form.fill_credentials(username=creds.get('username'), password=creds.get('password'))
        submitted_password, submitted_otp = form.password_field() is not None, form.kind == 'otp'
        if submitted_otp:
            if spec.get('otp'):
                form.fill_otp(str(spec['otp']))
            elif spec.get('totp_secret'):
                form.fill_otp(Totp(spec['totp_secret'], clock=self._clock).now())
            else:
                raise LoginError(f'{_safe_url(run.page.url)} asks for a one-time code but no totp_secret was given')
        form.fill(spec.get('fill') or {})

        if not (
            yield from self._navigate(run, form.to_navigation(submitter=True), self._follow_options(run, step.follow))
        ):
            return
        yield from self._follow(run, step.follow)

        if spec.get('detect_rejection') and run.saml.response is None and run.page is not None:
            again = run.page.login_form()
            if again is not None and (
                (submitted_password and again.password_field() is not None) or (submitted_otp and again.kind == 'otp')
            ):
                what = 'one-time code' if submitted_otp else 'login'
                raise LoginError(f'{what} rejected: {run.page.error_text() or "the same form came back"}')

    def _do_extract(self, run: _Run, step: Step) -> None:
        self._extract(run, step.extract)

    def _do_set(self, run: _Run, step: Step) -> None:
        for key, value in (step.spec or {}).items():
            run.ctx[key] = render(value, run.ctx)

    def _do_sleep(self, run: _Run, step: Step) -> Ops:
        yield Sleep(float(render(step.spec, run.ctx) or 0))

    def _do_fail(self, run: _Run, step: Step) -> None:
        raise LoginError(str(render(step.spec, run.ctx) or 'recipe failed'))

    def _do_loop(self, run: _Run, step: Step) -> Ops:
        spec = step.spec
        limit = int(render(spec.get('max', DEFAULT_LOOP_MAX), run.ctx))
        for _ in range(limit):
            for child in step.steps:
                yield from self._step(run, child)
            if self._condition(spec['until'], run.ctx):
                return
        raise LoginError(
            (spec.get('message') and render(spec['message'], run.ctx)) or f'loop did not finish in {limit} iterations'
        )

    def _do_mfa(self, run: _Run, step: Step) -> None:
        spec = render(step.spec, run.ctx)
        factor = spec['factor']
        if factor == 'totp':
            if spec.get('uri'):
                totp = Totp.from_uri(spec['uri'], clock=self._clock)
            elif spec.get('secret'):
                totp = Totp(
                    spec['secret'],
                    digits=int(spec.get('digits', 6)),
                    period=int(spec.get('period', 30)),
                    algorithm=spec.get('algorithm', 'SHA1'),
                    clock=self._clock,
                )
            else:
                raise LoginError('totp factor needs a secret or uri')
            run.ctx[spec['into']] = totp.now()
        elif factor == 'webauthn':
            raw = spec.get('credential')
            if raw is None or not spec.get('challenge') or not spec.get('origin'):
                raise LoginError('webauthn factor needs credential, challenge and origin')
            credential = raw if isinstance(raw, Credential) else Credential.from_dict(raw)
            ceremony = credential.registration if spec.get('ceremony') == 'register' else credential.assertion
            try:
                run.ctx[spec['into']] = ceremony(spec['challenge'], spec['origin'], rp_id=spec.get('rp_id'))
            except ValueError as exc:
                raise LoginError(f'webauthn: {exc}') from None
            if isinstance(raw, dict):
                raw.update(credential.to_dict())  # caller persists the new signature counter

    # -- browser behaviour -------------------------------------------------------------------------------------

    def _follow_options(self, run: _Run, follow) -> dict | None:
        if follow is False:
            return None
        opts = render(follow, run.ctx) if isinstance(follow, dict) else {}
        return {
            'deliver_saml': opts.get('deliver_saml', True) not in (False, 'false', 'False', 0),
            'max_hops': int(opts.get('max_hops', self._max_hops)),
        }

    def _follow(self, run: _Run, follow) -> Ops:
        opts = self._follow_options(run, follow)
        if opts is None or run.page is None:
            return
        for _ in range(opts['max_hops']):
            nav = run.page.auto_navigation()
            if nav is None or not (yield from self._navigate(run, nav, opts)):
                return
        raise LoginError(f'page auto-navigation did not settle after {opts["max_hops"]} hops')

    def _navigate(self, run: _Run, nav: Navigation, opts: dict | None) -> Generator[Op, Any, bool]:
        """Send a page-initiated request. Returns False when it was withheld (undelivered SAML assertion)."""
        if 'SAMLResponse' in nav.data:
            self._capture_saml(run, nav.data.get('SAMLResponse'), nav.data.get('RelayState'), nav.url)
            if opts is not None and not opts['deliver_saml']:
                return False
        if nav.method == 'GET':
            yield from self._send(run, 'GET', nav.url, params=nav.data or None)
        else:
            yield from self._send(run, nav.method, nav.url, data=nav.data)
        return True

    def _send(self, run: _Run, method: str, url: str, **kwargs) -> Ops:
        kwargs = {k: v for k, v in kwargs.items() if v is not None}
        response = yield HttpRequest(method, url, kwargs)
        run.response = response
        run.page = Page(response.text, str(response.url))
        if (assertion := run.page.form_field('SAMLResponse')) and run.saml.response is None:
            form = next(f for f in run.page.forms() if 'SAMLResponse' in f.fields)
            self._capture_saml(run, assertion, form.fields.get('RelayState'), form.action)

    def _capture_saml(self, run: _Run, response: str | None, relay_state: str | None, acs_url: str) -> None:
        run.saml.response, run.saml.relay_state, run.saml.acs_url = response, relay_state, acs_url
        if self._stop_at_saml and response:
            raise _AssertionCaptured

    # -- extraction and conditions -----------------------------------------------------------------------------

    def _extract(self, run: _Run, rules: list[dict]) -> None:
        for rule in rules:
            value = self._extract_one(run, render(rule, run.ctx))
            if value is None and rule.get('required'):
                raise LoginError(f'could not extract {rule["name"]!r} from {_safe_url(run.base_url)}')
            run.ctx[rule['name']] = value

    def _extract_one(self, run: _Run, rule: dict) -> Any:
        source, response, page = rule['from'], run.response, run.page
        if source == 'cookie':
            return self.cookies.get(rule.get('cookie') or rule['name'])
        if response is None:
            return None
        if source == 'json':
            try:
                value = response.json()
            except ValueError:
                return None
            return lookup(value, rule['path']) if rule.get('path') else value
        if source == 'js_object':
            value = page.js_object(rule['var'])
            return lookup(value, rule['path']) if rule.get('path') and value is not None else value
        if source == 'html':
            node = next(iter(page.css(rule['selector'])), None)
            if node is None:
                return None
            return node.attributes.get(rule['attr']) if rule.get('attr') else node.text(strip=True)
        if source == 'form_field':
            return page.form_field(rule['field'])
        if source == 'regex':
            match = re.search(rule['pattern'], response.text)
            if match is None:
                return None
            return match.group(int(rule.get('group', 1 if match.re.groups else 0)))
        if source == 'header':
            return response.headers.get(rule['header'])
        if source == 'url':
            return str(response.url)
        if source == 'status':
            return response.status_code
        return None

    def _condition(self, cond: Any, ctx: dict) -> bool:
        if not isinstance(cond, dict):
            return _present(render(cond, ctx))
        if len(cond) != 1:
            return all(self._condition({k: v}, ctx) for k, v in cond.items())
        ((op, arg),) = cond.items()
        if op == 'exists':
            return _present(render(arg, ctx))
        if op == 'not_exists':
            return not _present(render(arg, ctx))
        if op in ('equals', 'not_equals'):
            left, right = (render(v, ctx) for v in arg)
            same = left == right or (left is not None and right is not None and str(left) == str(right))
            return same if op == 'equals' else not same
        if op == 'all':
            return all(self._condition(c, ctx) for c in arg)
        if op == 'any':
            return any(self._condition(c, ctx) for c in arg)
        if op == 'not':
            return not self._condition(arg, ctx)
        raise LoginError(f'unknown condition {op!r}')


def _present(value: Any) -> bool:
    return value is not None and value != '' and value is not False


def _redact(message: str, secrets: list[str]) -> str:
    for secret in secrets:
        message = message.replace(secret, '***')
    return message


def _safe_url(url) -> str:
    """URL without query or fragment, which tend to carry tokens."""
    parts = urlsplit(str(url))
    return f'{parts.scheme}://{parts.netloc}{parts.path}' if parts.scheme else parts.path


def _has_request(exc: httpx.HTTPError) -> bool:
    try:
        exc.request  # noqa: B018 - property raises when unset
    except RuntimeError:
        return False
    return True
