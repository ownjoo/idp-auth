"""The parts of a browser that IdP login pages actually rely on: forms, auto-submit, meta refresh, JS redirects,
and JSON config blobs embedded in ``<script>`` tags."""

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

from selectolax.lexbor import LexborHTMLParser, LexborNode

USERNAME_NAMES = {
    'username', 'user_name', 'user', 'login', 'loginfmt', 'email', 'identifier', 'userid', 'user_id', 'uid',
    'j_username', 'pf.username', 'usernameuserinput', 'ctl00$contentplaceholder1$usernametextbox',
}  # fmt: skip
OTP_NAMES = {
    'otp', 'totp', 'code', 'passcode', 'otpcode', 'mfacode', 'verificationcode', 'onetimecode', 'securitycode',
    'authcode', 'tokencode', 'jotp',
}  # fmt: skip
UNSUBMITTED_TYPES = {'submit', 'button', 'image', 'reset', 'file'}
SUBMIT_TYPES = {'submit', 'image'}
NON_VISIBLE_TYPES = {'hidden', 'checkbox', 'radio'}
ERROR_SELECTORS = (
    '[role=alert]', '#errorText', '#error-text', '.error', '.errors', '.error-message', '.errorText', '.output--error',
    '.alert-danger', '.alert-error', '.kc-feedback-text', '.form-error', '.ping-error', '.text-danger',
)  # fmt: skip
FEDERATION_FIELDS = {'SAMLResponse', 'SAMLRequest', 'wresult', 'wa'}

_META_URL = re.compile(r'url\s*=\s*([\'"]?)(.+?)\1\s*$', re.IGNORECASE)
_JS_ASSIGN = re.compile(
    r'(?:\b(?:window|document|top|self|parent)\.)?\blocation(?:\.href)?\s*=\s*([\'"])(.*?)(?<!\\)\1'
)
_JS_CALL = re.compile(r'\blocation\.(?:replace|assign)\(\s*([\'"])(.*?)(?<!\\)\1\s*\)')
_JS_ESCAPE = re.compile(r'\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)')
_SUBMIT_CALL = re.compile(r'\.submit\(\s*\)')
_LOGOUT = re.compile(r'log[-_]?out|sign[-_]?out|sign[-_]?off', re.IGNORECASE)
_SHELL_TEXT_LIMIT = 300  # visible characters; more than this and the page is content, not a redirect shell


@dataclass
class Navigation:
    """A request the page would make on its own, without user interaction."""

    method: str
    url: str
    data: dict = field(default_factory=dict)


@dataclass
class Form:
    method: str
    action: str
    fields: dict
    input_types: dict  # name -> lowercased input type, in document order
    autocomplete: dict = field(default_factory=dict)  # name -> lowercased autocomplete attribute
    submitter: tuple[str, str] | None = None  # default button's (name, value), sent when a user submits
    has_submit: bool = False

    @property
    def kind(self) -> str:
        """'credentials', 'otp', 'interstitial' (nothing to fill, just a button) or 'other'."""
        if self.password_field() is not None:
            return 'credentials'
        if self.otp_field() is not None:
            return 'otp'
        if self._username_field(fallback=False) is not None:
            return 'credentials'
        if self.has_submit and all(kind in NON_VISIBLE_TYPES for kind in self.input_types.values()):
            return 'interstitial'
        return 'other'

    @property
    def roles(self) -> frozenset[str]:
        """Which of username / password / otp this form asks a person for (hidden fields don't count)."""
        found = {
            role
            for role, name in (
                ('username', self._username_field(fallback=False)),
                ('password', self.password_field()),
                ('otp', self.otp_field()),
            )
            if name is not None
        }
        return frozenset(found)

    @property
    def hidden_only(self) -> bool:
        return bool(self.input_types) and all(kind == 'hidden' for kind in self.input_types.values())

    def fill(self, values: dict) -> None:
        self.fields.update(values)

    def fill_credentials(self, username: str | None = None, password: str | None = None) -> None:
        if password is not None and (name := self.password_field()):
            self.fields[name] = password
        if username is not None and (name := self._username_field()):
            self.fields[name] = username

    def fill_otp(self, code: str) -> bool:
        name = self.otp_field()
        if name is None:
            return False
        self.fields[name] = code
        return True

    def password_field(self) -> str | None:
        otp = self.otp_field()
        return next((n for n, k in self.input_types.items() if k == 'password' and n != otp), None)

    def otp_field(self) -> str | None:
        for name, kind in self.input_types.items():
            if kind not in ('text', 'tel', 'number', 'password'):
                continue
            if self.autocomplete.get(name) == 'one-time-code' or re.sub(r'[\W_]', '', name.lower()) in OTP_NAMES:
                return name
        return None

    def _username_field(self, fallback: bool = True) -> str | None:
        otp = self.otp_field()
        candidates = [(n, k) for n, k in self.input_types.items() if k not in NON_VISIBLE_TYPES and n != otp]
        for name, kind in candidates:
            if name.lower() in USERNAME_NAMES or kind == 'email' or self.autocomplete.get(name) == 'username':
                return name
        if not fallback:
            return None
        for name, kind in candidates:
            if kind == 'password':
                break
            if kind == 'text':
                return name
        return None

    def to_navigation(self, submitter: bool = False) -> Navigation:
        """``submitter=True`` mimics a person pressing the default button; script ``form.submit()`` omits it."""
        data = dict(self.fields)
        if submitter and self.submitter is not None:
            data[self.submitter[0]] = self.submitter[1]
        return Navigation(self.method, self.action, data)


class Page:
    def __init__(self, text: str, url: str):
        self.text, self.url = text, url
        self._tree = LexborHTMLParser(text)
        self._visible: str | None = None  # memoised; computed only if auto_navigation needs it

    # -- forms -------------------------------------------------------------------------------------------------

    def forms(self) -> list[Form]:
        return [self._form(node) for node in self._tree.css('form')]

    def form(self, selector: str | None = None) -> Form | None:
        node = self._tree.css_first(selector) if selector else self._tree.css_first('form')
        if node is not None and node.tag != 'form':
            node = None
        return self._form(node) if node is not None else None

    def login_form(self) -> Form | None:
        """The form a person would fill next: credentials, then a one-time code, then a bare continue/consent."""
        forms = self.forms()
        for kind in ('credentials', 'otp', 'interstitial'):
            for form in forms:
                if form.kind == kind:
                    return form
        return None

    def error_text(self) -> str | None:
        """Visible error message in a conventional container, truncated to 200 characters."""
        for selector in ERROR_SELECTORS:
            for node in self._tree.css(selector):
                text = ' '.join(node.text(separator=' ').split())
                if text:
                    return text[:200]
        return None

    def form_field(self, name: str) -> str | None:
        for form in self.forms():
            if name in form.fields:
                return form.fields[name]
        return None

    def _form(self, node: LexborNode) -> Form:
        fields, types, autocomplete = {}, {}, {}
        submitter, has_submit = None, False
        for control in node.css('input, select, textarea, button'):
            attrs = control.attributes
            name = attrs.get('name')
            if 'disabled' in attrs:
                continue
            if _is_submit(control):
                if not has_submit and name:
                    submitter = (name, attrs.get('value') or '')
                has_submit = True
                continue
            if not name or control.tag == 'button':
                continue
            if control.tag == 'select':
                options = control.css('option')
                chosen = next((o for o in options if 'selected' in o.attributes), options[0] if options else None)
                if chosen is not None:
                    fields[name] = chosen.attributes.get('value') or chosen.text(strip=True)
                types[name] = 'select'
                continue
            if control.tag == 'textarea':
                fields[name], types[name] = control.text(), 'textarea'
                continue
            kind = (attrs.get('type') or 'text').lower()
            if kind in UNSUBMITTED_TYPES:
                continue
            types[name] = kind
            if attrs.get('autocomplete'):
                autocomplete[name] = attrs['autocomplete'].lower()
            if kind in ('checkbox', 'radio'):
                if 'checked' in attrs:
                    fields[name] = attrs.get('value') or 'on'
                continue
            fields[name] = attrs.get('value') or ''
        attrs = node.attributes
        return Form(
            method=(attrs.get('method') or 'GET').upper(),
            action=urljoin(self.url, attrs.get('action') or self.url),
            fields=fields,
            input_types=types,
            autocomplete=autocomplete,
            submitter=submitter,
            has_submit=has_submit,
        )

    # -- navigation --------------------------------------------------------------------------------------------

    def auto_navigation(self) -> Navigation | None:
        forms = self.forms()
        scripts = [node.text() for node in self._tree.css('script')]
        body = self._tree.body
        onload = (body.attributes.get('onload') or '') if body is not None else ''
        script_submits = bool(_SUBMIT_CALL.search(onload)) or any(_SUBMIT_CALL.search(s) for s in scripts)

        candidates = [f for f in forms if f.hidden_only and not _is_logout(f)]
        for form in candidates:
            if script_submits or FEDERATION_FIELDS & form.fields.keys():
                return form.to_navigation()

        for meta in self._tree.css('meta'):
            if (meta.attributes.get('http-equiv') or '').lower() == 'refresh':
                if meta.attributes.get('data-url'):  # PingFederate templates
                    return Navigation('GET', urljoin(self.url, meta.attributes['data-url'].strip()))
                match = _META_URL.search(meta.attributes.get('content') or '')
                if match:
                    return Navigation('GET', urljoin(self.url, match.group(2).strip()))

        # A lone hidden-only form with no button can only be submitted by script; when the script is external we
        # can't see the submit() call, so follow it if the page is otherwise just a "please wait" shell.
        if (
            len(forms) == 1
            and candidates
            and not candidates[0].has_submit
            and scripts
            and len(self._visible_text()) < _SHELL_TEXT_LIMIT
        ):
            return candidates[0].to_navigation()

        if any(kind != 'hidden' for form in forms for kind in form.input_types.values()):
            return None  # an interactive page; any location= in its scripts is behind user action
        for script in scripts:
            match = _JS_CALL.search(script) or _JS_ASSIGN.search(script)
            if match:
                return Navigation('GET', urljoin(self.url, _unescape_js(match.group(2))))
        return None

    # -- embedded data -----------------------------------------------------------------------------------------

    def js_object(self, var: str) -> dict | list | None:
        """Parse the JSON literal assigned to ``var`` in an inline script, e.g. Entra's ``$Config={...};``."""
        for match in re.finditer(re.escape(var) + r'\s*=\s*(?=[{\[])', self.text):
            literal = _balanced(self.text, match.end())
            if literal is not None:
                try:
                    return json.loads(literal)
                except json.JSONDecodeError:
                    continue
        return None

    def css(self, selector: str) -> list[LexborNode]:
        return self._tree.css(selector)

    def _visible_text(self) -> str:
        if self._visible is None:
            tree = LexborHTMLParser(self.text)
            tree.strip_tags(['script', 'style', 'noscript', 'template'])
            body = tree.body
            self._visible = ' '.join(body.text(separator=' ').split()) if body is not None else ''
        return self._visible


def _is_logout(form: 'Form') -> bool:
    """A form is a sign-out if its action says so or a field carries a WS-Federation signout (wa=wsignout...)."""
    return bool(_LOGOUT.search(form.action)) or any(_LOGOUT.search(str(v)) for v in form.fields.values())


def _is_submit(control: LexborNode) -> bool:
    kind = (control.attributes.get('type') or '').lower()
    if control.tag == 'button':
        return kind in ('', 'submit')  # a <button> without a type is a submit button
    return control.tag == 'input' and kind in SUBMIT_TYPES


def _unescape_js(text: str) -> str:
    def replace(match: re.Match) -> str:
        esc = match.group(1)
        if esc[0] in 'ux' and len(esc) > 1:
            return chr(int(esc[1:], 16))
        return {'n': '\n', 't': '\t', 'r': '\r'}.get(esc, esc)

    return _JS_ESCAPE.sub(replace, text)


def _balanced(text: str, start: int) -> str | None:
    pairs = {'{': '}', '[': ']'}
    stack, quote, i = [], None, start
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == '\\':
                i += 1
            elif ch == quote:
                quote = None
        elif ch in '"\'':
            quote = ch
        elif ch in pairs:
            stack.append(pairs[ch])
        elif ch in '}]':
            if not stack or stack.pop() != ch:
                return None
            if not stack:
                return text[start : i + 1]
        i += 1
    return None
