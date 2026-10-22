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
UNSUBMITTED_TYPES = {'submit', 'button', 'image', 'reset', 'file'}
FEDERATION_FIELDS = {'SAMLResponse', 'SAMLRequest', 'wresult', 'wa'}

_META_URL = re.compile(r'url\s*=\s*([\'"]?)(.+?)\1\s*$', re.IGNORECASE)
_JS_ASSIGN = re.compile(
    r'(?:\b(?:window|document|top|self|parent)\.)?\blocation(?:\.href)?\s*=\s*([\'"])(.*?)(?<!\\)\1'
)
_JS_CALL = re.compile(r'\blocation\.(?:replace|assign)\(\s*([\'"])(.*?)(?<!\\)\1\s*\)')
_JS_ESCAPE = re.compile(r'\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)')
_SUBMIT_CALL = re.compile(r'\.submit\(\s*\)')


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

    def fill(self, values: dict) -> None:
        self.fields.update(values)

    def fill_credentials(self, username: str | None = None, password: str | None = None) -> None:
        if password is not None:
            for name, kind in self.input_types.items():
                if kind == 'password':
                    self.fields[name] = password
                    break
        if username is not None and (name := self._username_field()):
            self.fields[name] = username

    def _username_field(self) -> str | None:
        for name, kind in self.input_types.items():
            if name.lower() in USERNAME_NAMES or kind == 'email':
                return name
        for name, kind in self.input_types.items():
            if kind == 'password':
                break
            if kind == 'text':
                return name
        return None

    def to_navigation(self) -> Navigation:
        return Navigation(self.method, self.action, dict(self.fields))


class Page:
    def __init__(self, text: str, url: str):
        self.text, self.url = text, url
        self._tree = LexborHTMLParser(text)

    # -- forms -------------------------------------------------------------------------------------------------

    def forms(self) -> list[Form]:
        return [self._form(node) for node in self._tree.css('form')]

    def form(self, selector: str | None = None) -> Form | None:
        node = self._tree.css_first(selector) if selector else self._tree.css_first('form')
        if node is not None and node.tag != 'form':
            node = None
        return self._form(node) if node is not None else None

    def form_field(self, name: str) -> str | None:
        for form in self.forms():
            if name in form.fields:
                return form.fields[name]
        return None

    def _form(self, node: LexborNode) -> Form:
        fields, types = {}, {}
        for control in node.css('input, select, textarea'):
            attrs = control.attributes
            name = attrs.get('name')
            if not name or 'disabled' in attrs:
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
        )

    # -- navigation --------------------------------------------------------------------------------------------

    def auto_navigation(self) -> Navigation | None:
        forms = self.forms()
        scripts = [node.text() for node in self._tree.css('script')]
        body = self._tree.body
        onload = (body.attributes.get('onload') or '') if body is not None else ''
        script_submits = bool(_SUBMIT_CALL.search(onload)) or any(_SUBMIT_CALL.search(s) for s in scripts)

        for form in forms:
            hidden_only = form.input_types and all(kind == 'hidden' for kind in form.input_types.values())
            if hidden_only and (script_submits or FEDERATION_FIELDS & form.fields.keys()):
                return form.to_navigation()

        for meta in self._tree.css('meta'):
            if (meta.attributes.get('http-equiv') or '').lower() == 'refresh':
                match = _META_URL.search(meta.attributes.get('content') or '')
                if match:
                    return Navigation('GET', urljoin(self.url, match.group(2).strip()))

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
