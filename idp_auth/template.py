"""``${dotted.path}`` substitution over the flow context.

A string that is exactly one ``${...}`` expression renders to the raw value (dicts, ints, None survive);
anything else interpolates as text. Inside dicts, entries whose key or value renders to None are dropped,
which lets recipes reference optional fields (e.g. an anti-CSRF token only some pages carry).
"""

import re
from typing import Any

_EXPR = re.compile(r'\$\{([^}]+)\}')


def lookup(ctx: Any, path: str) -> Any:
    value = ctx
    for part in path.strip().split('.'):
        if isinstance(value, dict):
            value = value.get(part)
        elif isinstance(value, (list, tuple)) and part.lstrip('-').isdigit():
            index = int(part)
            value = value[index] if -len(value) <= index < len(value) else None
        else:
            value = getattr(value, part, None) if not isinstance(value, (str, bytes)) else None
        if value is None:
            return None
    return value


def render(value: Any, ctx: dict) -> Any:
    if isinstance(value, str):
        whole = _EXPR.fullmatch(value)
        if whole:
            return lookup(ctx, whole.group(1))
        return _EXPR.sub(lambda m: _text(lookup(ctx, m.group(1))), value)
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            key, val = render(k, ctx), render(v, ctx)
            if key is not None and val is not None:
                out[key] = val
        return out
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    return value


def _text(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return str(value)
