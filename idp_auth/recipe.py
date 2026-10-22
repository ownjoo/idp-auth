"""Declarative login recipes: an IdP's flow as data, validated before anything runs."""

import json
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from idp_auth.errors import RecipeError

ACTIONS = {'request', 'submit_form', 'extract', 'set', 'mfa', 'sleep', 'loop', 'fail'}
MODIFIERS = {'when', 'id', 'extract', 'follow', 'name'}
EXTRACT_SOURCES = {'json', 'js_object', 'html', 'form_field', 'regex', 'header', 'cookie', 'url', 'status'}
FACTORS = {'totp', 'webauthn'}


@dataclass
class Step:
    action: str
    spec: Any
    when: Any = None
    extract: list = field(default_factory=list)
    follow: Any = True
    label: str | None = None
    steps: list['Step'] = field(default_factory=list)  # loop body


@dataclass
class InputSpec:
    name: str
    default: Any = None
    required: bool = True
    secret: bool = False


@dataclass
class Recipe:
    name: str
    steps: list[Step]
    inputs: dict[str, InputSpec] = field(default_factory=dict)
    outputs: dict = field(default_factory=dict)
    description: str = ''

    @classmethod
    def from_dict(cls, data: dict) -> 'Recipe':
        if not isinstance(data, dict) or not data.get('name'):
            raise RecipeError('recipe must be a mapping with a name')
        return cls(
            name=data['name'],
            description=data.get('description', ''),
            inputs=_parse_inputs(data.get('inputs') or {}),
            steps=_parse_steps(data.get('steps') or [], path='steps'),
            outputs=data.get('outputs') or {},
        )

    @classmethod
    def load(cls, name_or_path: str | Path) -> 'Recipe':
        path = Path(name_or_path)
        if path.suffix in ('.yaml', '.yml', '.json') or path.exists():
            text = path.read_text(encoding='utf-8')
            data = json.loads(text) if path.suffix == '.json' else yaml.safe_load(text)
            return cls.from_dict(data)
        bundled = resources.files('idp_auth') / 'recipes' / f'{name_or_path}.yaml'
        if not bundled.is_file():
            raise FileNotFoundError(f'no bundled recipe named {name_or_path!r}; available: {cls.bundled()}')
        return cls.from_dict(yaml.safe_load(bundled.read_text(encoding='utf-8')))

    @staticmethod
    def bundled() -> list[str]:
        folder = resources.files('idp_auth') / 'recipes'
        return sorted(p.name.removesuffix('.yaml') for p in folder.iterdir() if p.name.endswith('.yaml'))

    def bind_inputs(self, given: dict) -> dict:
        unknown = set(given) - set(self.inputs)
        if unknown:
            raise RecipeError(f'unknown inputs for recipe {self.name!r}: {sorted(unknown)}')
        bound = {}
        for name, spec in self.inputs.items():
            if name in given:
                bound[name] = given[name]
            elif spec.required:
                raise RecipeError(f'recipe {self.name!r} requires input {name!r}')
            else:
                bound[name] = spec.default
        return bound

    def secret_inputs(self) -> set[str]:
        return {name for name, spec in self.inputs.items() if spec.secret}


def _parse_inputs(raw) -> dict[str, InputSpec]:
    if isinstance(raw, list):
        raw = {name: {} for name in raw}
    if not isinstance(raw, dict):
        raise RecipeError('inputs must be a list of names or a mapping')
    specs = {}
    for name, spec in raw.items():
        spec = spec or {}
        specs[name] = InputSpec(
            name=name,
            default=spec.get('default'),
            required='default' not in spec,
            secret=bool(spec.get('secret', False)),
        )
    return specs


def _parse_steps(raw, path: str) -> list[Step]:
    if not isinstance(raw, list):
        raise RecipeError(f'{path} must be a list')
    return [_parse_step(item, f'{path}[{i}]') for i, item in enumerate(raw)]


def _parse_step(raw, path: str) -> Step:
    if not isinstance(raw, dict):
        raise RecipeError(f'{path} must be a mapping')
    unknown = set(raw) - ACTIONS - MODIFIERS
    if unknown:
        raise RecipeError(f'{path}: unknown keys {sorted(unknown)}')
    actions = (set(raw) & ACTIONS) - {'extract'}
    if not actions and 'extract' in raw:
        actions = {'extract'}
    if len(actions) != 1:
        raise RecipeError(f'{path}: a step needs exactly one action, got {sorted(actions) or "none"}')
    action = actions.pop()
    spec = raw[action]
    extract = raw.get('extract') or []
    if not isinstance(extract, list):
        raise RecipeError(f'{path}.extract must be a list')
    for i, rule in enumerate(extract):
        _check_extract(rule, f'{path}.extract[{i}]')

    step = Step(
        action=action,
        spec=None if action == 'extract' else spec,
        when=raw.get('when'),
        extract=extract,
        follow=raw.get('follow', True),
        label=raw.get('name') or raw.get('id'),
    )
    if action == 'loop':
        if not isinstance(spec, dict) or 'until' not in spec:
            raise RecipeError(f'{path}.loop needs an "until" condition')
        step.steps = _parse_steps(spec.get('steps') or [], f'{path}.loop.steps')
    elif action == 'mfa':
        if not isinstance(spec, dict) or spec.get('factor') not in FACTORS or not spec.get('into'):
            raise RecipeError(f'{path}.mfa needs factor (one of {sorted(FACTORS)}) and into')
    elif action in ('request', 'set', 'submit_form') and spec is not None and not isinstance(spec, dict):
        raise RecipeError(f'{path}.{action} must be a mapping')
    return step


def _check_extract(rule, path: str) -> None:
    if not isinstance(rule, dict) or not rule.get('name') or rule.get('from') not in EXTRACT_SOURCES:
        raise RecipeError(f'{path} needs a name and from (one of {sorted(EXTRACT_SOURCES)})')
