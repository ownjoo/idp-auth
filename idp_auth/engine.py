"""Sync and async drivers: perform the I/O that a sans-I/O ``Flow`` asks for, on an httpx client."""

import asyncio
import time
from collections.abc import Awaitable, Callable, Generator
from typing import Any

import httpx

from idp_auth.flow import DEFAULT_MAX_HOPS, Flow, HttpRequest, LoginResult, Op, Sleep
from idp_auth.recipe import Recipe

DEFAULT_HEADERS = {
    # Some IdPs (Entra among them) serve a degraded or "unsupported browser" page to unknown user agents.
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/140.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
}
DEFAULT_TIMEOUT = 30


class AsyncEngine:
    def __init__(
        self,
        client: httpx.AsyncClient,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        max_hops: int = DEFAULT_MAX_HOPS,
    ):
        if not isinstance(client, httpx.AsyncClient):
            raise TypeError('AsyncEngine needs an httpx.AsyncClient; use SyncEngine with httpx.Client')
        self.client = client
        self._clock = clock
        self._sleep = sleep
        self._max_hops = max_hops

    async def run(self, recipe: Recipe, inputs: dict) -> LoginResult:
        flow = Flow(recipe, inputs, cookies=self.client.cookies, clock=self._clock, max_hops=self._max_hops)
        ops = flow.execute()
        reply, error = None, None
        while True:
            try:
                op = ops.throw(error) if error is not None else ops.send(reply)
            except StopIteration as done:
                return done.value
            reply, error = None, None
            try:
                if isinstance(op, HttpRequest):
                    reply = await self.client.request(op.method, op.url, follow_redirects=True, **op.kwargs)
                elif isinstance(op, Sleep):
                    await self._sleep(op.seconds)
            except httpx.HTTPError as exc:
                error = exc


class SyncEngine:
    def __init__(
        self,
        client: httpx.Client,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], Any] = time.sleep,
        max_hops: int = DEFAULT_MAX_HOPS,
    ):
        if not isinstance(client, httpx.Client):
            raise TypeError('SyncEngine needs an httpx.Client; use AsyncEngine with httpx.AsyncClient')
        self.client = client
        self._clock = clock
        self._sleep = sleep
        self._max_hops = max_hops

    def run(self, recipe: Recipe, inputs: dict) -> LoginResult:
        flow = Flow(recipe, inputs, cookies=self.client.cookies, clock=self._clock, max_hops=self._max_hops)
        ops: Generator[Op, Any, LoginResult] = flow.execute()
        reply, error = None, None
        while True:
            try:
                op = ops.throw(error) if error is not None else ops.send(reply)
            except StopIteration as done:
                return done.value
            reply, error = None, None
            try:
                if isinstance(op, HttpRequest):
                    reply = self.client.request(op.method, op.url, follow_redirects=True, **op.kwargs)
                elif isinstance(op, Sleep):
                    self._sleep(op.seconds)
            except httpx.HTTPError as exc:
                error = exc


Engine = AsyncEngine  # name used by the first release


def _as_recipe(recipe: str | Recipe | dict) -> Recipe:
    if isinstance(recipe, Recipe):
        return recipe
    if isinstance(recipe, dict):
        return Recipe.from_dict(recipe)
    return Recipe.load(recipe)


async def login(
    recipe: str | Recipe | dict,
    inputs: dict,
    client: httpx.AsyncClient | None = None,
    **engine_kwargs,
) -> LoginResult:
    """Run a recipe (bundled name, path, dict or Recipe). Creates a browser-like client if none is given."""
    recipe = _as_recipe(recipe)
    if client is not None:
        return await AsyncEngine(client, **engine_kwargs).run(recipe, inputs)
    async with httpx.AsyncClient(headers=DEFAULT_HEADERS, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as own:
        return await AsyncEngine(own, **engine_kwargs).run(recipe, inputs)


def login_sync(
    recipe: str | Recipe | dict,
    inputs: dict,
    client: httpx.Client | None = None,
    **engine_kwargs,
) -> LoginResult:
    """Blocking counterpart of ``login()``, on ``httpx.Client``. Safe to call from inside a running event loop."""
    recipe = _as_recipe(recipe)
    if client is not None:
        return SyncEngine(client, **engine_kwargs).run(recipe, inputs)
    with httpx.Client(headers=DEFAULT_HEADERS, follow_redirects=True, timeout=DEFAULT_TIMEOUT) as own:
        return SyncEngine(own, **engine_kwargs).run(recipe, inputs)
