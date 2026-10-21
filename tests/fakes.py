"""Strict, discovery-validated fake of the googleapiclient Gmail v1 service.

Every method call is checked against the bundled Gmail discovery document the
same way the real client does it: unknown keyword arguments, missing required
parameters and bad enum values raise TypeError at call time. `body` is only
accepted by methods that declare a request body.

Usage:
    svc = StrictGmail({"users.drafts.get": lambda **kw: {...}})
    svc.users().drafts().get(userId="me", id="d1", format="full").execute()
    svc.calls  # [("users.drafts.get", {...}), ...]

Handlers are keyed by dotted method path and receive the validated kwargs.
Calling a method with no handler raises AssertionError (the test forgot it)."""

from __future__ import annotations

import json
from collections.abc import Callable
from functools import lru_cache
from types import SimpleNamespace
from typing import Any

from googleapiclient.discovery_cache import get_static_doc


@lru_cache(maxsize=None)
def gmail_discovery() -> dict:
    return json.loads(get_static_doc("gmail", "v1"))


def _validate(path: str, method: dict, kwargs: dict) -> None:
    params = method.get("parameters", {})
    allowed = set(params) | ({"body"} if method.get("request") else set())
    for k in kwargs:
        if k not in allowed:
            raise TypeError(f'Got an unexpected keyword argument {k}')
    for name, spec in params.items():
        if spec.get("required") and name not in kwargs:
            raise TypeError(f'Missing required parameter "{name}"')
        if name in kwargs and "enum" in spec:
            values = kwargs[name] if spec.get("repeated") and isinstance(kwargs[name], list) else [kwargs[name]]
            for v in values:
                if v not in spec["enum"]:
                    raise TypeError(f'Parameter "{name}" value "{v}" is not an allowed value in {spec["enum"]}')


class _Resource:
    def __init__(self, root: StrictGmail, path: str, doc: dict):
        self._root, self._path, self._doc = root, path, doc

    def __getattr__(self, name: str):
        sub = self._doc.get("resources", {}).get(name)
        if sub is not None:
            return lambda: _Resource(self._root, f"{self._path}.{name}".lstrip("."), sub)
        method = self._doc.get("methods", {}).get(name)
        if method is not None:
            return self._root._method(f"{self._path}.{name}".lstrip("."), method)
        raise AttributeError(f"Gmail resource '{self._path or 'root'}' has no attribute '{name}'")


class StrictGmail(_Resource):
    def __init__(self, handlers: dict[str, Callable[..., Any]] | None = None):
        self.handlers: dict[str, Callable[..., Any]] = dict(handlers or {})
        self.calls: list[tuple[str, dict]] = []
        super().__init__(self, "", gmail_discovery())

    def _method(self, path: str, method: dict):
        def call(**kwargs):
            _validate(path, method, kwargs)
            self.calls.append((path, kwargs))
            handler = self.handlers.get(path)
            if handler is None:
                raise AssertionError(f"no fake handler for {path}")
            return SimpleNamespace(execute=lambda: handler(**kwargs))

        return call

    def calls_to(self, path: str) -> list[dict]:
        return [kw for p, kw in self.calls if p == path]
