"""AuthPlugin: the minimal composition unit (DESIGN §20.2, extracting §11).

A plugin is an id plus extra routes — nothing else. Handlers share the
built-in signature ``(auth, request) -> Response``, so promoting built-in
code to a plugin (or vice versa) is a dictionary move. Schema extensions
and lifecycle hooks stayed out on purpose: no second consumer exists yet
(§20.2 rejection table).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

Routes = Mapping[tuple[str, str], Any]


@dataclass(frozen=True)
class AuthPlugin:
    id: str
    routes: Routes = field(default_factory=dict)
