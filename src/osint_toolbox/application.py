"""Transport-independent collection boundary shared by local and team services.

Adapters do not authorize requests. Every execution must supply a backend-specific
authorization callback which records/checks consent before the adapter is called.
This module has no optional team dependencies and does not provide a network API.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .providers import PreparedCollection


TEAM_PROVIDERS = frozenset({"rdap", "dns", "crtsh", "wayback", "commoncrawl"})
TEAM_ANALYZERS = frozenset({"ffprobe", "exiftool"})


def validate_collection(provider: str, target: str, options: Mapping[str, str]) -> None:
    from .providers import PROVIDERS, _validate_collection_options

    if provider not in PROVIDERS:
        raise ValueError("Unknown collection provider")
    if not isinstance(target, str) or not target.strip() or len(target) > 2000:
        raise ValueError("Collection requires a bounded, non-empty target")
    if any(ord(c) < 32 for c in target):
        raise ValueError("Collection target contains control characters")
    if not isinstance(options, Mapping) or len(options) > 20 or any(
        not isinstance(k, str) or not isinstance(v, str) or len(k) > 80 or len(v) > 2000
        for k, v in options.items()
    ):
        raise ValueError("Invalid collection options")
    _validate_collection_options(provider, dict(options))


def execute_collection(provider: str, target: str, options: Mapping[str, str], *,
                       authorize: Callable[[], None]) -> PreparedCollection:
    """Validate, authorize, then collect. Never accept a client-supplied approval flag here."""
    from .providers import PREPARERS

    selected = dict(options)
    validate_collection(provider, target, selected)
    authorize()
    result = PREPARERS[provider](target, selected)
    if result.provider != provider:
        raise ValueError("Adapter returned a different provider identity")
    return result
