"""Tagging policy: which tag keys are required and what values they may hold."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    """Raised when a policy file is malformed."""


@dataclass
class TagRule:
    key: str
    allowed: list[str] | None = None
    pattern: re.Pattern[str] | None = None
    ignore_case: bool = False

    def check_value(self, value: str) -> str | None:
        """Return a human-readable reason if ``value`` breaks the rule, else None."""
        if self.allowed is not None:
            if self.ignore_case:
                ok = value.lower() in {a.lower() for a in self.allowed}
            else:
                ok = value in self.allowed
            if not ok:
                return f"not one of: {', '.join(self.allowed)}"
        if self.pattern is not None and not self.pattern.search(value):
            return f"does not match /{self.pattern.pattern}/"
        return None


@dataclass
class TypeOverride:
    tags: dict[str, TagRule] = field(default_factory=dict)
    skip: set[str] = field(default_factory=set)
    ignore: bool = False


@dataclass
class Policy:
    tags: dict[str, TagRule]
    owner_key: str = "Owner"
    overrides: dict[str, TypeOverride] = field(default_factory=dict)

    def rules_for(self, resource_type: str) -> dict[str, TagRule] | None:
        """Effective rules for a resource type, or None if the type is ignored.

        Overrides keyed by a bare service ("s3") apply first, then overrides
        keyed by "service:type" ("ec2:snapshot"), so the more specific one wins.
        """
        rules = dict(self.tags)
        service = resource_type.split(":", 1)[0]
        keys = [service] if service == resource_type else [service, resource_type]
        for k in keys:
            ov = self.overrides.get(k)
            if ov is None:
                continue
            if ov.ignore:
                return None
            for key in ov.skip:
                rules.pop(key, None)
            rules.update(ov.tags)
        return rules


def _parse_rule(key: str, spec: Any, where: str) -> TagRule:
    if spec is None:
        spec = {}
    if not isinstance(spec, dict):
        raise PolicyError(f"{where}.{key}: expected a mapping, got {type(spec).__name__}")
    unknown = set(spec) - {"allowed", "pattern", "ignore_case"}
    if unknown:
        raise PolicyError(f"{where}.{key}: unknown field(s) {', '.join(sorted(unknown))}")
    allowed = spec.get("allowed")
    if allowed is not None:
        if not isinstance(allowed, list) or not allowed:
            raise PolicyError(f"{where}.{key}.allowed must be a non-empty list")
        allowed = [str(a) for a in allowed]
    pattern = spec.get("pattern")
    compiled = None
    if pattern is not None:
        try:
            compiled = re.compile(str(pattern))
        except re.error as exc:
            raise PolicyError(f"{where}.{key}.pattern is not a valid regex: {exc}") from exc
    return TagRule(key=key, allowed=allowed, pattern=compiled, ignore_case=bool(spec.get("ignore_case", False)))


def _parse_tags(raw: Any, where: str) -> dict[str, TagRule]:
    if raw is None:
        return {}
    if isinstance(raw, list):  # shorthand: just a list of required keys
        raw = {str(k): {} for k in raw}
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}: expected a mapping or list of tag keys")
    return {str(k): _parse_rule(str(k), v, where) for k, v in raw.items()}


def parse_policy(data: Any) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping at the top level")
    unknown = set(data) - {"tags", "owner_key", "resource_types"}
    if unknown:
        raise PolicyError(f"unknown top-level field(s): {', '.join(sorted(unknown))}")
    tags = _parse_tags(data.get("tags"), "tags")
    if not tags:
        raise PolicyError("policy defines no required tags")
    overrides: dict[str, TypeOverride] = {}
    for rtype, spec in (data.get("resource_types") or {}).items():
        where = f"resource_types.{rtype}"
        spec = spec or {}
        if not isinstance(spec, dict):
            raise PolicyError(f"{where}: expected a mapping")
        unknown = set(spec) - {"tags", "skip", "ignore"}
        if unknown:
            raise PolicyError(f"{where}: unknown field(s) {', '.join(sorted(unknown))}")
        overrides[str(rtype)] = TypeOverride(
            tags=_parse_tags(spec.get("tags"), f"{where}.tags"),
            skip={str(s) for s in spec.get("skip") or []},
            ignore=bool(spec.get("ignore", False)),
        )
    return Policy(tags=tags, owner_key=str(data.get("owner_key", "Owner")), overrides=overrides)


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        import yaml

        data = yaml.safe_load(text)
    return parse_policy(data)
