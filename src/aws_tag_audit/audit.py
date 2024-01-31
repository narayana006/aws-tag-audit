"""Check resources against a tagging policy."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass

from .policy import Policy
from .resources import Resource

UNOWNED = "(no owner)"


@dataclass(frozen=True)
class Finding:
    arn: str
    account: str
    region: str
    service: str
    resource_type: str
    owner: str
    key: str
    problem: str  # missing | empty | invalid | key-case
    value: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class AuditResult:
    findings: list[Finding]
    checked: int
    compliant: int
    skipped: int

    @property
    def noncompliant(self) -> int:
        return self.checked - self.compliant

    def counts(self, group_by: str) -> Counter[str]:
        """Number of non-compliant resources per group (not number of findings)."""
        seen: dict[str, set[str]] = {}
        for f in self.findings:
            seen.setdefault(getattr(f, group_by), set()).add(f.arn)
        return Counter({g: len(arns) for g, arns in seen.items()})


def _owner(resource: Resource, owner_key: str) -> str:
    value = resource.tags.get(owner_key, "").strip()
    if value:
        return value
    lowered = owner_key.lower()
    for k, v in resource.tags.items():
        if k.lower() == lowered and v.strip():
            return v.strip()
    return UNOWNED


def check_resource(resource: Resource, policy: Policy) -> list[Finding] | None:
    """Findings for one resource, or None if its type is ignored by the policy."""
    rules = policy.rules_for(resource.resource_type)
    if rules is None:
        return None
    owner = _owner(resource, policy.owner_key)
    lower_keys = {k.lower(): k for k in resource.tags}

    def make(key: str, problem: str, value: str, detail: str) -> Finding:
        return Finding(
            arn=resource.arn,
            account=resource.account,
            region=resource.region,
            service=resource.service,
            resource_type=resource.resource_type,
            owner=owner,
            key=key,
            problem=problem,
            value=value,
            detail=detail,
        )

    findings = []
    for key, rule in rules.items():
        if key not in resource.tags:
            actual = lower_keys.get(key.lower())
            if actual is not None:
                findings.append(make(key, "key-case", resource.tags[actual], f"found as '{actual}'"))
            else:
                findings.append(make(key, "missing", "", "required tag not present"))
            continue
        value = resource.tags[key]
        if not value.strip():
            findings.append(make(key, "empty", value, "tag present with an empty value"))
            continue
        reason = rule.check_value(value)
        if reason:
            findings.append(make(key, "invalid", value, reason))
    return findings


def audit(resources: list[Resource], policy: Policy) -> AuditResult:
    findings: list[Finding] = []
    checked = compliant = skipped = 0
    for r in resources:
        result = check_resource(r, policy)
        if result is None:
            skipped += 1
            continue
        checked += 1
        if result:
            findings.extend(result)
        else:
            compliant += 1
    return AuditResult(findings=findings, checked=checked, compliant=compliant, skipped=skipped)
