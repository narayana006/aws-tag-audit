"""Loading tagged resources from exported JSON or the Resource Groups Tagging API."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Iterator


@dataclass(frozen=True)
class Resource:
    arn: str
    tags: dict[str, str]

    @property
    def _parts(self) -> list[str]:
        return self.arn.split(":", 5)

    @property
    def service(self) -> str:
        parts = self._parts
        return parts[2] if len(parts) > 2 else "unknown"

    @property
    def region(self) -> str:
        parts = self._parts
        return (parts[3] if len(parts) > 3 else "") or "global"

    @property
    def account(self) -> str:
        parts = self._parts
        return (parts[4] if len(parts) > 4 else "") or "-"

    @property
    def resource_type(self) -> str:
        """``service:type`` derived from the ARN, or just ``service`` if the ARN has no type.

        arn:aws:ec2:us-east-1:123456789012:instance/i-0abc   -> ec2:instance
        arn:aws:lambda:us-east-1:123456789012:function:api   -> lambda:function
        arn:aws:s3:::my-bucket                               -> s3
        """
        parts = self._parts
        if len(parts) < 6:
            return self.service
        resource = parts[5]
        cut = min((i for i in (resource.find("/"), resource.find(":")) if i >= 0), default=-1)
        if cut > 0:
            return f"{self.service}:{resource[:cut]}"
        return self.service


def _tags_from_list(raw: Any) -> dict[str, str]:
    if isinstance(raw, dict):
        return {str(k): "" if v is None else str(v) for k, v in raw.items()}
    tags: dict[str, str] = {}
    for item in raw or []:
        tags[str(item["Key"])] = "" if item.get("Value") is None else str(item["Value"])
    return tags


def resources_from_mappings(mappings: Iterable[dict[str, Any]]) -> list[Resource]:
    out = []
    for m in mappings:
        if "ResourceARN" not in m:
            raise ValueError(f"entry without ResourceARN: {m!r}")
        out.append(Resource(arn=m["ResourceARN"], tags=_tags_from_list(m.get("Tags"))))
    return out


def _iter_mappings(doc: Any) -> Iterator[dict[str, Any]]:
    if isinstance(doc, list):
        for item in doc:
            if isinstance(item, dict) and "ResourceTagMappingList" in item:
                yield from item["ResourceTagMappingList"]
            else:
                yield item
    elif isinstance(doc, dict) and "ResourceTagMappingList" in doc:
        yield from doc["ResourceTagMappingList"]
    else:
        raise ValueError("expected get-resources output (an object with ResourceTagMappingList) or a list")


def load_resources(text: str) -> list[Resource]:
    """Parse ``aws resourcegroupstaggingapi get-resources`` output.

    Accepts a single response object, a JSON list of response pages, a plain
    list of ResourceTagMapping entries, or concatenated JSON documents (one
    page after another, as produced by ``--no-paginate`` loops).
    """
    decoder = json.JSONDecoder()
    idx, docs = 0, []
    text = text.strip()
    while idx < len(text):
        doc, end = decoder.raw_decode(text, idx)
        docs.append(doc)
        idx = end
        while idx < len(text) and text[idx].isspace():
            idx += 1
    if not docs:
        raise ValueError("input is empty")
    mappings: list[dict[str, Any]] = []
    for doc in docs:
        mappings.extend(_iter_mappings(doc))
    return resources_from_mappings(mappings)


def fetch_resources(client: Any, resource_types: list[str] | None = None) -> list[Resource]:
    """Read every tagged resource visible to ``client`` (a boto3 resourcegroupstaggingapi client).

    Read-only: only calls tag:GetResources.
    """
    paginator = client.get_paginator("get_resources")
    kwargs: dict[str, Any] = {}
    if resource_types:
        kwargs["ResourceTypeFilters"] = resource_types
    mappings: list[dict[str, Any]] = []
    for page in paginator.paginate(**kwargs):
        mappings.extend(page.get("ResourceTagMappingList", []))
    return resources_from_mappings(mappings)
