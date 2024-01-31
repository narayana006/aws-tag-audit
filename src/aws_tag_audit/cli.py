"""Command-line entry point for aws-tag-audit."""

from __future__ import annotations

import argparse
import sys
from typing import Any, Sequence

from . import __version__
from .audit import audit
from .policy import PolicyError, load_policy
from .report import GROUPS, RENDERERS
from .resources import fetch_resources, load_resources

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-tag-audit",
        description="Check AWS resources against a tagging policy.",
    )
    p.add_argument("-p", "--policy", required=True, help="policy file (.yaml, .yml or .json)")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "-i", "--input", metavar="FILE",
        help="exported 'aws resourcegroupstaggingapi get-resources' JSON ('-' for stdin)",
    )
    src.add_argument("--live", action="store_true", help="read resources with tag:GetResources")
    p.add_argument("--region", help="AWS region for --live")
    p.add_argument("--profile", help="AWS profile for --live")
    p.add_argument(
        "--resource-type", action="append", default=[], metavar="TYPE",
        help="ResourceTypeFilters value for --live, e.g. ec2:instance (repeatable)",
    )
    p.add_argument("-f", "--format", choices=sorted(RENDERERS), default="table")
    p.add_argument("-g", "--group-by", choices=GROUPS, default="service")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    p.add_argument("--no-fail", action="store_true", help="exit 0 even when findings exist")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _live_client(region: str | None, profile: str | None) -> Any:
    import boto3

    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client("resourcegroupstaggingapi")


def main(argv: Sequence[str] | None = None, client: Any = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = load_policy(args.policy)
    except (OSError, PolicyError, ValueError) as exc:
        print(f"aws-tag-audit: policy error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        if args.live:
            client = client or _live_client(args.region, args.profile)
            resources = fetch_resources(client, args.resource_type or None)
        else:
            if args.input == "-":
                text = sys.stdin.read()
            else:
                with open(args.input, encoding="utf-8") as fh:
                    text = fh.read()
            resources = load_resources(text)
    except (OSError, ValueError, KeyError) as exc:
        print(f"aws-tag-audit: input error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # botocore errors: credentials, access denied, throttling
        print(f"aws-tag-audit: AWS error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    result = audit(resources, policy)
    report = RENDERERS[args.format](result, args.group_by)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
    else:
        sys.stdout.write(report)
    if result.findings and not args.no_fail:
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
