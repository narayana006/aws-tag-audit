# aws-tag-audit

Check AWS resources against your tagging policy: missing, empty or invalid tags, reported by service, account and owner.

**Status:** policy file (YAML/JSON) with required keys, allowed values, regex patterns and per-resource-type overrides; offline audit of exported `get-resources` JSON; live read through the Resource Groups Tagging API; table, JSON and CSV output; CI-friendly exit codes. All of it is covered by tests (the live path is tested against [moto](https://github.com/getmoto/moto), not real AWS).

## Install

```bash
pip install git+https://github.com/narayana006/aws-tag-audit
```

Python 3.10 or newer. Dependencies: `boto3`, `PyYAML`.

## Quick start

The repo ships an illustrative policy and a hand-written, fictional inventory (account `123456789012`) in [`examples/`](examples/):

```bash
aws-tag-audit --policy examples/policy.yaml --input examples/resources.json
```

```text
Checked 8 resources: 3 compliant, 5 non-compliant (1 skipped by policy)
Findings: 5 missing, 1 empty, 2 invalid, 1 key-case

SERVICE  NON-COMPLIANT
-------  -------------
ec2      2
lambda   1
rds      1
s3       1

RESOURCE                                                         TAG                 PROBLEM   VALUE                 DETAIL
---------------------------------------------------------------  ------------------  --------  --------------------  -------------------------------
arn:aws:ec2:us-east-1:123456789012:instance/i-0a1b2c3d4e5f60002  CostCenter          missing                         required tag not present
arn:aws:ec2:us-east-1:123456789012:instance/i-0a1b2c3d4e5f60002  Environment         invalid   production            not one of: prod, staging, dev
arn:aws:ec2:us-east-1:123456789012:volume/vol-0f1e2d3c4b5a60003  Owner               key-case  data-eng@example.com  found as 'owner'
arn:aws:lambda:eu-west-1:210987654321:function:thumbnailer       CostCenter          invalid   1234                  does not match /^CC-[0-9]{4}$/
arn:aws:lambda:eu-west-1:210987654321:function:thumbnailer       Owner               empty                           tag present with an empty value
arn:aws:rds:eu-west-1:210987654321:db:orders-replica             CostCenter          missing                         required tag not present
arn:aws:rds:eu-west-1:210987654321:db:orders-replica             Environment         missing                         required tag not present
arn:aws:rds:eu-west-1:210987654321:db:orders-replica             Owner               missing                         required tag not present
arn:aws:s3:::acme-invoices-123456789012                          DataClassification  missing                         required tag not present
```

The exit code is `1` because there are findings.

## Auditing your own account

Export the inventory with the AWS CLI (it paginates for you), then audit the file. This keeps the audit itself offline and repeatable:

```bash
aws resourcegroupstaggingapi get-resources --region us-east-1 > resources.json
aws-tag-audit -p policy.yaml -i resources.json
```

Or read directly with boto3 (uses your normal credential chain):

```bash
aws-tag-audit -p policy.yaml --live --region us-east-1 --profile audit
aws-tag-audit -p policy.yaml --live --region us-east-1 --resource-type ec2:instance --resource-type s3
```

The Tagging API is regional: run once per region you care about.

## Policy file

```yaml
owner_key: Owner            # tag used for the "owner" grouping (default: Owner)

tags:                       # required on every resource
  Owner:
    pattern: '^[a-z0-9.-]+@example\.com$'
  Environment:
    allowed: [prod, staging, dev]
    ignore_case: false      # default
  CostCenter:
    pattern: '^CC-[0-9]{4}$'

resource_types:             # optional overrides
  s3:                       # a bare service applies to every type in it
    tags:
      DataClassification:
        allowed: [public, internal, confidential]
  ec2:snapshot:             # service:type, applied after the service-level override
    skip: [CostCenter]
  logs:log-group:
    ignore: true            # don't check this type at all
```

`tags` may also be a plain list of keys (`tags: [Owner, Environment]`) when any non-empty value is fine. A `.json` policy uses the same structure.

The resource type of each resource is taken from its ARN: `service:type`, where `type` is the part of the resource segment before the first `/` or `:` (`ec2:instance`, `lambda:function`, `rds:db`, `elasticloadbalancing:loadbalancer`). ARNs without a type segment, such as S3 buckets (`arn:aws:s3:::bucket`) or SNS topics, are just the service (`s3`, `sns`).

## What counts as a finding

| Problem | Meaning |
|---|---|
| `missing` | Required key is not present. |
| `empty` | Key is present but the value is empty or whitespace. |
| `invalid` | Value is not in `allowed`, or does not match `pattern`. |
| `key-case` | Key exists with different capitalisation (e.g. `owner` instead of `Owner`). Tag keys are case-sensitive in AWS, so cost allocation reports treat these as different keys. |

A resource with no owner tag is grouped under `(no owner)`. If the exact owner key is missing but a different-case variant has a value, that value is used for grouping.

## Usage

```
aws-tag-audit -p POLICY (-i FILE | --live) [options]

  -i, --input FILE       get-resources JSON; '-' reads stdin. Accepts one response
                         object, a list of pages, or concatenated pages.
  --live                 read with tag:GetResources (boto3)
  --region, --profile    for --live
  --resource-type TYPE   ResourceTypeFilters for --live (repeatable)
  -f, --format           table (default), json, csv
  -g, --group-by         service (default), account, owner, resource_type, region
  -o, --output FILE      write the report to a file
  --no-fail              exit 0 even with findings
```

Exit codes: `0` all checked resources compliant, `1` findings, `2` bad policy, bad input or AWS error.

JSON output has a `summary` (counts, plus non-compliant resources per group) and a flat `findings` list; CSV is one row per finding with the columns `arn, account, region, service, resource_type, owner, key, problem, value, detail`.

## Required permissions

Only for `--live`, and read-only:

- `tag:GetResources`

The offline `--input` mode needs no AWS access at all.

## Features

- [x] Policy file (YAML or JSON): required keys, allowed values, regex, case-insensitive matching
- [x] Per-service and per-resource-type overrides (add keys, skip keys, ignore a type)
- [x] Offline input from `aws resourcegroupstaggingapi get-resources` output (file or stdin)
- [x] Live read via `get_resources` with pagination and resource type filters
- [x] Findings for missing, empty, invalid and wrong-case keys
- [x] Grouping by service, account, owner, resource type or region
- [x] Table, JSON and CSV output; exit codes for CI
- [ ] Multi-region live scan in one run
- [ ] Inventory sources beyond the Tagging API (e.g. AWS Config) to catch never-tagged resources

## Limitations

- **The Resource Groups Tagging API only returns resources that have, or previously had, tags**, and only resource types the API supports. A resource that has never been tagged will not appear, so it cannot be reported as missing tags. Treat this tool as a check on tag quality, not a complete inventory.
- `--live` scans one region per run.
- AWS-managed `aws:` tags are not treated specially; they are simply ignored unless your policy names them.
- The resource-type rule derived from the ARN is a convention, not an official mapping; check `-f json` output (`resource_type`) when writing overrides.

## Contributing

Issues and pull requests are welcome. To develop:

```bash
pip install -e ".[dev]"
pytest
```

Tests never contact AWS: the live path runs against moto.

Built and maintained by [Narayana Vemburaj](https://github.com/narayana006).

## License

[MIT](LICENSE)
