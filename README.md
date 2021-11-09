# aws-tag-audit

Check AWS resources against your tagging policy: missing, empty or invalid tags, with a report by owner and service.

## Planned scope

Policy file (YAML/JSON) of required keys, allowed values/regex, per-resource-type overrides. Read resources via Resource Groups Tagging API get_resources (paginated, injectable client, tested with moto) or offline from exported JSON. Report missing/invalid tags grouped by service, account, owner; CSV/JSON/table; exit codes. Read-only: IAM tag:GetResources only. Note in README that the Tagging API only returns resources that have or had tags.
