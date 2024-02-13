import json

import pytest

from aws_tag_audit.policy import PolicyError, load_policy, parse_policy


def test_list_shorthand_and_defaults():
    p = parse_policy({"tags": ["Owner", "Environment"]})
    assert set(p.tags) == {"Owner", "Environment"}
    assert p.owner_key == "Owner"
    assert p.tags["Owner"].check_value("anything") is None


def test_allowed_and_pattern():
    p = parse_policy({"tags": {"Env": {"allowed": ["prod", "dev"]}, "CC": {"pattern": r"^CC-\d{4}$"}}})
    assert p.tags["Env"].check_value("prod") is None
    assert "not one of" in p.tags["Env"].check_value("Prod")
    assert p.tags["CC"].check_value("CC-0001") is None
    assert "does not match" in p.tags["CC"].check_value("cc-1")


def test_ignore_case_allowed():
    p = parse_policy({"tags": {"Env": {"allowed": ["prod"], "ignore_case": True}}})
    assert p.tags["Env"].check_value("PROD") is None


def test_overrides_service_then_type():
    p = parse_policy({
        "tags": ["Owner", "CostCenter"],
        "resource_types": {
            "ec2": {"tags": ["Name"]},
            "ec2:snapshot": {"skip": ["CostCenter", "Name"]},
            "logs": {"ignore": True},
        },
    })
    assert set(p.rules_for("ec2:instance")) == {"Owner", "CostCenter", "Name"}
    assert set(p.rules_for("ec2:snapshot")) == {"Owner"}
    assert set(p.rules_for("s3")) == {"Owner", "CostCenter"}
    assert p.rules_for("logs:log-group") is None


@pytest.mark.parametrize("bad, msg", [
    ([], "mapping at the top level"),
    ({"tags": []}, "no required tags"),
    ({"tags": ["A"], "extra": 1}, "unknown top-level"),
    ({"tags": {"A": {"pattern": "("}}}, "not a valid regex"),
    ({"tags": {"A": {"allowed": []}}}, "non-empty list"),
    ({"tags": {"A": {"regex": "x"}}}, "unknown field"),
    ({"tags": ["A"], "resource_types": {"s3": {"require": ["B"]}}}, "unknown field"),
])
def test_policy_errors(bad, msg):
    with pytest.raises(PolicyError, match=msg):
        parse_policy(bad)


def test_load_yaml_and_json(tmp_path):
    y = tmp_path / "p.yaml"
    y.write_text("tags:\n  Owner: {}\n")
    assert "Owner" in load_policy(y).tags
    j = tmp_path / "p.json"
    j.write_text(json.dumps({"tags": {"Owner": {}}, "owner_key": "Team"}))
    assert load_policy(j).owner_key == "Team"
