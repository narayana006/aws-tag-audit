from aws_tag_audit.audit import UNOWNED, audit
from aws_tag_audit.policy import parse_policy
from aws_tag_audit.resources import Resource

POLICY = parse_policy({
    "tags": {"Owner": {}, "Env": {"allowed": ["prod", "dev"]}},
    "resource_types": {"logs": {"ignore": True}},
})


def r(arn, **tags):
    return Resource(arn=arn, tags=tags)


def problems(result):
    return sorted((f.key, f.problem) for f in result.findings)


def test_compliant():
    res = audit([r("arn:aws:s3:::b", Owner="a", Env="prod")], POLICY)
    assert (res.checked, res.compliant, res.findings) == (1, 1, [])


def test_missing_empty_invalid():
    res = audit([r("arn:aws:s3:::b", Owner="  ", Env="test")], POLICY)
    assert problems(res) == [("Env", "invalid"), ("Owner", "empty")]
    res = audit([r("arn:aws:s3:::b")], POLICY)
    assert problems(res) == [("Env", "missing"), ("Owner", "missing")]


def test_key_case_and_owner_fallback():
    res = audit([r("arn:aws:s3:::b", owner="team-a", Env="dev")], POLICY)
    [f] = res.findings
    assert (f.problem, f.value, f.owner) == ("key-case", "team-a", "team-a")
    assert "'owner'" in f.detail


def test_unowned_and_grouping():
    res = audit([
        r("arn:aws:ec2:us-east-1:111111111111:instance/i-1"),
        r("arn:aws:ec2:us-east-1:111111111111:instance/i-2", Owner="x"),
        r("arn:aws:s3:::b", Owner="x", Env="prod"),
    ], POLICY)
    assert res.noncompliant == 2
    assert res.counts("service") == {"ec2": 2}
    assert res.counts("owner") == {UNOWNED: 1, "x": 1}
    assert res.counts("account") == {"111111111111": 2}


def test_ignored_types_are_skipped():
    res = audit([r("arn:aws:logs:us-east-1:111111111111:log-group:/x")], POLICY)
    assert (res.checked, res.skipped, res.findings) == (0, 1, [])
