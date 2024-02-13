"""--live path against moto's Resource Groups Tagging API (no real AWS)."""

import boto3

from aws_tag_audit.cli import main
from aws_tag_audit.resources import fetch_resources


def _setup():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    ec2.run_instances(
        ImageId=image, MinCount=3, MaxCount=3,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Owner", "Value": "team-a"}]}],
    )
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="acme-test-bucket")
    s3.put_bucket_tagging(Bucket="acme-test-bucket", Tagging={"TagSet": [
        {"Key": "Owner", "Value": "team-b"}, {"Key": "Environment", "Value": "prod"}]})
    return boto3.client("resourcegroupstaggingapi", region_name="us-east-1")


def test_fetch_paginates(moto_env):
    client = _setup()
    resources = fetch_resources(client)
    types = sorted(r.resource_type for r in resources)
    assert types.count("ec2:instance") == 3
    assert "s3" in types
    only_ec2 = fetch_resources(client, ["ec2:instance"])
    assert {r.resource_type for r in only_ec2} == {"ec2:instance"}


def test_cli_live_with_injected_client(moto_env, tmp_path, capsys):
    client = _setup()
    policy = tmp_path / "p.yaml"
    policy.write_text("tags:\n  Owner: {}\n  Environment: {allowed: [prod]}\n")
    code = main(["-p", str(policy), "--live", "--resource-type", "ec2:instance", "-g", "owner"], client=client)
    out = capsys.readouterr().out
    assert code == 1
    assert "Checked 3 resources: 0 compliant, 3 non-compliant" in out
    assert "team-a" in out
