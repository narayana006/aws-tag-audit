import json

import pytest

from aws_tag_audit.resources import Resource, load_resources


@pytest.mark.parametrize("arn, rtype, account, region", [
    ("arn:aws:ec2:us-east-1:123456789012:instance/i-1", "ec2:instance", "123456789012", "us-east-1"),
    ("arn:aws:lambda:eu-west-1:123456789012:function:api", "lambda:function", "123456789012", "eu-west-1"),
    ("arn:aws:s3:::bucket", "s3", "-", "global"),
    ("arn:aws:sns:us-east-1:123456789012:alerts", "sns", "123456789012", "us-east-1"),
    ("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/abc",
     "elasticloadbalancing:loadbalancer", "123456789012", "us-east-1"),
    ("arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/x", "logs:log-group", "123456789012", "us-east-1"),
])
def test_arn_parsing(arn, rtype, account, region):
    r = Resource(arn=arn, tags={})
    assert (r.resource_type, r.account, r.region) == (rtype, account, region)


def test_load_single_page():
    doc = {"ResourceTagMappingList": [{"ResourceARN": "arn:aws:s3:::b", "Tags": [{"Key": "A", "Value": "1"}]}]}
    [r] = load_resources(json.dumps(doc))
    assert r.tags == {"A": "1"}


def test_load_pages_list_and_concatenated():
    page = {"ResourceTagMappingList": [{"ResourceARN": "arn:aws:s3:::b", "Tags": []}]}
    assert len(load_resources(json.dumps([page, page]))) == 2
    assert len(load_resources(json.dumps(page) + "\n" + json.dumps(page))) == 2


def test_load_plain_list_and_missing_value():
    doc = [{"ResourceARN": "arn:aws:s3:::b", "Tags": [{"Key": "A"}]}]
    [r] = load_resources(json.dumps(doc))
    assert r.tags == {"A": ""}


@pytest.mark.parametrize("text", ["", "{}", '[{"Tags": []}]'])
def test_load_errors(text):
    with pytest.raises(ValueError):
        load_resources(text)
