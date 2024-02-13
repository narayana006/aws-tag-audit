import csv
import io
import json
from pathlib import Path

from aws_tag_audit.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
POLICY = str(EXAMPLES / "policy.yaml")
RESOURCES = str(EXAMPLES / "resources.json")


def test_example_table(capsys):
    assert main(["-p", POLICY, "-i", RESOURCES]) == 1
    out = capsys.readouterr().out
    assert "Checked 8 resources: 3 compliant, 5 non-compliant (1 skipped by policy)" in out
    assert "production" in out and "key-case" in out


def test_example_json(capsys):
    main(["-p", POLICY, "-i", RESOURCES, "-f", "json", "-g", "owner"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["non_compliant"] == 5
    assert doc["summary"]["non_compliant_by_owner"]["(no owner)"] == 2
    kinds = {(f["arn"].rsplit(":", 1)[-1], f["key"], f["problem"]) for f in doc["findings"]}
    assert ("thumbnailer", "CostCenter", "invalid") in kinds
    assert ("acme-invoices-123456789012", "DataClassification", "missing") in kinds
    # snapshots skip CostCenter
    assert not any("snapshot" in f["arn"] and f["key"] == "CostCenter" for f in doc["findings"])


def test_csv_to_file(tmp_path):
    out = tmp_path / "r.csv"
    assert main(["-p", POLICY, "-i", RESOURCES, "-f", "csv", "-o", str(out), "--no-fail"]) == 0
    rows = list(csv.DictReader(io.StringIO(out.read_text())))
    assert rows and set(rows[0]) >= {"arn", "key", "problem", "owner"}


def test_stdin(monkeypatch, capsys):
    doc = {"ResourceTagMappingList": [{"ResourceARN": "arn:aws:s3:::b", "Tags": [
        {"Key": "Owner", "Value": "a@example.com"}, {"Key": "Environment", "Value": "dev"},
        {"Key": "CostCenter", "Value": "CC-0001"}, {"Key": "DataClassification", "Value": "internal"}]}]}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(doc)))
    assert main(["-p", POLICY, "-i", "-"]) == 0
    assert "1 compliant" in capsys.readouterr().out


def test_errors(tmp_path, capsys):
    assert main(["-p", str(tmp_path / "nope.yaml"), "-i", RESOURCES]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert main(["-p", POLICY, "-i", str(bad)]) == 2
    assert "input error" in capsys.readouterr().err
