import json

from policyglass import Condition


def test_json():
    subject = Condition("Key", "Operator", ["Value"])

    assert subject.json() == json.dumps({"key": "Key", "operator": "Operator", "values": ["Value"]})
