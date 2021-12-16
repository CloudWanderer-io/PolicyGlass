import json

from policyglass import Principal


def test_json():
    subject = Principal("AWS", "*")

    assert subject.json() == json.dumps({"type": "AWS", "value": "*"})
