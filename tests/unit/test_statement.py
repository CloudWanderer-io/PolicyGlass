from policyglass import Statement
import pytest
import json

ENSURE_LIST_SCENARIOS = {
    "action": {"input": {"Effect": "Allow", "Action": "s3:*"}, "expected": {"Effect": "Allow", "Action": ["s3:*"]}},
    "not_action": {
        "input": {"Effect": "Allow", "NotAction": "s3:*"},
        "expected": {"Effect": "Allow", "NotAction": ["s3:*"]},
    },
    "resource": {
        "input": {"Effect": "Allow", "Resource": "arn:aws:ec2:*:*:volume/*"},
        "expected": {"Effect": "Allow", "Resource": ["arn:aws:ec2:*:*:volume/*"]},
    },
    "not_resource": {
        "input": {"Effect": "Allow", "NotResource": "arn:aws:ec2:*:*:volume/*"},
        "expected": {"Effect": "Allow", "NotResource": ["arn:aws:ec2:*:*:volume/*"]},
    },
}


@pytest.mark.parametrize("_, scenario", ENSURE_LIST_SCENARIOS.items())
def test_ensure_list(_, scenario):
    assert Statement(**scenario["input"]).policy_json() == json.dumps(scenario["expected"])


def test_ensure_condition_value_list():
    subject = Statement(
        **{
            "Effect": "Allow",
            "Condition": {"ArnEquals": {"ec2:SourceInstanceARN": "arn:aws:ec2:*:*:instance/instance-id"}},
        }
    )

    assert subject.policy_json() == json.dumps(
        {
            "Effect": "Allow",
            "Condition": {"ArnEquals": {"ec2:SourceInstanceARN": ["arn:aws:ec2:*:*:instance/instance-id"]}},
        }
    )


def ensure_principal_dict():
    subject = Statement(**{"Effect": "Allow", "Prinncipal": "*"})

    assert subject.policy_json() == json.dumps({"Effect": "Allow", "Principal": {"AWS": ["*"]}})


def ensure_principal_dict_list():
    subject = Statement(**{"Effect": "Allow", "Prinncipal": {"AWS": ["*"]}})

    assert subject.policy_json() == json.dumps({"Effect": "Allow", "Principal": {"AWS": ["*"]}})
