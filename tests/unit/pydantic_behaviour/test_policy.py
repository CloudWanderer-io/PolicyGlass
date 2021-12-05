from policyglass import Policy

import pytest
import json


POLICIES = {
    "simple_iam_policy_strings": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ec2:AttachVolume"],
                "Resource": ["arn:aws:ec2:*:*:volume/*"],
            }
        ],
    },
    "simple_iam_policy_lists": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ec2:AttachVolume"],
                "Resource": ["arn:aws:ec2:*:*:volume/*"],
            }
        ],
    },
    "complex_iam_policy": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ec2:AttachVolume"],
                "Resource": ["arn:aws:ec2:*:*:volume/*"],
                "Condition": {"ArnEquals": {"ec2:SourceInstanceARN": ["arn:aws:ec2:*:*:instance/instance-id"]}},
            }
        ],
    },
    "complex_resource_policy": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ec2:AttachVolume"],
                "Principal": {"AWS": ["arn:aws:iam::123456789012:role/role-name"]},
                "Condition": {"ArnEquals": {"ec2:SourceInstanceARN": ["arn:aws:ec2:*:*:instance/instance-id"]}},
            }
        ],
    },
}


@pytest.mark.parametrize("_, policy", POLICIES.items())
def test_policy_json_equality(_, policy):
    assert Policy(**policy).policy_json() == json.dumps(policy)
