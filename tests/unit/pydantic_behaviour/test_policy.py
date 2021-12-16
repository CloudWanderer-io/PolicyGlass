import json

import pytest

from policyglass import ConditionCollection, Policy

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
                "Action": ["s3:PutObject", "s3:PutObjectAcl"],
                "Resource": ["arn:aws:s3:::DOC-EXAMPLE-BUCKET/*"],
                "Principal": {"AWS": ["arn:aws:iam::111122223333:root", "arn:aws:iam::444455556666:root"]},
                "Condition": {"StringEquals": {"s3:x-amz-acl": ["public-read"]}},
            }
        ],
    },
}


@pytest.mark.parametrize("_, policy", POLICIES.items())
def test_policy_json_equality(_, policy):
    assert Policy(**policy).policy_json() == json.dumps(policy)


@pytest.mark.parametrize("_, policy", POLICIES.items())
def test_policy_types(_, policy):
    subject = Policy(**policy).statement[0].condition

    assert isinstance(subject, ConditionCollection) or subject is None
