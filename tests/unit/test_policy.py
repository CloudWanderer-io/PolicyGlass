import pytest

from policyglass import (
    Action,
    Condition,
    EffectiveAction,
    EffectivePrincipal,
    EffectiveResource,
    Policy,
    PolicyShard,
    Principal,
    Resource,
)

POLICIES = {
    "simple_iam_policy": {
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["ec2:AttachVolume"],
                    "Resource": ["arn:aws:ec2:*:*:volume/*"],
                }
            ],
        },
        "shards": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("ec2:AttachVolume"), exclusions=frozenset()),
                effective_resource=EffectiveResource(
                    inclusion=Resource("arn:aws:ec2:*:*:volume/*"), exclusions=frozenset()
                ),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
            )
        ],
    },
    "complex_iam_policy": {
        "policy": {
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
        "shards": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("ec2:AttachVolume"), exclusions=frozenset()),
                effective_resource=EffectiveResource(
                    inclusion=Resource("arn:aws:ec2:*:*:volume/*"), exclusions=frozenset()
                ),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(
                    {
                        Condition(
                            key="ec2:SourceInstanceARN",
                            operator="ArnEquals",
                            values=["arn:aws:ec2:*:*:instance/instance-id"],
                        )
                    }
                ),
            )
        ],
    },
    "complex_resource_policy": {
        "policy": {
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
        "shards": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:PutObject"), exclusions=frozenset()),
                effective_resource=EffectiveResource(
                    inclusion=Resource("arn:aws:s3:::DOC-EXAMPLE-BUCKET/*"), exclusions=frozenset()
                ),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="arn:aws:iam::111122223333:root"), exclusions=frozenset()
                ),
                conditions=frozenset({Condition(key="s3:x-amz-acl", operator="StringEquals", values=["public-read"])}),
            ),
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:PutObject"), exclusions=frozenset()),
                effective_resource=EffectiveResource(
                    inclusion=Resource("arn:aws:s3:::DOC-EXAMPLE-BUCKET/*"), exclusions=frozenset()
                ),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="arn:aws:iam::444455556666:root"), exclusions=frozenset()
                ),
                conditions=frozenset({Condition(key="s3:x-amz-acl", operator="StringEquals", values=["public-read"])}),
            ),
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:PutObjectAcl"), exclusions=frozenset()),
                effective_resource=EffectiveResource(
                    inclusion=Resource("arn:aws:s3:::DOC-EXAMPLE-BUCKET/*"), exclusions=frozenset()
                ),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="arn:aws:iam::111122223333:root"), exclusions=frozenset()
                ),
                conditions=frozenset({Condition(key="s3:x-amz-acl", operator="StringEquals", values=["public-read"])}),
            ),
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:PutObjectAcl"), exclusions=frozenset()),
                effective_resource=EffectiveResource(
                    inclusion=Resource("arn:aws:s3:::DOC-EXAMPLE-BUCKET/*"), exclusions=frozenset()
                ),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="arn:aws:iam::444455556666:root"), exclusions=frozenset()
                ),
                conditions=frozenset({Condition(key="s3:x-amz-acl", operator="StringEquals", values=["public-read"])}),
            ),
        ],
    },
}


@pytest.mark.parametrize(
    "_, policy, shards", [(name, value["policy"], value["shards"]) for name, value in POLICIES.items()]
)
def test_policy_shards(_, policy, shards):
    assert Policy(**policy).policy_shards == shards
