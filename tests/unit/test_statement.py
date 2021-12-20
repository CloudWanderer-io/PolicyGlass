from policyglass import (
    Action,
    EffectiveAction,
    EffectivePrincipal,
    EffectiveResource,
    PolicyShard,
    Principal,
    Resource,
    Statement,
)
from policyglass.condition import Condition


def test_policy_shards():
    statement = Statement(**{"Effect": "Allow", "Action": "s3:*", "Principal": "*", "Resource": "*"})

    assert statement.policy_shards == [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        )
    ]


def test_policy_shards_not_resource_condition():
    statement = Statement(
        **{
            "Effect": "Deny",
            "Action": [
                "s3:PutObject",
            ],
            "NotResource": "arn:aws:s3:::examplebucket/*",
            "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption": "AES256"}},
        }
    )

    assert statement.policy_shards == [
        PolicyShard(
            effect="Deny",
            effective_action=EffectiveAction(inclusion=Action("s3:PutObject"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("*"), exclusions=frozenset({Resource("arn:aws:s3:::examplebucket/*")})
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {Condition(key="s3:x-amz-server-side-encryption", operator="StringNotEquals", values=["AES256"])}
            ),
        )
    ]
