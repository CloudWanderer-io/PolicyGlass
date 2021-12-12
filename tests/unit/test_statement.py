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


def test_policy_shards():
    statement = Statement(**{"Effect": "Allow", "Action": "s3:*", "Principal": "*", "Resource": "*"})

    assert statement.policy_shards == [
        PolicyShard(
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        )
    ]
