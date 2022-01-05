from policyglass import (
    Action,
    Condition,
    EffectiveAction,
    EffectivePrincipal,
    EffectiveResource,
    PolicyShard,
    Principal,
    Resource,
)


def test_factory():

    subject = PolicyShard.factory(
        effect="Allow",
        effective_action=EffectiveAction(Action("S3:*")),
        effective_resource=EffectiveResource(Resource("*")),
        effective_principal=EffectivePrincipal(Principal("AWS", "*")),
        conditions=frozenset({Condition("TestKey1", "StringLike", ["TestValue"])}),
        not_conditions=frozenset({Condition("TestKey2", "StringLike", ["TestValue"])}),
    )

    assert subject == PolicyShard(
        effect="Allow",
        effective_action=EffectiveAction(Action("S3:*")),
        effective_resource=EffectiveResource(Resource("*")),
        effective_principal=EffectivePrincipal(Principal("AWS", "*")),
        conditions=frozenset(
            {Condition("TestKey2", "StringNotLike", ["TestValue"]), Condition("TestKey1", "StringLike", ["TestValue"])}
        ),
    )
