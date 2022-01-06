from policyglass import PolicyShard
from policyglass.action import Action, EffectiveAction
from policyglass.condition import Condition, EffectiveCondition
from policyglass.principal import EffectivePrincipal, Principal
from policyglass.resource import EffectiveResource, Resource


def test_elimination():
    shard_a = PolicyShard(
        effect="Allow",
        effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
        effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
        effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        effective_condition=EffectiveCondition(frozenset({Condition("aws:username", "StringEquals", ["johndoe"])})),
    )

    shard_b = PolicyShard(
        effect="Allow",
        effective_action=EffectiveAction(inclusion=Action("s3:getobject"), exclusions=frozenset()),
        effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
        effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        effective_condition=EffectiveCondition(frozenset({Condition("aws:username", "StringEquals", ["johndoe"])})),
    )

    assert shard_a.union(shard_b) == [shard_a]


def test_disjoint():
    shard_a = PolicyShard(
        effect="Allow",
        effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
        effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
        effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
    )

    shard_b = PolicyShard(
        effect="Allow",
        effective_action=EffectiveAction(inclusion=Action("ec2:*"), exclusions=frozenset()),
        effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
        effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
    )

    assert shard_a.union(shard_b) == [shard_a, shard_b]


def test_condition():
    shard_a = PolicyShard(
        effect="Allow",
        effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
        effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
        effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
    )

    shard_b = PolicyShard(
        effect="Allow",
        effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
        effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
        effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        effective_condition=EffectiveCondition(frozenset({Condition("aws:username", "StringEquals", ["johndoe"])})),
    )

    assert shard_a.union(shard_b) == [shard_a]


def test_multiple_conditions():
    shard_a = PolicyShard(
        effect="Allow",
        effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
        effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
        effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        effective_condition=EffectiveCondition(
            frozenset(
                {
                    Condition("aws:username", "StringEquals", ["johndoe"]),
                    Condition("testkey", "testoperator", ["testvalue"]),
                }
            )
        ),
    )

    shard_b = PolicyShard(
        effect="Allow",
        effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
        effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
        effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        effective_condition=EffectiveCondition(frozenset({Condition("aws:username", "StringEquals", ["johndoe"])})),
    )

    assert shard_a.union(shard_b) == [shard_b]
