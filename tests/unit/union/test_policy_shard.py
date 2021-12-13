from policyglass import PolicyShard
from policyglass.action import Action, EffectiveAction
from policyglass.condition import Condition
from policyglass.principal import EffectivePrincipal, Principal
from policyglass.resource import EffectiveResource, Resource


def test_elimination():
    shard_a = PolicyShard(
        effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
        effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
        effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        conditions=frozenset({Condition("aws:username", "StringEquals", "johndoe")}),
    )

    shard_b = PolicyShard(
        effective_action=EffectiveAction(inclusion=Action("s3:getobject"), exclusions=frozenset()),
        effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
        effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        conditions=frozenset({Condition("aws:username", "StringEquals", "johndoe")}),
    )

    assert shard_a.union(shard_b) == [shard_a]


def test_disjoint():
    shard_a = PolicyShard(
        effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
        effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
        effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        conditions=frozenset(),
    )

    shard_b = PolicyShard(
        effective_action=EffectiveAction(inclusion=Action("ec2:*"), exclusions=frozenset()),
        effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
        effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        conditions=frozenset(),
    )

    assert shard_a.union(shard_b) == [shard_a, shard_b]


def test_disjoint_condition():
    shard_a = PolicyShard(
        effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
        effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
        effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        conditions=frozenset(),
    )

    shard_b = PolicyShard(
        effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
        effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
        effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        conditions=frozenset({Condition("aws:username", "StringEquals", "johndoe")}),
    )

    assert shard_a.union(shard_b) == [shard_a, shard_b]
