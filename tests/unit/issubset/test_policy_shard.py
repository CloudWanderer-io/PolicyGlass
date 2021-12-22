import pytest

from policyglass import Action, EffectiveAction, EffectivePrincipal, EffectiveResource, PolicyShard, Principal, Resource
from policyglass.condition import Condition

POLICYS_SHARD_ISSUBSET_SCENARIOS = {
    "smaller": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:get*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        ),
    ],
    "exactly_equal": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        ),
    ],
    "exactly_equal_but_condition": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset({Condition(key="TestKey", operator="TestOperator", values=["TestValue"])}),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        ),
    ],
}


@pytest.mark.parametrize("_, scenario", POLICYS_SHARD_ISSUBSET_SCENARIOS.items())
def test_policy_shard_issubset(_, scenario):
    assert scenario[0].issubset(scenario[1])


POLICY_SHARD_NOT_ISSUBSET_SCENARIOS = {
    "larger": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:get*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        ),
    ],
    "equal_with_opposite_effects": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        ),
        PolicyShard(
            effect="Deny",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        ),
    ],
}


@pytest.mark.parametrize("_, scenario", POLICY_SHARD_NOT_ISSUBSET_SCENARIOS.items())
def test_policy_shard_not_issubset(_, scenario):
    assert not scenario[0].issubset(scenario[1])
