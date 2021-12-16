import pytest

from policyglass import PolicyShard
from policyglass.action import Action, EffectiveAction
from policyglass.condition import Condition
from policyglass.policy_shard import policy_shards_effect
from policyglass.principal import EffectivePrincipal, Principal
from policyglass.resource import EffectiveResource, Resource

POLICY_SHARDS_EFFECT_SCENARIOS = {
    "eliminate": {
        "input": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
            ),
            PolicyShard(
                effect="Deny",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
            ),
        ],
        "expected": [],
    },
    "exception": {
        "input": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
            ),
            PolicyShard(
                effect="Deny",
                effective_action=EffectiveAction(inclusion=Action("s3:Get*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
            ),
        ],
        "expected": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:Get*")})),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
            )
        ],
    },
    "multi_exception": {
        "input": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
            ),
            PolicyShard(
                effect="Deny",
                effective_action=EffectiveAction(inclusion=Action("s3:Get*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
            ),
            PolicyShard(
                effect="Deny",
                effective_action=EffectiveAction(inclusion=Action("s3:Put*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
            ),
        ],
        "expected": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(
                    inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:Get*"), Action("s3:Put*")})
                ),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
            )
        ],
    },
    "complex_exception": {
        "input": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
            ),
            PolicyShard(
                effect="Deny",
                effective_action=EffectiveAction(
                    inclusion=Action("s3:Get*"), exclusions=frozenset({Action("s3:GetObject")})
                ),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset({Condition("s3:x-amz-server-side-encryption", "StringNotEquals", ["AES256"])}),
            ),
        ],
        "expected": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:Get*")})),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
            ),
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:GetObject"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
            ),
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(
                    inclusion=Action("s3:Get*"), exclusions=frozenset({Action("s3:GetObject")})
                ),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                not_conditions=frozenset({Condition("s3:x-amz-server-side-encryption", "StringNotEquals", ["AES256"])}),
            ),
        ],
    },
}


@pytest.mark.parametrize(
    "_, input, expected",
    [(name, value["input"], value["expected"]) for name, value in POLICY_SHARDS_EFFECT_SCENARIOS.items()],
)
def test_policy_shards_effect_simple(_, input, expected):
    assert policy_shards_effect(input) == expected
