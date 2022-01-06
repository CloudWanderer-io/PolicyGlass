import pytest

from policyglass import Action, EffectiveAction, EffectivePrincipal, EffectiveResource, PolicyShard, Principal, Resource
from policyglass.condition import Condition, EffectiveCondition

POLICYS_SHARD_ISSUBSET_SCENARIOS = {
    "smaller": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:get*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
    ],
    "exactly_equal": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:PutObject"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("*"), exclusions=frozenset({Resource("arn:aws:s3:::examplebucket/*")})
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:PutObject"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("*"), exclusions=frozenset({Resource("arn:aws:s3:::examplebucket/*")})
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
    ],
    "exactly_equal_but_condition": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset({Condition(key="TestKey", operator="TestOperator", values=["TestValue"])})
            ),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
    ],
    "exactly_equal_but_not_condition": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset({Condition(key="Key", operator="BinaryEquals", values=["QmluYXJ5VmFsdWVJbkJhc2U2NA=="])})
            ),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
    ],
    "exactly_equal_but_more_conditions": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset(
                    {
                        Condition(key="TestKey", operator="TestOperator", values=["TestValue"]),
                        Condition(key="OtherTestKey", operator="TestOperator", values=["TestValue"]),
                    }
                )
            ),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset({Condition(key="TestKey", operator="TestOperator", values=["TestValue"])})
            ),
        ),
    ],
    "exactly_equal_but_one_has_not_condition": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                inclusions=frozenset(
                    {Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"])}
                ),
                exclusions=frozenset(
                    {Condition(key="Key", operator="BinaryEquals", values=["QmluYXJ5VmFsdWVJbkJhc2U2NA=="])}
                ),
            ),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset(
                    {Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"])}
                )
            ),
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
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:get*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
    ],
    "equal_with_opposite_effects": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
        PolicyShard(
            effect="Deny",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
    ],
    "action_not_subset_resource_is": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("*"), exclusions=frozenset({Resource("arn:aws:s3:::examplebucket/*")})
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
    ],
    "equal_except_for_exclusion": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:role/RoleName")),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(
                Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")})
            ),
        ),
    ],
    "exactly_equal_but_differing_conditions": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset(
                    {
                        Condition(key="SomesTestKey", operator="TestOperator", values=["TestValue"]),
                        Condition(key="OtherTestKey", operator="TestOperator", values=["TestValue"]),
                    }
                )
            ),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset({Condition(key="TestKey", operator="TestOperator", values=["TestValue"])})
            ),
        ),
    ],
}


@pytest.mark.parametrize("_, scenario", POLICY_SHARD_NOT_ISSUBSET_SCENARIOS.items())
def test_policy_shard_not_issubset(_, scenario):
    assert not scenario[0].issubset(scenario[1])
