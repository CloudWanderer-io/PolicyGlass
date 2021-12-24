import pytest

from policyglass import Policy, PolicyShard
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
                effective_action=EffectiveAction(inclusion=Action("s3:GetObject"), exclusions=frozenset()),
                effective_resource=EffectiveResource(
                    inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
                ),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
                not_conditions=frozenset(),
            ),
            PolicyShard(
                effect="Deny",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(
                    inclusion=Resource("*"), exclusions=frozenset({Resource("arn:aws:s3:::examplebucket/*")})
                ),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(
                    {Condition(key="s3:x-amz-server-side-encryption", operator="StringNotEquals", values=["AES256"])}
                ),
                not_conditions=frozenset(),
            ),
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(
                    {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
                ),
                not_conditions=frozenset(),
            ),
        ],
        "expected": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:GetObject"), exclusions=frozenset()),
                effective_resource=EffectiveResource(
                    inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
                ),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
                not_conditions=frozenset(),
            ),
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(
                    inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
                ),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(
                    {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
                ),
                not_conditions=frozenset(),
            ),
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(
                    {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
                ),
                not_conditions=frozenset(
                    {Condition(key="s3:x-amz-server-side-encryption", operator="StringNotEquals", values=["AES256"])}
                ),
            ),
        ],
    },
    "identical_except_different_conditions": {
        "input": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(
                    {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
                ),
                not_conditions=frozenset(),
            ),
            PolicyShard(
                effect="Deny",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*")),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(
                    {Condition(key="s3:x-amz-server-side-encryption", operator="StringNotEquals", values=["AES256"])}
                ),
                not_conditions=frozenset(),
            ),
        ],
        "expected": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(
                    {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
                ),
                not_conditions=frozenset(
                    {Condition(key="s3:x-amz-server-side-encryption", operator="StringNotEquals", values=["AES256"])}
                ),
            ),
        ],
    },
    "allow_allow_deny_except_second_allow": {
        "input": Policy(
            **{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:*"],
                        "Resource": "*",
                        "Condition": {"StringNotEquals": {"aws:PrincipalOrgId": "o-123456"}},
                    },
                    {"Effect": "Allow", "Action": ["s3:*"], "Resource": "arn:aws:s3:::examplebucket/*"},
                    {
                        "Effect": "Deny",
                        "Action": ["s3:PutObject"],
                        "NotResource": "arn:aws:s3:::examplebucket/*",
                        "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption": "AES256"}},
                    },
                ],
            }
        ).policy_shards,
        "expected": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(
                    inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})
                ),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(
                    {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
                ),
                not_conditions=frozenset(),
            ),
            # Yes this shard is a duplicate, but that's because policy_shards_effect doesn't deduplicate!
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(
                    inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
                ),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(
                    {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
                ),
                not_conditions=frozenset(),
            ),
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(
                    {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
                ),
                not_conditions=frozenset(
                    {Condition(key="s3:x-amz-server-side-encryption", operator="StringNotEquals", values=["AES256"])}
                ),
            ),
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(
                    inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
                ),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
                not_conditions=frozenset(),
            ),
        ],
    },
}


@pytest.mark.parametrize(
    "_, input, expected",
    [(name, value["input"], value["expected"]) for name, value in POLICY_SHARDS_EFFECT_SCENARIOS.items()],
)
def test_policy_shards_effect(_, input, expected):
    assert policy_shards_effect(input) == expected
