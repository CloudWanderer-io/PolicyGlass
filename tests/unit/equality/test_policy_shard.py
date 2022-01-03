import pytest

from policyglass import PolicyShard
from policyglass.action import Action, EffectiveAction
from policyglass.condition import Condition
from policyglass.principal import EffectivePrincipal, Principal
from policyglass.resource import EffectiveResource, Resource

SHARD_MATCH_SCENARIOS = {
    "exactly_equal": [
        [
            PolicyShard(
                effect="Deny",
                effective_action=EffectiveAction(inclusion=Action("s3:PutObject"), exclusions=frozenset()),
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
            )
        ],
        [
            PolicyShard(
                effect="Deny",
                effective_action=EffectiveAction(inclusion=Action("s3:PutObject"), exclusions=frozenset()),
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
            )
        ],
    ]
}


@pytest.mark.parametrize("_, scenario", SHARD_MATCH_SCENARIOS.items())
def test_shard_equality(_, scenario):
    assert scenario[0] == scenario[1]


SHARD_NOT_MATCH_SCENARIOS = {
    "different_condition": [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
            ),
            not_conditions=frozenset(),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {
                    Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                }
            ),
            not_conditions=frozenset(),
        ),
    ],
}


@pytest.mark.parametrize("_, scenario", SHARD_NOT_MATCH_SCENARIOS.items())
def test_sgard_inequality(_, scenario):
    assert scenario[0] != scenario[1]
