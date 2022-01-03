import pytest

from policyglass import PolicyShard
from policyglass.action import Action, EffectiveAction
from policyglass.condition import Condition
from policyglass.principal import EffectivePrincipal, Principal
from policyglass.resource import EffectiveResource, Resource


def test_bad_intersection():
    with pytest.raises(ValueError) as ex:
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
            not_conditions=frozenset(),
        ).intersection(Action("S3:*"))

    assert "Cannot intersect PolicyShard with Action" in str(ex.value)


INTERSECTION_SCENARIOS = {
    "test_subset": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
            not_conditions=frozenset(),
        ),
        "second": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:GetObject"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset({}),
            not_conditions=frozenset(),
        ),
        "result": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:GetObject"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset({}),
            not_conditions=frozenset(),
        ),
    },
    "test_exactly_equal": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
            not_conditions=frozenset(),
        ),
        "second": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset({}),
            not_conditions=frozenset(),
        ),
        "result": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset({}),
            not_conditions=frozenset(),
        ),
    },
    "test_disjoint_conditions": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
            ),
            not_conditions=frozenset(),
        ),
        "second": PolicyShard(
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
        "result": None,
    },
    "test_matching_equal_one_with_one_without_condition": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
            not_conditions=frozenset(),
        ),
        "second": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {
                    Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"]),
                }
            ),
            not_conditions=frozenset(),
        ),
        "result": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
            not_conditions=frozenset(),
        ),
    },
    "test_matching_subset_conditions_larger_first": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
            ),
            not_conditions=frozenset(),
        ),
        "second": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {
                    Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"]),
                    Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                }
            ),
            not_conditions=frozenset(),
        ),
        "result": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
            ),
            not_conditions=frozenset(),
        ),
    },
    "test_matching_subset_conditions_smaller_first": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {
                    Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"]),
                    Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                }
            ),
            not_conditions=frozenset(),
        ),
        "second": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
            ),
            not_conditions=frozenset(),
        ),
        "result": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {
                    Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                    Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"]),
                }
            ),
            not_conditions=frozenset(),
        ),
    },
    "test_allow_without_condition_vs_deny_with_condition": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
            not_conditions=frozenset(),
        ),
        "second": PolicyShard(
            effect="Deny",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("*"), exclusions=frozenset({Resource("arn:aws:s3:::examplebucket/*")})
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {Condition(key="s3:x-amz-server-side-encryption", operator="StringNotEquals", values=["AES256"])}
            ),
            not_conditions=frozenset(),
        ),
        "result": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("*"), exclusions=frozenset({Resource("arn:aws:s3:::examplebucket/*")})
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
            not_conditions=frozenset(),
        ),
    },
}


@pytest.mark.parametrize("_, scenario", INTERSECTION_SCENARIOS.items())
def test_intersection(_, scenario):
    first, second, result = scenario.values()
    assert first.intersection(second) == result
