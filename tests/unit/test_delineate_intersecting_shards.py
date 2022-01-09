from policyglass import PolicyShard
from policyglass.action import Action, EffectiveAction
from policyglass.condition import Condition, EffectiveCondition
from policyglass.policy_shard import dedupe_policy_shards
from policyglass.principal import EffectivePrincipal, Principal
from policyglass.resource import EffectiveResource, Resource


def test_dedupe_policy_shards_simple():
    shards = [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
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
        PolicyShard(
            effect="Deny",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
    ]

    assert dedupe_policy_shards(shards) == [
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
    ]


def test_dedupe_policy_shards_complex_overlap():
    shards = [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:get*")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:getobject*")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
    ]

    assert dedupe_policy_shards(shards) == [shards[1]]


def test_larger_after_smaller():

    shards = [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(
                inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
    ]

    assert dedupe_policy_shards(shards) == [shards[1]]


def test_identical():
    shards = [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
    ]

    assert dedupe_policy_shards(shards) == [shards[1]]


def test_identical_except_one_with_one_without_condition():
    shards = [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset({Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])})
            ),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
    ]

    assert dedupe_policy_shards(shards) == [shards[1]]


def test_matching_subset_conditions():
    shards = [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset({Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])})
            ),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset(
                    {
                        Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"]),
                        Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                    }
                )
            ),
        ),
    ]

    assert dedupe_policy_shards(shards) == [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:PutObject"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset(
                    {
                        Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"]),
                        Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                    }
                )
            ),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset({Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])})
            ),
        ),
    ]


def test_matching_subset_conditions_and_condition_exclusions():
    shards = [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset({Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])})
            ),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                inclusions=frozenset(
                    {
                        Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"]),
                    }
                ),
                exclusions=frozenset(
                    {
                        Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                    }
                ),
            ),
        ),
    ]

    assert dedupe_policy_shards(shards) == [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:PutObject"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                inclusions=frozenset(
                    {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
                ),
                exclusions=frozenset(
                    {
                        Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                    }
                ),
            ),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset(
                    {
                        Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"]),
                    }
                )
            ),
        ),
    ]


def test_subset_arps_differing_conditions():
    shards = [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset({Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])})
            ),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                frozenset(
                    {
                        Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                    }
                )
            ),
        ),
    ]

    assert dedupe_policy_shards(shards) == list(reversed(shards))


def test_result_of_denying_action_and_resource():
    shards = [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("*"), exclusions=frozenset({Resource("arn:aws:s3:::examplebucket/*")})
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(inclusions=frozenset(), exclusions=frozenset()),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(
                inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(inclusions=frozenset(), exclusions=frozenset()),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(inclusions=frozenset(), exclusions=frozenset()),
        ),
    ]

    assert dedupe_policy_shards(shards) == [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset({Action("S3:PutObject")})),
            effective_resource=EffectiveResource(
                inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(inclusions=frozenset(), exclusions=frozenset()),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("*"), exclusions=frozenset({Resource("arn:aws:s3:::examplebucket/*")})
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(inclusions=frozenset(), exclusions=frozenset()),
        ),
    ]


def test_result_of_difference_of_deny_action_and_resource_subsets():
    # This corresponds to the output of difference/test_policyshard::deny_action_and_resource_subsets
    # And demonstrates that counterintuitive output is resolved by dedupe_policy_shards
    shards = [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("*"), exclusions=frozenset({Resource("arn:aws:s3:::examplebucket/*")})
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(inclusions=frozenset(), exclusions=frozenset()),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(inclusions=frozenset(), exclusions=frozenset()),
        ),
    ]

    assert dedupe_policy_shards(shards) == [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(
                inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(inclusions=frozenset(), exclusions=frozenset()),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("*"), exclusions=frozenset({Resource("arn:aws:s3:::examplebucket/*")})
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(inclusions=frozenset(), exclusions=frozenset()),
        ),
    ]
