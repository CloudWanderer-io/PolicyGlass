from policyglass import PolicyShard
from policyglass.action import Action, EffectiveAction
from policyglass.condition import Condition
from policyglass.policy_shard import delineate_intersecting_shards
from policyglass.principal import EffectivePrincipal, Principal
from policyglass.resource import EffectiveResource, Resource


def test_delineate_intersecting_shards_simple():
    shards = [
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
        PolicyShard(
            effect="Deny",
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
    ]

    assert delineate_intersecting_shards(shards) == [
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
    ]


def test_delineate_intersecting_shards_complex_overlap():
    shards = [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:get*")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:getobject*")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        ),
    ]

    assert delineate_intersecting_shards(shards) == [shards[1]]


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

    assert delineate_intersecting_shards(shards) == [shards[1]]


def test_identical():
    shards = [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
            not_conditions=frozenset(),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
            not_conditions=frozenset(),
        ),
    ]

    assert delineate_intersecting_shards(shards) == [shards[1]]


def test_identical_except_one_with_one_without_condition():
    shards = [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
            ),
            not_conditions=frozenset(),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
            not_conditions=frozenset(),
        ),
    ]

    assert delineate_intersecting_shards(shards) == [shards[1]]


def test_matching_subset_conditions():
    shards = [
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
                    Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"]),
                    Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                }
            ),
            not_conditions=frozenset(),
        ),
    ]

    assert delineate_intersecting_shards(shards) == [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:PutObject"), exclusions=frozenset()),
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
    ]


def test_matching_subset_conditions_and_not_conditions():
    shards = [
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
                    Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"]),
                }
            ),
            not_conditions=frozenset(
                {
                    Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                }
            ),
        ),
    ]

    assert delineate_intersecting_shards(shards) == [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:PutObject"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
            ),
            not_conditions=frozenset(
                {
                    Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                }
            ),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(
                {
                    Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"]),
                }
            ),
            not_conditions=frozenset(),
        ),
    ]


def test_subset_arps_differing_conditions():
    shards = [
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
    ]

    assert delineate_intersecting_shards(shards) == list(reversed(shards))