import pytest

from policyglass import Action, EffectiveAction, EffectivePrincipal, EffectiveResource, PolicyShard, Principal, Resource
from policyglass.condition import Condition


def test_bad_difference():
    with pytest.raises(ValueError) as ex:
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*")),
            conditions=frozenset(),
        ).difference(Principal("AWS", "*"))

    assert "Cannot diff PolicyShard with Principal" in str(ex.value)


DIFFERENCE_SCENARIOS = {
    "proper_subset": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "*")),
            conditions=frozenset(),
        ),
        "second": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
            conditions=frozenset(),
        ),
        "result": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*")),
                effective_resource=EffectiveResource(inclusion=Resource("*")),
                effective_principal=EffectivePrincipal(
                    Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")})
                ),
                conditions=frozenset(),
            )
        ],
    },
    "proper_subset_with_exclusions": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "*")),
            conditions=frozenset(),
        ),
        "second": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(
                Principal("AWS", "arn:aws:iam::123456789012:root"),
                frozenset({Principal("AWS", "arn:aws:iam::123456789012:role/RoleName")}),
            ),
            conditions=frozenset(),
        ),
        "result": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*")),
                effective_resource=EffectiveResource(inclusion=Resource("*")),
                effective_principal=EffectivePrincipal(
                    Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")})
                ),
                conditions=frozenset(),
            ),
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*")),
                effective_resource=EffectiveResource(inclusion=Resource("*")),
                effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:role/RoleName")),
                conditions=frozenset(),
            ),
        ],
    },
    "excluded_proper_subset": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(
                Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")})
            ),
            conditions=frozenset(),
        ),
        "second": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
            conditions=frozenset(),
        ),
        "result": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*")),
                effective_resource=EffectiveResource(inclusion=Resource("*")),
                effective_principal=EffectivePrincipal(
                    Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")})
                ),
                conditions=frozenset(),
            )
        ],
    },
    "subset": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "*")),
            conditions=frozenset(),
        ),
        "second": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "*")),
            conditions=frozenset(),
        ),
        "result": [],
    },
    "disjoint": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
            conditions=frozenset(),
        ),
        "second": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::098765432109:root")),
            conditions=frozenset(),
        ),
        "result": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("s3:*")),
                effective_resource=EffectiveResource(inclusion=Resource("*")),
                effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
                conditions=frozenset(),
            )
        ],
    },
    "proper_subset_with_condition": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "*")),
            conditions=frozenset(),
        ),
        "second": PolicyShard(
            effect="Deny",
            effective_action=EffectiveAction(inclusion=Action("*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
            conditions=frozenset({Condition("Key", "Operator", ["Value"])}),
        ),
        "result": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"),
                    exclusions=frozenset({Principal(type="AWS", value="arn:aws:iam::123456789012:root")}),
                ),
                conditions=frozenset(),
                not_conditions=frozenset(),
            ),
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
                not_conditions=frozenset({Condition(key="Key", operator="Operator", values=["Value"])}),
            ),
        ],
    },
    "exact_match_on_inclusion_with_exclusion_and_condition": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "*")),
            conditions=frozenset(),
        ),
        "second": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*")),
            effective_resource=EffectiveResource(
                inclusion=Resource("*"), exclusions=frozenset({Resource("arn:aws:s3:::DOC-EXAMPLE-BUCKET/*")})
            ),
            effective_principal=EffectivePrincipal(Principal("AWS", "*")),
            conditions=frozenset({Condition("Key", "Operator", ["Value"])}),
        ),
        "result": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(
                    inclusion=Resource("arn:aws:s3:::DOC-EXAMPLE-BUCKET/*"), exclusions=frozenset()
                ),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
                not_conditions=frozenset(),
            ),
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
                not_conditions=frozenset({Condition(key="Key", operator="Operator", values=["Value"])}),
            ),
        ],
    },
    "simple_deny_with_exclusion": {
        "first": PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
        "second": PolicyShard(
            effect="Deny",
            effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset()),
            effective_resource=EffectiveResource(
                inclusion=Resource("*"), exclusions=frozenset({Resource("arn:aws:s3:::examplebucket/*")})
            ),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            not_conditions=frozenset(),
        ),
        "result": [
            PolicyShard(
                effect="Allow",
                effective_action=EffectiveAction(inclusion=Action("*"), exclusions=frozenset()),
                effective_resource=EffectiveResource(
                    inclusion=Resource("arn:aws:s3:::examplebucket/*"), exclusions=frozenset()
                ),
                effective_principal=EffectivePrincipal(
                    inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()
                ),
                conditions=frozenset(),
                not_conditions=frozenset(),
            )
        ],
    },
}


@pytest.mark.parametrize("_, scenario", DIFFERENCE_SCENARIOS.items())
def test_difference(_, scenario):
    first, second, result = scenario.values()
    assert first.difference(second) == result
