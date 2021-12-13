import pytest

from policyglass import Action, EffectiveAction, EffectivePrincipal, EffectiveResource, PolicyShard, Principal, Resource


def test_bad_difference():
    with pytest.raises(ValueError) as ex:
        PolicyShard(
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*")),
            conditions=frozenset(),
        ).difference(Principal("AWS", "*"))

    assert "Cannot union PolicyShard with Principal" in str(ex.value)


DIFFERENCE_SCENARIOS = {
    "proper_subset": {
        "first": PolicyShard(
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "*")),
            conditions=frozenset(),
        ),
        "second": PolicyShard(
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
            conditions=frozenset(),
        ),
        "result": [
            PolicyShard(
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
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "*")),
            conditions=frozenset(),
        ),
        "second": PolicyShard(
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
                effective_action=EffectiveAction(inclusion=Action("s3:*")),
                effective_resource=EffectiveResource(inclusion=Resource("*")),
                effective_principal=EffectivePrincipal(
                    Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")})
                ),
                conditions=frozenset(),
            ),
            PolicyShard(
                effective_action=EffectiveAction(inclusion=Action("s3:*")),
                effective_resource=EffectiveResource(inclusion=Resource("*")),
                effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:role/RoleName")),
                conditions=frozenset(),
            ),
        ],
    },
    "excluded_proper_subset": {
        "first": PolicyShard(
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(
                Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")})
            ),
            conditions=frozenset(),
        ),
        "second": PolicyShard(
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
            conditions=frozenset(),
        ),
        "result": [
            PolicyShard(
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
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "*")),
            conditions=frozenset(),
        ),
        "second": PolicyShard(
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "*")),
            conditions=frozenset(),
        ),
        "result": [],
    },
    "disjoint": {
        "first": PolicyShard(
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
            conditions=frozenset(),
        ),
        "second": PolicyShard(
            effective_action=EffectiveAction(inclusion=Action("s3:*")),
            effective_resource=EffectiveResource(inclusion=Resource("*")),
            effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::098765432109:root")),
            conditions=frozenset(),
        ),
        "result": [
            PolicyShard(
                effective_action=EffectiveAction(inclusion=Action("s3:*")),
                effective_resource=EffectiveResource(inclusion=Resource("*")),
                effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
                conditions=frozenset(),
            )
        ],
    },
}


@pytest.mark.parametrize("_, scenario", DIFFERENCE_SCENARIOS.items())
def test_difference(_, scenario):
    first, second, result = scenario.values()
    assert first.difference(second) == result
