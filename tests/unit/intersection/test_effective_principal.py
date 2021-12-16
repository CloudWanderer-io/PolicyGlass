import pytest

from policyglass import EffectivePrincipal, Principal


def test_bad_intersection():
    with pytest.raises(ValueError) as ex:
        EffectivePrincipal(Principal("AWS", "*")).intersection(Principal("AWS", "*"))

    assert "Cannot intersect EffectivePrincipal with Principal" in str(ex.value)


INTERSECTION_SCENARIOS = {
    "proper_subset": {
        "first": EffectivePrincipal(Principal("AWS", "*")),
        "second": EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
        "result": EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
    },
    "proper_subset_with_exclusions": {
        "first": EffectivePrincipal(Principal("AWS", "*")),
        "second": EffectivePrincipal(
            Principal("AWS", "arn:aws:iam::123456789012:root"),
            frozenset({Principal("AWS", "arn:aws:iam::123456789012:role/RoleName")}),
        ),
        "result": EffectivePrincipal(
            Principal("AWS", "arn:aws:iam::123456789012:root"),
            frozenset({Principal("AWS", "arn:aws:iam::123456789012:role/RoleName")}),
        ),
    },
    "excluded_proper_subset": {
        "first": EffectivePrincipal(
            Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")})
        ),
        "second": EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
        "result": None,
    },
    "subset": {
        "first": EffectivePrincipal(Principal("AWS", "*")),
        "second": EffectivePrincipal(Principal("AWS", "*")),
        "result": EffectivePrincipal(Principal("AWS", "*")),
    },
    "disjoint": {
        "first": EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
        "second": EffectivePrincipal(Principal("AWS", "arn:aws:iam::098765432109:root")),
        "result": None,
    },
}


@pytest.mark.parametrize("_, scenario", INTERSECTION_SCENARIOS.items())
def test_intersection(_, scenario):
    first, second, result = scenario.values()
    assert first.intersection(second) == result
