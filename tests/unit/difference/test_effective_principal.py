import pytest

from policyglass import EffectivePrincipal, Principal


def test_bad_difference():
    with pytest.raises(ValueError) as ex:
        EffectivePrincipal(Principal("AWS", "*")).difference(Principal("AWS", "*"))

    assert "Cannot diff EffectivePrincipal with Principal" in str(ex.value)


DIFFERENCE_SCENARIOS = {
    "proper_subset": {
        "first": EffectivePrincipal(Principal("AWS", "*")),
        "second": EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
        "result": [
            EffectivePrincipal(Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")}))
        ],
    },
    "proper_subset_with_exclusions": {
        "first": EffectivePrincipal(Principal("AWS", "*")),
        "second": EffectivePrincipal(
            Principal("AWS", "arn:aws:iam::123456789012:root"),
            frozenset({Principal("AWS", "arn:aws:iam::123456789012:role/RoleName")}),
        ),
        "result": [
            EffectivePrincipal(Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")})),
            EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:role/RoleName")),
        ],
    },
    "excluded_proper_subset": {
        "first": EffectivePrincipal(
            Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")})
        ),
        "second": EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
        "result": [
            EffectivePrincipal(Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")}))
        ],
    },
    "subset": {
        "first": EffectivePrincipal(Principal("AWS", "*")),
        "second": EffectivePrincipal(Principal("AWS", "*")),
        "result": [],
    },
    "subset_with_exclusion": {
        "first": EffectivePrincipal(Principal("AWS", "*")),
        "second": EffectivePrincipal(
            Principal("AWS", "*"), exclusions=frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")})
        ),
        "result": [EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root"))],
    },
    "disjoint": {
        "first": EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
        "second": EffectivePrincipal(Principal("AWS", "arn:aws:iam::098765432109:root")),
        "result": [EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root"))],
    },
}


@pytest.mark.parametrize("_, scenario", DIFFERENCE_SCENARIOS.items())
def test_difference(_, scenario):
    first, second, result = scenario.values()
    assert first.difference(second) == result
