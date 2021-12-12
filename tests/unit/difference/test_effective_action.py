import pytest

from policyglass import Action, EffectiveAction


def test_bad_difference():
    with pytest.raises(ValueError) as ex:
        EffectiveAction(Action("S3:*")).difference(Action("S3:*"))

    assert "Cannot union EffectiveAction with Action" in str(ex.value)


DIFFERENCE_SCENARIOS = {
    "proper_subset": {
        "first": EffectiveAction(Action("S3:*")),
        "second": EffectiveAction(Action("S3:get*")),
        "result": [EffectiveAction(Action("S3:*"), frozenset({Action("S3:get*")}))],
    },
    "proper_subset_with_exclusions": {
        "first": EffectiveAction(Action("S3:*")),
        "second": EffectiveAction(Action("S3:get*"), frozenset({Action("S3:GetObject")})),
        "result": [
            EffectiveAction(Action("S3:*"), frozenset({Action("S3:get*")})),
            EffectiveAction(Action("S3:GetObject")),
        ],
    },
    "excluded_proper_subset": {
        "first": EffectiveAction(Action("S3:*"), frozenset({Action("S3:get*")})),
        "second": EffectiveAction(Action("S3:get*")),
        "result": [EffectiveAction(Action("S3:*"), frozenset({Action("S3:get*")}))],
    },
    "subset": {
        "first": EffectiveAction(Action("S3:*")),
        "second": EffectiveAction(Action("S3:*")),
        "result": [],
    },
    "no_intersection": {
        "first": EffectiveAction(Action("S3:*")),
        "second": EffectiveAction(Action("EC2:*")),
        "result": [EffectiveAction(Action("S3:*"))],
    },
}


@pytest.mark.parametrize("_, scenario", DIFFERENCE_SCENARIOS.items())
def test_difference(_, scenario):
    first, second, result = scenario.values()
    assert first.difference(second) == result


def test_difference_disjoint():

    assert EffectiveAction(Action("S3:*")).difference(EffectiveAction(Action("EC2:*"))) == [
        EffectiveAction(Action("S3:*"))
    ]
