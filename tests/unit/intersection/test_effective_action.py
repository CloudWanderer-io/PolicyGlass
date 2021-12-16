import pytest

from policyglass import Action, EffectiveAction


def test_bad_intersection():
    with pytest.raises(ValueError) as ex:
        EffectiveAction(Action("S3:*")).intersection(Action("S3:*"))

    assert "Cannot union EffectiveAction with Action" in str(ex.value)


INTERSECTION_SCENARIOS = {
    "proper_subset": {
        "first": EffectiveAction(Action("S3:*")),
        "second": EffectiveAction(Action("S3:get*")),
        "result": [EffectiveAction(Action("S3:get*"))],
    },
    "proper_subset_with_exclusions": {
        "first": EffectiveAction(Action("S3:*")),
        "second": EffectiveAction(Action("S3:get*"), frozenset({Action("S3:GetObject")})),
        "result": [EffectiveAction(Action("S3:get*"), frozenset({Action("S3:GetObject")}))],
    },
    "excluded_proper_subset": {
        "first": EffectiveAction(Action("S3:*"), frozenset({Action("S3:get*")})),
        "second": EffectiveAction(Action("S3:get*")),
        "result": [],
    },
    "subset": {
        "first": EffectiveAction(Action("S3:*")),
        "second": EffectiveAction(Action("S3:*")),
        "result": [EffectiveAction(Action("S3:*"))],
    },
    "no_intersection": {
        "first": EffectiveAction(Action("S3:*")),
        "second": EffectiveAction(Action("EC2:*")),
        "result": [],
    },
    "larger": {
        "first": EffectiveAction(Action("S3:Get*")),
        "second": EffectiveAction(Action("S3:*")),
        "result": [EffectiveAction(Action("S3:Get*"))],
    },
    "larger_with_exclusion": {
        "first": EffectiveAction(Action("S3:Get*")),
        "second": EffectiveAction(Action("S3:*"), frozenset({Action("S3:GetObject")})),
        "result": [EffectiveAction(Action("S3:Get*"), frozenset({Action("S3:GetObject")}))],
    },
}


@pytest.mark.parametrize("_, scenario", INTERSECTION_SCENARIOS.items())
def test_intersection(_, scenario):
    first, second, result = scenario.values()
    assert first.intersection(second) == result


def test_intersection_disjoint():

    assert EffectiveAction(Action("S3:*")).intersection(EffectiveAction(Action("EC2:*"))) == []
