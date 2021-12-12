import pytest

from policyglass import Action, EffectiveAction


def test_bad_difference():
    with pytest.raises(ValueError) as ex:
        EffectiveAction(Action("S3:*")).difference(Action("S3:*"))

    assert "Cannot union EffectiveAction with Action" in str(ex.value)


DIFFERENCE_SCENARIOS = {
    "simple": {
        "first": EffectiveAction(Action("S3:*")),
        "second": EffectiveAction(Action("S3:get*")),
        "result": [EffectiveAction(Action("S3:*"), frozenset({Action("S3:get*")}))],
    },
    "complex": {
        "first": EffectiveAction(Action("S3:*")),
        "second": EffectiveAction(Action("S3:get*"), frozenset({Action("S3:GetObject")})),
        "result": [
            EffectiveAction(Action("S3:*"), frozenset({Action("S3:get*")})),
            EffectiveAction(Action("S3:GetObject")),
        ],
    },
    "second_in_firsts_exclusions": {
        "first": EffectiveAction(Action("S3:*"), frozenset({Action("S3:get*")})),
        "second": EffectiveAction(Action("S3:get*")),
        "result": [EffectiveAction(Action("S3:*"), frozenset({Action("S3:get*")}))],
    },
    "full_overlap": {
        "first": EffectiveAction(Action("S3:*")),
        "second": EffectiveAction(Action("S3:*")),
        "result": [],
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
