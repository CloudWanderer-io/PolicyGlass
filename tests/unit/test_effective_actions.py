import pytest

from policyglass import Action, EffectiveAction


def test_in_exclusions_bad_comparison():
    assert not EffectiveAction(Action("S3:*"), frozenset({Action("s3:get*")})).in_exclusions(Action("s3:putobject"))


IN_EXCLUSIONS_TRUE_SCENARIOS = {
    "smaller": [EffectiveAction(Action("S3:*"), frozenset({Action("s3:get*")})), Action("s3:getobject")],
    "equal": [EffectiveAction(Action("S3:*"), frozenset({Action("s3:get*")})), Action("s3:get*")],
}


@pytest.mark.parametrize("_, scenario", IN_EXCLUSIONS_TRUE_SCENARIOS.items())
def test_in_exclusions_true(_, scenario):
    effective_action, action = scenario
    assert effective_action.in_exclusions(action)


def test_in_exclusions_false():
    assert not EffectiveAction(Action("S3:*"), frozenset({Action("s3:get*")})).in_exclusions(Action("s3:putobject"))
