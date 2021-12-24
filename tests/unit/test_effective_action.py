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


def test_raise_if_nonsense_arp():
    with pytest.raises(ValueError) as ex:
        EffectiveAction(Action("S3:*"), frozenset({Action("*")}))
    assert "Exclusions ([Action('*')]) are not within the inclusion (Action('S3:*'))" in str(ex.value)


def test_nothing_if_nonsense_arp_factory():

    assert EffectiveAction.factory(Action("S3:*"), frozenset({Action("*")})) is None
