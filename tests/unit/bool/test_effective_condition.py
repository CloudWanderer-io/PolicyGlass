import pytest

from policyglass import Condition, EffectiveCondition

TRUTHY_EFFECTIVE_CONDITION_SCENARIOS = {
    "inclusions_populated": EffectiveCondition(
        frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}),
        frozenset(),
    ),
    "exclusions_populated": EffectiveCondition(
        frozenset(),
        frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}),
    ),
}


@pytest.mark.parametrize("_, scenario", TRUTHY_EFFECTIVE_CONDITION_SCENARIOS.items())
def test_effective_condition_truthy(_, scenario):
    assert scenario


FALSEY_EFFECTIVE_CONDITION_SCENARIOS = {
    "nothing_populated": EffectiveCondition(
        frozenset(),
        frozenset(),
    ),
}


@pytest.mark.parametrize("_, scenario", FALSEY_EFFECTIVE_CONDITION_SCENARIOS.items())
def test_effective_condition_falsey(_, scenario):
    assert not scenario
