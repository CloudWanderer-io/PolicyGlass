import pytest

from policyglass import Action

ACTION_LT_SCENARIOS = {
    "smaller": ["s3:get*", "s3:*"],
    "smaller_mismatching_case": ["s3:get*", "S3:*"],
}


@pytest.mark.parametrize("_, scenario", ACTION_LT_SCENARIOS.items())
def test_action_less_than(_, scenario):
    assert Action(scenario[0]) < Action(scenario[1])


ACTION_GT_SCENARIOS = {
    "exactly_equal": ["s3:*", "s3:*"],
    "case_unequal": ["S3:*", "s3:*"],
    "larger": ["s3:*", "s3:get*"],
}


@pytest.mark.parametrize("_, scenario", ACTION_GT_SCENARIOS.items())
def test_action_greater_than(_, scenario):
    assert not Action(scenario[0]) < Action(scenario[1])
