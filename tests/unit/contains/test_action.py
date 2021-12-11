import pytest

from policyglass import Action

ACTION_IN_SCENARIOS = {
    "smaller": ["s3:get*", "s3:*"],
    "smaller_mismatching_case": ["s3:get*", "S3:*"],
}


@pytest.mark.parametrize("_, scenario", ACTION_IN_SCENARIOS.items())
def test_action_contains(_, scenario):
    assert Action(scenario[0]) in Action(scenario[1])


ACTION_NOT_IN_SCENARIOS = {
    "exactly_equal": ["s3:*", "s3:*"],
    "case_unequal": ["S3:*", "s3:*"],
    "larger": ["s3:*", "s3:get*"],
}


@pytest.mark.parametrize("_, scenario", ACTION_NOT_IN_SCENARIOS.items())
def test_action_not_contains(_, scenario):
    assert Action(scenario[0]) not in Action(scenario[1])
