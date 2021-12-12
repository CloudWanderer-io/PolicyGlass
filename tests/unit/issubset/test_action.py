import pytest

from policyglass import Action

ACTION_ISSUBSET_SCENARIOS = {
    "smaller": ["s3:get*", "s3:*"],
    "smaller_mismatching_case": ["s3:get*", "S3:*"],
    "exactly_equal": ["s3:*", "s3:*"],
    "case_unequal": ["S3:*", "s3:*"],
}


@pytest.mark.parametrize("_, scenario", ACTION_ISSUBSET_SCENARIOS.items())
def test_action_issubset(_, scenario):
    assert Action(scenario[0]).issubset(Action(scenario[1]))


ACTION_NOT_ISSUBSET_SCENARIOS = {
    "larger": ["s3:*", "s3:get*"],
}


@pytest.mark.parametrize("_, scenario", ACTION_NOT_ISSUBSET_SCENARIOS.items())
def test_action_not_issubset(_, scenario):
    assert not Action(scenario[0]).issubset(Action(scenario[1]))
