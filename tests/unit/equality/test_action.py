import pytest

from policyglass import Action

ACTION_MATCH_SCENARIOS = {"exactly_equal": ["s3:*", "s3:*"], "case_unequal": ["S3:*", "s3:*"]}


@pytest.mark.parametrize("_, scenario", ACTION_MATCH_SCENARIOS.items())
def test_action_equality(_, scenario):
    assert Action(scenario[0]) == Action(scenario[1])
