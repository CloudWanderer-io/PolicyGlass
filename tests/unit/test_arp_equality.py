from policyglass import (
    RawAction,
    RawPrincipal,
    RawResource,
    RawCondition,
    RawConditionKey,
    RawConditionOperator,
    RawConditionValue,
)
import pytest

ACTION_SCENARIOS = {"exactly_equal": ["s3:*", "s3:*"], "case_unequal": ["S3:*", "s3:*"]}


@pytest.mark.parametrize("_, scenario", ACTION_SCENARIOS.items())
def test_action_equality(_, scenario):
    assert RawAction(scenario[0]) == RawAction(scenario[1])
