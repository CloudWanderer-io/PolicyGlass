import pytest

from policyglass import Principal

PRINCIPAL_MATCH_SCENARIOS = {
    "exactly_equal": [
        Principal("AWS", "arn:aws:iam::123456789012:role/RoleName"),
        Principal("AWS", "arn:aws:iam::123456789012:role/RoleName"),
    ],
}


@pytest.mark.parametrize("_, scenario", PRINCIPAL_MATCH_SCENARIOS.items())
def test_action_equality(_, scenario):
    assert scenario[0] == scenario[1]


PRINCIPAL_NOT_MATCH_SCENARIOS = {
    "case_unequal": [
        Principal("AWS", "arn:aws:iam::123456789012:role/RoleName"),
        Principal("AWS", "arn:aws:iam::123456789012:role/rolename"),
    ],
}


@pytest.mark.parametrize("_, scenario", PRINCIPAL_NOT_MATCH_SCENARIOS.items())
def test_action_unequality(_, scenario):
    assert scenario[0] != scenario[1]
