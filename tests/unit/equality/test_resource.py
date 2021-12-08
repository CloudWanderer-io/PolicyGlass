import pytest

from policyglass import Resource

RESOURCE_SCENARIOS = {
    "exactly_equal": [
        "arn:aws:iam::123456789012:role/role-name",
        "arn:aws:iam::123456789012:role/role-name",
    ],
}


@pytest.mark.parametrize("_, scenario", RESOURCE_SCENARIOS.items())
def test_resource_equality(_, scenario):
    assert Resource(scenario[0]) == Resource(scenario[1])


RESOURCE_NOT_MATCH_SCENARIOS = {
    "case_unequal": [
        "arn:aws:iam::123456789012:role/role-name",
        "arn:aws:iam::123456789012:role/Role-Name",
    ],
}


@pytest.mark.parametrize("_, scenario", RESOURCE_NOT_MATCH_SCENARIOS.items())
def test_resource_inequality(_, scenario):
    assert Resource(scenario[0]) != Resource(scenario[1])
