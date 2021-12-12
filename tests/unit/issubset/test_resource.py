import pytest

from policyglass import Resource

RESOURCE_IN_SCENARIOS = {
    "smaller": ["arn:aws:ec2:*:*:volume/vol-1*", "arn:aws:ec2:*:*:volume/*"],
    "exactly_equal": ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:volume/*"],
}
# "arn:aws:ec2:*:*:volume/vol-12345678", "arn:aws:ec2:*:*:volume/*"


@pytest.mark.parametrize("_, scenario", RESOURCE_IN_SCENARIOS.items())
def test_action_issubset(_, scenario):
    assert Resource(scenario[0]).issubset(Resource(scenario[1]))


RESOURCE_NOT_IN_SCENARIOS = {
    "larger": ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:volume/vol-1*"],
    "case_unequal": ["arn:aws:ec2:*:*:Volume/*", "arn:aws:ec2:*:*:volume/*"],
    "smaller_mismatching_case": ["arn:aws:ec2:*:*:volume/vol-1*", "arn:aws:ec2:*:*:Volume/*"],
}


@pytest.mark.parametrize("_, scenario", RESOURCE_NOT_IN_SCENARIOS.items())
def test_action_not_issubset(_, scenario):
    assert not Resource(scenario[0]).issubset(Resource(scenario[1]))
