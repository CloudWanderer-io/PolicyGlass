import pytest

from policyglass import Resource

RESOURCE_LT_SCENARIOS = {
    "smaller": ["arn:aws:ec2:*:*:volume/vol-12345678", "arn:aws:ec2:*:*:volume/*"],
}


@pytest.mark.parametrize("_, scenario", RESOURCE_LT_SCENARIOS.items())
def test_resource_contains(_, scenario):
    assert Resource(scenario[0]) < Resource(scenario[1])


RESOURCE_NOT_LT_SCENARIOS = {
    "exactly_equal": ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:volume/*"],
    "case_unequal": ["arn:aws:ec2:*:*Volume/*", "arn:aws:ec2:*:*:volume/*"],
    "larger": ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:volume/vol-12345678"],
}


@pytest.mark.parametrize("_, scenario", RESOURCE_NOT_LT_SCENARIOS.items())
def test_resource_not_less_than(_, scenario):
    assert not Resource(scenario[0]) < Resource(scenario[1])
