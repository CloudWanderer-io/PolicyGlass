import pytest

from policyglass import EffectiveResource, Resource

RESOURCE_LT_SCENARIOS = {
    "smaller": [
        EffectiveResource(Resource("arn:aws:ec2:*:*:volume/vol-12345678")),
        EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*")),
    ],
}


@pytest.mark.parametrize("_, scenario", RESOURCE_LT_SCENARIOS.items())
def test_resource_contains(_, scenario):
    assert scenario[0] < scenario[1]


RESOURCE_NOT_LT_SCENARIOS = {
    "exactly_equal": [
        EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*")),
        EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*")),
    ],
    "case_unequal": [
        EffectiveResource(Resource("arn:aws:ec2:*:*:Volume/*")),
        EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*")),
    ],
    "larger": [
        EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*")),
        EffectiveResource(Resource("arn:aws:ec2:*:*:volume/vol-12345678")),
    ],
}


@pytest.mark.parametrize("_, scenario", RESOURCE_NOT_LT_SCENARIOS.items())
def test_resource_not_less_than(_, scenario):
    assert not scenario[0] < scenario[1]
