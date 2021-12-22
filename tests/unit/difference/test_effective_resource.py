import pytest

from policyglass import EffectiveResource, Resource


def test_bad_difference():
    with pytest.raises(ValueError) as ex:
        EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*")).difference(Resource("arn:aws:ec2:*:*:volume/*"))

    assert "Cannot diff EffectiveResource with Resource" in str(ex.value)


# ["arn:aws:ec2:*:*:volume/*", "arn:aws:ec2:*:*:volume/vol-12345678"]

DIFFERENCE_SCENARIOS = {
    "proper_subset": {
        "first": EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*")),
        "second": EffectiveResource(Resource("arn:aws:ec2:*:*:volume/vol-123*")),
        "result": [
            EffectiveResource(
                Resource("arn:aws:ec2:*:*:volume/*"), frozenset({Resource("arn:aws:ec2:*:*:volume/vol-123*")})
            )
        ],
    },
    "proper_subset_with_exclusions": {
        "first": EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*")),
        "second": EffectiveResource(
            Resource("arn:aws:ec2:*:*:volume/vol-123*"), frozenset({Resource("arn:aws:ec2:*:*:volume/vol-12345678")})
        ),
        "result": [
            EffectiveResource(
                Resource("arn:aws:ec2:*:*:volume/*"), frozenset({Resource("arn:aws:ec2:*:*:volume/vol-123*")})
            ),
            EffectiveResource(Resource("arn:aws:ec2:*:*:volume/vol-12345678")),
        ],
    },
    "excluded_proper_subset": {
        "first": EffectiveResource(
            Resource("arn:aws:ec2:*:*:volume/*"), frozenset({Resource("arn:aws:ec2:*:*:volume/vol-123*")})
        ),
        "second": EffectiveResource(Resource("arn:aws:ec2:*:*:volume/vol-123*")),
        "result": [
            EffectiveResource(
                Resource("arn:aws:ec2:*:*:volume/*"), frozenset({Resource("arn:aws:ec2:*:*:volume/vol-123*")})
            )
        ],
    },
    "subset": {
        "first": EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*")),
        "second": EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*")),
        "result": [],
    },
    "subset_with_exclusion": {
        "first": EffectiveResource(Resource("*")),
        "second": EffectiveResource(Resource("*"), exclusions=frozenset({Resource("arn:aws:ec2:*:*:volume/*")})),
        "result": [EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*"))],
    },
    "disjoint": {
        "first": EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*")),
        "second": EffectiveResource(Resource("EC2:*")),
        "result": [EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*"))],
    },
}


@pytest.mark.parametrize("_, scenario", DIFFERENCE_SCENARIOS.items())
def test_difference(_, scenario):
    first, second, result = scenario.values()
    assert first.difference(second) == result
