from policyglass import EffectiveResource, Resource


def test_equality_true():
    assert EffectiveResource(Resource("arn:aws:ec2:*:*:volume/vol-1*")) == EffectiveResource(
        Resource("arn:aws:ec2:*:*:volume/vol-1*")
    )
