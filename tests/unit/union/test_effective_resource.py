import pytest

from policyglass import EffectiveResource, Resource


def test_bad_union():
    with pytest.raises(ValueError) as ex:
        EffectiveResource(Resource("arn:aws:ec2:*:*:volume/vol-1*")).union(Resource("arn:aws:ec2:*:*:volume/vol-1*"))

    assert "Cannot union EffectiveResource with Resource" in str(ex.value)


def test_union_simple():
    assert EffectiveResource(Resource("arn:aws:ec2:*:*:volume/vol-1*")).union(
        EffectiveResource(Resource("arn:aws:ec2:*:*:volume/vol-123123123"))
    ) == [EffectiveResource(Resource("arn:aws:ec2:*:*:volume/vol-1*"))]


def test_union_excluded_resource_addition():
    """If we have an inclusion that is a subset of another EffectiveResource's exclusions it must not be eliminated.
    This is because it represents an additional allow which wasn't subject to the same exclusion in its original
    statement. If it had been then it would have self-destructed by its own exclusions.
    """
    a = EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*"), frozenset({Resource("arn:aws:ec2:*:*:volume/vol-1*")}))
    b = EffectiveResource(Resource("arn:aws:ec2:*:*:volume/vol-123123123"))

    assert a.union(b) == [
        EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*"), frozenset({Resource("arn:aws:ec2:*:*:volume/vol-1*")})),
        EffectiveResource(Resource("arn:aws:ec2:*:*:volume/vol-123123123")),
    ]


def test_union_disjoint():
    a = EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*"), frozenset({Resource("arn:aws:ec2:*:*:volume/vol-1*")}))
    b = EffectiveResource(Resource("arn:aws:s3:::examplebucket/*"))

    assert a.union(b) == [
        EffectiveResource(Resource("arn:aws:ec2:*:*:volume/*"), frozenset({Resource("arn:aws:ec2:*:*:volume/vol-1*")})),
        EffectiveResource(Resource("arn:aws:s3:::examplebucket/*")),
    ]
