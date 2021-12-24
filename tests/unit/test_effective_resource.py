import pytest

from policyglass import EffectiveResource, Resource


def test_nonsense_effective_resource():
    with pytest.raises(ValueError):
        EffectiveResource(
            inclusion=Resource("arn:aws:s3:::examplebucket/*"),
            exclusions=frozenset({Resource("arn:aws:s3:::examplebucket/*")}),
        )
