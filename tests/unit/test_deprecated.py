import pytest

from policyglass import delineate_intersecting_shards


def test_delineate_intersecting_shards():
    with pytest.deprecated_call():
        delineate_intersecting_shards(shards=[])
