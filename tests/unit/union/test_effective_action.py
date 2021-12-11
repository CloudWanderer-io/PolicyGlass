import pytest

from policyglass import Action, EffectiveAction


def test_bad_union():
    with pytest.raises(ValueError) as ex:
        EffectiveAction(Action("S3:*")).union(Action("s3:*"))

    assert "Cannot union EffectiveAction with Action" in str(ex.value)


def test_union_simple():
    assert EffectiveAction(Action("s3:*")).union(EffectiveAction(Action("s3:getObject"))) == [
        EffectiveAction(Action("s3:*"))
    ]
