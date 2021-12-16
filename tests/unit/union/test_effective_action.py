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


def test_union_excluded_action_addition():
    """If we have an inclusion that is a subset of another EffectiveAction's exclusions it must not be eliminated.
    This is because it represents an additional allow which wasn't subject to the same exclusion in its original
    statement. If it had been then it would have self-destructed by its own exclusions.
    """
    a = EffectiveAction(Action("s3:*"), frozenset({Action("s3:get*")}))
    b = EffectiveAction(Action("s3:getObject"))

    assert a.union(b) == [
        EffectiveAction(Action("s3:*"), frozenset({Action("s3:get*")})),
        EffectiveAction(Action("s3:getObject")),
    ]


def test_union_complex_overlap():
    """If we have an exclusion that is a subset of another EffectiveAction's exclusions it should be eliminated.
    This is because it represents a smaller set of exclusions overall.
    """
    a = EffectiveAction(Action("s3:*"), frozenset({Action("s3:get*")}))
    b = EffectiveAction(Action("s3:*"), frozenset({Action("s3:getobject")}))

    assert a.union(b) == [
        EffectiveAction(Action("s3:*"), frozenset({Action("s3:getobject")})),
    ]


def test_union_disjoint():
    a = EffectiveAction(Action("s3:*"), frozenset({Action("s3:get*")}))
    b = EffectiveAction(Action("ec2:get*"))

    assert a.union(b) == [
        EffectiveAction(Action("s3:*"), frozenset({Action("s3:get*")})),
        EffectiveAction(Action("ec2:get*")),
    ]
