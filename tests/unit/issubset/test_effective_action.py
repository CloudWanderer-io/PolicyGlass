import pytest

from policyglass import Action, EffectiveAction


def test_bad_issubset():
    with pytest.raises(ValueError) as ex:
        EffectiveAction(Action("S3:*")).issubset(Action("s3:*"))

    assert "Cannot compare EffectiveAction and Action" in str(ex.value)


def test_issubset_simple_false():
    assert not EffectiveAction(Action("s3:*")).issubset(EffectiveAction(Action("s3:getObject")))


def test_issubset_simple_true():
    assert EffectiveAction(Action("s3:getObject")).issubset(EffectiveAction(Action("s3:getObject")))


def test_issubset_exclusion_true():
    assert EffectiveAction(Action("s3:*"), frozenset({Action("s3:getObject")})).issubset(
        EffectiveAction(Action("s3:*"), frozenset({Action("s3:getObject")}))
    )


def test_issubset_excluded_action():
    a = EffectiveAction(Action("s3:*"), frozenset({Action("s3:get*")}))
    b = EffectiveAction(Action("s3:getObject"))

    assert not a.issubset(b)


def test_issubset_disjoint():
    a = EffectiveAction(Action("ec2:get*"))
    b = EffectiveAction(Action("s3:*"), frozenset({Action("s3:get*")}))

    assert not a.issubset(b)


def test_union_complex_overlap():
    """If we have an exclusion that is a subset of another EffectiveAction's exclusions then the effective
    action is not a subset because it allows things the other doesn't.
    """
    a = EffectiveAction(Action("s3:*"), frozenset({Action("s3:getobject")}))
    b = EffectiveAction(Action("s3:*"), frozenset({Action("s3:get*")}))

    assert a.issubset(b) is False


def test_exclusion_not_subset_of_no_exclusion():

    a = EffectiveAction(inclusion=Action("*"), exclusions=frozenset())
    b = EffectiveAction(inclusion=Action("*"), exclusions=frozenset({Action("s3:getobject")}))
    assert a.issubset(b) is False
