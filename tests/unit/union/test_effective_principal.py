import pytest

from policyglass import EffectivePrincipal, Principal


def test_bad_union():
    with pytest.raises(ValueError) as ex:
        EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")).union(
            Principal("AWS", "arn:aws:iam::123456789012:root")
        )

    assert "Cannot union EffectivePrincipal with Principal" in str(ex.value)


def test_union_simple():
    assert EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")).union(
        EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:role/RoleName"))
    ) == [EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root"))]


def test_union_excluded_principal_addition():
    """If we have an inclusion that is a subset of another EffectivePrincipal's exclusions it must not be eliminated.
    This is because it represents an additional allow which wasn't subject to the same exclusion in its original
    statement. If it had been then it would have self-destructed by its own exclusions.
    """
    a = EffectivePrincipal(Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")}))
    b = EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:role/RoleName"))

    assert a.union(b) == [
        EffectivePrincipal(Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")})),
        EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:role/RoleName")),
    ]


def test_union_disjoint():
    a = EffectivePrincipal(
        Principal("AWS", "arn:aws:iam::123456789012:root"),
        frozenset({Principal("AWS", "arn:aws:iam::123456789012:role/RoleName")}),
    )
    b = EffectivePrincipal(Principal("AWS", "arn:aws:iam::098765432109:root"))

    assert a.union(b) == [
        EffectivePrincipal(
            Principal("AWS", "arn:aws:iam::123456789012:root"),
            frozenset({Principal("AWS", "arn:aws:iam::123456789012:role/RoleName")}),
        ),
        EffectivePrincipal(Principal("AWS", "arn:aws:iam::098765432109:root")),
    ]
