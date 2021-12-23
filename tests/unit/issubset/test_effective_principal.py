from policyglass import EffectivePrincipal, Principal


def test_excluded():
    principal_a = EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:role/RoleName"))
    principal_b = EffectivePrincipal(
        Principal("AWS", "*"), frozenset({Principal("AWS", "arn:aws:iam::123456789012:root")})
    )

    assert not principal_a.issubset(principal_b)
