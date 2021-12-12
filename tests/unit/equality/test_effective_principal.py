from policyglass import EffectivePrincipal, Principal


def test_equality_true():
    assert EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")) == EffectivePrincipal(
        Principal("AWS", "arn:aws:iam::123456789012:root")
    )
