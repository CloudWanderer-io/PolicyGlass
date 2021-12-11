from policyglass import Action, EffectiveAction


def test_equality_true():
    assert EffectiveAction(Action("s3:*")) == EffectiveAction(Action("s3:*"))
