import pytest

from policyglass import Action, EffectiveAction, Resource


def test_bad_contains():
    with pytest.raises(ValueError) as ex:
        Resource("*") in EffectiveAction(Action("S3:PutObject"))

    assert "Cannot check if EffectiveAction contains a Resource" in str(ex)


EFFECTIVE_ACTION_CONTAINS_SCENARIOS = {
    "exactly_equal": {"container": EffectiveAction(Action("S3:PutObject")), "contains": Action("S3:PutObject")},
    "subset": {"container": EffectiveAction(Action("S3:Put*")), "contains": Action("S3:PutObject")},
    "not_excluded": {
        "container": EffectiveAction(Action("S3:Put*"), frozenset({Action("S3:PutACL")})),
        "contains": Action("S3:PutObject"),
    },
}


@pytest.mark.parametrize("_, scenario", EFFECTIVE_ACTION_CONTAINS_SCENARIOS.items())
def test_action_contains(_, scenario):
    container = scenario["container"]
    contains = scenario["contains"]

    assert contains in container


EFFECTIVE_ACTION_NOT_CONTAINS_SCENARIOS = {
    "superset": {"container": EffectiveAction(Action("S3:PutObject")), "contains": Action("S3:*")},
    "excluded": {
        "container": EffectiveAction(Action("S3:Put*"), frozenset({Action("S3:PutObject")})),
        "contains": Action("S3:PutObject"),
    },
}


@pytest.mark.parametrize("_, scenario", EFFECTIVE_ACTION_NOT_CONTAINS_SCENARIOS.items())
def test_action_not_contains(_, scenario):
    container = scenario["container"]
    contains = scenario["contains"]

    assert contains not in container
