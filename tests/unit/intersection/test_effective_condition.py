import pytest

from policyglass import Action, Condition, EffectiveCondition


def test_bad_intersection():
    with pytest.raises(ValueError) as ex:
        EffectiveCondition(
            frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}), frozenset()
        ).intersection(Action("S3:*"))

    assert "Cannot intersect EffectiveCondition with Action" in str(ex.value)


INTERSECTION_SCENARIOS = {
    "proper_subset": {
        "first": EffectiveCondition(
            frozenset(
                {
                    Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"]),
                    Condition(key="s3:x-amz-server-side-encryption", operator="StringNotEquals", values=["AES256"]),
                }
            ),
            frozenset(),
        ),
        "second": EffectiveCondition(
            frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}), frozenset()
        ),
        "result": EffectiveCondition(
            frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}), frozenset()
        ),
    },
    "proper_subset_with_exclusions": {
        "first": EffectiveCondition(
            frozenset(
                {
                    Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"]),
                    Condition(key="s3:x-amz-server-side-encryption", operator="StringNotEquals", values=["AES256"]),
                }
            ),
            frozenset(),
        ),
        "second": EffectiveCondition(
            frozenset(
                {
                    Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"]),
                }
            ),
            frozenset({Condition(key="key", operator="BinaryEquals", values=["QmluYXJ5VmFsdWVJbkJhc2U2NA=="])}),
        ),
        "result": EffectiveCondition(
            frozenset(
                {
                    Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"]),
                }
            ),
            frozenset(),
        ),
    },
    # This is commented out until we deal with the fact that some conditions can negate each other, as the exclusions
    # of first set won't negate second, but a condition in first that negates a condition in second will.
    # "excluded_proper_subset": {
    #     "first": EffectiveCondition(
    #         frozenset(
    #             {
    #                 Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"]),
    #                 Condition(key="s3:x-amz-server-side-encryption", operator="StringNotEquals", values=["AES256"]),
    #             }
    #         ),
    #         frozenset({Condition(key="key", operator="BinaryEquals", values=["QmluYXJ5VmFsdWVJbkJhc2U2NA=="])}),
    #     ),
    #     "second": EffectiveCondition(
    #         frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}), frozenset()
    #     ),
    #     "result": None,
    # },
    "subset": {
        "first": EffectiveCondition(
            frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}), frozenset()
        ),
        "second": EffectiveCondition(
            frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}), frozenset()
        ),
        "result": EffectiveCondition(
            frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}), frozenset()
        ),
    },
    "disjoint": {
        "first": EffectiveCondition(
            frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}), frozenset()
        ),
        "second": EffectiveCondition(
            frozenset(
                {Condition(key="s3:x-amz-server-side-encryption", operator="StringNotEquals", values=["AES256"])}
            ),
            frozenset(),
        ),
        "result": EffectiveCondition(frozenset(), frozenset()),
    },
    "larger": {
        "first": EffectiveCondition(
            frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}),
            frozenset(),
        ),
        "second": EffectiveCondition(
            frozenset(
                {
                    Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"]),
                    Condition(key="s3:x-amz-server-side-encryption", operator="StringNotEquals", values=["AES256"]),
                }
            ),
            frozenset(),
        ),
        "result": EffectiveCondition(
            frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}),
            frozenset(),
        ),
    },
    # "larger_with_exclusion": {
    #     "first": EffectiveCondition(Action("S3:Get*")),
    #     "second": EffectiveCondition(
    #         frozenset(
    #             {
    #                 Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"]),
    #                 Condition(key="s3:x-amz-server-side-encryption", operator="StringNotEquals", values=["AES256"]),
    #             }
    #         ),
    #         frozenset(),
    #     ),
    #     "result": EffectiveCondition(Action("S3:Get*"), frozenset({Action("S3:GetObject")})),
    # },
}


@pytest.mark.parametrize("_, scenario", INTERSECTION_SCENARIOS.items())
def test_intersection(_, scenario):
    first, second, result = scenario.values()
    assert first.intersection(second) == result
