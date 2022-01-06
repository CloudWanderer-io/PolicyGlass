import pytest

from policyglass import Condition, EffectiveCondition

EFFECTIVE_CONDITION_SCENARIOS = {
    "exactly_equal": [
        EffectiveCondition(
            frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}),
            frozenset({Condition("Key", "BinaryEquals", ["QmluYXJ5VmFsdWVJbkJhc2U2NA=="])}),
        ),
        EffectiveCondition(
            frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}),
            frozenset({Condition("Key", "BinaryEquals", ["QmluYXJ5VmFsdWVJbkJhc2U2NA=="])}),
        ),
    ],
    "equal_different_order": [
        EffectiveCondition(
            frozenset(
                {
                    Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"]),
                    Condition("Key", "BinaryEquals", ["QmluYXJ5VmFsdWVJbkJhc2U2NA=="]),
                }
            ),
            frozenset({}),
        ),
        EffectiveCondition(
            frozenset(
                {
                    Condition("Key", "BinaryEquals", ["QmluYXJ5VmFsdWVJbkJhc2U2NA=="]),
                    Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"]),
                }
            ),
            frozenset({}),
        ),
    ],
    "equal_different_case_operator": [
        EffectiveCondition(
            frozenset(
                {
                    Condition("aws:PrincipalOrgId", "stringnotequals", ["o-123456"]),
                }
            ),
            frozenset({}),
        ),
        EffectiveCondition(
            frozenset(
                {
                    Condition("aws:PrincipalOrgId", "STRINGNOTEQUALS", ["o-123456"]),
                }
            ),
            frozenset({}),
        ),
    ],
    "equal_different_case_key": [
        EffectiveCondition(
            frozenset(
                {
                    Condition("aws:PRINCIPALORGID", "StringNotEquals", ["o-123456"]),
                }
            ),
            frozenset({}),
        ),
        EffectiveCondition(
            frozenset(
                {
                    Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"]),
                }
            ),
            frozenset({}),
        ),
    ],
}


@pytest.mark.parametrize("_, scenario", EFFECTIVE_CONDITION_SCENARIOS.items())
def test_effective_condition_equality(_, scenario):
    assert scenario[0] == scenario[1]


EFFECTIVE_CONDITION_NOT_MATCH_SCENARIOS = {
    "entirely_different": [
        EffectiveCondition(
            frozenset({Condition("Key", "BinaryEquals", ["QmluYXJ5VmFsdWVJbkJhc2U2NA=="])}), frozenset()
        ),
        EffectiveCondition(frozenset({Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"])}), frozenset()),
    ],
    "different_case_value": [
        EffectiveCondition(
            frozenset(
                {
                    Condition("aws:PrincipalOrgId", "StringNotEquals", ["o-123456"]),
                }
            ),
            frozenset({}),
        ),
        EffectiveCondition(
            frozenset(
                {
                    Condition("aws:PrincipalOrgId", "StringNotEquals", ["O-123456"]),
                }
            ),
            frozenset({}),
        ),
    ],
}


@pytest.mark.parametrize("_, scenario", EFFECTIVE_CONDITION_NOT_MATCH_SCENARIOS.items())
def test_effective_condition_inequality(_, scenario):
    assert scenario[0] != scenario[1]
