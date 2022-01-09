from policyglass import Condition, EffectiveCondition


def test_different_inclusions():
    effective_condition_a = EffectiveCondition(frozenset({Condition("Key", "Operator", ["value"])}))
    effective_condition_b = EffectiveCondition(frozenset({Condition("AnotherKey", "Operator", ["value"])}))

    assert effective_condition_a.union(effective_condition_b) == EffectiveCondition(
        frozenset({Condition("Key", "Operator", ["value"]), Condition("AnotherKey", "Operator", ["value"])}),
    )


def test_same_inclusions():
    effective_condition_a = EffectiveCondition(frozenset({Condition("Key", "Operator", ["value"])}))
    effective_condition_b = EffectiveCondition(frozenset({Condition("Key", "Operator", ["value"])}))

    assert effective_condition_a.union(effective_condition_b) == EffectiveCondition(
        frozenset({Condition("Key", "Operator", ["value"])})
    )


def test_different_exclusions():
    effective_condition_a = EffectiveCondition(frozenset(), frozenset({Condition("Key", "Operator", ["value"])}))
    effective_condition_b = EffectiveCondition(frozenset(), frozenset({Condition("AnotherKey", "Operator", ["value"])}))

    assert effective_condition_a.union(effective_condition_b) == EffectiveCondition(
        frozenset(),
        frozenset({Condition("Key", "Operator", ["value"]), Condition("AnotherKey", "Operator", ["value"])}),
    )


def test_same_exclusions():
    effective_condition_a = EffectiveCondition(frozenset(), frozenset({Condition("Key", "Operator", ["value"])}))
    effective_condition_b = EffectiveCondition(frozenset(), frozenset({Condition("Key", "Operator", ["value"])}))

    assert effective_condition_a.union(effective_condition_b) == EffectiveCondition(
        frozenset(), frozenset({Condition("Key", "Operator", ["value"])})
    )
