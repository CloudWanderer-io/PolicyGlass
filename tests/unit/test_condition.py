import pytest

from policyglass import Condition, ConditionOperator

CONDITION_REVERSIBLE_SCENARIOS = {
    "StringEquals": {
        "input": Condition("TestKey", "StringEquals", ["TestValue"]),
        "output": Condition("TestKey", "StringNotEquals", ["TestValue"]),
    },
    "StringNotEquals": {
        "input": Condition("TestKey", "StringNotEquals", ["TestValue"]),
        "output": Condition("TestKey", "StringEquals", ["TestValue"]),
    },
    "StringEqualsIgnoreCase": {
        "input": Condition("TestKey", "StringEqualsIgnoreCase", ["TestValue"]),
        "output": Condition("TestKey", "StringNotEqualsIgnoreCase", ["TestValue"]),
    },
    "StringNotEqualsIgnoreCase": {
        "input": Condition("TestKey", "StringNotEqualsIgnoreCase", ["TestValue"]),
        "output": Condition("TestKey", "StringEqualsIgnoreCase", ["TestValue"]),
    },
    "StringLike": {
        "input": Condition("TestKey", "StringLike", ["TestValue"]),
        "output": Condition("TestKey", "StringNotLike", ["TestValue"]),
    },
    "StringNotLike": {
        "input": Condition("TestKey", "StringNotLike", ["TestValue"]),
        "output": Condition("TestKey", "StringLike", ["TestValue"]),
    },
    "NumericEquals": {
        "input": Condition("TestKey", "NumericEquals", ["1"]),
        "output": Condition("TestKey", "NumericNotEquals", ["1"]),
    },
    "NumericNotEquals": {
        "input": Condition("TestKey", "NumericNotEquals", ["1"]),
        "output": Condition("TestKey", "NumericEquals", ["1"]),
    },
    "NumericLessThan": {
        "input": Condition("TestKey", "NumericLessThan", ["1"]),
        "output": Condition("TestKey", "NumericGreaterThanEquals", ["1"]),
    },
    "NumericGreaterThan": {
        "input": Condition("TestKey", "NumericGreaterThan", ["1"]),
        "output": Condition("TestKey", "NumericLessThanEquals", ["1"]),
    },
    "NumericLessThanEquals": {
        "input": Condition("TestKey", "NumericLessThanEquals", ["1"]),
        "output": Condition("TestKey", "NumericGreaterThan", ["1"]),
    },
    "NumericGreaterThanEquals": {
        "input": Condition("TestKey", "NumericGreaterThanEquals", ["1"]),
        "output": Condition("TestKey", "NumericLessThan", ["1"]),
    },
    "DateEquals": {
        "input": Condition("TestKey", "DateEquals", ["2020-01-01T00:00:01Z"]),
        "output": Condition("TestKey", "DateNotEquals", ["2020-01-01T00:00:01Z"]),
    },
    "DateNotEquals": {
        "input": Condition("TestKey", "DateNotEquals", ["2020-01-01T00:00:01Z"]),
        "output": Condition("TestKey", "DateEquals", ["2020-01-01T00:00:01Z"]),
    },
    "DateLessThan": {
        "input": Condition("TestKey", "DateLessThan", ["2020-01-01T00:00:01Z"]),
        "output": Condition("TestKey", "DateGreaterThanEquals", ["2020-01-01T00:00:01Z"]),
    },
    "DateGreaterThan": {
        "input": Condition("TestKey", "DateGreaterThan", ["2020-01-01T00:00:01Z"]),
        "output": Condition("TestKey", "DateLessThanEquals", ["2020-01-01T00:00:01Z"]),
    },
    "DateLessThanEquals": {
        "input": Condition("TestKey", "DateLessThanEquals", ["2020-01-01T00:00:01Z"]),
        "output": Condition("TestKey", "DateGreaterThan", ["2020-01-01T00:00:01Z"]),
    },
    "DateGreaterThanEquals": {
        "input": Condition("TestKey", "DateGreaterThanEquals", ["2020-01-01T00:00:01Z"]),
        "output": Condition("TestKey", "DateLessThan", ["2020-01-01T00:00:01Z"]),
    },
    "IpAddress": {
        "input": Condition("TestKey", "IpAddress", ["203.0.113.0/24"]),
        "output": Condition("TestKey", "NotIpAddress", ["203.0.113.0/24"]),
    },
    "NotIpAddress": {
        "input": Condition("TestKey", "NotIpAddress", ["203.0.113.0/24"]),
        "output": Condition("TestKey", "IpAddress", ["203.0.113.0/24"]),
    },
    "ArnEquals": {
        "input": Condition("TestKey", "ArnEquals", ["203.0.113.0/24"]),
        "output": Condition("TestKey", "ArnNotEquals", ["203.0.113.0/24"]),
    },
    "ArnNotEquals": {
        "input": Condition("TestKey", "ArnNotEquals", ["203.0.113.0/24"]),
        "output": Condition("TestKey", "ArnEquals", ["203.0.113.0/24"]),
    },
}


@pytest.mark.parametrize("_, scenario", CONDITION_REVERSIBLE_SCENARIOS.items())
def test_condition_reversible(_, scenario):
    input = scenario["input"]
    output = scenario["output"]

    assert input.reverse == output


@pytest.mark.parametrize("_, scenario", CONDITION_REVERSIBLE_SCENARIOS.items())
def test_condition_reversible_if_exists(_, scenario):
    input = scenario["input"]
    input.operator = ConditionOperator(input.operator + "IfExists")
    output = scenario["output"]
    output.operator = ConditionOperator(output.operator + "IfExists")

    assert input.reverse == output


CONDITION_NON_REVERSIBLE_SCENARIOS = {
    "BinaryEquals": {
        "input": Condition("TestKey", "BinaryEquals", ["TestValue"]),
    }
}


@pytest.mark.parametrize("_, scenario", CONDITION_NON_REVERSIBLE_SCENARIOS.items())
def test_condition_not_reversible(_, scenario):
    input = scenario["input"]

    with pytest.raises(ValueError) as ex:
        input.reverse
    assert f"Cannot reverse conditions with operator {input.operator}" in str(ex.value)
