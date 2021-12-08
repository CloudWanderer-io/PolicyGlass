import pytest

from policyglass import Condition, ConditionShard

CONDITION_MATCH_SCENARIOS = {
    "exactly_equal": [
        {"ArnEquals": {"ec2:SourceInstanceARN": ["arn:aws:ec2:*:*:instance/instance-id"]}},
        {"ArnEquals": {"ec2:SourceInstanceARN": ["arn:aws:ec2:*:*:instance/instance-id"]}},
    ],
    "mismatched_operator_case": [
        {"ArnEquals": {"ec2:SourceInstanceARN": ["arn:aws:ec2:*:*:instance/instance-id"]}},
        {"ArnEquals": {"ec2:SourceInstanceArn": ["arn:aws:ec2:*:*:instance/instance-id"]}},
    ],
    "mismatched_key_case": [
        {"ArnEquals": {"ec2:SourceInstanceARN": ["arn:aws:ec2:*:*:instance/instance-id"]}},
        {"arnequals": {"ec2:SourceInstanceARN": ["arn:aws:ec2:*:*:instance/instance-id"]}},
    ],
}


@pytest.mark.parametrize("_, scenario", CONDITION_MATCH_SCENARIOS.items())
def test_condition_equality(_, scenario):
    assert Condition(**scenario[0]) == Condition(**scenario[1])


CONDITION_NOT_MATCH_SCENARIOS = {
    "mismatched_value_case": [
        {"ArnEquals": {"ec2:SourceInstanceARN": ["arn:aws:ec2:*:*:instance/Instance-Id"]}},
        {"ArnEquals": {"ec2:SourceInstanceARN": ["arn:aws:ec2:*:*:instance/instance-id"]}},
    ],
}


@pytest.mark.parametrize("_, scenario", CONDITION_NOT_MATCH_SCENARIOS.items())
def test_condition_inequality(_, scenario):
    assert Condition(**scenario[0]) != Condition(**scenario[1])


@pytest.mark.parametrize("_, scenario", CONDITION_MATCH_SCENARIOS.items())
def test_condition_shard_equality(_, scenario):
    assert ConditionShard.factory(scenario[0]) == ConditionShard.factory(scenario[1])
