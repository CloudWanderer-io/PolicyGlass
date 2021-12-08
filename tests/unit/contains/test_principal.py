import pytest

from policyglass import Principal

PRINCIPAL_NOT_IN_SCENARIOS = {
    "exactly_equal": [
        {"AWS": ["arn:aws:iam::123456789012:role/role-name"]},
        {"AWS": ["arn:aws:iam::123456789012:role/role-name"]},
    ],
    "case_unequal": [
        {"AWS": ["arn:aws:iam::123456789012:role/Role-Name"]},
        {"AWS": ["arn:aws:iam::123456789012:role/role-name"]},
    ],
    "larger": [{"AWS": ["arn:aws:iam::123456789012:role/*"]}, {"AWS": ["arn:aws:iam::123456789012:role/role-name"]}],
    "smaller": [{"AWS": ["arn:aws:iam::123456789012:role/role-name"]}, {"AWS": ["arn:aws:iam::123456789012:role/*"]}],
}


@pytest.mark.parametrize("_, scenario", PRINCIPAL_NOT_IN_SCENARIOS.items())
def test_principal_not_contains(_, scenario):
    assert Principal(scenario[0]) not in Principal(scenario[1])


def test_principal_not_contains_key():
    assert "AWS" not in Principal({"AWS": ["arn:aws:iam::123456789012:role/*"]})
