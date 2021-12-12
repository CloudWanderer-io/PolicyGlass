import pytest

from policyglass import Principal

PRINCIPAL_ISSUBSET_SCENARIOS = {
    "wildcard": [
        Principal("AWS", "arn:aws:iam::123456789012:role/RoleName"),
        Principal("AWS", "*"),
    ],
    "full_account": [
        Principal("AWS", "arn:aws:iam::123456789012:role/RoleName"),
        Principal("AWS", "arn:aws:iam::123456789012:root"),
    ],
    "short_account": [
        Principal("AWS", "arn:aws:iam::123456789012:role/RoleName"),
        Principal("AWS", "123456789012"),
    ],
    "exactly_equal": [
        Principal("AWS", "arn:aws:iam::123456789012:role/role-name"),
        Principal("AWS", "arn:aws:iam::123456789012:role/role-name"),
    ],
}


@pytest.mark.parametrize("_, scenario", PRINCIPAL_ISSUBSET_SCENARIOS.items())
def test_principal_lt(_, scenario):
    assert scenario[0].issubset(scenario[1])


PRINCIPAL_NOT_ISSUBSET_SCENARIOS = {
    "case_unequal": [
        Principal("AWS", "arn:aws:iam::123456789012:role/Role-Name"),
        Principal("AWS", "arn:aws:iam::123456789012:role/role-name"),
    ],
    "larger": [
        Principal("AWS", "arn:aws:iam::123456789012:role/*"),
        Principal("AWS", "arn:aws:iam::123456789012:role/role-name"),
    ],
    "smaller": [
        Principal("AWS", "arn:aws:iam::123456789012:role/role-name"),
        Principal("AWS", "arn:aws:iam::123456789012:role/*"),
    ],
    "type_incorrect": [
        Principal("AWS", "arn:aws:iam::123456789012:role/role-name"),
        Principal("Federated", "*"),
    ],
}


@pytest.mark.parametrize("_, scenario", PRINCIPAL_NOT_ISSUBSET_SCENARIOS.items())
def test_principal_not_contains(_, scenario):
    assert not scenario[0].issubset(scenario[1])
