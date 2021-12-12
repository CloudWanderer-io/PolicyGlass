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
        Principal("AWS", "arn:aws:iam::123456789012:role/RoleName"),
        Principal("AWS", "arn:aws:iam::123456789012:role/RoleName"),
    ],
}


@pytest.mark.parametrize("_, scenario", PRINCIPAL_ISSUBSET_SCENARIOS.items())
def test_principal_lt(_, scenario):
    assert scenario[0].issubset(scenario[1])


PRINCIPAL_NOT_ISSUBSET_SCENARIOS = {
    "case_unequal": [
        Principal("AWS", "arn:aws:iam::123456789012:role/RoleName"),
        Principal("AWS", "arn:aws:iam::123456789012:role/rolename"),
    ],
    "larger": [
        Principal("AWS", "arn:aws:iam::123456789012:root"),
        Principal("AWS", "arn:aws:iam::123456789012:role/RoleName"),
    ],
    "type_incorrect": [
        Principal("AWS", "arn:aws:iam::123456789012:role/RoleName"),
        Principal("Federated", "*"),
    ],
}


@pytest.mark.parametrize("_, scenario", PRINCIPAL_NOT_ISSUBSET_SCENARIOS.items())
def test_principal_not_contains(_, scenario):
    assert not scenario[0].issubset(scenario[1])
