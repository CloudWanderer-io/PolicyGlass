from policyglass import Principal


def test_short_account_id():
    assert str(Principal("AWS", "123456789012")) == "type='AWS' value='arn:aws:iam::123456789012:root'"


def test_account_id():
    assert Principal(type="AWS", value="arn:aws:iam::123456789012:root").account_id == "123456789012"


def test_is_account():
    assert Principal(type="AWS", value="arn:aws:iam::123456789012:root").is_account


def test_is_account_false():
    assert not Principal("AWS", "arn:aws:iam::123456789012:role/role-name").is_account


def test_arn_elements():
    assert Principal("AWS", "arn:aws:iam::123456789012:role/role-name").arn_elements == [
        "arn",
        "aws",
        "iam",
        "",
        "123456789012",
        "role/role-name",
    ]
