from policyglass import Principal, PrincipalCollection


def test_principals():
    assert PrincipalCollection({"AWS": ["arn:aws:iam::123456789012:root"]}).principals == [
        Principal(type="AWS", value="arn:aws:iam::123456789012:root")
    ]
