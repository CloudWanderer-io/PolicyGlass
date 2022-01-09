from policyglass import Condition, EffectiveCondition


def test_factory():

    subject = EffectiveCondition(
        inclusions=frozenset({Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}),
        exclusions=frozenset(
            {
                Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                Condition(key="key", operator="BinaryEquals", values=["QmluYXJ5VmFsdWVJbkJhc2U2NA=="]),
            },
        ),
    )

    assert subject == EffectiveCondition(
        frozenset(
            {
                Condition(key="s3:x-amz-server-side-encryption", operator="StringNotEquals", values=["AES256"]),
                Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"]),
            }
        ),
        frozenset(
            {
                Condition(key="key", operator="BinaryEquals", values=["QmluYXJ5VmFsdWVJbkJhc2U2NA=="]),
            },
        ),
    )


def test_reverse():

    subject = EffectiveCondition(
        inclusions=frozenset({Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}),
        exclusions=frozenset(
            {
                Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                Condition(key="key", operator="BinaryEquals", values=["QmluYXJ5VmFsdWVJbkJhc2U2NA=="]),
            },
        ),
    )

    assert subject.reverse == EffectiveCondition(
        frozenset(
            {
                Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
                Condition(key="aws:PrincipalOrgId", operator="StringEquals", values=["o-123456"]),
                Condition(key="key", operator="BinaryEquals", values=["QmluYXJ5VmFsdWVJbkJhc2U2NA=="]),
            }
        )
    )
