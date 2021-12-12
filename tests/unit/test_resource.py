from policyglass import Resource


def test_arn_elements():
    assert Resource("arn:aws:ec2:*:*:volume/*").arn_elements == ["arn", "aws", "ec2", "*", "*", "volume/*"]


def test_arn_elements_blanks():
    assert Resource("arn:aws:s3:::bucket_name/key_name").arn_elements == [
        "arn",
        "aws",
        "s3",
        "*",
        "*",
        "bucket_name/key_name",
    ]
