from policyglass import PolicyShard
from policyglass.action import Action, EffectiveAction
from policyglass.condition import Condition
from policyglass.principal import EffectivePrincipal, Principal
from policyglass.resource import EffectiveResource, Resource


def test_policy_shards_explain():
    shard = PolicyShard(
        effect="Allow",
        effective_action=EffectiveAction(inclusion=Action("s3:Get*"), exclusions=frozenset({Action("s3:GetObject")})),
        effective_resource=EffectiveResource(
            inclusion=Resource("*"), exclusions=frozenset({Resource("arn:aws:s3:::DOC-EXAMPLE-BUCKET/*")})
        ),
        effective_principal=EffectivePrincipal(
            inclusion=Principal(type="AWS", value="*"),
            exclusions=frozenset({Principal("AWS", "arn:aws:iam::123456789012:role/role-name")}),
        ),
        conditions=frozenset({Condition("s3:x-amz-server-side-encryption", "StringNotEquals", ["AES256"])}),
        not_conditions=frozenset({Condition("s3:x-amz-server-side-encryption", "StringNotEquals", ["AES256"])}),
    )

    assert (
        shard.explain == "Allow action s3:Get* (except for s3:GetObject) on resource * "
        "(except for arn:aws:s3:::DOC-EXAMPLE-BUCKET/*) with principal AWS * "
        "(except principals AWS arn:aws:iam::123456789012:role/role-name). "
        "Provided conditions s3:x-amz-server-side-encryption StringNotEquals ['AES256'] are met. "
        "Unless conditions s3:x-amz-server-side-encryption StringNotEquals ['AES256'] are met."
    )
