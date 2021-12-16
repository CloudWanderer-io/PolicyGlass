import json

from policyglass import (
    Action,
    Condition,
    EffectiveAction,
    EffectivePrincipal,
    EffectiveResource,
    PolicyShard,
    Principal,
    Resource,
)


def test_json():
    subject = PolicyShard(
        effect="Allow",
        effective_action=EffectiveAction(inclusion=Action("s3:*")),
        effective_resource=EffectiveResource(inclusion=Resource("*")),
        effective_principal=EffectivePrincipal(Principal("AWS", "arn:aws:iam::123456789012:root")),
        conditions=frozenset([Condition("Key", "Operator", ["Value"])]),
    )

    assert subject.json() == json.dumps(
        {
            "effective_action": {"inclusion": "s3:*", "exclusions": []},
            "effective_resource": {"inclusion": "*", "exclusions": []},
            "effective_principal": {
                "inclusion": {"type": "AWS", "value": "arn:aws:iam::123456789012:root"},
                "exclusions": [],
            },
            "conditions": [{"key": "Key", "operator": "Operator", "values": ["Value"]}],
            "not_conditions": [],
        }
    )
