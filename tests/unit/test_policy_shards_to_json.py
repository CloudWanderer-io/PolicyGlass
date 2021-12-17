from policyglass import PolicyShard
from policyglass.action import Action, EffectiveAction
from policyglass.condition import Condition
from policyglass.policy_shard import policy_shards_to_json
from policyglass.principal import EffectivePrincipal, Principal
from policyglass.resource import EffectiveResource, Resource


def test_policy_shards_to_json():
    shards = [
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:Get*")})),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:GetObject"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            conditions=frozenset(),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(
                inclusion=Action("s3:Get*"), exclusions=frozenset({Action("s3:GetObject")})
            ),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            not_conditions=frozenset({Condition("s3:x-amz-server-side-encryption", "StringNotEquals", ["AES256"])}),
        ),
    ]

    assert (
        policy_shards_to_json(shards, indent=2)
        == """[
  {
    "effective_action": {
      "inclusion": "s3:*",
      "exclusions": [
        "s3:Get*"
      ]
    },
    "effective_resource": {
      "inclusion": "*",
      "exclusions": []
    },
    "effective_principal": {
      "inclusion": {
        "type": "AWS",
        "value": "*"
      },
      "exclusions": []
    },
    "conditions": [],
    "not_conditions": []
  },
  {
    "effective_action": {
      "inclusion": "s3:GetObject",
      "exclusions": []
    },
    "effective_resource": {
      "inclusion": "*",
      "exclusions": []
    },
    "effective_principal": {
      "inclusion": {
        "type": "AWS",
        "value": "*"
      },
      "exclusions": []
    },
    "conditions": [],
    "not_conditions": []
  },
  {
    "effective_action": {
      "inclusion": "s3:Get*",
      "exclusions": [
        "s3:GetObject"
      ]
    },
    "effective_resource": {
      "inclusion": "*",
      "exclusions": []
    },
    "effective_principal": {
      "inclusion": {
        "type": "AWS",
        "value": "*"
      },
      "exclusions": []
    },
    "conditions": [],
    "not_conditions": [
      {
        "key": "s3:x-amz-server-side-encryption",
        "operator": "StringNotEquals",
        "values": [
          "AES256"
        ]
      }
    ]
  }
]"""
    )
