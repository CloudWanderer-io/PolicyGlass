from policyglass import PolicyShard
from policyglass.action import Action, EffectiveAction
from policyglass.condition import Condition, EffectiveCondition
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
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(inclusion=Action("s3:GetObject"), exclusions=frozenset()),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
        ),
        PolicyShard(
            effect="Allow",
            effective_action=EffectiveAction(
                inclusion=Action("s3:Get*"), exclusions=frozenset({Action("s3:GetObject")})
            ),
            effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
            effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
            effective_condition=EffectiveCondition(
                exclusions=frozenset({Condition("key", "BinaryEquals", ["QmluYXJ5VmFsdWVJbkJhc2U2NA=="])})
            ),
        ),
    ]

    assert (
        policy_shards_to_json(shards, exclude_defaults=True, indent=2)
        == """[
  {
    "effective_action": {
      "inclusion": "s3:*",
      "exclusions": [
        "s3:Get*"
      ]
    },
    "effective_resource": {
      "inclusion": "*"
    },
    "effective_principal": {
      "inclusion": {
        "type": "AWS",
        "value": "*"
      }
    }
  },
  {
    "effective_action": {
      "inclusion": "s3:GetObject"
    },
    "effective_resource": {
      "inclusion": "*"
    },
    "effective_principal": {
      "inclusion": {
        "type": "AWS",
        "value": "*"
      }
    }
  },
  {
    "effective_action": {
      "inclusion": "s3:Get*",
      "exclusions": [
        "s3:GetObject"
      ]
    },
    "effective_resource": {
      "inclusion": "*"
    },
    "effective_principal": {
      "inclusion": {
        "type": "AWS",
        "value": "*"
      }
    },
    "effective_condition": {
      "exclusions": [
        {
          "key": "key",
          "operator": "BinaryEquals",
          "values": [
            "QmluYXJ5VmFsdWVJbkJhc2U2NA=="
          ]
        }
      ]
    }
  }
]"""
    )
