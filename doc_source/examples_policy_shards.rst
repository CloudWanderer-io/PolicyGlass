Examples of PolicyShards
==========================

Below you can find some examples on how PolicyGlass can be used to understand complex policies in a consistent way.

We're going to use :meth:`~policyglass.policy_shard.policy_shards_to_json` to make the output a bit easier to read.

.. tip::

   Remember :class:`~policyglass.policy_shard.PolicyShard` objects are *not* policies. 
   They represent policies in an abstracted way that makes them easier to understand programmatically, the JSON output
   you see in the examples is not a policy you can use directly in AWS.

Simple
-----------

.. doctest:: 

   >>> from policyglass import Policy, dedupe_policy_shards, policy_shards_effect, policy_shards_to_json
   >>> policy_a = Policy(**{
   ...     "Version": "2012-10-17",
   ...     "Statement": [
   ...         {
   ...             "Effect": "Allow",
   ...             "Action": [
   ...                 "s3:*"
   ...             ],
   ...             "Resource": "*"
   ...         }
   ...     ]
   ... })
   >>> policy_b = Policy(**{
   ...     "Version": "2012-10-17",
   ...     "Statement": [
   ...         {
   ...             "Effect": "Deny",
   ...             "Action": [
   ...                 "s3:*"
   ...             ],
   ...             "Resource": "arn:aws:s3:::examplebucket/*"
   ...         }
   ...     ]
   ... })
   >>> policy_shards = policy_shards_effect([*policy_a.policy_shards, *policy_b.policy_shards])
   >>> print(policy_shards_to_json(policy_shards, exclude_defaults=True, indent=2))
   [
      {
        "effective_action": {
          "inclusion": "s3:*"
        },
        "effective_resource": {
          "inclusion": "*",
          "exclusions": [
            "arn:aws:s3:::examplebucket/*"
          ]
        },
        "effective_principal": {
          "inclusion": {
            "type": "AWS",
            "value": "*"
          }
        }
      }
    ]
   
PolicyShard #1 (first dictonary in list) tells us:
   #. `s3:*` is allowed for all resources **except** ``arn:aws:s3:::examplebucket/*``

What occurred:
   #. The ``resource`` from the deny was added to the allow's ``EffectiveResource``'s ``exclusions``

De-duplicate
-------------

.. doctest:: 

   >>> from policyglass import Policy, dedupe_policy_shards, policy_shards_to_json
   >>> policy_a = Policy(**{
   ...     "Version": "2012-10-17",
   ...     "Statement": [
   ...         {
   ...             "Effect": "Allow",
   ...             "Action": [
   ...                 "s3:*"
   ...             ],
   ...             "Resource": "*"
   ...         }
   ...     ]
   ... })
   >>> policy_b = Policy(**{
   ...     "Version": "2012-10-17",
   ...     "Statement": [
   ...         {
   ...             "Effect": "Allow",
   ...             "Action": [
   ...                 "s3:*"
   ...             ],
   ...             "Resource": "*"
   ...         }
   ...     ]
   ... })
   >>> policy_shards = dedupe_policy_shards([*policy_a.policy_shards, *policy_b.policy_shards])
   >>> print(policy_shards_to_json(policy_shards, exclude_defaults=True, indent=2))
   [
      {
        "effective_action": {
          "inclusion": "s3:*"
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
      }
    ]

PolicyShard #1 (first dictonary in list) tells us:
   #. ``s3:*`` is allowed on all resources.

What occurred:
   #. One of the two ``s3:*`` policy shards was removed because it was a duplicate.

Deny Not Resource Policy
--------------------------
.. doctest:: 

   >>> from policyglass import Policy, policy_shards_effect, policy_shards_to_json
   >>> policy_a = Policy(**{
   ...     "Version": "2012-10-17",
   ...     "Statement": [
   ...         {
   ...             "Effect": "Allow",
   ...             "Action": [
   ...                 "s3:*",
   ...                 "s3:GetObject"
   ...             ],
   ...             "Resource": "*"
   ...         },
   ...         {
   ...             "Effect": "Deny",
   ...             "Action": [
   ...                 "s3:*",
   ...             ],
   ...             "NotResource": "arn:aws:s3:::examplebucket/*",
   ...             "Condition": {
   ...                  "StringNotEquals": {
   ...                      "s3:x-amz-server-side-encryption": "AES256"
   ...                  }
   ...             }
   ...         }
   ...     ]
   ... })
   >>> shards_effect = policy_shards_effect(policy_a.policy_shards)
   >>> print(policy_shards_to_json(shards_effect, exclude_defaults=True, indent=2))
   [
      {
        "effective_action": {
          "inclusion": "s3:*"
        },
        "effective_resource": {
          "inclusion": "arn:aws:s3:::examplebucket/*"
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
          "inclusion": "s3:*"
        },
        "effective_resource": {
          "inclusion": "*",
          "exclusions": [
            "arn:aws:s3:::examplebucket/*"
          ]
        },
        "effective_principal": {
          "inclusion": {
            "type": "AWS",
            "value": "*"
          }
        },
        "conditions": [
          {
            "key": "s3:x-amz-server-side-encryption",
            "operator": "StringEquals",
            "values": [
              "AES256"
            ]
          }
        ]
      }
    ]
   
The output has two policy shards.

PolicyShard #1 (first dictionary in list) tells us:
   #. Allow ``s3:*``
   #. On ``arn:aws:s3:::examplebucket/*``
   #. No conditions

PolicyShard #2 (second dictionary in list) tells us:
   #. Allow ``s3:*`` 
   #. On all resources
   #. If the condition applies.

What occurred:
   #. ``s3:GetObject`` was removed from the allow because it was totally within ``s3:*``
   #. A new ``PolicyShard`` was created with ``s3:*``
   #. The deny's ``condition`` got reversed from ``StringNotEquals`` to ``StringEquals`` and added to the new allow ``PolicyShard``.
