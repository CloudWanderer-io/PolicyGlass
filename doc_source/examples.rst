Examples
============

Below you can find some examples on how PolicyGlass can be used to understand complex policies in a consistent way.

Simple
-----------

.. doctest:: 

   >>> from policyglass import Policy, dedupe_policy_shards, policy_shards_effect
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
   >>> policy_shards = [*policy_a.policy_shards, *policy_b.policy_shards]
   >>> print(policy_shards_effect(policy_shards))
   [PolicyShard(effect='Allow', 
      effective_action=EffectiveAction(inclusion=Action('s3:*'), 
         exclusions=frozenset()), 
      effective_resource=EffectiveResource(inclusion=Resource('*'), 
         exclusions=frozenset({Resource('arn:aws:s3:::examplebucket/*')})), 
      effective_principal=EffectivePrincipal(inclusion=Principal(type='AWS', value='*'), 
         exclusions=frozenset()), 
      conditions=frozenset(),
      not_conditions=frozenset())]

PolicyShard #1 tells us:
   #. `s3:*` is allowed for all resources **except** ``arn:aws:s3:::examplebucket/*``

What occurred:
   #. The ``resource`` from the deny was added to the allow's ``EffectiveResource``'s ``exclusions``

De-duplicate
-------------

.. doctest:: 

   >>> from policyglass import Policy, dedupe_policy_shards
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
   >>> policy_shards = [*policy_a.policy_shards, *policy_b.policy_shards]
   >>> print(dedupe_policy_shards(policy_shards))
   [PolicyShard(effect='Allow', 
      effective_action=EffectiveAction(inclusion=Action('s3:*'), 
         exclusions=frozenset()), 
      effective_resource=EffectiveResource(inclusion=Resource('*'), 
         exclusions=frozenset()), 
      effective_principal=EffectivePrincipal(inclusion=Principal(type='AWS', value='*'), 
         exclusions=frozenset()), 
      conditions=frozenset(),
      not_conditions=frozenset())]

PolicyShard 1 tells us:
   #. ``s3:*`` is allowed on all resources.

What occurred:
   #. One of the two ``s3:*`` policy shards was removed because it was a duplicate.

Complex Single Policy
--------------------------
.. doctest:: 

   >>> from policyglass import Policy, dedupe_policy_shards, policy_shards_effect
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
   ...                 "s3:PutObject",
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
   >>> deduped_shards = dedupe_policy_shards(policy_a.policy_shards)
   >>> print(policy_shards_effect(deduped_shards))
   [PolicyShard(effect='Allow', 
      effective_action=EffectiveAction(inclusion=Action('s3:*'), 
         exclusions=frozenset({Action('s3:PutObject')})), 
      effective_resource=EffectiveResource(inclusion=Resource('*'), 
         exclusions=frozenset()), 
      effective_principal=EffectivePrincipal(inclusion=Principal(type='AWS', value='*'), 
         exclusions=frozenset()), 
      conditions=frozenset(), 
      not_conditions=frozenset()), 
   PolicyShard(effect='Allow', 
      effective_action=EffectiveAction(inclusion=Action('s3:PutObject'), 
         exclusions=frozenset()), 
      effective_resource=EffectiveResource(inclusion=Resource('*'), 
         exclusions=frozenset({Resource('arn:aws:s3:::examplebucket/*')})), 
      effective_principal=EffectivePrincipal(inclusion=Principal(type='AWS', value='*'),
         exclusions=frozenset()),
      conditions=frozenset(),
      not_conditions=frozenset({Condition(key='StringNotEquals', operator='s3:x-amz-server-side-encryption', values=['AES256'])}))]
   
The output has two policy shards.

PolicyShard #1 tells us:
   #. Allow ``s3:*`` except for ``s3:PutObject`` 
   #. On **all** resources.
   #. No conditions

PolicyShard #2 tells us:
   #. Allow ``s3:PutObject`` 
   #. On all resources **except** ``arn:aws:s3:::examplebucket/*``
   #. *except* If the condition applies.

What occurred:
   #. ``s3:GetObject`` was removed from the allow because it was totally within ``s3:*``
   #. ``s3:PutObject`` was added to the ``EffectiveAction``'s ``exclusions`` so it could be split out into a second ``PolicyShard``.
   #. A new ``PolicyShard`` was created with ``s3:PutObject``
   #. The deny's ``condition`` became a ``not_condition`` on the new ``PolicyShard``.
