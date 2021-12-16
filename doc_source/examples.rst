Examples
============


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
   