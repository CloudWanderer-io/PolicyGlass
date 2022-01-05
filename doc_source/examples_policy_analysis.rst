Examples of Policy Analysis
=============================

Example Policy
---------------------

Let's use a complex IAM policy as our example to demonstrate the value in analyzing policies with PolicyGlas.

.. doctest:: 

    >>> from policyglass import Policy
    >>> test_policy = Policy(**{
    ...   "Version": "2012-10-17",
    ...   "Statement": [
    ...     {
    ...       "Effect": "Allow",
    ...       "Action": [
    ...         "s3:*"
    ...       ],
    ...       "Resource": "*",
    ...       "Condition": {
    ...         "NumericLessThan": {
    ...             "s3:TlsVersion": 1.2
    ...         }
    ...       }
    ...     },
    ...     {
    ...       "Effect": "Allow",
    ...       "Action": [
    ...         "s3:*"
    ...       ],
    ...       "Resource": "arn:aws:s3:::examplebucket/*"
    ...     },
    ...     {
    ...       "Effect": "Deny",
    ...       "Action": [
    ...         "s3:PutObject"
    ...       ],
    ...       "NotResource": "arn:aws:s3:::examplebucket/*",
    ...       "Condition": {
    ...         "StringNotEquals": {
    ...           "s3:x-amz-server-side-encryption": "AES256"
    ...         }
    ...       }
    ...     }
    ...   ]
    ... })

Understanding a Policy
""""""""""""""""""""""""""

To understand the policy, let's get the :meth:`~policyglass.policy_shard.policy_shards_effect` then use the :meth:`~policyglass.policy_shard.explain_policy_shards` method to explain them.

.. doctest:: 

    >>> from policyglass import policy_shards_effect, explain_policy_shards
    >>> test_policy_shards = policy_shards_effect(test_policy.policy_shards)
    >>> explain_policy_shards(test_policy_shards)
    ["Allow action s3:PutObject on resource * (except for arn:aws:s3:::examplebucket/*) with principal AWS *. 
        Provided conditions s3:TlsVersion NumericLessThan ['1.2'] and 
            s3:x-amz-server-side-encryption StringEquals ['AES256'] are met.", 
    "Allow action s3:* (except for s3:PutObject) on resource * with principal AWS *. 
        Provided conditions s3:TlsVersion NumericLessThan ['1.2'] are met.", 
    'Allow action s3:PutObject on resource arn:aws:s3:::examplebucket/* with principal AWS *.']

That helps clarify what the policy results in for humans. But what if we want to programatically ask a question about what this allows?

Interrogating a Policy
""""""""""""""""""""""""""""

Question:
    Is ``s3:PutObject`` allowed on  ``arn:aws:s3:::some-other-bucket/*``?

To answer this we need to check 2 things:

#. Is ``s3:PutObject`` allowed on the shard?
#. If so, is ``resource arn:aws:s3:::examplebucket/*`` allowed on the same shard?

As we have multiple (3) shards we have to make sure both of the answers are true for the same shard.

We can do this with a list comprehension

.. doctest:: 

    >>> from policyglass import (
    ...     Action,
    ...     Resource,
    ...     Principal,
    ...     PolicyShard,
    ...     EffectiveAction,
    ...     EffectiveResource,
    ...     EffectivePrincipal,
    ...     Condition
    ... )
    >>> action = Action('s3:PutObject')
    >>> resource = Resource('arn:aws:s3:::some-other-bucket/*')
    >>> result = [
    ...     shard 
    ...     for shard in test_policy_shards
    ...     if action in shard.effective_action
    ...     and resource in shard.effective_resource
    ... ]
    >>> result # doctest: +SKIP
    [PolicyShard(effect='Allow', 
        effective_action=EffectiveAction(inclusion=Action('s3:PutObject'), exclusions=frozenset()), 
        effective_resource=EffectiveResource(inclusion=Resource('*'), exclusions=frozenset({Resource('arn:aws:s3:::examplebucket/*')})), 
        effective_principal=EffectivePrincipal(inclusion=Principal(type='AWS', value='*'), exclusions=frozenset()), 
        conditions=frozenset({Condition(key='s3:x-amz-server-side-encryption', operator='StringEquals', values=['AES256']), 
            Condition(key='s3:TlsVersion', operator='NumericLessThan', values=['1.2'])}), 
        not_conditions=frozenset())]

.. doctest::
    :hide:

    >>> assert result == [PolicyShard(effect='Allow', 
    ... effective_action=EffectiveAction(inclusion=Action('s3:PutObject'), exclusions=frozenset()), 
    ... effective_resource=EffectiveResource(inclusion=Resource('*'), exclusions=frozenset({Resource('arn:aws:s3:::examplebucket/*')})), 
    ... effective_principal=EffectivePrincipal(inclusion=Principal(type='AWS', value='*'), exclusions=frozenset()), 
    ... conditions=frozenset({Condition(key='s3:x-amz-server-side-encryption', operator='StringEquals', values=['AES256']), 
    ...     Condition(key='s3:TlsVersion', operator='NumericLessThan', values=['1.2'])}), 
    ... not_conditions=frozenset())]

From this check we can see that it is allowed by at least one shard! **But** there are two conditions.

Checking if Conditions exist
""""""""""""""""""""""""""""""""
Whether we want to check these conditions depends on what kind of question we want to ask. 
Either way it's trivial to check if a condition exists or not.

.. doctest::

    >>> bool(result[0].conditions)
    True
    >>> bool(result[0].not_conditions)
    False
    
.. tip::

    You'll find that ``not_conditions`` are quite rare, as most condition operators can be flipped into ``conditions``.
    Check the :attr:`~policyglass.condition.OPERATOR_REVERSAL_INDEX` for a full list of operators that can be converted.
