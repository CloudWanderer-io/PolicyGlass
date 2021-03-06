Understanding Policy Shards
==================================

Dedupe & Merge
--------------------

:class:`~policyglass.policy_shard.PolicyShard` objects need to go through two phases to correct their sizes.

1. Dedupe using :func:`~policyglass.policy_shard.dedupe_policy_shard_subsets`
2. Merge using :func:`~policyglass.policy_shard.dedupe_policy_shards`

The first collapses all PolicyShards which are subsets of each other into each other, in other words eliminating 
all smaller PolicyShards that can fit into bigger PolicyShards.

The second reverses that where necessary, identifying shards that are not subsets of each other but nonetheless 
have some intersection and therefore duplicate the permissions space.

When does a PolicyShard intesect without being a subset?
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""

This is a departure from EffectiveARPs (Action, Resource, Principal) objects which by contrast cannot intersect without
being subsets. 

Let's consider this scenario

.. doctest:: 

    >>> from policyglass import PolicyShard
    >>> from policyglass.action import Action, EffectiveAction
    >>> from policyglass.condition import Condition, EffectiveCondition
    >>> from policyglass.principal import EffectivePrincipal, Principal
    >>> from policyglass.resource import EffectiveResource, Resource
    >>> shard_a = PolicyShard(
    ...     effect="Allow",
    ...     effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})),
    ...     effective_resource=EffectiveResource(inclusion=Resource("*")),
    ...     effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*")),
    ...     effective_condition=EffectiveCondition(frozenset(
    ...         {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
    ...     )),
    ... )
    >>> shard_b = PolicyShard(
    ...     effect="Allow",
    ...     effective_action=EffectiveAction(inclusion=Action("s3:*")),
    ...     effective_resource=EffectiveResource(inclusion=Resource("*")),
    ...     effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*")),
    ...     effective_condition=EffectiveCondition(frozenset(
    ...         {
    ...             Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"]),
    ...             Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
    ...         }
    ...     )),
    ... )

Shard A
    #. Has a single condition
    #. Excludes ``s3:PutObject``

Shard B
    #. Has two conditions, one of which is the same as Shard A
    #. Does not exclude ``s3:PutObject``

This means that.

#. Because Shard A and Shard B both have conditions they can never be considered subsets of one another even during the decomposition process
#. They do intersect because every part of ``s3:*`` apart from ``s3:PutObject`` is less restrictively allowed by Shard A
#. We want to reduce the scope of Shard B to just ``s3:PutObject``

To do this we use :func:`~policyglass.policy_shard.dedupe_policy_shards`

.. doctest:: 

    >>> from policyglass.policy_shard import dedupe_policy_shards
    >>> shard_b_delineated, shard_a_delineated = dedupe_policy_shards([shard_a, shard_b])
    >>> assert shard_a_delineated == PolicyShard(
    ...     effect='Allow', 
    ...     effective_action=EffectiveAction(inclusion=Action('s3:*'), exclusions=frozenset({Action('s3:PutObject')})), 
    ...     effective_resource=EffectiveResource(inclusion=Resource('*')),
    ...     effective_principal=EffectivePrincipal(inclusion=Principal(type='AWS', value='*')), 
    ...     effective_condition=EffectiveCondition(frozenset(
    ...         {Condition(key='aws:PrincipalOrgId', operator='StringNotEquals', values=['o-123456'])}
    ...     )), 
    ... )
    >>> assert shard_b_delineated == PolicyShard(
    ...    effect='Allow', 
    ...    effective_action=EffectiveAction(inclusion=Action('s3:PutObject')), 
    ...    effective_resource=EffectiveResource(inclusion=Resource('*')), 
    ...    effective_principal=EffectivePrincipal(inclusion=Principal(type='AWS', value='*')), 
    ...    effective_condition=EffectiveCondition(frozenset({
    ...        Condition(key='aws:PrincipalOrgId', operator='StringNotEquals', values=['o-123456']),
    ...        Condition(key='s3:x-amz-server-side-encryption', operator='StringEquals', values=['AES256'])
    ...    })), 
    ... )

You'll notice that the intersection has been removed, as Shard B now only has ``s3:PutObject`` as the rest of ``s3:*`` was covered by Shard A.
