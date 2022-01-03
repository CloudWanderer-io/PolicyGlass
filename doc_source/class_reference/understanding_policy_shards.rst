Understanding Policy Shards
==================================

Dedupe & Merge
--------------------

:class:`policyglass.policy_shard.PolicyShard` objects need to go through two phases to correct their sizes.

1. Dedupe using :func:`policyglass.policy_shard.dedupe_policy_shard_subsets`
2. Merge using :func:`policyglass.policy_shard.dedupe_policy_shards`

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
    >>> from policyglass.condition import Condition
    >>> from policyglass.policy_shard import dedupe_policy_shards
    >>> from policyglass.principal import EffectivePrincipal, Principal
    >>> from policyglass.resource import EffectiveResource, Resource
    >>> shard_a = PolicyShard(
    ...     effect="Allow",
    ...     effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset({Action("s3:PutObject")})),
    ...     effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
    ...     effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
    ...     conditions=FrozenConditionCollection(
    ...         {Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"])}
    ...     ),
    ...     not_conditions=FrozenConditionCollection(),
    ... )
    >>> shard_b = PolicyShard(
    ...     effect="Allow",
    ...     effective_action=EffectiveAction(inclusion=Action("s3:*"), exclusions=frozenset()),
    ...     effective_resource=EffectiveResource(inclusion=Resource("*"), exclusions=frozenset()),
    ...     effective_principal=EffectivePrincipal(inclusion=Principal(type="AWS", value="*"), exclusions=frozenset()),
    ...     conditions=FrozenConditionCollection(
    ...         {
    ...             Condition(key="aws:PrincipalOrgId", operator="StringNotEquals", values=["o-123456"]),
    ...             Condition(key="s3:x-amz-server-side-encryption", operator="StringEquals", values=["AES256"]),
    ...         }
    ...     ),
    ...     not_conditions=FrozenConditionCollection(),
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
