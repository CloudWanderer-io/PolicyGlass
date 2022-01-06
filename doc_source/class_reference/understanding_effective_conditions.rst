Understanding Effective Conditions
===================================

Policy conditions, when they exist, are always restrictions on the scenarios in which a policy applies.
Every :class:`~policyglass.policy_shard.PolicyShard` object will have a :class:`~policyglass.condition.EffectiveCondition`
object, even if the :class:`~policyglass.condition.EffectiveCondition` has no ``inclusions`` or ``exclusions`` specified.

What is an inclusion/exclusion?
---------------------------------

An :class:`~policyglass.condition.EffectiveCondition` ``inclusion`` is a :class:`~policyglass.condition.Condition` which 
must be true, for a :class:`~policyglass.policy_shard.PolicyShard` to apply. 
An :class:`~policyglass.condition.EffectiveCondition` ``exclusion`` is a :class:`~policyglass.condition.Condition` which 
must be **false**, for a :class:`~policyglass.policy_shard.PolicyShard` to apply. 

.. doctest::

    >>> from policyglass import PolicyShard, EffectiveAction, Action, EffectiveResource, Resource, EffectivePrincipal, Principal, EffectiveCondition, Condition
    >>> effective_condition = EffectiveCondition(
    ...     inclusions=frozenset({
    ...         Condition("aws:PrincipalOrgId", "StringEquals", ["o-123456"]),
    ...     }), 
    ...     exclusions=frozenset({
    ...         Condition(key="TestKey", operator="BinaryEquals", values=["QmluYXJ5VmFsdWVJbkJhc2U2NA=="])
    ...    }),
    ... )
    >>> policy_shard = PolicyShard(
    ...     effect="Allow",
    ...     effective_action=EffectiveAction(Action("*")),
    ...     effective_resource=EffectiveResource(Resource("*")),
    ...     effective_principal=EffectivePrincipal(Principal("AWS", "*")),
    ...     effective_condition=effective_condition
    ... )

This ``effective_condition``'s ``inclusions`` dictate that for ``Action``, ``Resource`` and ``Principal`` to be allowed, then at the time the API call takes place the 
following be true:

#. ``aws:PrincipalOrgId`` must ``StringEquals`` a value of ``o-123456``.
#. ``TestKey`` must **NOT** ``BinaryEquals`` a value of ``QmluYXJ5VmFsdWVJbkJhc2U2NA==``

When would an exclusion occur?
--------------------------------

An :class:`~policyglass.condition.EffectiveCondition` ``exclusion`` is quite a rare phenomenon. 
Normally when ``Deny`` :class:`~policyglass.policy_shard.PolicyShard` conditions are folded into 
``Allow`` :class:`~policyglass.policy_shard.PolicyShard` objects, they are reversed using the 
:attr:`~policyglass.condition.Condition.reverse` attribute.  

For example ``StringNotEquals`` on a ``Deny`` PolicyShard will become ``StringEquals`` on an ``Allow`` PolicyShard.
This simplifies the intelligibility of the ``Allow`` shards significantly.

When a ``Deny`` statement has a condition that cannot be reversed (e.g. ``BinaryEquals`` for which there is no corresponding ``BinaryNotEquals``)
then the condition must be placed into the ``exclusions`` of the :attr:`~policyglass.policy_shard.PolicyShard.effective_condition` of the ``Allow`` PolicyShard.
