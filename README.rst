PolicyGlass
===========

.. |version|
   image:: https://img.shields.io/pypi/v/policyglass?style=flat-square
      :alt: PyPI
      :target: https://pypi.org/project/policyglass/

.. |checks|
   image:: https://img.shields.io/github/workflow/status/CloudWanderer-io/PolicyGlass/PolicyGlass%20Linting%20&%20Testing/main?style=flat-square
      :alt: GitHub Workflow Status (branch)
      :target: https://github.com/CloudWanderer-io/PolicyGlass/actions?query=branch%3Amain

.. |docs|
   image:: https://readthedocs.org/projects/cloudwanderer/badge/?version=latest&style=flat-square
      :target: https://www.cloudwanderer.io/en/latest/?badge=latest
      :alt: Documentation Status


.. image:: https://user-images.githubusercontent.com/803607/146429306-b132f7b2-79b9-44a0-a38d-f46127746c46.png

|version| |checks| |docs|

| **Documentation**: `policyglass.cloudwanderer.io <https://policyglass.cloudwanderer.io>`__
| **GitHub**: `https://github.com/CloudWanderer-io/PolicyGlass <https://github.com/CloudWanderer-io/PolicyGlass>`__

PolicyGlass allows you to combine multiple AWS IAM policies/statements into their 'effective permissions', deduplicating permissions, and eliminating denied permissions along the way.

PolicyGlass will **always** result in only allow ``PolicyShard`` objects, no matter how complex the policy. This makes understanding the effect of your policies programmatically a breeze.


Installation 
"""""""""""""""


.. code-block ::

   pip install policyglass


Usage
""""""""""""""""""""""""

Let's take two policies, *a* and *b* and pit them against each other.

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

Two policies, two statements, resulting in a single allow ``PolicyShard``.
More complex policies will result in multiple shards, but they will always be **allows**, no matter how complex the policy.
