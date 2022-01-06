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

Try it out
""""""""""""

.. image:: https://github.com/CloudWanderer-io/PolicyGlass/blob/dbc313d065247b557e36bfb8dc7ece2684a9cc81/doc_source/images/policyglass-sandbox.gif?raw=true
   :alt: PolicyGlass Sandbox screenshot
   :target: https://sandbox.policyglass.cloudwanderer.io
   :height: 25em

Try out custom policies quickly without installing anything with the `PolicyGlass Sandbox <https://sandbox.policyglass.cloudwanderer.io>`__.

Installation 
"""""""""""""""


.. code-block ::

   pip install policyglass


Usage
""""""""""""""""""""""""

Let's take two policies, *a* and *b* and pit them against each other.

.. doctest:: 

   >>> from policyglass import Policy, policy_shards_effect
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
   >>> effect = policy_shards_effect(policy_shards)
   >>> effect
   [PolicyShard(effect='Allow', 
      effective_action=EffectiveAction(inclusion=Action('s3:*'), 
         exclusions=frozenset()), 
      effective_resource=EffectiveResource(inclusion=Resource('*'), 
         exclusions=frozenset({Resource('arn:aws:s3:::examplebucket/*')})), 
      effective_principal=EffectivePrincipal(inclusion=Principal(type='AWS', value='*'), 
         exclusions=frozenset()), 
      effective_condition=EffectiveCondition(inclusions=frozenset(), exclusions=frozenset()))]

Two policies, two statements, resulting in a single allow ``PolicyShard``.
More complex policies will result in multiple shards, but they will always be **allows**, no matter how complex the policy.

You can also make them human readable!

.. doctest:: 

   >>> from policyglass import explain_policy_shards
   >>> explain_policy_shards(effect)
   ['Allow action s3:* on resource * (except for arn:aws:s3:::examplebucket/*) with principal AWS *.']
