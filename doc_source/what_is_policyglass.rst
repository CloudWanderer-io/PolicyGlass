What is PolicyGlass?
======================

PolicyGlass is an effective permission parser for AWS Policies. It takes normal JSON policies of any type 
(Principal, Resource, or Endpoint) and converts them into :class:`~policyglass.policy_shard.PolicyShard` objects
that are *always* assertions about what is allowed.

Use Cases
----------

There are two main use cases for this tool:

#. Writing tools that audit the permissions provided to AWS resources/principals
#. Validating your understanding of the complex policy you're writing. 


Why do I need PolicyGlass?
--------------------------------------

Isn't this a simple problem? I can just check actions and resources in each statement, boom, done.

Understanding AWS policies programmatically is harder than it looks.

You can write code easily enough to check what resources and actions are in each statement, 
and that might seem like enough. But what happens when you throw a ``Deny`` statement into the mix?
Well that's okay, you just check each statement to see if it's an allow or a deny and if it's a deny
then you just remove any resources from the allow that exist in the deny right?
Easy enough, but what about resources that are just ``*`` or are ARNs with wildcards in them?
Once you've got past that, you have to deal with statements that contain negations 
(``NotAction``, ``NotResource``, and ``NotPrincipal``), it's starting to get harder.
Then you have to add in the complexity of conditions, and all this is without even mentioning the complexity
of parsing an AWS Policy in the first place with the variants of ``Actions`` as a list or as a string, or 
``Resources`` that may be a string or a dictionary.

PolicyGlass takes care of all this for you by breaking down a policy into its components and applying set
operations in order to build shards that describe the effective permissions.
