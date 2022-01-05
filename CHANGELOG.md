# 0.6.0

- Renamed `delineate_intersecting_shards` to `dedupe_policy_shards` to better reflect how people will use it.
- Added `explain_policy_shards` to eventually replace `explain` attribute on `PolicyShard` class entirely.
- Added `__contains__` to `EffectiveARP` classes
- Added `reverse` method to `Condition` to reverse the operator/value to reverse the effect of the condition.
- Added `EffectiveCondition` class to house `factory` method which normalisises `not_conditions` into `conditions` where possible. This may end up being a replacement for the `conditions` and `not_conditions` attributes on `PolicyShard`.
- Normlised `not_conditions` into `conditions` where possible upon instantiation of `PolicyShard`.

# 0.5.0

- Renamed `dedupe_policy_shards` to `dedupe_policy_shard_subsets` to differentiate it from `delineate_intersecting_shards`.
- Added `delineate_intersecting_shards` to reduce the size of `PolicyShard`s which have conditions whose ARPs intersect with ones without conditions.
    This helps clear up [#10](https://github.com/CloudWanderer-io/PolicyGlass/issues/10)
- Improved `issubset` on `PolicyShard` to recognise that a shard without conditions CANNOT be a subset of a shard with conditions.
- Added `<` and `>` to `PolicyShard`.
- Updated `difference` on `PolicyShard` so that it only adds `other`'s conditions to `self`'s not_conditions if self is allow and other is deny.
- Added documentation on how PolicyShard dedupe works
- Renamed `ConditionCollection` to `RawConditionCollection`
- Ensured that Conditions are always treated as a set not a list.
- Ensured that Condition's Operator, Key, Values are always of type ConditionOperator, ConditionKey and ConditionValue.
- Corrected bug in `CaseInsensitiveString` that caused it to generate case sensitive hashes.
- Added `dedupe_result` param to `difference` method on `PolicyShard` to allow merging of intersecting shards that are not subsets of one another.
- Added `intersection` to `PolicyShard`.
- Prevent attempting to calculate the difference between a Deny shard and an Allow shard. Other way makes sense as that's effective permission.
- Updated PolicyShard implementation to Support pydantic 1.9

# 0.4.7

- Fixed case insensitive `fnmatch` for resources
- Made it impossible to instantiate EffectiveARPs that have exclusions that are not proper subsets of their inclusions
- Ensured EffectiveARP's `intersection` filters out conditions from `other` that don't overlap `self` and vice versa when assembling new ARPs
- Added `Factory` method on EffectiveARP to faciltate creation of objects whose inclusions may overlap their inclusions (i.e. by returning `None`)
- Added `__lt__` and `__gt__` to EffectiveARP to represent proper subsets
- 

# 0.4.6

- Reverse order for second pass of dedupe to prevent failing to merge things due to sort order.
# 0.4.5

- Fixed PolicyShards with _additional_ conditions not being marked as subsets of shards that had a subset of those conditions
- Ensured that conditions are taken into effect properly for PolicyShard's `issubset`

# 0.4.4

- Fixed equal `EffectiveARPs` not being considerered subsets of each toher.
- Fixed PolicyShard's `difference` to consider `conditions` and `not_conditions` in whether the shards overlap wholly.
- Updated PolicyShard's `difference` to only add a `difference` shard if there _is_ in fact a difference.
- Updated PolicyShard's `difference` to add a `PolicyShard` that is identical to self with other's condition as a not_condition if the conditions are not equal.
- Updated Policyshard's `difference` to create every possible combination of `difference_<ARP>`, `self.effective_<ARP>` and `intersection_<ARP>` and then dedupe the results to accurately compute the difference. (The  test result of `difference/test_policyshard.py::deny_action_and_resource_subsets` is not how I would express it but is accurate.)
- Fixed PolicyShard equality not considering not_conditions
- EffectiveARP - If any of other's exclusions excludes something self DOESN'T then self is not a subset of other.
- EffectiveARP - Fixed `issubset` bug when self was excluded by other.
- Consider a `PolicyShard` that has a condition a subset of a `PolicyShard` that doesn't have a condition if all other signs point to it being a subset.

# 0.4.3

- Fixed bug causing `EffectiveARP` exclusions not to be honoured by `difference` methods.

# 0.4.2

- Fixed bug causing Condition Keys and Operators to be swapped.

# 0.4.1

- Improved formatting of `PolicyShard` explain.

# 0.4.0

 - Added `PolicyShard` explain.

# 0.3.0 

- Updated examples to be easier to read.
- Added `policy_shards_to_json`.
- Added `exclude_defults` to `EffectiveARP.dict()`.

# 0.2.1

- Added `not_conditions` into the repr for `PolicyShard`
- Added `not_conditions` into the simple diff scenario
- Added `conditions` into the complex diff scenario
- Added `not_action`, `not_resource`, and `not_principal` into `policy_shards` returned from `Statement`.
- Added `examples.rst`

# 0.2.0

 - First functional candidate

# 0.1.0

 - PyPi name placeholder.
