# 0.4.5

- Fixed equal `EffectiveARPs` not being considerered subsets of each toher.
- Fixed PolicyShard's `difference` to consider `conditions` and `not_conditions` in whether the shards overlap wholly.
- Updated PolicyShard's `difference` to only add a `difference` shard if there _is_ in fact a difference.
- Updated PolicyShard's `difference` to add a `PolicyShard` that is identical to self with other's condition as a not_condition if the conditions are not equal.
- Fixed PolicyShard equality not considering not_conditions

# 0.4.4

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
