# 0.5.0 

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
