# import pytest

# from policyglass import Principal, EffectivePrincipal


# def test_bad_difference():
#     with pytest.raises(ValueError) as ex:
#         EffectivePrincipal(Principal({"AWS": ["S3:*"]})).difference(Principal({"AWS": ["S3:*"]}))

#     assert "Cannot union EffectivePrincipal with Principal" in str(ex.value)


# DIFFERENCE_SCENARIOS = {
#     "proper_subset": {
#         "first": EffectivePrincipal(Principal({"AWS": ["S3:*"]})),
#         "second": EffectivePrincipal(Principal({"AWS": ["S3:get*"]})),
#         "result": [EffectivePrincipal(Principal({"AWS": ["S3:*"]}), frozenset({Principal({"AWS": ["S3:get*"]})}))],
#     },
#     "proper_subset_with_exclusions": {
#         "first": EffectivePrincipal(Principal({"AWS": ["S3:*"]})),
#         "second": EffectivePrincipal(
#             Principal({"AWS": ["S3:get*"]}), frozenset({Principal({"AWS": ["S3:GetObject"]})})
#         ),
#         "result": [
#             EffectivePrincipal(Principal({"AWS": ["S3:*"]}), frozenset({Principal({"AWS": ["S3:get*"]})})),
#             EffectivePrincipal(Principal({"AWS": ["S3:GetObject"]})),
#         ],
#     },
#     "excluded_proper_subset": {
#         "first": EffectivePrincipal(Principal({"AWS": ["S3:*"]}), frozenset({Principal({"AWS": ["S3:get*"]})})),
#         "second": EffectivePrincipal(Principal({"AWS": ["S3:get*"]})),
#         "result": [EffectivePrincipal(Principal({"AWS": ["S3:*"]}), frozenset({Principal({"AWS": ["S3:get*"]})}))],
#     },
#     "subset": {
#         "first": EffectivePrincipal(Principal({"AWS": ["S3:*"]})),
#         "second": EffectivePrincipal(Principal({"AWS": ["S3:*"]})),
#         "result": [],
#     },
#     "no_intersection": {
#         "first": EffectivePrincipal(Principal({"AWS": ["S3:*"]})),
#         "second": EffectivePrincipal(Principal({"AWS": ["EC2:*"]})),
#         "result": [EffectivePrincipal(Principal({"AWS": ["S3:*"]}))],
#     },
# }


# @pytest.mark.parametrize("_, scenario", DIFFERENCE_SCENARIOS.items())
# def test_difference(_, scenario):
#     first, second, result = scenario.values()
#     assert first.difference(second) == result


# def test_difference_disjoint():

#     assert EffectivePrincipal(Principal({"AWS": ["S3:*"]})).difference(
#         EffectivePrincipal(Principal({"AWS": ["EC2:*"]}))
#     ) == [EffectivePrincipal(Principal({"AWS": ["S3:*"]}))]
