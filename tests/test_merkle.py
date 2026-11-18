from hypothesis import given
from hypothesis import strategies as st

from agentblackbox import inclusion_proof, merkle_root, verify_inclusion


def test_merkle_proofs_for_all_leaves_with_odd_tree():
    values = ["a", "b", "c", "d", "e"]
    root = merkle_root(values)
    for index, value in enumerate(values):
        proof = inclusion_proof(values, index)
        assert verify_inclusion(value, proof, root)
        assert not verify_inclusion("wrong", proof, root)


@given(st.lists(st.integers(), min_size=1, max_size=100))
def test_merkle_round_trip(values):
    root = merkle_root(values)
    for index, value in enumerate(values):
        assert verify_inclusion(value, inclusion_proof(values, index), root)
