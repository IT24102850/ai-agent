"""Merkle roots and inclusion proofs."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass

from .canonical import canonical_json


@dataclass(frozen=True)
class MerkleProof:
    index: int
    leaves_count: int
    siblings: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "leaves_count": self.leaves_count,
            "siblings": list(self.siblings),
        }


def leaf_hash(value) -> str:
    return hashlib.sha256(b"\x00" + canonical_json(value)).hexdigest()


def node_hash(left: str, right: str) -> str:
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def merkle_root(values: Iterable) -> str:
    level = [leaf_hash(value) for value in values]
    if not level:
        return hashlib.sha256(b"\x00").hexdigest()
    while len(level) > 1:
        next_level = []
        for index in range(0, len(level), 2):
            right = level[index + 1] if index + 1 < len(level) else level[index]
            next_level.append(node_hash(level[index], right))
        level = next_level
    return level[0]


def inclusion_proof(values: Iterable, index: int) -> MerkleProof:
    items = list(values)
    if index < 0 or index >= len(items):
        raise IndexError("Merkle leaf index out of range")

    level = [leaf_hash(value) for value in items]
    siblings: list[str] = []
    current = index
    while len(level) > 1:
        if current % 2 == 0:
            sibling_index = current + 1
            siblings.append(level[sibling_index] if sibling_index < len(level) else level[current])
        else:
            siblings.append(level[current - 1])
        next_level = []
        for offset in range(0, len(level), 2):
            right = level[offset + 1] if offset + 1 < len(level) else level[offset]
            next_level.append(node_hash(level[offset], right))
        level = next_level
        current //= 2
    return MerkleProof(index=index, leaves_count=len(items), siblings=tuple(siblings))


def verify_inclusion(value, proof: MerkleProof, root: str) -> bool:
    if proof.index < 0 or proof.leaves_count < 1:
        return False
    if proof.index >= proof.leaves_count:
        return False
    if len(proof.siblings) == 0:
        return proof.leaves_count == 1 and leaf_hash(value) == root
    current = leaf_hash(value)
    index = proof.index
    level_size = proof.leaves_count
    for sibling in proof.siblings:
        if len(sibling) != 64:
            return False
        current = node_hash(current, sibling) if index % 2 == 0 else node_hash(sibling, current)
        index //= 2
        level_size = (level_size + 1) // 2
    return current == root
