import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentblackbox import canonical_json, sha256_json


def test_key_and_unicode_are_deterministic():
    value = {"z": "é", "a": [2, 1]}
    assert canonical_json(value) == b'{"a":[2,1],"z":"\xc3\xa9"}'
    assert sha256_json(value) == sha256_json({"a": [2, 1], "z": "é"})


def test_rejects_nan_and_infinity():
    for value in (math.nan, math.inf, -math.inf):
        with pytest.raises(ValueError):
            canonical_json(value)


def test_normalizes_unicode_rejects_surrogates_and_stringifies_large_integers():
    assert canonical_json({"value": "e\u0301"}) == canonical_json({"value": "é"})
    assert canonical_json(2**53 + 1) == b'"9007199254740993"'
    with pytest.raises(ValueError):
        canonical_json("\ud800")


@given(
    st.dictionaries(
        st.text(min_size=1, max_size=20),
        st.one_of(st.none(), st.booleans(), st.integers(), st.text()),
        max_size=20,
    )
)
def test_canonical_json_is_repeatable(value):
    assert canonical_json(value) == canonical_json(dict(reversed(list(value.items()))))
