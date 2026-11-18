import copy

from hypothesis import given
from hypothesis import strategies as st

from agentblackbox import create_chain, verify_chain
from agentblackbox.hashchain import entry_hash, verify_chain_result


def test_chain_round_trip_and_tamper_detection():
    chain = create_chain([{"kind": "start", "tool": "shell"}, {"kind": "end"}])
    assert verify_chain(chain)
    tampered = copy.deepcopy(chain)
    tampered[1] = copy.deepcopy(tampered[1])
    object.__setattr__(tampered[1], "payload", {"kind": "changed"})
    assert not verify_chain(tampered)


def test_hash_fields_are_length_prefixed_and_context_bound():
    payload = {"value": "x"}
    first = entry_hash(1, payload, "a" * 64, session_id="ab", event_type="c")
    second = entry_hash(1, payload, "a" * 64, session_id="a", event_type="bc")
    assert first != second
    assert entry_hash(1, payload, "a" * 64, session_id="ab", event_type="c") == first


def test_verification_result_reports_first_broken_sequence():
    chain = create_chain([{"ok": True}, {"ok": True}])
    chain[1] = copy.deepcopy(chain[1])
    object.__setattr__(chain[1], "previous_hash", "f" * 64)
    result = verify_chain_result(chain)
    assert result.valid is False
    assert result.sequence == 1
    assert result.reason == "previous_hash_mismatch"


@given(st.lists(st.one_of(st.none(), st.booleans(), st.integers(), st.text()), max_size=50))
def test_chain_properties(payloads):
    chain = create_chain(payloads)
    assert verify_chain(chain)
    assert len(chain) == len(payloads)
