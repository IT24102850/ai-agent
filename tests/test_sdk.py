import pytest
from agentblackbox_sdk import Recorder, ReplayDivergence, ReplayGuardError, tool


def test_replay_guard_never_executes_uncaptured_or_captured_tool():
    calls = []

    @tool(recorder=None)
    def ordinary(value):
        calls.append(value)
        return value * 2

    assert ordinary(3) == 6

    replay = Recorder(
        replay=True,
        recorded_events=[{"payload": {"data": {"tool_name": "captured", "result": 42}}}],
    )

    @tool(recorder=replay, name="captured")
    def captured():
        raise AssertionError("real tool must not execute during replay")

    assert captured() == 42

    @tool(recorder=replay, name="uncaptured")
    def uncaptured():
        raise AssertionError("real tool must not execute during replay")

    with pytest.raises(ReplayGuardError):
        uncaptured()


def test_replay_collects_argument_divergence():
    replay = Recorder(
        replay=True,
        recorded_events=[
            {
                "payload": {
                    "data": {
                        "tool_name": "lookup",
                        "args": [7],
                        "kwargs": {"region": "west"},
                        "result": "old",
                    }
                }
            }
        ],
        collect_replay_divergences=True,
    )

    @tool(recorder=replay, name="lookup")
    def lookup(value, region):
        raise AssertionError("must not execute")

    assert lookup(8, region="east") is None
    assert replay.replay_divergences[0]["kind"] == "arguments_mismatch"


def test_replay_argument_divergence_is_replay_divergence():
    replay = Recorder(
        replay=True,
        recorded_events=[
            {
                "payload": {
                    "data": {
                        "tool_name": "lookup",
                        "args": [7],
                        "kwargs": {},
                        "result": "old",
                    }
                }
            }
        ],
    )

    @tool(recorder=replay, name="lookup")
    def lookup(value):
        raise AssertionError("must not execute")

    with pytest.raises(ReplayDivergence):
        lookup(8)
