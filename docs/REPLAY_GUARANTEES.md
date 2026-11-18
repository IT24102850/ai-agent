# Replay Guarantees

## Determinism

The first slice can deterministically canonicalize supported JSON values,
recompute ordered chain entries, calculate Merkle roots, verify inclusion
proofs, produce stable structured diffs, and evaluate policy expressions.

## Replay assumptions

Replay is valid only when the caller also reproduces the exact rule set, policy
expression, context values, hash format version, and payload bytes. Python
floating-point values are normalized as JSON numbers only when finite; callers
should preserve numeric types and avoid NaN/infinity.

## Explicit non-guarantees

AgentBlackbox does not capture wall-clock nondeterminism, model provider
responses, tool side effects, random seeds, dependency versions, container
state, network state, or private runtime configuration. A future replay system
must record those inputs and their checksums separately.

## Tool replay (bounded slice)

The SDK can replay recorded `tool.call` results without calling the decorated
function. It matches the tool name, call position, positional arguments, and
keyword arguments. A missing recording or argument mismatch raises
`ReplayDivergence`; callers may enable `collect_replay_divergences=True` to
continue and inspect the collected records.

This guarantee covers only the recorded tool result and call inputs. It does
not replay filesystem, network, process, clock, random, or provider state.

Replay and candidate execution expose an explicit `Sandbox`/`ReplaySandbox`
interface that denies network access, credentials, processes, and real tool
calls. Candidate test runs perform only local diff/policy evaluation; they do
not execute candidate tools. This repository does not claim a container,
microVM, or OS sandbox unless a deployment supplies and validates one.
