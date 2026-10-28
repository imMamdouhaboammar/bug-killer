# Deep Analysis and Threat Intelligence

Bug Killer incorporates deep static analysis engines and multi-agent threat swarm orchestration.

External CLI scanners run as host child processes; callers must treat scanner binaries and arguments as trusted until a separate OS sandbox boundary is enforced.

## Tool Capability Broker

The broker provisions, schedules, and executes deep analysis tooling with deterministic receipts.

Requests via [[src/deep/broker.rs#BrokerExecutionRequest]] return [[src/deep/broker.rs#ToolExecutionReceipt]] records. Missing, unlicensed, and merely discovered tools never claim a successful execution.

The in-memory [[src/deep/broker.rs#ExecutionLedger]] digest covers receipt fields in order. Integrity checking requires a separately retained digest; there is no durable append log or authenticated signer.

## Sandboxed Tool Execution

The broker currently launches configured binaries directly, outside bubblewrap.

It hashes complete stdout and stderr streams without retaining raw output; filesystem, network, and environment restrictions still need enforced isolation.

## ThreatSwarm Multi-Agent Swarm

ThreatSwarm coordinates autonomous agent investigations across discovered threat surfaces.

Network boundaries and targets are constrained deterministically by [[src/deep/threatswarm.rs#ThreatswarmScopeEnforcer]] and analyzed via [[src/deep/threatswarm.rs#ThreatswarmAdapter]].
