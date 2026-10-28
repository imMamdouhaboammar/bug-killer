# Deep Analysis and Threat Intelligence

Bug Killer incorporates deep static analysis engines and multi-agent threat swarm orchestration.

External deep analysis tools run in strictly isolated sandboxes to prevent untrusted code execution.

## Tool Capability Broker

The broker provisions, schedules, and executes deep analysis tooling with deterministic receipts.

Requests are structured via [[src/deep/broker.rs#BrokerExecutionRequest]] and evaluated through [[src/deep/broker.rs#ToolCapabilityBroker]], returning verifiable [[src/deep/broker.rs#ToolExecutionReceipt]] records.

## Sandboxed Tool Execution

Deep tools like CodeQL, Semgrep, and Joern execute within unprivileged bubblewrap sandbox boundaries.

Sandboxing restricts network access, filesystem visibility, and kernel capabilities to prevent escape.

## ThreatSwarm Multi-Agent Swarm

ThreatSwarm coordinates autonomous agent investigations across discovered threat surfaces.

Network boundaries and targets are constrained deterministically by [[src/deep/threatswarm.rs#ThreatswarmScopeEnforcer]] and analyzed via [[src/deep/threatswarm.rs#ThreatswarmAdapter]].
