# Adaptix OpsGraph Starter Kit

Passive, live, evidence-based operation graph scaffolding for AdaptixC2.

This starter kit is designed as a PR-ready architectural skeleton, not a drop-in patch. It intentionally avoids new enumeration, exploitation, payload, evasion, credential theft, lateral movement, or stealth logic. It only models facts already present in Adaptix data sources such as agents, completed task output, credentials, targets, and teamserver events.

## What is included

```text
server/core/opsgraph/         Go service, models, parser router, store contract, path engine
server/core/database/         SQL schema proposal for existing SQLite DBMS
server/core/connector/        REST handler skeleton for /opsgraph/*
server/core/server/           Teamserver lifecycle integration notes and sync skeleton
client/Headers/UI/OpsGraph/   Qt C++ UI headers
client/Source/UI/OpsGraph/    Qt C++ UI source skeleton
docs/                         PR plan, API schema, test plan, UI visual identity
```

## Integration philosophy

1. Add `core/opsgraph` as an internal Teamserver service.
2. Store graph data in Adaptix existing SQLite DBMS.
3. Publish graph deltas through Adaptix existing realtime sync model.
4. Add a new `Operation Graph` tab in the Qt client.
5. Keep evidence references on every node and edge.
6. Do not create guessed attack paths.

## MVP scope

- Ingest agent metadata.
- Ingest completed task outputs passively.
- Parse basic identity/computer/domain context.
- Create Agent, Computer, User, Domain nodes.
- Create RunningOn, RunningAs, InDomain edges.
- Attach evidence.
- Poll every 10 seconds as fallback.
- Show graph/search/filter/evidence panel in Qt.

## Safety boundary

OpsGraph is a read-only awareness and reporting layer. It must not create tasks, run commands, perform collection, or automate exploitation.
