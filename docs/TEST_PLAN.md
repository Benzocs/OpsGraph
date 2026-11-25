# OpsGraph Test Plan

## Unit tests

- Stable ID generation.
- Domain/user/computer normalization.
- Node upsert idempotency.
- Edge upsert idempotency.
- Evidence append and linking.
- Parser golden input/output samples.
- Host state transitions.
- Trust direction property preservation.
- Pathfinding over observed edges only.

## Integration tests

- Empty DB initializes without breaking Teamserver.
- Agent metadata creates Agent/Computer/User/Domain graph.
- Completed task is parsed once.
- Rebuild processes historical tasks.
- Delta endpoint returns only changed objects.
- UI loads state and applies delta.

## Safety tests

- OpsGraph code does not call task creation routes.
- OpsGraph code does not execute commands.
- Export redacts sensitive evidence by default.
- Parser errors do not crash Teamserver or client.
