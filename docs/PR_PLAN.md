# First PR Plan

## PR 1: Backend foundation

- Add `core/opsgraph` package.
- Add SQL schema to Adaptix DB init path.
- Add models: Node, Edge, Evidence, ParseError, Delta, State.
- Add idempotent store contract.
- Add normalizer.
- Add parser contract and basic parsers.
- Add `/opsgraph/state` and `/opsgraph/search` handlers.

## PR 2: Passive ingestion

- Add agent metadata ingestion.
- Add task polling fallback every 10 seconds.
- Add cursor storage.
- Add parse error storage.
- Add delta generation.
- Add WebSocket sync packet category for `opsgraph.delta`.

## PR 3: Qt MVP tab

- Add `Operation Graph` tab.
- Load state.
- Apply deltas.
- Implement search, filter, evidence panel.
- Implement live on/off.

## PR 4: v1 parsers and path engine

- LDAP parser.
- AD-BOF parser.
- SAL/SAR parser.
- Credential parser.
- Session/logon parser.
- Trust parser.
- Evidence-only path to high-value nodes.
