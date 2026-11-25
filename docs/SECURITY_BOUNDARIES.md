# Security and Safety Boundaries

OpsGraph is a passive awareness and reporting layer.

## Allowed

- Read existing agent metadata.
- Read existing completed task outputs.
- Read existing credential and target records.
- Parse observed facts.
- Store evidence.
- Visualize graph state.
- Search graph.
- Export evidence-backed graph data.

## Not allowed

- Creating new tasks.
- Running new commands.
- Automatic enumeration.
- Active scanning.
- Exploit automation.
- Payload generation.
- Evasion logic.
- Credential theft logic.
- Lateral movement automation.
- Guessing edges or fake paths.
