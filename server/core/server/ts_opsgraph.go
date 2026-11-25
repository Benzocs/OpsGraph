package server

// Teamserver integration skeleton:
//
// 1. Add field to Teamserver struct:
//      OpsGraph *opsgraph.Service
//
// 2. In NewTeamserver, after DBMS/TaskManager/MessageBroker initialization:
//      ts.OpsGraph = opsgraph.NewService(opsStore, taskSource, opsDeltaPublisher)
//
// 3. In Start(), after restore/sync components are ready:
//      _ = ts.OpsGraph.Start(context.Background())
//
// 4. Publish delta through MessageBroker using existing sync packet conventions:
//      ts.TsSyncAllClients("opsgraph.delta", delta)
//
// 5. Hook passive events only:
//      task completed -> ProcessTask
//      agent create/update/tick -> IngestAgentSnapshot
//      credential added -> passive credential graph relation
//      target added/updated -> passive target graph relation
//
// No task creation, no command execution, no collection logic.
