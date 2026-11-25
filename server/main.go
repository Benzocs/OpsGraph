package main

import (
    "context"
    "log"
    "net/http"
    "os"

    "opsgraph/server/core/connector"
    "opsgraph/server/core/database"
    "opsgraph/server/core/opsgraph"
)

type noopTaskSource struct{}

func (noopTaskSource) CompletedTasksSince(ctx context.Context, cursor string) ([]opsgraph.TaskSnapshot, string, error) {
    return nil, cursor, nil
}

type noopPublisher struct{}

func (noopPublisher) PublishOpsGraphDelta(delta opsgraph.Delta) {}

func main() {
    dbPath := envOr("OPSGRAPH_DB", "./opsgraph.db")
    addr := envOr("OPSGRAPH_ADDR", ":8081")

    store, err := database.NewSQLiteStore(dbPath)
    if err != nil {
        log.Fatalf("store: %v", err)
    }

    svc := opsgraph.NewService(store, noopTaskSource{}, noopPublisher{})
    if err := svc.Start(context.Background()); err != nil {
        log.Fatalf("service: %v", err)
    }
    defer svc.Stop()

    router := connector.NewRouter(svc)
    log.Printf("[opsgraph] :%s db=%s", addr, dbPath)
    log.Fatal(http.ListenAndServe(addr, router))
}

func envOr(k, d string) string {
    if v := os.Getenv(k); v != "" {
        return v
    }
    return d
}
