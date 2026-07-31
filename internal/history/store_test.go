package history

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(context.Background(), filepath.Join(parent, "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return store
}

func TestOpenCreatesProtectedMigratedDatabase(t *testing.T) {
	store := openTestStore(t)
	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("database permissions = %04o, want 0600", got)
	}
	var version int
	if err := store.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != currentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, currentSchemaVersion)
	}
	for _, table := range []string{
		"projects", "scan_runs", "dependency_state", "dependency_version_events",
		"update_jobs", "operations", "operation_events", "notification_outbox",
		"approval_requests", "operator_commands", "schema_migrations",
		"deployment_contracts", "deployment_releases",
	} {
		var count int
		if err := store.db.QueryRow(
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("table %s was not migrated", table)
		}
	}
}

func TestOpenRejectsBroadExistingPermissions(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), filepath.Join(parent, "history.db"))
	if err == nil {
		t.Fatal("Open accepted broad directory permissions")
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	store := openTestStore(t)
	path := store.Path()
	if _, err := store.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", currentSchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store.db = nil
	if _, err := Open(context.Background(), path); err == nil {
		t.Fatal("Open accepted a newer schema")
	}
}

func TestDeploymentContractAndTransitionsAreDurableAndAtomic(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 30, 13, 0, 0, 0, time.UTC)
	contract := DeploymentContract{
		ProjectName: "api", ProjectRoot: "/projects/api",
		Fingerprint: "contract-one", Repository: "example/api", Branch: "main",
		Commit:       "0123456789abcdef0123456789abcdef01234567",
		ComposeFiles: []string{"compose.yml", "compose.prod.yml"},
		Services:     []string{"api", "worker"}, TrafficService: "api",
		StableUpstream: "api", InternalPort: 8000,
		MigrationPaths: []string{"alembic/versions"}, Status: "ready",
		DiscoveredAt: now, UpdatedAt: now,
	}
	if err := store.RecordDeploymentContract(ctx, contract); err != nil {
		t.Fatal(err)
	}
	contracts, err := store.DeploymentContracts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(contracts) != 1 || contracts[0].Fingerprint != contract.Fingerprint {
		t.Fatalf("contracts = %#v", contracts)
	}

	release, err := store.CreateDeploymentRelease(ctx, DeploymentRelease{
		ProjectName: "api", ProjectRoot: "/projects/api",
		ReleaseRepository: "example/vuelta-control", ReleaseWorkflow: "release.yml",
		SourceRepository: "example/api",
		SourceCommit:     "0123456789abcdef0123456789abcdef01234567",
		ImageRepository:  "ghcr.io/example/api", ContractFingerprint: "contract-one",
		State: "discovered", RequestedAt: now, UpdatedAt: now,
	}, OperationEvent{
		Type: "release_discovered", Summary: "api release discovered",
		IdempotencyKey: "release-discovered", Notify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	release.State = "building"
	release.GitHubRunID = 42
	release.RunURL = "https://github.com/example/vuelta-control/actions/runs/42"
	release.UpdatedAt = now.Add(time.Minute)
	event := OperationEvent{
		Type: "release_building", Summary: "api release building",
		IdempotencyKey: "release-building", Notify: true,
	}
	for range 2 {
		if err := store.TransitionDeploymentRelease(ctx, release, event); err != nil {
			t.Fatal(err)
		}
	}
	releases, err := store.DeploymentReleases(ctx, "api", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(releases) != 1 || releases[0].State != "building" || releases[0].GitHubRunID != 42 {
		t.Fatalf("releases = %#v", releases)
	}
	var events, outbox int
	if err := store.db.QueryRow(
		"SELECT COUNT(*) FROM operation_events WHERE operation_id=?", release.OperationID,
	).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(
		`SELECT COUNT(*) FROM notification_outbox o
		 JOIN operation_events e ON e.id=o.event_id WHERE e.operation_id=?`,
		release.OperationID,
	).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if events != 2 || outbox != 2 {
		t.Fatalf("deployment events=%d outbox=%d, want 2/2", events, outbox)
	}
}

func TestApprovalIsExactExpiringAndOneTime(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 30, 15, 0, 0, 0, time.UTC)
	operationID, err := store.RecordOperation(ctx, Operation{
		ID: "deploy-approval-operation", Kind: "deploy", Status: "blocked", At: now,
		Event: OperationEvent{
			Type: "deploy_blocked", Summary: "deploy blocked",
			IdempotencyKey: "deploy-blocked",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := store.CreateApprovalRequest(ctx, ApprovalRequest{
		OperationID: operationID, Type: "migration",
		SubjectFingerprint: "exact-project-commit-digest-migrations",
		SubjectSummary:     `{"project":"api","commit":"0123456789abcdef0123456789abcdef01234567"}`,
		CreatedAt:          now, ExpiresAt: now.Add(time.Hour),
	}, OperationEvent{
		Type: "migration_approval_required", Summary: "api migration approval required",
		IdempotencyKey: "migration-approval", Notify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DecideApproval(ctx, request.ID, "approved", "operator:1", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.DecideApproval(ctx, request.ID, "approved", "operator:1", now.Add(2*time.Minute)); err == nil {
		t.Fatal("approval decision was accepted twice")
	}
	approved, err := store.ApprovalByFingerprint(
		ctx, operationID, "migration", request.SubjectFingerprint, now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if approved == nil || approved.Status != "approved" || approved.DecisionIdentity != "operator:1" {
		t.Fatalf("approval = %#v", approved)
	}
}

func TestRecordScanDeduplicatesStateAndRecordsOnlyChanges(t *testing.T) {
	store := openTestStore(t)
	base := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	record := ScanRecord{
		ID: "scan-one", ProjectName: "api", ProjectRoot: "/projects/api",
		BaseCommit: "0123456789abcdef", Status: "succeeded",
		StartedAt: base, CompletedAt: base.Add(time.Minute),
		Dependencies: []DependencyObservation{{
			Ecosystem: "npm", Name: "example", Direct: true,
			DeclaredVersion: "^1.0.0", ResolvedVersion: "1.0.0", NewestStable: "1.1.0",
			FirstObservedAt: base, EligibleAt: base.Add(14 * 24 * time.Hour),
			VersionClass: "minor", Disposition: "deferred",
		}},
	}
	if err := store.RecordScan(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	record.ID = "scan-two"
	record.StartedAt = base.Add(time.Hour)
	record.CompletedAt = base.Add(time.Hour + time.Minute)
	if err := store.RecordScan(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	var states, events int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM dependency_state").Scan(&states); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT COUNT(*) FROM dependency_version_events").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if states != 1 || events != 0 {
		t.Fatalf("identical scans: states=%d events=%d, want 1/0", states, events)
	}
	record.ID = "scan-three"
	record.StartedAt = base.Add(2 * time.Hour)
	record.CompletedAt = base.Add(2*time.Hour + time.Minute)
	record.Dependencies[0].ResolvedVersion = "1.1.0"
	if err := store.RecordScan(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT COUNT(*) FROM dependency_version_events").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("changed scans: events=%d, want 1", events)
	}
	history, err := store.ProjectHistory(context.Background(), "api", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].ObservedAt.Location() != time.UTC {
		t.Fatalf("project history = %#v, want one UTC event", history)
	}
}

func TestOperationEventAndOutboxAreAtomicAndIdempotent(t *testing.T) {
	store := openTestStore(t)
	operation := Operation{
		ID: "operation-one", ProjectName: "api", ProjectRoot: "/projects/api",
		Kind: "update", Status: "requested", At: time.Now().UTC(),
		Event: OperationEvent{
			Type: "update_requested", Summary: "api update requested",
			IdempotencyKey: "requested", Notify: true,
		},
	}
	for range 2 {
		if _, err := store.RecordOperation(context.Background(), operation); err != nil {
			t.Fatal(err)
		}
	}
	var events, outbox int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM operation_events").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT COUNT(*) FROM notification_outbox").Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if events != 1 || outbox != 1 {
		t.Fatalf("events=%d outbox=%d, want 1/1", events, outbox)
	}
}

func TestConcurrentWritersRemainBounded(t *testing.T) {
	store := openTestStore(t)
	const writers = 12
	var group sync.WaitGroup
	errorsSeen := make(chan error, writers)
	for index := range writers {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := store.RecordOperation(context.Background(), Operation{
				ID:   fmt.Sprintf("operation-%d", index),
				Kind: "scan", Status: "completed", At: time.Now().UTC(),
				Event: OperationEvent{
					Type: "scan_completed", Summary: "scan completed",
					IdempotencyKey: "completed",
				},
			})
			errorsSeen <- err
		}()
	}
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM operations").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != writers {
		t.Fatalf("operations=%d, want %d", count, writers)
	}
}

func TestTypedCommandsRejectUnknownAndClaimOnce(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	if _, err := store.EnqueueCommand(ctx, OperatorCommand{
		Type: "shell", Project: "api", IdempotencyKey: "bad",
	}); err == nil {
		t.Fatal("unknown command was accepted")
	}
	if _, err := store.EnqueueCommand(ctx, OperatorCommand{
		ID: "command-one", Type: "request_update", Project: "api",
		IdempotencyKey: "telegram-1", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	command, err := store.ClaimUpdateCommand(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if command == nil || command.Project != "api" {
		t.Fatalf("claimed command = %#v", command)
	}
	if err := store.CompleteCommand(ctx, command.ID, true, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := store.db.QueryRow("SELECT status FROM operator_commands WHERE id=?", command.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "completed" {
		t.Fatalf("completed command status = %q", status)
	}
	command, err = store.ClaimUpdateCommand(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if command != nil {
		t.Fatalf("command was claimed twice: %#v", command)
	}
}

func TestTypedDeployCommandUsesGenericClosedConsumer(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	if _, err := store.EnqueueCommand(ctx, OperatorCommand{
		ID: "deploy-command", Type: "request_deploy", Project: "api",
		IdempotencyKey: "telegram-deploy-1", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	command, err := store.ClaimOperatorCommand(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if command == nil || command.Type != "request_deploy" || command.Project != "api" {
		t.Fatalf("command = %#v", command)
	}
	if err := store.CompleteCommand(ctx, command.ID, true, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateJobTransitionIsIdempotent(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	operationID, err := store.RecordOperation(ctx, Operation{
		ID: "operation-job", ProjectName: "api", ProjectRoot: "/projects/api",
		Kind: "update", Status: "queued", At: now,
		Event: OperationEvent{
			Type: "update_requested", Summary: "api update requested",
			IdempotencyKey: "requested",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	job := UpdateJob{
		ID: "job-one", OperationID: operationID, ProjectName: "api",
		ProjectRoot: "/projects/api", Repository: "example/api",
		Workflow: "vuelta-update.yml", GitHubRunID: 42,
		RunURL:          "https://github.com/example/api/actions/runs/42",
		RequestedCommit: "0123456789abcdef0123456789abcdef01234567",
		Status:          "queued", RequestedAt: now, UpdatedAt: now,
	}
	if err := store.RecordUpdateJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	job.Status = "succeeded"
	job.UpdatedAt = now.Add(time.Minute)
	event := OperationEvent{
		Type: "update_succeeded", Summary: "api GitHub update succeeded",
		IdempotencyKey: "github-completed-success", Notify: true,
	}
	for range 2 {
		if err := store.UpdateJobState(ctx, job, event); err != nil {
			t.Fatal(err)
		}
	}
	var events, outbox int
	if err := store.db.QueryRow(
		"SELECT COUNT(*) FROM operation_events WHERE operation_id=? AND event_type='update_succeeded'",
		operationID,
	).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(
		`SELECT COUNT(*) FROM notification_outbox o
		 JOIN operation_events e ON e.id=o.event_id
		 WHERE e.operation_id=? AND e.event_type='update_succeeded'`,
		operationID,
	).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if events != 1 || outbox != 1 {
		t.Fatalf("transition events=%d outbox=%d, want 1/1", events, outbox)
	}
}
