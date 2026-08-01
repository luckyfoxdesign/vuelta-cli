package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// OperationEvent is a safe structured transition. Summary must already be
// redacted and remains bounded by the store.
type OperationEvent struct {
	Type           string
	Summary        string
	IdempotencyKey string
	Notify         bool
}

// Operation records a state transition and its optional notification intent.
type Operation struct {
	ID          string
	ProjectName string
	ProjectRoot string
	Kind        string
	Status      string
	At          time.Time
	Event       OperationEvent
}

// RecordOperation atomically commits the operation, event, and optional
// outbox intent. Delivery can never own or roll back operation state.
func (s *Store) RecordOperation(ctx context.Context, operation Operation) (string, error) {
	if operation.ID == "" {
		id, err := newID()
		if err != nil {
			return "", err
		}
		operation.ID = id
	}
	if operation.At.IsZero() {
		operation.At = time.Now().UTC()
	}
	for label, value := range map[string]string{
		"operation ID": operation.ID, "operation kind": operation.Kind,
		"operation status": operation.Status, "event type": operation.Event.Type,
		"event idempotency key": operation.Event.IdempotencyKey,
	} {
		if err := validateText(label, value, maxNameBytes, true); err != nil {
			return "", err
		}
	}
	if err := validateText("event summary", operation.Event.Summary, maxSummaryBytes, true); err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin operation write: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var projectID any
	if operation.ProjectName != "" {
		id, projectErr := upsertProject(ctx, tx, operation.ProjectName, operation.ProjectRoot, operation.At)
		if projectErr != nil {
			return "", projectErr
		}
		projectID = id
	}
	timestamp := formatTime(operation.At)
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id, project_id, kind, status, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at`,
		operation.ID, projectID, operation.Kind, operation.Status, timestamp, timestamp,
	); err != nil {
		return "", fmt.Errorf("upsert operation: %w", err)
	}
	eventID, err := newID()
	if err != nil {
		return "", err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO operation_events(
		id, operation_id, event_type, summary, idempotency_key, created_at
	) VALUES(?, ?, ?, ?, ?, ?)
	ON CONFLICT(operation_id, idempotency_key) DO NOTHING`,
		eventID, operation.ID, operation.Event.Type, operation.Event.Summary,
		operation.Event.IdempotencyKey, timestamp,
	)
	if err != nil {
		return "", fmt.Errorf("insert operation event: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("inspect operation event insert: %w", err)
	}
	if operation.Event.Notify && inserted == 1 {
		outboxID, idErr := newID()
		if idErr != nil {
			return "", idErr
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO notification_outbox(
			id, event_id, event_type, summary, available_at, created_at
		) VALUES(?, ?, ?, ?, ?, ?)`,
			outboxID, eventID, operation.Event.Type, operation.Event.Summary, timestamp, timestamp,
		); err != nil {
			return "", fmt.Errorf("insert notification intent: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit operation write: %w", err)
	}
	return operation.ID, nil
}

// UpdateJob is a known GitHub-hosted update run.
type UpdateJob struct {
	ID              string    `json:"id"`
	OperationID     string    `json:"operation_id"`
	ProjectName     string    `json:"project"`
	ProjectRoot     string    `json:"-"`
	Repository      string    `json:"repository"`
	Workflow        string    `json:"workflow"`
	GitHubRunID     int64     `json:"github_run_id"`
	RunURL          string    `json:"run_url"`
	RequestedCommit string    `json:"requested_commit"`
	Status          string    `json:"status"`
	Branch          string    `json:"branch,omitempty"`
	PullRequestURL  string    `json:"pull_request_url,omitempty"`
	RequestedAt     time.Time `json:"requested_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// RecordUpdateJob commits the run returned by GitHub.
func (s *Store) RecordUpdateJob(ctx context.Context, job UpdateJob) error {
	if job.ID == "" {
		id, err := newID()
		if err != nil {
			return err
		}
		job.ID = id
	}
	if job.OperationID == "" {
		return errors.New("update job operation ID is required")
	}
	if job.RequestedAt.IsZero() {
		job.RequestedAt = time.Now().UTC()
	}
	if job.UpdatedAt.IsZero() {
		job.UpdatedAt = job.RequestedAt
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin update job write: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := upsertProject(ctx, tx, job.ProjectName, job.ProjectRoot, job.UpdatedAt)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO update_jobs(
		id, operation_id, project_id, repository, workflow, github_run_id, run_url,
		requested_commit, status, branch, pull_request_url, requested_at, updated_at
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		job.ID, job.OperationID, projectID, job.Repository, job.Workflow, job.GitHubRunID,
		job.RunURL, job.RequestedCommit, job.Status, job.Branch, job.PullRequestURL,
		formatTime(job.RequestedAt), formatTime(job.UpdatedAt),
	); err != nil {
		return fmt.Errorf("insert update job: %w", err)
	}
	return tx.Commit()
}

// PendingUpdateJobs returns only known unfinished runs.
func (s *Store) PendingUpdateJobs(ctx context.Context, project string) ([]UpdateJob, error) {
	query := `SELECT j.id, j.operation_id, p.name, p.root, j.repository, j.workflow,
		j.github_run_id, j.run_url, j.requested_commit, j.status, j.branch,
		j.pull_request_url, j.requested_at, j.updated_at
		FROM update_jobs j JOIN projects p ON p.id=j.project_id
		WHERE j.status IN ('queued', 'in_progress')`
	args := []any{}
	if project != "" {
		query += " AND p.name=?"
		args = append(args, project)
	}
	query += " ORDER BY j.updated_at"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query pending update jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var jobs []UpdateJob
	for rows.Next() {
		var job UpdateJob
		var requested, updated string
		if err := rows.Scan(
			&job.ID, &job.OperationID, &job.ProjectName, &job.ProjectRoot,
			&job.Repository, &job.Workflow, &job.GitHubRunID, &job.RunURL,
			&job.RequestedCommit, &job.Status, &job.Branch, &job.PullRequestURL,
			&requested, &updated,
		); err != nil {
			return nil, fmt.Errorf("scan pending update job: %w", err)
		}
		job.RequestedAt, err = parseTime(requested)
		if err != nil {
			return nil, err
		}
		job.UpdatedAt, err = parseTime(updated)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// UpdateJobs returns newest-first durable runs for status views.
func (s *Store) UpdateJobs(ctx context.Context, project string, limit int) ([]UpdateJob, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `SELECT j.id, j.operation_id, p.name, p.root, j.repository, j.workflow,
		j.github_run_id, j.run_url, j.requested_commit, j.status, j.branch,
		j.pull_request_url, j.requested_at, j.updated_at
		FROM update_jobs j JOIN projects p ON p.id=j.project_id`
	args := []any{}
	if project != "" {
		query += " WHERE p.name=?"
		args = append(args, project)
	}
	query += " ORDER BY j.updated_at DESC, j.id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query update jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var jobs []UpdateJob
	for rows.Next() {
		var job UpdateJob
		var requested, updated string
		if err := rows.Scan(
			&job.ID, &job.OperationID, &job.ProjectName, &job.ProjectRoot,
			&job.Repository, &job.Workflow, &job.GitHubRunID, &job.RunURL,
			&job.RequestedCommit, &job.Status, &job.Branch, &job.PullRequestURL,
			&requested, &updated,
		); err != nil {
			return nil, fmt.Errorf("scan update job: %w", err)
		}
		job.RequestedAt, err = parseTime(requested)
		if err != nil {
			return nil, err
		}
		job.UpdatedAt, err = parseTime(updated)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// UpdateJobState applies one observed GitHub transition and its event/outbox
// atomically. Repeating the same transition is idempotent.
func (s *Store) UpdateJobState(ctx context.Context, job UpdateJob, event OperationEvent) error {
	if job.ID == "" || job.OperationID == "" {
		return errors.New("known update job IDs are required")
	}
	if job.UpdatedAt.IsZero() {
		job.UpdatedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin update job transition: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE update_jobs SET status=?, branch=?,
		pull_request_url=?, updated_at=? WHERE id=? AND operation_id=?`,
		job.Status, job.Branch, job.PullRequestURL, formatTime(job.UpdatedAt), job.ID, job.OperationID,
	)
	if err != nil {
		return fmt.Errorf("update known job: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return errors.New("update job is not known")
	}
	if _, err := tx.ExecContext(ctx, "UPDATE operations SET status=?, updated_at=? WHERE id=?",
		job.Status, formatTime(job.UpdatedAt), job.OperationID,
	); err != nil {
		return fmt.Errorf("update job operation: %w", err)
	}
	eventID, err := newID()
	if err != nil {
		return err
	}
	insert, err := tx.ExecContext(ctx, `INSERT INTO operation_events(
		id, operation_id, event_type, summary, idempotency_key, created_at
	) VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(operation_id, idempotency_key) DO NOTHING`,
		eventID, job.OperationID, event.Type, event.Summary, event.IdempotencyKey, formatTime(job.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("insert job transition event: %w", err)
	}
	inserted, _ := insert.RowsAffected()
	if event.Notify && inserted == 1 {
		outboxID, idErr := newID()
		if idErr != nil {
			return idErr
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO notification_outbox(
			id, event_id, event_type, summary, available_at, created_at
		) VALUES(?, ?, ?, ?, ?, ?)`,
			outboxID, eventID, event.Type, event.Summary,
			formatTime(job.UpdatedAt), formatTime(job.UpdatedAt),
		); err != nil {
			return fmt.Errorf("insert job transition notification: %w", err)
		}
	}
	return tx.Commit()
}

// OperatorCommand is a closed request written by an external interface.
type OperatorCommand struct {
	ID             string
	Type           string
	Project        string
	SubjectID      string
	IdempotencyKey string
	RequestedBy    string
	SourceUpdateID int64
	CreatedAt      time.Time
}

var allowedCommandTypes = map[string]bool{
	"request_scan": true, "request_update": true, "request_deploy": true, "request_rollback": true,
}

// EnqueueCommand accepts closed identifiers only; it cannot carry argv or
// arbitrary payload text.
func (s *Store) EnqueueCommand(ctx context.Context, command OperatorCommand) (string, error) {
	if !allowedCommandTypes[command.Type] {
		return "", fmt.Errorf("unknown operator command type %q", command.Type)
	}
	if command.ID == "" {
		id, err := newID()
		if err != nil {
			return "", err
		}
		command.ID = id
	}
	if command.CreatedAt.IsZero() {
		command.CreatedAt = time.Now().UTC()
	}
	for label, value := range map[string]string{
		"command ID": command.ID, "command project": command.Project,
		"command idempotency key": command.IdempotencyKey,
	} {
		if err := validateText(label, value, maxNameBytes, true); err != nil {
			return "", err
		}
	}
	if err := validateText("command subject", command.SubjectID, maxNameBytes, false); err != nil {
		return "", err
	}
	if err := validateText("command requester", command.RequestedBy, maxNameBytes, false); err != nil {
		return "", err
	}
	if command.SourceUpdateID < 0 {
		return "", errors.New("command source update ID cannot be negative")
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO operator_commands(
		id, command_type, project_name, subject_id, idempotency_key, created_at,
		requested_by, source_update_id
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(idempotency_key) DO NOTHING`,
		command.ID, command.Type, command.Project, command.SubjectID,
		command.IdempotencyKey, formatTime(command.CreatedAt), command.RequestedBy,
		command.SourceUpdateID,
	)
	if err != nil {
		return "", fmt.Errorf("enqueue operator command: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("inspect operator command insert: %w", err)
	}
	if inserted == 0 {
		if err := s.db.QueryRowContext(ctx,
			"SELECT id FROM operator_commands WHERE idempotency_key=?", command.IdempotencyKey,
		).Scan(&command.ID); err != nil {
			return "", fmt.Errorf("read idempotent operator command: %w", err)
		}
	}
	return command.ID, nil
}

// ClaimUpdateCommand atomically claims the oldest pending update request.
func (s *Store) ClaimUpdateCommand(ctx context.Context, now time.Time) (*OperatorCommand, error) {
	return s.claimCommand(ctx, now, []string{"request_update"})
}

// ClaimOperatorCommand atomically claims the oldest closed command type.
func (s *Store) ClaimOperatorCommand(ctx context.Context, now time.Time) (*OperatorCommand, error) {
	return s.claimCommand(ctx, now, []string{
		"request_scan", "request_update", "request_deploy", "request_rollback",
	})
}

func (s *Store) claimCommand(
	ctx context.Context,
	now time.Time,
	commandTypes []string,
) (*OperatorCommand, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin operator command claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var command OperatorCommand
	var created string
	placeholders := make([]string, len(commandTypes))
	args := make([]any, len(commandTypes))
	for index, commandType := range commandTypes {
		if !allowedCommandTypes[commandType] {
			return nil, errors.New("internal operator command claim type is invalid")
		}
		placeholders[index] = "?"
		args[index] = commandType
	}
	if len(placeholders) == 0 {
		return nil, errors.New("at least one operator command claim type is required")
	}
	query := `SELECT id, command_type, project_name, subject_id,
		idempotency_key, requested_by, source_update_id, created_at FROM operator_commands
		WHERE status='pending' AND command_type IN (` + strings.Join(placeholders, ",") + `)
		ORDER BY created_at, id LIMIT 1`
	err = tx.QueryRowContext(ctx, query, args...).Scan(
		&command.ID, &command.Type, &command.Project, &command.SubjectID,
		&command.IdempotencyKey, &command.RequestedBy, &command.SourceUpdateID, &created,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("select operator command: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE operator_commands SET status='processing',
		consumed_at=? WHERE id=? AND status='pending'`, formatTime(now), command.ID)
	if err != nil {
		return nil, fmt.Errorf("claim operator command: %w", err)
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return nil, errors.New("operator command claim raced with another consumer")
	}
	command.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit operator command claim: %w", err)
	}
	return &command, nil
}

// CompleteCommand closes one previously claimed command.
func (s *Store) CompleteCommand(ctx context.Context, id string, succeeded bool, now time.Time) error {
	status := "completed"
	if !succeeded {
		status = "rejected"
	}
	result, err := s.db.ExecContext(ctx, `UPDATE operator_commands SET status=?, consumed_at=?
		WHERE id=? AND status='processing'`, status, formatTime(now), id)
	if err != nil {
		return fmt.Errorf("complete operator command: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect operator command completion: %w", err)
	}
	if affected != 1 {
		return errors.New("operator command is not processing")
	}
	return nil
}
