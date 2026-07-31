package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var (
	shaPattern    = regexp.MustCompile(`^[a-f0-9]{40}$`)
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

var deploymentStates = map[string]bool{
	"discovered": true, "building": true, "ready": true, "pulling": true,
	"starting": true, "healthy": true, "switching": true, "draining": true,
	"deployed": true, "blocked": true, "failed": true, "rolled_back": true,
}

// DeploymentContract is the durable safe structural view discovered from a
// configured workspace. Slice fields contain names and relative paths only.
type DeploymentContract struct {
	ProjectName    string    `json:"project"`
	ProjectRoot    string    `json:"-"`
	Fingerprint    string    `json:"fingerprint"`
	Repository     string    `json:"repository"`
	Branch         string    `json:"branch"`
	Commit         string    `json:"commit"`
	ComposeFiles   []string  `json:"compose_files"`
	Services       []string  `json:"services"`
	TrafficService string    `json:"traffic_service"`
	StableUpstream string    `json:"stable_upstream"`
	InternalPort   int       `json:"internal_port"`
	MigrationPaths []string  `json:"migration_paths"`
	Status         string    `json:"status"`
	Blockers       []string  `json:"blockers"`
	DiscoveredAt   time.Time `json:"discovered_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// RecordDeploymentContract replaces one derived contract only in the
// machine-owned database. It never writes to the managed repository.
func (s *Store) RecordDeploymentContract(ctx context.Context, contract DeploymentContract) error {
	if contract.DiscoveredAt.IsZero() {
		contract.DiscoveredAt = time.Now().UTC()
	}
	if contract.UpdatedAt.IsZero() {
		contract.UpdatedAt = contract.DiscoveredAt
	}
	if contract.Status != "ready" && contract.Status != "blocked" {
		return errors.New("deployment contract status must be ready or blocked")
	}
	for label, value := range map[string]string{
		"project name": contract.ProjectName, "contract fingerprint": contract.Fingerprint,
	} {
		if err := validateText(label, value, maxPathBytes, true); err != nil {
			return err
		}
	}
	requireIdentity := contract.Status == "ready"
	for label, value := range map[string]string{
		"repository": contract.Repository, "branch": contract.Branch, "commit": contract.Commit,
	} {
		if err := validateText(label, value, maxPathBytes, requireIdentity); err != nil {
			return err
		}
	}
	if contract.Commit != "" && !shaPattern.MatchString(contract.Commit) {
		return errors.New("deployment contract commit must be a full lowercase SHA")
	}
	compose, err := boundedJSON(contract.ComposeFiles)
	if err != nil {
		return fmt.Errorf("encode deployment compose files: %w", err)
	}
	services, err := boundedJSON(contract.Services)
	if err != nil {
		return fmt.Errorf("encode deployment services: %w", err)
	}
	migrations, err := boundedJSON(contract.MigrationPaths)
	if err != nil {
		return fmt.Errorf("encode deployment migration paths: %w", err)
	}
	blockers, err := boundedJSON(contract.Blockers)
	if err != nil {
		return fmt.Errorf("encode deployment blockers: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin deployment contract write: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := upsertProject(ctx, tx, contract.ProjectName, contract.ProjectRoot, contract.UpdatedAt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO deployment_contracts(
		project_id, fingerprint, repository, branch, commit_sha, compose_files,
		services, traffic_service, stable_upstream, internal_port, migration_paths,
		status, blockers, discovered_at, updated_at
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(project_id) DO UPDATE SET
		fingerprint=excluded.fingerprint, repository=excluded.repository,
		branch=excluded.branch, commit_sha=excluded.commit_sha,
		compose_files=excluded.compose_files, services=excluded.services,
		traffic_service=excluded.traffic_service, stable_upstream=excluded.stable_upstream,
		internal_port=excluded.internal_port, migration_paths=excluded.migration_paths,
		status=excluded.status, blockers=excluded.blockers, updated_at=excluded.updated_at`,
		projectID, contract.Fingerprint, contract.Repository, contract.Branch, contract.Commit,
		compose, services, contract.TrafficService, contract.StableUpstream,
		contract.InternalPort, migrations, contract.Status, blockers,
		formatTime(contract.DiscoveredAt), formatTime(contract.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("upsert deployment contract: %w", err)
	}
	return tx.Commit()
}

// DeploymentContracts returns derived contracts ordered by stable project
// name for status and planning views.
func (s *Store) DeploymentContracts(ctx context.Context) ([]DeploymentContract, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.name, p.root, c.fingerprint,
		c.repository, c.branch, c.commit_sha, c.compose_files, c.services,
		c.traffic_service, c.stable_upstream, c.internal_port, c.migration_paths,
		c.status, c.blockers, c.discovered_at, c.updated_at
		FROM deployment_contracts c JOIN projects p ON p.id=c.project_id
		ORDER BY p.name`)
	if err != nil {
		return nil, fmt.Errorf("query deployment contracts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var contracts []DeploymentContract
	for rows.Next() {
		var contract DeploymentContract
		var compose, services, migrations, blockers, discovered, updated string
		if err := rows.Scan(
			&contract.ProjectName, &contract.ProjectRoot, &contract.Fingerprint,
			&contract.Repository, &contract.Branch, &contract.Commit, &compose, &services,
			&contract.TrafficService, &contract.StableUpstream, &contract.InternalPort,
			&migrations, &contract.Status, &blockers, &discovered, &updated,
		); err != nil {
			return nil, fmt.Errorf("scan deployment contract: %w", err)
		}
		if err := decodeJSONList(compose, &contract.ComposeFiles); err != nil {
			return nil, err
		}
		if err := decodeJSONList(services, &contract.Services); err != nil {
			return nil, err
		}
		if err := decodeJSONList(migrations, &contract.MigrationPaths); err != nil {
			return nil, err
		}
		if err := decodeJSONList(blockers, &contract.Blockers); err != nil {
			return nil, err
		}
		contract.DiscoveredAt, err = parseTime(discovered)
		if err != nil {
			return nil, err
		}
		contract.UpdatedAt, err = parseTime(updated)
		if err != nil {
			return nil, err
		}
		contracts = append(contracts, contract)
	}
	return contracts, rows.Err()
}

// DeploymentRelease is one exact source commit and immutable image lifecycle.
type DeploymentRelease struct {
	ID                  string     `json:"id"`
	OperationID         string     `json:"operation_id"`
	ProjectName         string     `json:"project"`
	ProjectRoot         string     `json:"-"`
	ReleaseRepository   string     `json:"release_repository"`
	ReleaseWorkflow     string     `json:"release_workflow"`
	GitHubRunID         int64      `json:"github_run_id,omitempty"`
	RunURL              string     `json:"run_url,omitempty"`
	SourceRepository    string     `json:"source_repository"`
	SourceCommit        string     `json:"source_commit"`
	ImageRepository     string     `json:"image_repository"`
	CandidateDigest     string     `json:"candidate_digest,omitempty"`
	PreviousDigest      string     `json:"previous_digest,omitempty"`
	CandidateSlot       string     `json:"candidate_slot,omitempty"`
	PreviousSlot        string     `json:"previous_slot,omitempty"`
	ContractFingerprint string     `json:"contract_fingerprint"`
	State               string     `json:"state"`
	RequestedAt         time.Time  `json:"requested_at"`
	StartedAt           *time.Time `json:"started_at,omitempty"`
	SwitchedAt          *time.Time `json:"switched_at,omitempty"`
	CompletedAt         *time.Time `json:"completed_at,omitempty"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// CreateDeploymentRelease atomically creates the release operation, first
// event/outbox intent, and exact source record.
func (s *Store) CreateDeploymentRelease(
	ctx context.Context,
	release DeploymentRelease,
	event OperationEvent,
) (DeploymentRelease, error) {
	if release.ID == "" {
		id, err := newID()
		if err != nil {
			return DeploymentRelease{}, err
		}
		release.ID = id
	}
	if release.OperationID == "" {
		id, err := newID()
		if err != nil {
			return DeploymentRelease{}, err
		}
		release.OperationID = id
	}
	if release.RequestedAt.IsZero() {
		release.RequestedAt = time.Now().UTC()
	}
	if release.UpdatedAt.IsZero() {
		release.UpdatedAt = release.RequestedAt
	}
	if err := validateDeploymentRelease(release); err != nil {
		return DeploymentRelease{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeploymentRelease{}, fmt.Errorf("begin deployment release write: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	projectID, err := upsertProject(ctx, tx, release.ProjectName, release.ProjectRoot, release.UpdatedAt)
	if err != nil {
		return DeploymentRelease{}, err
	}
	timestamp := formatTime(release.UpdatedAt)
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(
		id, project_id, kind, status, created_at, updated_at
	) VALUES(?, ?, 'deploy', ?, ?, ?)`,
		release.OperationID, projectID, release.State, timestamp, timestamp,
	); err != nil {
		return DeploymentRelease{}, fmt.Errorf("insert deployment operation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO deployment_releases(
		id, operation_id, project_id, release_repository, release_workflow,
		github_run_id, run_url, source_repository, source_commit, image_repository,
		candidate_digest, previous_digest, candidate_slot, previous_slot,
		contract_fingerprint, state, requested_at, updated_at
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		release.ID, release.OperationID, projectID, release.ReleaseRepository,
		release.ReleaseWorkflow, release.GitHubRunID, release.RunURL,
		release.SourceRepository, release.SourceCommit, release.ImageRepository,
		release.CandidateDigest, release.PreviousDigest, release.CandidateSlot,
		release.PreviousSlot, release.ContractFingerprint, release.State,
		formatTime(release.RequestedAt), timestamp,
	); err != nil {
		return DeploymentRelease{}, fmt.Errorf("insert deployment release: %w", err)
	}
	if err := insertOperationEvent(ctx, tx, release.OperationID, event, release.UpdatedAt); err != nil {
		return DeploymentRelease{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeploymentRelease{}, fmt.Errorf("commit deployment release: %w", err)
	}
	return release, nil
}

// TransitionDeploymentRelease atomically advances release state and appends
// one idempotent event/outbox row.
func (s *Store) TransitionDeploymentRelease(
	ctx context.Context,
	release DeploymentRelease,
	event OperationEvent,
) error {
	if err := validateDeploymentRelease(release); err != nil {
		return err
	}
	if release.UpdatedAt.IsZero() {
		release.UpdatedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin deployment transition: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE deployment_releases SET
		github_run_id=?, run_url=?, candidate_digest=?, previous_digest=?,
		candidate_slot=?, previous_slot=?, state=?, started_at=?, switched_at=?,
		completed_at=?, updated_at=?
		WHERE id=? AND operation_id=? AND contract_fingerprint=?`,
		release.GitHubRunID, release.RunURL, release.CandidateDigest, release.PreviousDigest,
		release.CandidateSlot, release.PreviousSlot, release.State,
		optionalTime(release.StartedAt), optionalTime(release.SwitchedAt),
		optionalTime(release.CompletedAt), formatTime(release.UpdatedAt),
		release.ID, release.OperationID, release.ContractFingerprint,
	)
	if err != nil {
		return fmt.Errorf("update deployment release: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("deployment release transition did not match one exact record")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET status=?, updated_at=? WHERE id=?`,
		release.State, formatTime(release.UpdatedAt), release.OperationID,
	); err != nil {
		return fmt.Errorf("update deployment operation: %w", err)
	}
	if err := insertOperationEvent(ctx, tx, release.OperationID, event, release.UpdatedAt); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit deployment transition: %w", err)
	}
	return nil
}

// DeploymentReleases returns newest-first release state.
func (s *Store) DeploymentReleases(ctx context.Context, project string, limit int) ([]DeploymentRelease, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `SELECT r.id, r.operation_id, p.name, p.root, r.release_repository,
		r.release_workflow, r.github_run_id, r.run_url, r.source_repository,
		r.source_commit, r.image_repository, r.candidate_digest, r.previous_digest,
		r.candidate_slot, r.previous_slot, r.contract_fingerprint, r.state,
		r.requested_at, r.started_at, r.switched_at, r.completed_at, r.updated_at
		FROM deployment_releases r JOIN projects p ON p.id=r.project_id`
	args := []any{}
	if project != "" {
		query += " WHERE p.name=?"
		args = append(args, project)
	}
	query += " ORDER BY r.updated_at DESC, r.id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query deployment releases: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var releases []DeploymentRelease
	for rows.Next() {
		release, scanErr := scanDeploymentRelease(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		releases = append(releases, release)
	}
	return releases, rows.Err()
}

type rowScanner interface {
	Scan(...any) error
}

func scanDeploymentRelease(row rowScanner) (DeploymentRelease, error) {
	var release DeploymentRelease
	var requested, updated string
	var started, switched, completed sql.NullString
	if err := row.Scan(
		&release.ID, &release.OperationID, &release.ProjectName, &release.ProjectRoot,
		&release.ReleaseRepository, &release.ReleaseWorkflow, &release.GitHubRunID,
		&release.RunURL, &release.SourceRepository, &release.SourceCommit,
		&release.ImageRepository, &release.CandidateDigest, &release.PreviousDigest,
		&release.CandidateSlot, &release.PreviousSlot, &release.ContractFingerprint,
		&release.State, &requested, &started, &switched, &completed, &updated,
	); err != nil {
		return DeploymentRelease{}, fmt.Errorf("scan deployment release: %w", err)
	}
	var err error
	release.RequestedAt, err = parseTime(requested)
	if err != nil {
		return DeploymentRelease{}, err
	}
	release.UpdatedAt, err = parseTime(updated)
	if err != nil {
		return DeploymentRelease{}, err
	}
	for _, pair := range []struct {
		source      sql.NullString
		destination **time.Time
	}{
		{started, &release.StartedAt},
		{switched, &release.SwitchedAt},
		{completed, &release.CompletedAt},
	} {
		if pair.source.Valid {
			parsed, parseErr := parseTime(pair.source.String)
			if parseErr != nil {
				return DeploymentRelease{}, parseErr
			}
			*pair.destination = &parsed
		}
	}
	return release, nil
}

func validateDeploymentRelease(release DeploymentRelease) error {
	for label, value := range map[string]string{
		"release ID": release.ID, "operation ID": release.OperationID,
		"project": release.ProjectName, "release repository": release.ReleaseRepository,
		"release workflow": release.ReleaseWorkflow, "source repository": release.SourceRepository,
		"source commit": release.SourceCommit, "image repository": release.ImageRepository,
		"contract fingerprint": release.ContractFingerprint, "state": release.State,
	} {
		if err := validateText(label, value, maxPathBytes, true); err != nil {
			return err
		}
	}
	if !shaPattern.MatchString(release.SourceCommit) {
		return errors.New("deployment release source commit must be a full lowercase SHA")
	}
	if !deploymentStates[release.State] {
		return errors.New("deployment release state is invalid")
	}
	for _, digest := range []string{release.CandidateDigest, release.PreviousDigest} {
		if digest != "" && !digestPattern.MatchString(digest) {
			return errors.New("deployment release digest is invalid")
		}
	}
	return nil
}

func insertOperationEvent(
	ctx context.Context,
	tx *sql.Tx,
	operationID string,
	event OperationEvent,
	at time.Time,
) error {
	for label, value := range map[string]string{
		"event type": event.Type, "event idempotency key": event.IdempotencyKey,
	} {
		if err := validateText(label, value, maxNameBytes, true); err != nil {
			return err
		}
	}
	if err := validateText("event summary", event.Summary, maxSummaryBytes, true); err != nil {
		return err
	}
	eventID, err := newID()
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO operation_events(
		id, operation_id, event_type, summary, idempotency_key, created_at
	) VALUES(?, ?, ?, ?, ?, ?) ON CONFLICT(operation_id, idempotency_key) DO NOTHING`,
		eventID, operationID, event.Type, event.Summary, event.IdempotencyKey, formatTime(at),
	)
	if err != nil {
		return fmt.Errorf("insert deployment operation event: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if event.Notify && inserted == 1 {
		outboxID, idErr := newID()
		if idErr != nil {
			return idErr
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO notification_outbox(
			id, event_id, event_type, summary, available_at, created_at
		) VALUES(?, ?, ?, ?, ?, ?)`,
			outboxID, eventID, event.Type, event.Summary, formatTime(at), formatTime(at),
		); err != nil {
			return fmt.Errorf("insert deployment notification intent: %w", err)
		}
	}
	return nil
}

func boundedJSON(value []string) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if len(data) > maxContractBytes {
		return "", errors.New("structured deployment metadata exceeds bounded size")
	}
	return string(data), nil
}

func decodeJSONList(value string, destination *[]string) error {
	if len(value) > maxContractBytes {
		return errors.New("stored deployment metadata exceeds bounded size")
	}
	if err := json.Unmarshal([]byte(value), destination); err != nil {
		return errors.New("stored deployment metadata is invalid")
	}
	return nil
}

func optionalTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return formatTime(*value)
}
