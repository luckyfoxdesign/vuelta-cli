package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ApprovalRequest is one expiring, exact-bound operator decision.
type ApprovalRequest struct {
	ID                 string     `json:"id"`
	OperationID        string     `json:"operation_id"`
	Type               string     `json:"type"`
	SubjectFingerprint string     `json:"subject_fingerprint"`
	SubjectSummary     string     `json:"subject_summary"`
	Status             string     `json:"status"`
	ExpiresAt          time.Time  `json:"expires_at"`
	CreatedAt          time.Time  `json:"created_at"`
	DecidedAt          *time.Time `json:"decided_at,omitempty"`
	DecisionIdentity   string     `json:"decision_identity,omitempty"`
}

// CreateApprovalRequest atomically creates an exact request and its safe
// notification event. Repeated fingerprints reuse the existing request.
func (s *Store) CreateApprovalRequest(
	ctx context.Context,
	request ApprovalRequest,
	event OperationEvent,
) (ApprovalRequest, error) {
	if request.ID == "" {
		id, err := newID()
		if err != nil {
			return ApprovalRequest{}, err
		}
		request.ID = id
	}
	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now().UTC()
	}
	if request.ExpiresAt.IsZero() || !request.ExpiresAt.After(request.CreatedAt) {
		return ApprovalRequest{}, errors.New("approval expiry must be after creation")
	}
	for label, value := range map[string]string{
		"approval ID": request.ID, "operation ID": request.OperationID,
		"approval type": request.Type, "subject fingerprint": request.SubjectFingerprint,
	} {
		if err := validateText(label, value, maxNameBytes, true); err != nil {
			return ApprovalRequest{}, err
		}
	}
	if err := validateText("approval subject summary", request.SubjectSummary, maxContractBytes, true); err != nil {
		return ApprovalRequest{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ApprovalRequest{}, fmt.Errorf("begin approval request: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var existing ApprovalRequest
	var expires, created string
	var decided sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT id, operation_id, approval_type,
		subject_fingerprint, subject_summary, status, expires_at, created_at,
		decided_at, decision_identity
		FROM approval_requests
		WHERE operation_id=? AND approval_type=? AND subject_fingerprint=?
		ORDER BY created_at DESC LIMIT 1`,
		request.OperationID, request.Type, request.SubjectFingerprint,
	).Scan(
		&existing.ID, &existing.OperationID, &existing.Type, &existing.SubjectFingerprint,
		&existing.SubjectSummary, &existing.Status, &expires, &created, &decided,
		&existing.DecisionIdentity,
	)
	if err == nil {
		existing.ExpiresAt, _ = parseTime(expires)
		existing.CreatedAt, _ = parseTime(created)
		if decided.Valid {
			parsed, parseErr := parseTime(decided.String)
			if parseErr != nil {
				return ApprovalRequest{}, parseErr
			}
			existing.DecidedAt = &parsed
		}
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ApprovalRequest{}, fmt.Errorf("query approval request: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO approval_requests(
		id, operation_id, approval_type, subject_fingerprint, subject_summary,
		status, expires_at, created_at, decision_identity
	) VALUES(?, ?, ?, ?, ?, 'pending', ?, ?, '')`,
		request.ID, request.OperationID, request.Type, request.SubjectFingerprint,
		request.SubjectSummary, formatTime(request.ExpiresAt), formatTime(request.CreatedAt),
	); err != nil {
		return ApprovalRequest{}, fmt.Errorf("insert approval request: %w", err)
	}
	if err := insertOperationEvent(ctx, tx, request.OperationID, event, request.CreatedAt); err != nil {
		return ApprovalRequest{}, err
	}
	if err := tx.Commit(); err != nil {
		return ApprovalRequest{}, fmt.Errorf("commit approval request: %w", err)
	}
	request.Status = "pending"
	return request, nil
}

// ApprovalByFingerprint returns the exact current decision and expires pending
// requests before returning them.
func (s *Store) ApprovalByFingerprint(
	ctx context.Context,
	operationID, approvalType, fingerprint string,
	now time.Time,
) (*ApprovalRequest, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE approval_requests
		SET status='expired', decided_at=?
		WHERE operation_id=? AND approval_type=? AND subject_fingerprint=?
			AND status='pending' AND expires_at<=?`,
		formatTime(now), operationID, approvalType, fingerprint, formatTime(now),
	); err != nil {
		return nil, fmt.Errorf("expire approval request: %w", err)
	}
	var request ApprovalRequest
	var expires, created string
	var decided sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id, operation_id, approval_type,
		subject_fingerprint, subject_summary, status, expires_at, created_at,
		decided_at, decision_identity
		FROM approval_requests
		WHERE operation_id=? AND approval_type=? AND subject_fingerprint=?
		ORDER BY created_at DESC LIMIT 1`,
		operationID, approvalType, fingerprint,
	).Scan(
		&request.ID, &request.OperationID, &request.Type, &request.SubjectFingerprint,
		&request.SubjectSummary, &request.Status, &expires, &created, &decided,
		&request.DecisionIdentity,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read approval request: %w", err)
	}
	request.ExpiresAt, err = parseTime(expires)
	if err != nil {
		return nil, err
	}
	request.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, err
	}
	if decided.Valid {
		parsed, parseErr := parseTime(decided.String)
		if parseErr != nil {
			return nil, parseErr
		}
		request.DecidedAt = &parsed
	}
	return &request, nil
}

// DecideApproval records one authenticated exact decision. The bridge passes
// an already validated identity; it cannot alter the bound subject.
func (s *Store) DecideApproval(
	ctx context.Context,
	id, decision, identity string,
	now time.Time,
) error {
	if decision != "approved" && decision != "rejected" {
		return errors.New("approval decision must be approved or rejected")
	}
	if err := validateText("approval identity", identity, maxNameBytes, true); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE approval_requests
		SET status=?, decided_at=?, decision_identity=?
		WHERE id=? AND status='pending' AND expires_at>?`,
		decision, formatTime(now), identity, id, formatTime(now),
	)
	if err != nil {
		return fmt.Errorf("record approval decision: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("approval decision did not match one pending unexpired request")
	}
	return nil
}
