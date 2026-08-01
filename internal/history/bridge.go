package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	maxLeaseDuration = 5 * time.Minute
	maxQueryRows     = 100
)

// NotificationItem is one bounded, committed notification intent leased by
// an external delivery process. It contains no message template or secret.
type NotificationItem struct {
	ID             string
	EventID        string
	ApprovalID     string
	OperationID    string
	Project        string
	OperationKind  string
	OperationState string
	EventType      string
	Summary        string
	Attempts       int
	AvailableAt    time.Time
	CreatedAt      time.Time
}

// LeaseNotification claims one due notification. Expired leases are safe to
// reclaim after a bridge crash; callers must use a unique bounded owner ID.
func (s *Store) LeaseNotification(
	ctx context.Context,
	owner string,
	now time.Time,
	duration time.Duration,
) (*NotificationItem, error) {
	if err := validateText("notification lease owner", owner, maxNameBytes, true); err != nil {
		return nil, err
	}
	if duration <= 0 || duration > maxLeaseDuration {
		return nil, fmt.Errorf("notification lease duration must be between 1ns and %s", maxLeaseDuration)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin notification lease: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var item NotificationItem
	var approval sql.NullString
	var available, created string
	err = tx.QueryRowContext(ctx, `SELECT o.id, o.event_id, o.approval_id,
		e.operation_id, COALESCE(p.name, ''), op.kind, op.status,
		o.event_type, o.summary, o.attempts, o.available_at, o.created_at
		FROM notification_outbox o
		JOIN operation_events e ON e.id=o.event_id
		JOIN operations op ON op.id=e.operation_id
		LEFT JOIN projects p ON p.id=op.project_id
		WHERE (o.state='pending' AND o.available_at<=?)
			OR (o.state='leased' AND o.lease_until<=?)
		ORDER BY o.available_at, o.created_at, o.id LIMIT 1`,
		formatTime(now), formatTime(now),
	).Scan(
		&item.ID, &item.EventID, &approval, &item.OperationID, &item.Project,
		&item.OperationKind, &item.OperationState, &item.EventType, &item.Summary,
		&item.Attempts, &available, &created,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("select notification lease: %w", err)
	}
	if approval.Valid {
		item.ApprovalID = approval.String
	}
	result, err := tx.ExecContext(ctx, `UPDATE notification_outbox
		SET state='leased', lease_owner=?, lease_until=?, attempts=attempts+1
		WHERE id=? AND ((state='pending' AND available_at<=?)
			OR (state='leased' AND lease_until<=?))`,
		owner, formatTime(now.Add(duration)), item.ID, formatTime(now), formatTime(now),
	)
	if err != nil {
		return nil, fmt.Errorf("claim notification lease: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return nil, errors.New("notification lease raced with another bridge")
	}
	item.Attempts++
	item.AvailableAt, err = parseTime(available)
	if err != nil {
		return nil, fmt.Errorf("parse notification availability: %w", err)
	}
	item.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, fmt.Errorf("parse notification creation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit notification lease: %w", err)
	}
	return &item, nil
}

// CompleteNotification records the transport message identity and marks the
// leased item delivered in one transaction.
func (s *Store) CompleteNotification(
	ctx context.Context,
	itemID, owner, transport, destination string,
	messageID int64,
	mode string,
	now time.Time,
) error {
	for label, value := range map[string]string{
		"notification ID": itemID, "notification lease owner": owner,
		"notification transport": transport, "notification destination": destination,
	} {
		if err := validateText(label, value, maxNameBytes, true); err != nil {
			return err
		}
	}
	if messageID <= 0 {
		return errors.New("notification message ID must be positive")
	}
	if mode != "send" && mode != "edit" {
		return errors.New("notification delivery mode must be send or edit")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin notification completion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var operationID string
	if err := tx.QueryRowContext(ctx, `SELECT e.operation_id
		FROM notification_outbox o JOIN operation_events e ON e.id=o.event_id
		WHERE o.id=? AND o.state='leased' AND o.lease_owner=?`, itemID, owner,
	).Scan(&operationID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("notification is not leased by this bridge")
		}
		return fmt.Errorf("read leased notification: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO notification_deliveries(
		outbox_id, operation_id, transport, destination_id, message_id,
		delivery_mode, delivered_at
	) VALUES(?, ?, ?, ?, ?, ?, ?)`, itemID, operationID, transport,
		destination, messageID, mode, formatTime(now)); err != nil {
		return fmt.Errorf("record notification delivery: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE notification_outbox
		SET state='delivered', lease_owner='', lease_until=NULL, last_error_code=''
		WHERE id=? AND state='leased' AND lease_owner=?`, itemID, owner)
	if err != nil {
		return fmt.Errorf("complete notification: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("notification completion lost its lease")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit notification completion: %w", err)
	}
	return nil
}

// RetryNotification releases a lease for a bounded later retry or marks only
// the delivery permanently failed. Operation state is never changed.
func (s *Store) RetryNotification(
	ctx context.Context,
	itemID, owner, errorCode string,
	nextAttempt time.Time,
	permanent bool,
) error {
	for label, value := range map[string]string{
		"notification ID": itemID, "notification lease owner": owner,
	} {
		if err := validateText(label, value, maxNameBytes, true); err != nil {
			return err
		}
	}
	if err := validateText("notification error code", errorCode, maxNameBytes, true); err != nil {
		return err
	}
	state := "pending"
	if permanent {
		state = "failed"
	}
	if nextAttempt.IsZero() {
		nextAttempt = time.Now().UTC()
	}
	result, err := s.db.ExecContext(ctx, `UPDATE notification_outbox
		SET state=?, available_at=?, lease_owner='', lease_until=NULL, last_error_code=?
		WHERE id=? AND state='leased' AND lease_owner=?`,
		state, formatTime(nextAttempt), errorCode, itemID, owner,
	)
	if err != nil {
		return fmt.Errorf("release notification lease: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("notification retry did not match this bridge lease")
	}
	return nil
}

// LastOperationMessage returns the most recent delivered message used for an
// operation so routine progress can edit one message rather than flood chat.
func (s *Store) LastOperationMessage(
	ctx context.Context,
	operationID, transport, destination string,
) (int64, bool, error) {
	var messageID int64
	err := s.db.QueryRowContext(ctx, `SELECT message_id FROM notification_deliveries
		WHERE operation_id=? AND transport=? AND destination_id=?
		ORDER BY delivered_at DESC, outbox_id DESC LIMIT 1`,
		operationID, transport, destination,
	).Scan(&messageID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read operation message delivery: %w", err)
	}
	return messageID, true, nil
}

// BridgeCursor returns the last acknowledged update ID for one fixed bridge
// consumer identity.
func (s *Store) BridgeCursor(ctx context.Context, consumer string) (int64, error) {
	if err := validateText("bridge consumer", consumer, maxNameBytes, true); err != nil {
		return 0, err
	}
	var cursor int64
	err := s.db.QueryRowContext(ctx,
		"SELECT last_update_id FROM bridge_cursors WHERE consumer=?", consumer,
	).Scan(&cursor)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read bridge cursor: %w", err)
	}
	return cursor, nil
}

// AdvanceBridgeCursor moves a cursor monotonically after an update has been
// safely handled. Replayed older updates cannot move it backwards.
func (s *Store) AdvanceBridgeCursor(
	ctx context.Context,
	consumer string,
	updateID int64,
	now time.Time,
) error {
	if err := validateText("bridge consumer", consumer, maxNameBytes, true); err != nil {
		return err
	}
	if updateID < 0 {
		return errors.New("bridge update ID cannot be negative")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO bridge_cursors(consumer, last_update_id, updated_at)
		VALUES(?, ?, ?) ON CONFLICT(consumer) DO UPDATE SET
		last_update_id=excluded.last_update_id, updated_at=excluded.updated_at
		WHERE bridge_cursors.last_update_id<excluded.last_update_id`,
		consumer, updateID, formatTime(now),
	)
	if err != nil {
		return fmt.Errorf("advance bridge cursor: %w", err)
	}
	return nil
}

// OperationSummary is a bounded status row safe for an external interface.
type OperationSummary struct {
	ID        string
	Project   string
	Kind      string
	Status    string
	EventType string
	Summary   string
	UpdatedAt time.Time
}

// OperationSummaries returns newest-first safe operation status without logs,
// paths, digests, or arbitrary project content.
func (s *Store) OperationSummaries(
	ctx context.Context,
	project string,
	limit int,
) ([]OperationSummary, error) {
	if limit <= 0 || limit > maxQueryRows {
		limit = 20
	}
	query := `SELECT op.id, COALESCE(p.name, ''), op.kind, op.status,
		COALESCE((SELECT e.event_type FROM operation_events e
			WHERE e.operation_id=op.id ORDER BY e.created_at DESC, e.id DESC LIMIT 1), ''),
		COALESCE((SELECT e.summary FROM operation_events e
			WHERE e.operation_id=op.id ORDER BY e.created_at DESC, e.id DESC LIMIT 1), ''),
		op.updated_at
		FROM operations op LEFT JOIN projects p ON p.id=op.project_id`
	args := []any{}
	if project != "" {
		query += " WHERE p.name=?"
		args = append(args, project)
	}
	query += " ORDER BY op.updated_at DESC, op.id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query operation summaries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]OperationSummary, 0)
	for rows.Next() {
		var summary OperationSummary
		var updated string
		if err := rows.Scan(&summary.ID, &summary.Project, &summary.Kind, &summary.Status,
			&summary.EventType, &summary.Summary, &updated); err != nil {
			return nil, fmt.Errorf("scan operation summary: %w", err)
		}
		summary.UpdatedAt, err = parseTime(updated)
		if err != nil {
			return nil, fmt.Errorf("parse operation update time: %w", err)
		}
		result = append(result, summary)
	}
	return result, rows.Err()
}

// SafeOperationDetail contains only structured events already bounded at the
// owning Vuelta write boundary.
type SafeOperationDetail struct {
	Operation OperationSummary
	Events    []OperationEventDetail
}

// OperationEventDetail is one bounded safe event for /details.
type OperationEventDetail struct {
	Type      string
	Summary   string
	CreatedAt time.Time
}

// OperationDetails reads one exact opaque operation ID and a bounded number
// of its safe events.
func (s *Store) OperationDetails(
	ctx context.Context,
	operationID string,
	limit int,
) (*SafeOperationDetail, error) {
	if err := validateText("operation ID", operationID, maxNameBytes, true); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > maxQueryRows {
		limit = 20
	}
	var detail SafeOperationDetail
	var updated string
	err := s.db.QueryRowContext(ctx, `SELECT op.id, COALESCE(p.name, ''),
		op.kind, op.status, op.updated_at FROM operations op
		LEFT JOIN projects p ON p.id=op.project_id WHERE op.id=?`, operationID,
	).Scan(&detail.Operation.ID, &detail.Operation.Project, &detail.Operation.Kind,
		&detail.Operation.Status, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read operation details: %w", err)
	}
	detail.Operation.UpdatedAt, err = parseTime(updated)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT event_type, summary, created_at
		FROM operation_events WHERE operation_id=?
		ORDER BY created_at DESC, id DESC LIMIT ?`, operationID, limit)
	if err != nil {
		return nil, fmt.Errorf("query operation events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	detail.Events = make([]OperationEventDetail, 0)
	for rows.Next() {
		var event OperationEventDetail
		var created string
		if err := rows.Scan(&event.Type, &event.Summary, &created); err != nil {
			return nil, fmt.Errorf("scan operation event: %w", err)
		}
		event.CreatedAt, err = parseTime(created)
		if err != nil {
			return nil, err
		}
		detail.Events = append(detail.Events, event)
	}
	if len(detail.Events) > 0 {
		detail.Operation.EventType = detail.Events[0].Type
		detail.Operation.Summary = detail.Events[0].Summary
	}
	return &detail, rows.Err()
}

// ApprovalByID returns one exact approval for rendering and expires it first
// when its deadline has passed.
func (s *Store) ApprovalByID(ctx context.Context, id string, now time.Time) (*ApprovalRequest, error) {
	if err := validateText("approval ID", id, maxNameBytes, true); err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE approval_requests
		SET status='expired', decided_at=?
		WHERE id=? AND status='pending' AND expires_at<=?`,
		formatTime(now), id, formatTime(now)); err != nil {
		return nil, fmt.Errorf("expire approval by ID: %w", err)
	}
	var request ApprovalRequest
	var expires, created string
	var decided sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id, operation_id, approval_type,
		subject_fingerprint, subject_summary, status, expires_at, created_at,
		decided_at, decision_identity FROM approval_requests WHERE id=?`, id,
	).Scan(&request.ID, &request.OperationID, &request.Type, &request.SubjectFingerprint,
		&request.SubjectSummary, &request.Status, &expires, &created, &decided,
		&request.DecisionIdentity)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read approval by ID: %w", err)
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
		value, parseErr := parseTime(decided.String)
		if parseErr != nil {
			return nil, parseErr
		}
		request.DecidedAt = &value
	}
	return &request, nil
}

// PendingApprovalForDelivery resolves reply-bound textual confirmation only
// through the exact delivered prompt message.
func (s *Store) PendingApprovalForDelivery(
	ctx context.Context,
	transport, destination string,
	messageID int64,
	now time.Time,
) (*ApprovalRequest, error) {
	if messageID <= 0 {
		return nil, errors.New("approval message ID must be positive")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var approvalID string
	err := s.db.QueryRowContext(ctx, `SELECT o.approval_id
		FROM notification_deliveries d
		JOIN notification_outbox o ON o.id=d.outbox_id
		JOIN approval_requests a ON a.id=o.approval_id
		WHERE d.transport=? AND d.destination_id=? AND d.message_id=?
			AND a.status='pending'
		ORDER BY d.delivered_at DESC LIMIT 1`, transport, destination, messageID,
	).Scan(&approvalID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("resolve reply-bound approval: %w", err)
	}
	request, err := s.ApprovalByID(ctx, approvalID, now)
	if err != nil || request == nil || request.Status != "pending" {
		return nil, err
	}
	return request, nil
}

// DecideApprovalFromDelivery records one exact decision only when the
// callback message is the delivered prompt for that same approval.
func (s *Store) DecideApprovalFromDelivery(
	ctx context.Context,
	id, decision, identity, transport, destination string,
	messageID int64,
	now time.Time,
) error {
	if decision != "approved" && decision != "rejected" {
		return errors.New("approval decision must be approved or rejected")
	}
	for label, value := range map[string]string{
		"approval ID": id, "approval identity": identity,
		"approval transport": transport, "approval destination": destination,
	} {
		if err := validateText(label, value, maxNameBytes, true); err != nil {
			return err
		}
	}
	if messageID <= 0 {
		return errors.New("approval message ID must be positive")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	result, err := s.db.ExecContext(ctx, `UPDATE approval_requests
		SET status=?, decided_at=?, decision_identity=?
		WHERE id=? AND status='pending' AND expires_at>?
		AND EXISTS (
			SELECT 1 FROM notification_outbox o
			JOIN notification_deliveries d ON d.outbox_id=o.id
			WHERE o.approval_id=approval_requests.id AND d.transport=?
				AND d.destination_id=? AND d.message_id=?
		)`, decision, formatTime(now), identity, id, formatTime(now),
		transport, destination, messageID)
	if err != nil {
		return fmt.Errorf("record delivery-bound approval decision: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return errors.New("approval decision did not match its pending delivered prompt")
	}
	return nil
}

// PruneNotificationDeliveries removes only old terminal delivery metadata in
// bounded batches. Durable operation events remain untouched.
func (s *Store) PruneNotificationDeliveries(
	ctx context.Context,
	before time.Time,
	limit int,
) (int64, error) {
	if before.IsZero() {
		return 0, errors.New("notification retention cutoff is required")
	}
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin notification retention: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	args := []any{formatTime(before), limit}
	selection := `SELECT id FROM notification_outbox
		WHERE state IN ('delivered', 'failed') AND created_at<?
		ORDER BY created_at, id LIMIT ?`
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM notification_deliveries WHERE outbox_id IN ("+selection+")", args...,
	); err != nil {
		return 0, fmt.Errorf("prune notification deliveries: %w", err)
	}
	result, err := tx.ExecContext(ctx,
		"DELETE FROM notification_outbox WHERE id IN ("+selection+")", args...,
	)
	if err != nil {
		return 0, fmt.Errorf("prune notification outbox: %w", err)
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("inspect notification retention: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit notification retention: %w", err)
	}
	return removed, nil
}
