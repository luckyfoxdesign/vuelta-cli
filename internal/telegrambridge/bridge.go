package telegrambridge

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/history"
)

const telegramTransport = "telegram"

// Config defines one exact private operator boundary.
type Config struct {
	ChatID        int64
	UserID        int64
	Consumer      string
	LeaseOwner    string
	PollTimeout   time.Duration
	LeaseDuration time.Duration
	MaxAttempts   int
	Retention     time.Duration
}

// Bridge owns Telegram presentation and the narrow bridge-side SQLite API. It
// has no Docker, GitHub, registry, project-checkout, or shell dependency.
type Bridge struct {
	Store  *history.Store
	Client *Client
	Config Config
	Log    func(string)
	rate   attemptLimiter
}

// Run continuously alternates bounded outbox drains and long polling until
// cancellation. Cursor advancement happens only after an update is handled.
func (b *Bridge) Run(ctx context.Context) error {
	if err := b.validate(); err != nil {
		return err
	}
	b.safeLog("Telegram bridge started")
	defer b.safeLog("Telegram bridge stopped")
	cursor, err := b.Store.BridgeCursor(ctx, b.Config.Consumer)
	if err != nil {
		return err
	}
	_, _ = b.Store.PruneNotificationDeliveries(
		ctx, time.Now().UTC().Add(-b.Config.Retention), 500,
	)
	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if err := b.DrainNotifications(ctx, maxUpdates); err != nil {
			b.safeLog("notification drain failed; retrying")
		}
		updates, pollErr := b.Client.GetUpdates(
			ctx, cursor+1, b.Config.PollTimeout,
		)
		if pollErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			b.safeLog("Telegram polling failed; retrying")
			if !waitContext(ctx, backoff) {
				return nil
			}
			backoff = minDuration(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		for _, update := range updates {
			if update.ID <= cursor {
				continue
			}
			if err := b.handleUpdate(ctx, update); err != nil {
				b.safeLog("Telegram update handling failed; cursor retained")
				break
			}
			if err := b.Store.AdvanceBridgeCursor(ctx, b.Config.Consumer, update.ID, time.Now().UTC()); err != nil {
				return err
			}
			cursor = update.ID
		}
	}
}

func (b *Bridge) validate() error {
	if b.Store == nil || b.Client == nil {
		return errors.New("telegram bridge dependencies are incomplete")
	}
	if b.Config.ChatID == 0 || b.Config.UserID <= 0 {
		return errors.New("telegram bridge requires exact chat and user IDs")
	}
	if b.Config.Consumer == "" {
		b.Config.Consumer = "telegram-primary"
	}
	if b.Config.LeaseOwner == "" {
		return errors.New("telegram bridge lease owner is required")
	}
	if b.Config.PollTimeout <= 0 || b.Config.PollTimeout > 25*time.Second {
		b.Config.PollTimeout = 10 * time.Second
	}
	if b.Config.LeaseDuration <= 0 || b.Config.LeaseDuration > 5*time.Minute {
		b.Config.LeaseDuration = 45 * time.Second
	}
	if b.Config.MaxAttempts <= 0 || b.Config.MaxAttempts > 20 {
		b.Config.MaxAttempts = 8
	}
	if b.Config.Retention < 24*time.Hour {
		b.Config.Retention = 30 * 24 * time.Hour
	}
	return nil
}

// DrainNotifications processes at most limit committed outbox rows.
func (b *Bridge) DrainNotifications(ctx context.Context, limit int) error {
	if err := b.validate(); err != nil {
		return err
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	for range limit {
		item, err := b.Store.LeaseNotification(
			ctx, b.Config.LeaseOwner, time.Now().UTC(), b.Config.LeaseDuration,
		)
		if err != nil {
			return err
		}
		if item == nil {
			return nil
		}
		if err := b.deliver(ctx, *item); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bridge) deliver(ctx context.Context, item history.NotificationItem) error {
	text, keyboard, renderErr := b.renderNotification(ctx, item)
	if renderErr != nil {
		return b.Store.RetryNotification(
			ctx, item.ID, b.Config.LeaseOwner, "render_invalid", time.Now().UTC(), true,
		)
	}
	destination := strconv.FormatInt(b.Config.ChatID, 10)
	messageID, found, err := b.Store.LastOperationMessage(
		ctx, item.OperationID, telegramTransport, destination,
	)
	if err != nil {
		return b.retryDelivery(ctx, item, err)
	}
	mode := "send"
	if found && !importantEvent(item.EventType) && keyboard == nil {
		mode = "edit"
		messageID, err = b.Client.EditMessage(ctx, b.Config.ChatID, messageID, text, nil)
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Code == 400 {
			mode = "send"
			messageID, err = b.Client.SendMessage(ctx, b.Config.ChatID, text, keyboard)
		}
	} else {
		messageID, err = b.Client.SendMessage(ctx, b.Config.ChatID, text, keyboard)
	}
	if err != nil {
		return b.retryDelivery(ctx, item, err)
	}
	if err := b.Store.CompleteNotification(
		ctx, item.ID, b.Config.LeaseOwner, telegramTransport, destination,
		messageID, mode, time.Now().UTC(),
	); err != nil {
		return err
	}
	return nil
}

func (b *Bridge) renderNotification(
	ctx context.Context,
	item history.NotificationItem,
) (string, *InlineKeyboardMarkup, error) {
	if item.ApprovalID != "" {
		approval, err := b.Store.ApprovalByID(ctx, item.ApprovalID, time.Now().UTC())
		if err != nil {
			return "", nil, err
		}
		return renderApproval(approval)
	}
	detail, err := b.Store.OperationDetails(ctx, item.OperationID, 20)
	if err != nil {
		return "", nil, err
	}
	if detail == nil {
		return "", nil, errors.New("notification operation is unavailable")
	}
	return renderOperation(detail), nil, nil
}

func (b *Bridge) retryDelivery(
	ctx context.Context,
	item history.NotificationItem,
	deliveryErr error,
) error {
	permanent := item.Attempts >= b.Config.MaxAttempts
	errorCode := "telegram_delivery"
	delay := retryDelay(item.Attempts)
	var apiErr *APIError
	if errors.As(deliveryErr, &apiErr) {
		permanent = permanent || apiErr.Permanent()
		errorCode = apiErr.CodeName()
		if apiErr.RetryAfter > delay {
			delay = minDuration(apiErr.RetryAfter, 5*time.Minute)
		}
	}
	return b.Store.RetryNotification(
		ctx, item.ID, b.Config.LeaseOwner, errorCode,
		time.Now().UTC().Add(delay), permanent,
	)
}

func (b *Bridge) handleUpdate(ctx context.Context, update Update) error {
	switch {
	case update.Message != nil:
		return b.handleMessage(ctx, update.ID, update.Message)
	case update.CallbackQuery != nil:
		return b.handleCallback(ctx, update.CallbackQuery)
	default:
		return nil
	}
}

func (b *Bridge) handleMessage(ctx context.Context, updateID int64, message *Message) error {
	if !b.authorizedMessage(message) {
		return nil
	}
	if len(message.Text) > 512 {
		_, err := b.Client.SendMessage(ctx, b.Config.ChatID, "Command is too long.", nil)
		return err
	}
	text := strings.TrimSpace(message.Text)
	if strings.HasPrefix(text, "/") {
		return b.handleCommand(ctx, updateID, text)
	}
	decision, ok := textualDecision(text)
	if !ok || message.ReplyToMessage == nil {
		return nil
	}
	if !b.rate.allow(time.Now()) {
		_, err := b.Client.SendMessage(ctx, b.Config.ChatID, "Too many control attempts; try again shortly.", nil)
		return err
	}
	destination := strconv.FormatInt(b.Config.ChatID, 10)
	approval, err := b.Store.PendingApprovalForDelivery(
		ctx, telegramTransport, destination, message.ReplyToMessage.ID, time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	if approval == nil {
		return nil
	}
	err = b.Store.DecideApprovalFromDelivery(
		ctx, approval.ID, decision, b.operatorIdentity(), telegramTransport,
		destination, message.ReplyToMessage.ID, time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	_, err = b.Client.SendMessage(ctx, b.Config.ChatID,
		fmt.Sprintf("Approval %s recorded as %s.", shortID(approval.ID), decision), nil)
	return err
}

func (b *Bridge) handleCommand(ctx context.Context, updateID int64, text string) error {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return nil
	}
	command := strings.ToLower(strings.SplitN(fields[0], "@", 2)[0])
	switch command {
	case "/start", "/help":
		_, err := b.Client.SendMessage(ctx, b.Config.ChatID, renderHelp(), nil)
		return err
	case "/status":
		if len(fields) > 2 || (len(fields) == 2 && !validStableID(fields[1])) {
			return b.sendUsage(ctx, "/status [PROJECT]")
		}
		project := ""
		if len(fields) == 2 {
			project = fields[1]
		}
		rows, err := b.Store.OperationSummaries(ctx, project, 10)
		if err != nil {
			return err
		}
		_, err = b.Client.SendMessage(ctx, b.Config.ChatID, renderStatus(rows), nil)
		return err
	case "/details":
		if len(fields) != 2 || !validOpaqueID(fields[1]) {
			return b.sendUsage(ctx, "/details OPERATION_ID")
		}
		return b.sendDetails(ctx, fields[1])
	case "/scan", "/update", "/deploy", "/rollback":
		if len(fields) != 2 || !validStableID(fields[1]) {
			return b.sendUsage(ctx, command+" PROJECT")
		}
		if !b.rate.allow(time.Now()) {
			_, err := b.Client.SendMessage(ctx, b.Config.ChatID, "Too many control attempts; try again shortly.", nil)
			return err
		}
		typeName := map[string]string{
			"/scan": "request_scan", "/update": "request_update",
			"/deploy": "request_deploy", "/rollback": "request_rollback",
		}[command]
		id, err := b.Store.EnqueueCommand(ctx, history.OperatorCommand{
			Type: typeName, Project: fields[1],
			IdempotencyKey: fmt.Sprintf("telegram-update-%d", updateID),
			RequestedBy:    b.operatorIdentity(), SourceUpdateID: updateID,
			CreatedAt: time.Now().UTC(),
		})
		if err != nil {
			return err
		}
		_, err = b.Client.SendMessage(ctx, b.Config.ChatID,
			fmt.Sprintf("Queued %s for %s (%s).", strings.TrimPrefix(command, "/"), fields[1], shortID(id)), nil)
		return err
	default:
		_, err := b.Client.SendMessage(ctx, b.Config.ChatID, renderHelp(), nil)
		return err
	}
}

func (b *Bridge) handleCallback(ctx context.Context, callback *CallbackQuery) error {
	if !b.authorizedCallback(callback) {
		return nil
	}
	parts := strings.Split(callback.Data, ":")
	if len(parts) == 2 && parts[0] == "details" && validOpaqueID(parts[1]) {
		_ = b.Client.AnswerCallback(ctx, callback.ID, "Opening details", false)
		return b.sendDetails(ctx, parts[1])
	}
	if len(parts) != 3 || parts[0] != "approval" || !validOpaqueID(parts[1]) {
		_ = b.Client.AnswerCallback(ctx, callback.ID, "Invalid action", true)
		return nil
	}
	decision := ""
	switch parts[2] {
	case "approve":
		decision = "approved"
	case "reject":
		decision = "rejected"
	default:
		_ = b.Client.AnswerCallback(ctx, callback.ID, "Invalid action", true)
		return nil
	}
	if !b.rate.allow(time.Now()) {
		_ = b.Client.AnswerCallback(ctx, callback.ID, "Too many attempts", true)
		return nil
	}
	destination := strconv.FormatInt(b.Config.ChatID, 10)
	err := b.Store.DecideApprovalFromDelivery(
		ctx, parts[1], decision, b.operatorIdentity(), telegramTransport,
		destination, callback.Message.ID, time.Now().UTC(),
	)
	if err != nil {
		approval, readErr := b.Store.ApprovalByID(ctx, parts[1], time.Now().UTC())
		if readErr == nil && approval != nil && approval.Status != "pending" {
			_ = b.Client.AnswerCallback(ctx, callback.ID, "Already processed", true)
			return nil
		}
		return err
	}
	_ = b.Client.AnswerCallback(ctx, callback.ID, "Decision recorded", false)
	return nil
}

func (b *Bridge) sendDetails(ctx context.Context, operationID string) error {
	detail, err := b.Store.OperationDetails(ctx, operationID, 20)
	if err != nil {
		return err
	}
	_, err = b.Client.SendMessage(ctx, b.Config.ChatID, renderDetails(detail), nil)
	return err
}

func (b *Bridge) sendUsage(ctx context.Context, usage string) error {
	_, err := b.Client.SendMessage(ctx, b.Config.ChatID, "Usage: "+usage, nil)
	return err
}

func (b *Bridge) authorizedMessage(message *Message) bool {
	return message != nil && message.Chat.ID == b.Config.ChatID && message.Chat.Type == "private" &&
		message.From != nil && message.From.ID == b.Config.UserID && !message.From.IsBot &&
		len(message.ForwardOrigin) == 0 && len(message.SenderChat) == 0
}

func (b *Bridge) authorizedCallback(callback *CallbackQuery) bool {
	return callback != nil && callback.Message != nil && callback.Message.Chat.ID == b.Config.ChatID &&
		callback.Message.Chat.Type == "private" && callback.From.ID == b.Config.UserID &&
		!callback.From.IsBot && callback.ID != ""
}

func (b *Bridge) operatorIdentity() string {
	return fmt.Sprintf("telegram:user:%d", b.Config.UserID)
}

func (b *Bridge) safeLog(message string) {
	if b.Log != nil {
		b.Log(message)
	}
}

type attemptLimiter struct {
	times []time.Time
}

func (l *attemptLimiter) allow(now time.Time) bool {
	cutoff := now.Add(-time.Minute)
	kept := l.times[:0]
	for _, value := range l.times {
		if value.After(cutoff) {
			kept = append(kept, value)
		}
	}
	l.times = kept
	if len(l.times) >= 6 {
		return false
	}
	l.times = append(l.times, now)
	return true
}

func textualDecision(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "approve", "да", "одобрить":
		return "approved", true
	case "no", "reject", "нет", "отклонить":
		return "rejected", true
	default:
		return "", false
	}
}

func validStableID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index, character := range value {
		valid := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.'
		if !valid || index == 0 && (character == '-' || character == '.' || character == '_') {
			return false
		}
	}
	return true
}

func validOpaqueID(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, character := range value {
		valid := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_'
		if !valid {
			return false
		}
	}
	return true
}

func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := time.Second
	for range attempt - 1 {
		delay *= 2
		if delay >= 5*time.Minute {
			return 5 * time.Minute
		}
	}
	return delay
}

func waitContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func minDuration(first, second time.Duration) time.Duration {
	if first < second {
		return first
	}
	return second
}
