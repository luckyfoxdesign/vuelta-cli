// Package notify sends run results via webhook and/or Telegram.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

// ProjectResult is the structured, secret-free summary of one workspace's
// pipeline run. It never carries raw test logs or diffs (part C §15): the
// full log stays in a local 0600 file (part D).
type ProjectResult struct {
	Project        string   `json:"project"`
	Status         string   `json:"status"` // updated | dry_run | skipped | failed
	Reason         string   `json:"reason,omitempty"`
	Branch         string   `json:"branch,omitempty"`
	AutofixApplied bool     `json:"autofix_applied"`
	Packages       []string `json:"packages,omitempty"`
	CVERefs        []string `json:"cve_refs,omitempty"`
}

// RunSummary is the final, whole-run notification sent after every
// workspace has been processed.
type RunSummary struct {
	Started  time.Time       `json:"started"`
	Finished time.Time       `json:"finished"`
	Results  []ProjectResult `json:"results"`
}

// Sender is the common, message-only notification boundary. A notifier may
// have zero configured transports; Send still succeeds so local logging
// remains the sole delivery mechanism.
type Sender interface {
	Send(message string) error
}

// Counts tallies results by status.
func (s RunSummary) Counts() (updated, skipped, failed int) {
	for _, r := range s.Results {
		switch r.Status {
		case "updated":
			updated++
		case "skipped", "dry_run":
			skipped++
		case "failed", "blocked":
			failed++
		}
	}
	return
}

// Notifier sends project and run summaries via the configured webhook
// and/or Telegram bot. Both are best-effort and independent: a failure to
// deliver to one does not block the other.
type Notifier struct {
	cfg    config.NotifyConfig
	client *http.Client
}

// New builds a Notifier from the notify.* config block.
func New(cfg config.NotifyConfig) *Notifier {
	return &Notifier{cfg: cfg, client: &http.Client{Timeout: 10 * time.Second}}
}

// SendProjectResult delivers a single workspace's outcome.
func (n *Notifier) SendProjectResult(ctx context.Context, r ProjectResult) error {
	return n.send(ctx, r, projectResultText(r))
}

// SendRunSummary delivers the final whole-run summary.
func (n *Notifier) SendRunSummary(ctx context.Context, s RunSummary) error {
	return n.send(ctx, s, runSummaryText(s))
}

// Send delivers a compact, already-secret-free message through every
// configured transport. It is useful to callers that only have a summary.
func (n *Notifier) Send(message string) error {
	return n.send(context.Background(), map[string]string{"message": message}, message)
}

func (n *Notifier) send(ctx context.Context, payload any, text string) error {
	var errs []error
	if n.cfg.WebhookURL != "" {
		if err := n.sendWebhook(ctx, payload); err != nil {
			errs = append(errs, err)
		}
	}
	if n.cfg.Telegram.BotToken != "" && n.cfg.Telegram.ChatID != "" {
		if err := n.sendTelegram(ctx, text); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (n *Notifier) sendWebhook(ctx context.Context, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build webhook request to %s: %s", redactURL(n.cfg.WebhookURL), redactInMessage(err.Error(), n.cfg.WebhookURL))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("deliver webhook to %s: %s", redactURL(n.cfg.WebhookURL), redactInMessage(err.Error(), n.cfg.WebhookURL))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook %s responded with status %d", redactURL(n.cfg.WebhookURL), resp.StatusCode)
	}
	return nil
}

func (n *Notifier) sendTelegram(ctx context.Context, text string) error {
	apiURL := telegramURL(n.cfg.Telegram.BotToken)
	form := telegramForm(n.cfg.Telegram.ChatID, text)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build telegram request: %s", redactInMessage(err.Error(), apiURL))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("deliver telegram message: %s", redactInMessage(err.Error(), apiURL))
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram API responded with status %d", resp.StatusCode)
	}
	return nil
}

func telegramURL(botToken string) string {
	return fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
}

func telegramForm(chatID, text string) url.Values {
	return url.Values{
		"chat_id": {chatID},
		"text":    {text},
	}
}

// redactInMessage strips any occurrence of secretURL (e.g. the full webhook
// or Telegram API URL, complete with embedded token) out of msg. Go's HTTP
// client wraps transport failures in a *url.Error that echoes the exact
// request URL, so redacting our own error text is not enough — the
// underlying error string carries the secret too.
func redactInMessage(msg, secretURL string) string {
	if secretURL == "" {
		return msg
	}
	return strings.ReplaceAll(msg, secretURL, redactURL(secretURL))
}

// redactURL strips everything after the host so a webhook token embedded
// in the path or query string (common for Slack/Discord-style webhooks)
// never ends up in an error message or log line (part C §15).
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<redacted>"
	}
	return u.Scheme + "://" + u.Host + "/<redacted>"
}

func projectResultText(r ProjectResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "vuelta: %s — %s", r.Project, r.Status)
	if r.Reason != "" {
		fmt.Fprintf(&b, " (%s)", r.Reason)
	}
	if r.Branch != "" {
		fmt.Fprintf(&b, "\nbranch: %s", r.Branch)
	}
	if len(r.Packages) > 0 {
		fmt.Fprintf(&b, "\npackages: %s", strings.Join(r.Packages, ", "))
	}
	if len(r.CVERefs) > 0 {
		fmt.Fprintf(&b, "\ncve: %s", strings.Join(r.CVERefs, ", "))
	}
	return b.String()
}

func runSummaryText(s RunSummary) string {
	groups := make(map[string][]string)
	for _, result := range s.Results {
		if result.AutofixApplied {
			groups["autofix"] = append(groups["autofix"], result.Project)
			continue
		}
		groups[result.Status] = append(groups[result.Status], result.Project)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "vuelta run завершён: %s", s.Finished.Format("02.01.2006 15:04"))
	write := func(prefix, status string) {
		if names := groups[status]; len(names) > 0 {
			fmt.Fprintf(&b, "\n%s: %s", prefix, strings.Join(names, ", "))
		}
	}
	write("✅ обновлено и запушено", "updated")
	write("⏭  без изменений", "skipped")
	write("⚠️ автофикс применён", "autofix")
	write("❌ провал", "failed")
	write("🛑 CVE-блок", "blocked")
	return b.String()
}
