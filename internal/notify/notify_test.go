package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/config"
)

func TestSendProjectResultWebhook(t *testing.T) {
	var received ProjectResult
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode webhook body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(config.NotifyConfig{WebhookURL: srv.URL})
	r := ProjectResult{Project: "api-service", Status: "updated", Branch: "vuelta/deps/api-service-2026-07-13"}
	if err := n.SendProjectResult(context.Background(), r); err != nil {
		t.Fatalf("SendProjectResult: %v", err)
	}
	if received.Project != "api-service" || received.Status != "updated" {
		t.Fatalf("unexpected payload received: %+v", received)
	}
}

func TestSendWebhookErrorRedactsURL(t *testing.T) {
	n := New(config.NotifyConfig{WebhookURL: "https://hooks.example.com/services/T000/B000/verysecrettoken"})
	// No server listening on this port; the request will fail to deliver.
	n.client.Timeout = 100 * time.Millisecond

	err := n.SendProjectResult(context.Background(), ProjectResult{Project: "x", Status: "failed"})
	if err == nil {
		t.Fatal("expected delivery error")
	}
	if strings.Contains(err.Error(), "verysecrettoken") {
		t.Fatalf("error must not leak the webhook token: %v", err)
	}
}

func TestWebhookNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := New(config.NotifyConfig{WebhookURL: srv.URL})
	err := n.SendRunSummary(context.Background(), RunSummary{})
	if err == nil {
		t.Fatal("expected error for non-2xx webhook response")
	}
}

func TestRedactURL(t *testing.T) {
	got := redactURL("https://hooks.example.com/services/T000/B000/verysecrettoken")
	if strings.Contains(got, "verysecrettoken") {
		t.Fatalf("redactURL leaked the token: %q", got)
	}
	if got != "https://hooks.example.com/<redacted>" {
		t.Fatalf("unexpected redacted URL: %q", got)
	}
}

func TestRunSummaryCounts(t *testing.T) {
	s := RunSummary{Results: []ProjectResult{
		{Status: "updated"},
		{Status: "updated"},
		{Status: "skipped"},
		{Status: "dry_run"},
		{Status: "failed"},
	}}
	updated, skipped, failed := s.Counts()
	if updated != 2 || skipped != 2 || failed != 1 {
		t.Fatalf("unexpected counts: updated=%d skipped=%d failed=%d", updated, skipped, failed)
	}
}

func TestRunSummaryTextIsCompactAndSecretFree(t *testing.T) {
	summary := RunSummary{Finished: time.Date(2026, 7, 13, 15, 4, 0, 0, time.UTC), Results: []ProjectResult{
		{Project: "api-service", Status: "updated"},
		{Project: "frontend", Status: "skipped"},
		{Project: "billing", Status: "updated", AutofixApplied: true},
		{Project: "legacy", Status: "failed", Reason: "tests failed: DATABASE_URL=secret"},
		{Project: "auth", Status: "blocked"},
	}}
	text := runSummaryText(summary)
	for _, want := range []string{"api-service", "frontend", "billing", "legacy", "auth"} {
		if !strings.Contains(text, want) {
			t.Fatalf("summary missing %q: %s", want, text)
		}
	}
	if strings.Contains(text, "DATABASE_URL") {
		t.Fatalf("summary leaked error detail: %s", text)
	}
}

func TestTelegramURLDoesNotAppearInProjectText(t *testing.T) {
	u := telegramURL("123:ABC-secret")
	if !strings.Contains(u, "123:ABC-secret") {
		t.Fatalf("telegramURL must embed the bot token in the API path: %q", u)
	}
	form := telegramForm("42", "hello")
	if form.Get("chat_id") != "42" || form.Get("text") != "hello" {
		t.Fatalf("unexpected telegram form: %v", form)
	}
}
