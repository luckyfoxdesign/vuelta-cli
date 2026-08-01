package telegrambridge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/history"
)

func bridgeTestStore(t *testing.T) *history.Store {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := history.Open(context.Background(), filepath.Join(parent, "history.db"))
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

type fakeTelegram struct {
	server  *httptest.Server
	mu      sync.Mutex
	methods []string
	nextID  int64
}

func newFakeTelegram(t *testing.T) (*Client, *fakeTelegram) {
	t.Helper()
	fake := &fakeTelegram{nextID: 100}
	fake.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		method := request.URL.Path[strings.LastIndex(request.URL.Path, "/")+1:]
		fake.mu.Lock()
		fake.methods = append(fake.methods, method)
		fake.mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		switch method {
		case "sendMessage":
			fake.mu.Lock()
			fake.nextID++
			messageID := fake.nextID
			fake.mu.Unlock()
			_, _ = writer.Write([]byte(`{"ok":true,"result":{"message_id":` + intString(messageID) + `,"chat":{"id":42,"type":"private"}}}`))
		case "editMessageText":
			var payload struct {
				MessageID int64 `json:"message_id"`
			}
			_ = json.NewDecoder(request.Body).Decode(&payload)
			_, _ = writer.Write([]byte(`{"ok":true,"result":{"message_id":` + intString(payload.MessageID) + `,"chat":{"id":42,"type":"private"}}}`))
		case "answerCallbackQuery":
			_, _ = writer.Write([]byte(`{"ok":true,"result":true}`))
		case "getUpdates":
			_, _ = writer.Write([]byte(`{"ok":true,"result":[]}`))
		default:
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write([]byte(`{"ok":false,"error_code":400}`))
		}
	}))
	t.Cleanup(fake.server.Close)
	client, err := newClient(fake.server.URL, "123:test-token", fake.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client, fake
}

func (f *fakeTelegram) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.methods...)
}

func testBridge(t *testing.T, store *history.Store) (*Bridge, *fakeTelegram) {
	t.Helper()
	client, fake := newFakeTelegram(t)
	bridge := &Bridge{Store: store, Client: client, Config: Config{
		ChatID: 42, UserID: 7, Consumer: "test", LeaseOwner: "test-owner",
		PollTimeout: time.Second, LeaseDuration: time.Minute, MaxAttempts: 3,
		Retention: 24 * time.Hour,
	}}
	return bridge, fake
}

func TestDrainSendsThenEditsOneOperationMessage(t *testing.T) {
	store := bridgeTestStore(t)
	bridge, fake := testBridge(t, store)
	ctx := context.Background()
	now := time.Now().UTC()
	operationID, err := store.RecordOperation(ctx, history.Operation{
		ID: "operation-progress", ProjectName: "api", ProjectRoot: "/projects/api",
		Kind: "deploy", Status: "starting", At: now,
		Event: history.OperationEvent{Type: "deploy_started", Summary: "api deploy started",
			IdempotencyKey: "started", Notify: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.DrainNotifications(ctx, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordOperation(ctx, history.Operation{
		ID: operationID, ProjectName: "api", ProjectRoot: "/projects/api",
		Kind: "deploy", Status: "healthy", At: now,
		Event: history.OperationEvent{Type: "candidate_healthy", Summary: "api candidate healthy",
			IdempotencyKey: "healthy", Notify: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := bridge.DrainNotifications(ctx, 10); err != nil {
		t.Fatal(err)
	}
	calls := fake.calls()
	if len(calls) != 2 || calls[0] != "sendMessage" || calls[1] != "editMessageText" {
		t.Fatalf("Telegram calls = %v", calls)
	}
}

func TestCommandsAreAuthorizedTypedAndIdempotent(t *testing.T) {
	store := bridgeTestStore(t)
	bridge, _ := testBridge(t, store)
	ctx := context.Background()
	unauthorized := &Message{ID: 1, From: &User{ID: 8}, Chat: Chat{ID: 42, Type: "private"}, Text: "/deploy api"}
	if err := bridge.handleMessage(ctx, 10, unauthorized); err != nil {
		t.Fatal(err)
	}
	if command, err := store.ClaimOperatorCommand(ctx, time.Now().UTC()); err != nil || command != nil {
		t.Fatalf("unauthorized command = %#v, %v", command, err)
	}
	authorized := &Message{ID: 2, From: &User{ID: 7}, Chat: Chat{ID: 42, Type: "private"}, Text: "/deploy api"}
	for range 2 {
		if err := bridge.handleMessage(ctx, 11, authorized); err != nil {
			t.Fatal(err)
		}
	}
	command, err := store.ClaimOperatorCommand(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if command == nil || command.Type != "request_deploy" || command.Project != "api" ||
		command.RequestedBy != "telegram:user:7" || command.SourceUpdateID != 11 {
		t.Fatalf("typed command = %#v", command)
	}
	if err := store.CompleteCommand(ctx, command.ID, true, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if duplicate, err := store.ClaimOperatorCommand(ctx, time.Now().UTC()); err != nil || duplicate != nil {
		t.Fatalf("duplicate command = %#v, %v", duplicate, err)
	}
}

func TestApprovalCallbackMustMatchDeliveredMessage(t *testing.T) {
	store := bridgeTestStore(t)
	bridge, _ := testBridge(t, store)
	ctx := context.Background()
	now := time.Now().UTC()
	operationID, err := store.RecordOperation(ctx, history.Operation{
		ID: "approval-operation", Kind: "deploy", Status: "blocked", At: now,
		Event: history.OperationEvent{Type: "deploy_blocked", Summary: "deploy blocked", IdempotencyKey: "blocked"},
	})
	if err != nil {
		t.Fatal(err)
	}
	approval, err := store.CreateApprovalRequest(ctx, history.ApprovalRequest{
		ID: "approval-callback", OperationID: operationID, Type: "migration",
		SubjectFingerprint: "exact", SubjectSummary: `{"project":"api","commit":"0123456789abcdef","digest":"sha256:abc","migrations":["024.sql"]}`,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}, history.OperationEvent{Type: "migration_approval_required", Summary: "api approval required",
		IdempotencyKey: "approval", Notify: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.DrainNotifications(ctx, 10); err != nil {
		t.Fatal(err)
	}
	messageID, found, err := store.LastOperationMessage(ctx, operationID, "telegram", "42")
	if err != nil || !found {
		t.Fatalf("approval message = %d/%t, %v", messageID, found, err)
	}
	wrong := &CallbackQuery{ID: "wrong", From: User{ID: 7},
		Message: &Message{ID: messageID + 1, Chat: Chat{ID: 42, Type: "private"}},
		Data:    "approval:" + approval.ID + ":approve"}
	if err := bridge.handleCallback(ctx, wrong); err == nil {
		t.Fatal("wrong approval message was accepted")
	}
	correct := &CallbackQuery{ID: "correct", From: User{ID: 7},
		Message: &Message{ID: messageID, Chat: Chat{ID: 42, Type: "private"}},
		Data:    "approval:" + approval.ID + ":approve"}
	if err := bridge.handleCallback(ctx, correct); err != nil {
		t.Fatal(err)
	}
	decided, err := store.ApprovalByID(ctx, approval.ID, time.Now().UTC())
	if err != nil || decided == nil || decided.Status != "approved" {
		t.Fatalf("approval = %#v, %v", decided, err)
	}
}

func TestClientErrorsNeverContainTokenOrRequestURL(t *testing.T) {
	const secret = "123:very-secret-token"
	client, err := newClient("https://api.telegram.invalid", secret, &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return nil, errors.New(request.URL.String())
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetUpdates(context.Background(), 1, time.Second)
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "api.telegram.invalid") {
		t.Fatalf("unsafe client error: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func intString(value int64) string {
	return strings.TrimSpace(string(mustJSON(value)))
}

func mustJSON(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}
