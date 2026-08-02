package telegrambridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	TelegramAPIBase  = "https://api.telegram.org"
	maxResponseBytes = 1 << 20
	maxUpdates       = 25
)

// Client is the bounded Telegram Bot API surface used by the bridge.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient creates a production Telegram client. The token is retained only
// in memory and is never included in returned errors.
func NewClient(token string) (*Client, error) {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{
		Timeout:   35 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return newClient(TelegramAPIBase, token, client)
}

func newClient(baseURL, token string, client *http.Client) (*Client, error) {
	if !validBotToken(token) {
		return nil, errors.New("telegram bot token format is invalid")
	}
	if baseURL == "" || client == nil {
		return nil, errors.New("telegram API client configuration is incomplete")
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), token: token, http: client}, nil
}

func validBotToken(token string) bool {
	if len(token) < 3 || len(token) > 256 || !strings.Contains(token, ":") {
		return false
	}
	for _, character := range token {
		valid := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == ':' || character == '_' || character == '-'
		if !valid {
			return false
		}
	}
	return true
}

// APIError is a secret-free Telegram failure classification.
type APIError struct {
	Code       int
	RetryAfter time.Duration
	Transport  bool
}

func (e *APIError) Error() string {
	if e.Transport {
		return "Telegram transport request failed"
	}
	return fmt.Sprintf("Telegram API request failed with code %d", e.Code)
}

// Permanent reports failures that should not be retried for one outbox row.
func (e *APIError) Permanent() bool {
	return !e.Transport && e.Code >= 400 && e.Code < 500 && e.Code != http.StatusTooManyRequests
}

// CodeName is safe to persist in SQLite.
func (e *APIError) CodeName() string {
	if e.Transport {
		return "telegram_transport"
	}
	return fmt.Sprintf("telegram_http_%d", e.Code)
}

// Update contains only message and callback-query shapes requested by the
// bridge.
type Update struct {
	ID            int64          `json:"update_id"`
	Message       *Message       `json:"message,omitempty"`
	CallbackQuery *CallbackQuery `json:"callback_query,omitempty"`
}

// User is the bounded identity subset needed for authorization.
type User struct {
	ID    int64 `json:"id"`
	IsBot bool  `json:"is_bot"`
}

// Chat is the bounded chat subset needed for exact private-chat checks.
type Chat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

// Message is the bounded inbound/outbound Telegram message subset.
type Message struct {
	ID             int64           `json:"message_id"`
	From           *User           `json:"from,omitempty"`
	SenderChat     json.RawMessage `json:"sender_chat,omitempty"`
	Chat           Chat            `json:"chat"`
	Text           string          `json:"text,omitempty"`
	ForwardOrigin  json.RawMessage `json:"forward_origin,omitempty"`
	ReplyToMessage *Message        `json:"reply_to_message,omitempty"`
}

// CallbackQuery represents one inline approval action.
type CallbackQuery struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *Message `json:"message,omitempty"`
	Data    string   `json:"data,omitempty"`
}

// InlineKeyboardButton and InlineKeyboardMarkup are the only presentation
// structures emitted by this bridge.
type InlineKeyboardButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type InlineKeyboardMarkup struct {
	InlineKeyboard [][]InlineKeyboardButton `json:"inline_keyboard"`
}

type apiResponse[T any] struct {
	OK          bool   `json:"ok"`
	Result      T      `json:"result"`
	ErrorCode   int    `json:"error_code"`
	Description string `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// GetUpdates performs bounded long polling for only supported update types.
func (c *Client) GetUpdates(ctx context.Context, offset int64, timeout time.Duration) ([]Update, error) {
	seconds := int(timeout / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	if seconds > 25 {
		seconds = 25
	}
	payload := struct {
		Offset         int64    `json:"offset"`
		Limit          int      `json:"limit"`
		Timeout        int      `json:"timeout"`
		AllowedUpdates []string `json:"allowed_updates"`
	}{Offset: offset, Limit: maxUpdates, Timeout: seconds,
		AllowedUpdates: []string{"message", "callback_query"}}
	var updates []Update
	if err := c.call(ctx, "getUpdates", payload, &updates); err != nil {
		return nil, err
	}
	if updates == nil {
		updates = []Update{}
	}
	return updates, nil
}

// SendMessage creates one plain-text message with an optional reviewed inline
// keyboard.
func (c *Client) SendMessage(
	ctx context.Context,
	chatID int64,
	text string,
	keyboard *InlineKeyboardMarkup,
) (int64, error) {
	payload := struct {
		ChatID      int64                 `json:"chat_id"`
		Text        string                `json:"text"`
		ReplyMarkup *InlineKeyboardMarkup `json:"reply_markup,omitempty"`
		Protect     bool                  `json:"protect_content"`
	}{ChatID: chatID, Text: text, ReplyMarkup: keyboard, Protect: true}
	var message Message
	if err := c.call(ctx, "sendMessage", payload, &message); err != nil {
		return 0, err
	}
	if message.ID <= 0 {
		return 0, errors.New("telegram returned an invalid message ID")
	}
	return message.ID, nil
}

// EditMessage updates one existing bridge-owned operation message.
func (c *Client) EditMessage(
	ctx context.Context,
	chatID, messageID int64,
	text string,
	keyboard *InlineKeyboardMarkup,
) (int64, error) {
	payload := struct {
		ChatID      int64                 `json:"chat_id"`
		MessageID   int64                 `json:"message_id"`
		Text        string                `json:"text"`
		ReplyMarkup *InlineKeyboardMarkup `json:"reply_markup,omitempty"`
	}{ChatID: chatID, MessageID: messageID, Text: text, ReplyMarkup: keyboard}
	var message Message
	if err := c.call(ctx, "editMessageText", payload, &message); err != nil {
		return 0, err
	}
	if message.ID <= 0 {
		message.ID = messageID
	}
	return message.ID, nil
}

// AnswerCallback acknowledges a button press without leaking error details.
func (c *Client) AnswerCallback(ctx context.Context, callbackID, text string, alert bool) error {
	payload := struct {
		CallbackID string `json:"callback_query_id"`
		Text       string `json:"text,omitempty"`
		ShowAlert  bool   `json:"show_alert"`
	}{CallbackID: callbackID, Text: text, ShowAlert: alert}
	var result bool
	return c.call(ctx, "answerCallbackQuery", payload, &result)
}

func (c *Client) call(ctx context.Context, method string, payload, result any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode Telegram %s request: %w", method, err)
	}
	endpoint := c.baseURL + "/bot" + c.token + "/" + method
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build Telegram %s request", method)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return &APIError{Transport: true}
	}
	defer func() { _ = response.Body.Close() }()
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return &APIError{Transport: true}
	}
	if len(data) > maxResponseBytes {
		return errors.New("telegram response exceeded the size limit")
	}
	var envelope apiResponse[json.RawMessage]
	if err := json.Unmarshal(data, &envelope); err != nil {
		return errors.New("telegram returned malformed JSON")
	}
	if response.StatusCode >= 300 || !envelope.OK {
		code := envelope.ErrorCode
		if code == 0 {
			code = response.StatusCode
		}
		return &APIError{Code: code, RetryAfter: time.Duration(envelope.Parameters.RetryAfter) * time.Second}
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(envelope.Result, result); err != nil {
		return errors.New("telegram returned an invalid result")
	}
	return nil
}
