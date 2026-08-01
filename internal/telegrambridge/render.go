package telegrambridge

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/history"
)

const maxTelegramTextRunes = 3500

func renderOperation(detail *history.SafeOperationDetail) string {
	if detail == nil {
		return "Vuelta operation is unavailable."
	}
	project := detail.Operation.Project
	if project == "" {
		project = "vuelta"
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s · %s %s\n\n", project, detail.Operation.Kind, shortID(detail.Operation.ID))
	start := len(detail.Events) - 8
	if start < 0 {
		start = 0
	}
	for index := len(detail.Events) - 1; index >= start; index-- {
		event := detail.Events[index]
		fmt.Fprintf(&builder, "%s %s\n", eventIcon(event.Type), singleLine(event.Summary, 240))
	}
	if len(detail.Events) == 0 {
		fmt.Fprintf(&builder, "%s %s\n", statusIcon(detail.Operation.Status), detail.Operation.Status)
	}
	return boundedText(strings.TrimSpace(builder.String()))
}

func renderStatus(rows []history.OperationSummary) string {
	if len(rows) == 0 {
		return "Vuelta: no recorded operations."
	}
	var builder strings.Builder
	builder.WriteString("Vuelta status\n\n")
	for _, row := range rows {
		project := row.Project
		if project == "" {
			project = "vuelta"
		}
		fmt.Fprintf(&builder, "%s %s · %s · %s\n  %s · %s\n",
			statusIcon(row.Status), project, row.Kind, row.Status,
			shortID(row.ID), row.UpdatedAt.Local().Format("02 Jan 15:04"))
	}
	return boundedText(strings.TrimSpace(builder.String()))
}

func renderDetails(detail *history.SafeOperationDetail) string {
	if detail == nil {
		return "Operation not found."
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s\n\nOperation: %s\nState: %s\nUpdated: %s\n",
		renderOperation(detail), detail.Operation.ID, detail.Operation.Status,
		detail.Operation.UpdatedAt.Local().Format(time.RFC3339))
	return boundedText(builder.String())
}

type migrationSubject struct {
	Project    string   `json:"project"`
	Commit     string   `json:"commit"`
	Digest     string   `json:"digest"`
	Migrations []string `json:"migrations"`
}

func renderApproval(request *history.ApprovalRequest) (string, *InlineKeyboardMarkup, error) {
	if request == nil {
		return "", nil, fmt.Errorf("approval is unavailable")
	}
	if request.Status != "pending" {
		return fmt.Sprintf("Approval %s is %s.", shortID(request.ID), request.Status), nil, nil
	}
	var subject migrationSubject
	if err := json.Unmarshal([]byte(request.SubjectSummary), &subject); err != nil {
		return "", nil, fmt.Errorf("decode bounded approval subject: %w", err)
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "⚠️ %s · migration approval required\n\n", singleLine(subject.Project, 80))
	fmt.Fprintf(&builder, "Commit: %s\n", shortRevision(subject.Commit))
	fmt.Fprintf(&builder, "Image: %s\n", shortDigest(subject.Digest))
	builder.WriteString("Changed migrations:\n")
	if len(subject.Migrations) == 0 {
		builder.WriteString("- unknown\n")
	}
	for index, migration := range subject.Migrations {
		if index == 10 {
			builder.WriteString("- …\n")
			break
		}
		fmt.Fprintf(&builder, "- %s\n", singleLine(migration, 180))
	}
	builder.WriteString("\nExecution gate: blocked; no migration adapter is available.\n")
	fmt.Fprintf(&builder, "Expires: %s", request.ExpiresAt.Local().Format(time.RFC3339))
	keyboard := &InlineKeyboardMarkup{InlineKeyboard: [][]InlineKeyboardButton{{
		{Text: "Approve exact release", CallbackData: "approval:" + request.ID + ":approve"},
		{Text: "Reject", CallbackData: "approval:" + request.ID + ":reject"},
	}, {
		{Text: "Details", CallbackData: "details:" + request.OperationID},
	}}}
	return boundedText(builder.String()), keyboard, nil
}

func renderHelp() string {
	return strings.Join([]string{
		"Vuelta commands:",
		"/status [PROJECT]",
		"/scan PROJECT",
		"/update PROJECT",
		"/deploy PROJECT",
		"/rollback PROJECT",
		"/details OPERATION_ID",
	}, "\n")
}

func eventIcon(eventType string) string {
	lower := strings.ToLower(eventType)
	switch {
	case strings.Contains(lower, "fail"), strings.Contains(lower, "blocked"):
		return "❌"
	case strings.Contains(lower, "approval"):
		return "⚠️"
	case strings.Contains(lower, "complete"), strings.Contains(lower, "succeed"),
		strings.Contains(lower, "deployed"), strings.Contains(lower, "switched"):
		return "✅"
	case strings.Contains(lower, "start"), strings.Contains(lower, "building"),
		strings.Contains(lower, "pulling"), strings.Contains(lower, "healthy"):
		return "⏳"
	default:
		return "○"
	}
}

func statusIcon(status string) string {
	lower := strings.ToLower(status)
	switch {
	case strings.Contains(lower, "fail"), strings.Contains(lower, "blocked"),
		strings.Contains(lower, "reject"):
		return "❌"
	case strings.Contains(lower, "complete"), strings.Contains(lower, "succeed"),
		strings.Contains(lower, "deployed"):
		return "✅"
	default:
		return "⏳"
	}
}

func importantEvent(eventType string) bool {
	lower := strings.ToLower(eventType)
	return strings.Contains(lower, "approval") || strings.Contains(lower, "failed") ||
		strings.Contains(lower, "completed") || strings.Contains(lower, "rollback")
}

func shortID(value string) string {
	if len(value) <= 8 {
		return value
	}
	return value[:8]
}

func shortRevision(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func shortDigest(value string) string {
	if len(value) <= 20 {
		return value
	}
	return value[:20] + "…"
}

func singleLine(value string, limit int) string {
	value = strings.Map(func(character rune) rune {
		if character == '\n' || character == '\r' || character == '\t' || character < 0x20 {
			return ' '
		}
		return character
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	return boundRunes(value, limit)
}

func boundedText(value string) string { return boundRunes(value, maxTelegramTextRunes) }

func boundRunes(value string, limit int) string {
	characters := []rune(value)
	if len(characters) <= limit {
		return value
	}
	if limit <= 1 {
		return "…"
	}
	return string(characters[:limit-1]) + "…"
}
