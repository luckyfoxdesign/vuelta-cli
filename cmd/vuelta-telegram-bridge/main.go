// Command vuelta-telegram-bridge presents Vuelta's SQLite contract through
// one exactly authorized private Telegram chat.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/history"
	"github.com/luckyfoxdesign/vuelta/internal/telegrambridge"
)

const (
	tokenEnvironment = "VUELTA_TELEGRAM_BOT_TOKEN"
	chatEnvironment  = "VUELTA_TELEGRAM_CHAT_ID"
	userEnvironment  = "VUELTA_TELEGRAM_USER_ID"
)

func main() {
	if err := run(); err != nil {
		log.Printf("vuelta-telegram-bridge stopped: %v", err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("vuelta-telegram-bridge", flag.ContinueOnError)
	database := flags.String("database", "", "absolute path to Vuelta's protected SQLite database")
	consumer := flags.String("consumer", "telegram-primary", "stable cursor consumer ID")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *database == "" || len(flags.Args()) != 0 {
		return errors.New("usage: vuelta-telegram-bridge --database /absolute/path/history.db")
	}
	token, ok := os.LookupEnv(tokenEnvironment)
	if !ok || token == "" {
		return fmt.Errorf("%s is required", tokenEnvironment)
	}
	chatID, err := requiredPositiveID(chatEnvironment, true)
	if err != nil {
		return err
	}
	userID, err := requiredPositiveID(userEnvironment, false)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := history.Open(ctx, *database)
	if err != nil {
		return fmt.Errorf("open protected Vuelta state: %w", err)
	}
	defer func() { _ = store.Close() }()
	client, err := telegrambridge.NewClient(token)
	if err != nil {
		return err
	}
	bridge := &telegrambridge.Bridge{
		Store: store, Client: client,
		Config: telegrambridge.Config{
			ChatID: chatID, UserID: userID, Consumer: *consumer,
			LeaseOwner:  fmt.Sprintf("telegram-bridge-%d", os.Getpid()),
			PollTimeout: 10 * time.Second, LeaseDuration: 45 * time.Second,
			MaxAttempts: 8, Retention: 30 * 24 * time.Hour,
		},
		Log: func(message string) { log.Print(message) },
	}
	return bridge.Run(ctx)
}

func requiredPositiveID(name string, allowNegative bool) (int64, error) {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return 0, fmt.Errorf("%s is required", name)
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed == 0 || !allowNegative && parsed < 0 {
		return 0, fmt.Errorf("%s must be a valid Telegram ID", name)
	}
	return parsed, nil
}
