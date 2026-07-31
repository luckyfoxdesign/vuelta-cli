package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/luckyfoxdesign/vuelta/internal/gateway"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "vuelta-gateway:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "protected gateway config path")
	checkURL := flag.String("check", "", "check one loopback route")
	flag.Parse()
	if flag.NArg() != 0 || (*configPath == "") == (*checkURL == "") {
		return errors.New("exactly one of --config or --check is required")
	}
	if *checkURL != "" {
		return check(*checkURL)
	}
	if *configPath == "" {
		return errors.New("--config is required")
	}
	config, err := gateway.Load(*configPath)
	if err != nil {
		return err
	}
	handler, err := gateway.NewHandler(config)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: config.Listen, Handler: handler,
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second,
	}
	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	reloads := make(chan os.Signal, 1)
	signal.Notify(reloads, syscall.SIGHUP)
	defer signal.Stop(reloads)
	go func() {
		for range reloads {
			candidate, loadErr := gateway.Load(*configPath)
			if loadErr == nil && candidate.Listen == config.Listen {
				_ = handler.Reload(candidate)
			}
		}
	}()
	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func check(rawURL string) error {
	target, err := url.Parse(rawURL)
	if err != nil || target.Scheme != "http" ||
		(target.Hostname() != "127.0.0.1" && target.Hostname() != "localhost") ||
		target.Port() == "" || target.User != nil {
		return errors.New("check URL must be loopback HTTP with an explicit port")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(target.String())
	if err != nil {
		return errors.New("gateway check failed")
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return fmt.Errorf("gateway check returned HTTP %d", response.StatusCode)
	}
	return nil
}
