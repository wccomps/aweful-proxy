package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	configPath := flag.String("config", "/etc/aweful-proxy/config.json", "Path to aweful-proxy JSON configuration file")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	logLevel := slog.LevelInfo
	if *debug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		slog.Error("Invalid configuration", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	resolver := NewResolver(cfg)
	socksServer := NewSocks5Server(cfg, resolver)
	if err := socksServer.Start(ctx); err != nil {
		slog.Error("Failed to start SOCKS5 listeners", "err", err)
		os.Exit(1)
	}
	slog.Info("Started SOCKS5 listeners",
		"base_port", cfg.BaseSocksPort,
		"team_ports_start", cfg.BaseSocksPort+1,
		"team_ports_end", cfg.BaseSocksPort+cfg.NumberOfTeams,
		"teams", cfg.NumberOfTeams,
		"domain", cfg.TeamDomainName,
	)

	httpServer := &http.Server{
		Addr:              cfg.HTTPListenAddr,
		Handler:           NewHTTPHandler(cfg),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		slog.Info("Starting HTTP management server", "addr", cfg.HTTPListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP management server failed", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	slog.Info("Shutting down aweful-proxy")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	_ = socksServer.Close()
}
