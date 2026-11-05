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

	if int(cfg.TeamDNSServerLastOctet) == 0 || cfg.TeamDomainName == "" || cfg.TeamDomainName == "auto" {
		slog.Info("Auto-discovering team DNS server and domain name",
			"external_mask", cfg.ExternalMask,
			"internal_mask", cfg.InternalMask,
		)
		discCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		res, discErr := DiscoverEnvironment(discCtx, cfg)
		cancel()
		if discErr != nil {
			slog.Warn("Initial DNS auto-discovery did not succeed (can retry via POST /discover)", "err", discErr)
		} else {
			if int(cfg.TeamDNSServerLastOctet) == 0 {
				cfg.TeamDNSServerLastOctet = FlexibleOctet(res.DNSServerLastOctet)
			}
			if cfg.TeamDomainName == "" || cfg.TeamDomainName == "auto" {
				cfg.TeamDomainName = res.TeamDomainName
			}
			slog.Info("Auto-discovered team DNS configuration",
				"dns_server_last_octet", int(cfg.TeamDNSServerLastOctet),
				"team_domain_name", cfg.TeamDomainName,
				"sample_host", res.SampleHost,
				"from_ip", res.DiscoveredFromIP,
			)
		}
	}

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
		"dns_octet", int(cfg.TeamDNSServerLastOctet),
	)

	httpServer := &http.Server{
		Addr:              cfg.HTTPListenAddr,
		Handler:           NewHTTPHandler(resolver),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
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
