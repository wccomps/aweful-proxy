package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	socks5Version = 0x05
	authVersion   = 0x01

	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded             = 0x00
	repNotAllowedByRuleset   = 0x02
	repNetworkUnreachable    = 0x03
	repHostUnreachable       = 0x04
	repConnectionRefused     = 0x05
	repCommandNotSupported   = 0x07
	repAddressTypeNotSupport = 0x08

	maxConcurrentConns = 1024
	maxConnsPerClient  = 128
)

func ParseTeamUsername(username string, numberOfTeams int) (int, error) {
	u := strings.ToLower(strings.TrimSpace(username))
	if after, ok := strings.CutPrefix(u, "team"); ok {
		if strings.HasPrefix(after, "-") || strings.HasPrefix(after, "_") {
			after = after[1:]
		}
		u = after
	}
	if u == "" || strings.HasPrefix(u, "+") || strings.HasPrefix(u, "-") {
		return 0, fmt.Errorf("invalid team identifier in username %q", username)
	}
	team, err := strconv.Atoi(u)
	if err != nil || team < 0 || team > numberOfTeams {
		return 0, fmt.Errorf("team %q out of range 0..%d", username, numberOfTeams)
	}
	return team, nil
}

type teamListener struct {
	addr string
	ln   net.Listener
}

type Socks5Server struct {
	resolver    *Resolver
	baseCtx     context.Context
	closed      bool
	listeners   map[int]teamListener
	activeConns map[net.Conn]struct{}
	clientConns map[string]int
	connSem     chan struct{}
	mu          sync.Mutex
	wg          sync.WaitGroup
}

func NewSocks5Server(resolver *Resolver) *Socks5Server {
	return &Socks5Server{
		resolver:    resolver,
		listeners:   make(map[int]teamListener),
		activeConns: make(map[net.Conn]struct{}),
		clientConns: make(map[string]int),
		connSem:     make(chan struct{}, maxConcurrentConns),
	}
}

func (s *Socks5Server) Start(ctx context.Context) error {
	s.mu.Lock()
	s.baseCtx = ctx
	s.mu.Unlock()
	return s.Reconcile(s.resolver.ConfigSnapshot())
}

func (s *Socks5Server) Reconcile(cfg Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("SOCKS5 server is closed")
	}
	ctx := s.baseCtx
	if ctx == nil {
		ctx = context.Background()
	}

	newlyOpened := make(map[int]teamListener)
	for team := 0; team <= cfg.NumberOfTeams; team++ {
		port := cfg.BaseSocksPort + team
		wantAddr := net.JoinHostPort(cfg.SocksListenHost, strconv.Itoa(port))
		if existing, exists := s.listeners[team]; exists && existing.addr == wantAddr {
			continue
		}
		ln, err := net.Listen("tcp", wantAddr)
		if err != nil {
			for _, tl := range newlyOpened {
				_ = tl.ln.Close()
			}
			return fmt.Errorf("listening on SOCKS5 port %d (team %d): %w", port, team, err)
		}
		newlyOpened[team] = teamListener{addr: wantAddr, ln: ln}
	}

	for team, tl := range s.listeners {
		if _, replaced := newlyOpened[team]; replaced || team > cfg.NumberOfTeams {
			_ = tl.ln.Close()
			delete(s.listeners, team)
		}
	}
	for team, tl := range newlyOpened {
		s.listeners[team] = tl
	}

	s.resolver.UpdateConfig(cfg)

	for team, tl := range newlyOpened {
		fixedTeam := team
		s.wg.Add(1)
		go func(l net.Listener, t int) {
			defer s.wg.Done()
			s.acceptLoop(ctx, l, t)
		}(tl.ln, fixedTeam)
	}
	return nil
}

func (s *Socks5Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.closeLocked()
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

func (s *Socks5Server) closeLocked() {
	for team, tl := range s.listeners {
		_ = tl.ln.Close()
		delete(s.listeners, team)
	}
	for conn := range s.activeConns {
		_ = conn.Close()
	}
}

func (s *Socks5Server) trackConn(conn net.Conn, active bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if active {
		if s.closed {
			return false
		}
		s.activeConns[conn] = struct{}{}
	} else {
		delete(s.activeConns, conn)
	}
	return true
}

func (s *Socks5Server) acquireClientConn(conn net.Conn) (string, bool) {
	clientIP := normalizeIPString(conn.RemoteAddr().String())
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", false
	}
	if clientIP != "" && s.clientConns[clientIP] >= maxConnsPerClient {
		return "", false
	}
	if clientIP != "" {
		s.clientConns[clientIP]++
	}
	s.activeConns[conn] = struct{}{}
	return clientIP, true
}

func (s *Socks5Server) releaseClientConn(conn net.Conn, clientIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.activeConns, conn)
	if clientIP != "" {
		if n := s.clientConns[clientIP] - 1; n <= 0 {
			delete(s.clientConns, clientIP)
		} else {
			s.clientConns[clientIP] = n
		}
	}
}

func (s *Socks5Server) acceptLoop(ctx context.Context, ln net.Listener, fixedTeam int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Warn("SOCKS5 accept error", "team", fixedTeam, "err", err)
			continue
		}
		select {
		case s.connSem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		clientIP, ok := s.acquireClientConn(conn)
		if !ok {
			<-s.connSem
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func(c net.Conn, ip string) {
			defer func() {
				s.releaseClientConn(c, ip)
				<-s.connSem
				s.wg.Done()
			}()
			s.handleConnection(ctx, c, fixedTeam)
		}(conn, clientIP)
	}
}

func (s *Socks5Server) handleConnection(ctx context.Context, clientConn net.Conn, fixedTeam int) {
	defer clientConn.Close()
	cfg := s.resolver.ConfigSnapshot()
	remoteStr := clientConn.RemoteAddr().String()
	if !IsClientAllowed(cfg, remoteStr) {
		slog.Warn("SOCKS5 rejected disallowed client IP", "remote", remoteStr, "fixed_team", fixedTeam)
		return
	}
	_ = clientConn.SetDeadline(time.Now().Add(cfg.DialTimeout() + cfg.DNSTimeout()))

	team, authUser, err := s.negotiateAuth(clientConn, fixedTeam, cfg, remoteStr)
	if err != nil {
		slog.Debug("SOCKS5 auth failed", "fixed_team", fixedTeam, "remote", remoteStr, "err", err)
		return
	}

	targetHost, targetPort, atyp, cmd, err := s.readRequest(clientConn)
	if err != nil {
		slog.Debug("SOCKS5 invalid request", "team", team, "remote", remoteStr, "err", err)
		return
	}

	if cmd != cmdConnect {
		_ = writeSocks5Reply(clientConn, repCommandNotSupported)
		return
	}
	if atyp != atypIPv4 && atyp != atypDomain {
		_ = writeSocks5Reply(clientConn, repAddressTypeNotSupport)
		return
	}

	translatedIP, err := s.resolver.Resolve(ctx, team, targetHost)
	if err != nil {
		if errors.Is(err, ErrDestinationNotAllowed) {
			slog.Warn("SOCKS5 rejected disallowed destination",
				"team", team,
				"user", authUser,
				"requested_host", targetHost,
				"port", targetPort,
				"remote", remoteStr,
			)
			_ = writeSocks5Reply(clientConn, repNotAllowedByRuleset)
			return
		}
		slog.Debug("SOCKS5 host resolution failed",
			"team", team,
			"requested_host", targetHost,
			"err", err,
		)
		_ = writeSocks5Reply(clientConn, repHostUnreachable)
		return
	}

	destAddr := net.JoinHostPort(translatedIP, strconv.Itoa(int(targetPort)))
	dialer := net.Dialer{Timeout: cfg.DialTimeout()}
	upstreamConn, err := dialer.DialContext(ctx, "tcp", destAddr)
	if err != nil {
		slog.Debug("SOCKS5 upstream dial failed",
			"team", team,
			"requested_host", targetHost,
			"dest_addr", destAddr,
			"err", err,
		)
		_ = writeSocks5Reply(clientConn, classifyDialError(err))
		return
	}
	if !s.trackConn(upstreamConn, true) {
		_ = upstreamConn.Close()
		return
	}
	defer func() {
		s.trackConn(upstreamConn, false)
		_ = upstreamConn.Close()
	}()

	if err := writeSocks5Reply(clientConn, repSucceeded); err != nil {
		return
	}

	slog.Info("SOCKS5 CONNECT established",
		"team", team,
		"user", authUser,
		"requested_host", targetHost,
		"dest_addr", destAddr,
		"remote", remoteStr,
	)

	_ = clientConn.SetDeadline(time.Time{})
	_ = upstreamConn.SetDeadline(time.Time{})
	pipeConnections(clientConn, upstreamConn, cfg.IdleTimeout())
}

func (s *Socks5Server) negotiateAuth(conn io.ReadWriter, fixedTeam int, cfg Config, remoteAddr string) (int, string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, "", err
	}
	if header[0] != socks5Version {
		return 0, "", fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, "", err
	}

	auth := s.resolver.Auth()
	if slices.Contains(methods, methodNoAuth) && (fixedTeam > 0 || !slices.Contains(methods, methodUserPass)) {
		if authUser, ok := CheckSocksAuth(auth, cfg, remoteAddr, "", ""); ok {
			if _, err := conn.Write([]byte{socks5Version, methodNoAuth}); err != nil {
				return 0, "", err
			}
			return fixedTeam, authUser, nil
		}
	}

	if slices.Contains(methods, methodUserPass) {
		if _, err := conn.Write([]byte{socks5Version, methodUserPass}); err != nil {
			return 0, "", err
		}
		return s.readUserPassAuth(conn, fixedTeam, cfg, auth, remoteAddr)
	}

	_, _ = conn.Write([]byte{socks5Version, methodNoAcceptable})
	return 0, "", errors.New("client offered no acceptable or authorized auth methods")
}

func (s *Socks5Server) readUserPassAuth(conn io.ReadWriter, fixedTeam int, cfg Config, auth *Authenticator, remoteAddr string) (int, string, error) {
	verAndULen := make([]byte, 2)
	if _, err := io.ReadFull(conn, verAndULen); err != nil {
		return 0, "", err
	}
	if verAndULen[0] != authVersion {
		_, _ = conn.Write([]byte{authVersion, 0x01})
		return 0, "", fmt.Errorf("unsupported RFC 1929 auth version %d", verAndULen[0])
	}
	uLen := int(verAndULen[1])
	uname := make([]byte, uLen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return 0, "", err
	}
	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return 0, "", err
	}
	passwd := make([]byte, int(pLenBuf[0]))
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return 0, "", err
	}

	team, candidateUser, err := parseTeamAndUser(string(uname), fixedTeam, cfg.NumberOfTeams)
	if err != nil {
		_, _ = conn.Write([]byte{authVersion, 0x01})
		return 0, "", err
	}

	authUser, ok := CheckSocksAuth(auth, cfg, remoteAddr, candidateUser, string(passwd))
	if !ok {
		_, _ = conn.Write([]byte{authVersion, 0x01})
		return 0, "", errors.New("SOCKS5 SSO authentication failed")
	}

	if _, err := conn.Write([]byte{authVersion, 0x00}); err != nil {
		return 0, "", err
	}
	return team, authUser, nil
}

func parseTeamAndUser(rawUsername string, fixedTeam, numberOfTeams int) (int, string, error) {
	trimmed := strings.TrimSpace(rawUsername)
	if trimmed == "" {
		if fixedTeam > 0 {
			return fixedTeam, "", nil
		}
		return 0, "", errors.New("empty username on base port")
	}
	if teamPart, userPart, ok := strings.Cut(trimmed, "+"); ok {
		if team, err := ParseTeamUsername(teamPart, numberOfTeams); err == nil {
			if fixedTeam > 0 && team != fixedTeam {
				return 0, "", fmt.Errorf("username team %d does not match port team %d", team, fixedTeam)
			}
			return team, strings.TrimSpace(userPart), nil
		}
	}
	if team, err := ParseTeamUsername(trimmed, numberOfTeams); err == nil {
		if fixedTeam > 0 && team != fixedTeam {
			return 0, "", fmt.Errorf("username team %d does not match port team %d", team, fixedTeam)
		}
		return team, trimmed, nil
	}
	if fixedTeam > 0 {
		return fixedTeam, trimmed, nil
	}
	return 0, "", fmt.Errorf("invalid team identifier in username %q", rawUsername)
}

func (s *Socks5Server) readRequest(conn io.ReadWriter) (host string, port uint16, atyp byte, cmd byte, err error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", 0, 0, 0, err
	}
	if hdr[0] != socks5Version {
		return "", 0, 0, 0, fmt.Errorf("invalid SOCKS5 request version %d", hdr[0])
	}
	cmd = hdr[1]
	atyp = hdr[3]

	switch atyp {
	case atypIPv4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", 0, atyp, cmd, err
		}
		host = net.IP(ipBuf).String()
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", 0, atyp, cmd, err
		}
		domainBuf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return "", 0, atyp, cmd, err
		}
		host = string(domainBuf)
	case atypIPv6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return "", 0, atyp, cmd, err
		}
		host = net.IP(ipBuf).String()
	default:
		return "", 0, atyp, cmd, nil
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, atyp, cmd, err
	}
	port = binary.BigEndian.Uint16(portBuf)
	return host, port, atyp, cmd, nil
}

func writeSocks5Reply(w io.Writer, rep byte) error {
	reply := []byte{
		socks5Version,
		rep,
		0x00,
		atypIPv4,
		0, 0, 0, 0,
		0, 0,
	}
	_, err := w.Write(reply)
	return err
}

func classifyDialError(err error) byte {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused"):
		return repConnectionRefused
	case strings.Contains(msg, "network is unreachable"):
		return repNetworkUnreachable
	default:
		return repHostUnreachable
	}
}

type closeWriter interface {
	CloseWrite() error
}

func pipeConnections(a, b net.Conn, idleTimeout time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyOneWay := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			if idleTimeout > 0 {
				_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
			}
			n, rErr := src.Read(buf)
			if n > 0 {
				if idleTimeout > 0 {
					_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
				}
				if _, wErr := dst.Write(buf[:n]); wErr != nil {
					break
				}
			}
			if rErr != nil {
				break
			}
		}
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}

	go copyOneWay(a, b)
	go copyOneWay(b, a)
	wg.Wait()
}
