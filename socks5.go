package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	repGeneralFailure        = 0x01
	repNotAllowedByRuleset   = 0x02
	repNetworkUnreachable    = 0x03
	repHostUnreachable       = 0x04
	repConnectionRefused     = 0x05
	repCommandNotSupported   = 0x07
	repAddressTypeNotSupport = 0x08
)

// ParseTeamUsername extracts the 1-based team number from a SOCKS5 username
// such as "team1", "team01", "Team6", or "6".
func ParseTeamUsername(username string, numberOfTeams int) (int, error) {
	u := strings.ToLower(strings.TrimSpace(username))
	u = strings.TrimPrefix(u, "team")
	u = strings.TrimPrefix(u, "-")
	u = strings.TrimPrefix(u, "_")
	if u == "" {
		return 0, fmt.Errorf("empty team identifier in username %q", username)
	}
	team, err := strconv.Atoi(u)
	if err != nil || team < 1 || team > numberOfTeams {
		return 0, fmt.Errorf("team %q out of range 1..%d", username, numberOfTeams)
	}
	return team, nil
}

type Socks5Server struct {
	cfg       Config
	resolver  *Resolver
	listeners []net.Listener
	mu        sync.Mutex
	wg        sync.WaitGroup
}

func NewSocks5Server(cfg Config, resolver *Resolver) *Socks5Server {
	return &Socks5Server{
		cfg:      cfg,
		resolver: resolver,
	}
}

// Start binds the multiplexed base port (base_socks_port) and all per-team ports
// (base_socks_port + 1 .. base_socks_port + number_of_teams).
func (s *Socks5Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for team := 0; team <= s.cfg.NumberOfTeams; team++ {
		port := s.cfg.BaseSocksPort + team
		addr := net.JoinHostPort(s.cfg.SocksListenHost, strconv.Itoa(port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			s.closeListenersLocked()
			return fmt.Errorf("listening on SOCKS5 port %d (team %d): %w", port, team, err)
		}
		s.listeners = append(s.listeners, ln)

		fixedTeam := team
		s.wg.Add(1)
		go func(l net.Listener, t int) {
			defer s.wg.Done()
			s.acceptLoop(ctx, l, t)
		}(ln, fixedTeam)
	}
	return nil
}

func (s *Socks5Server) Close() error {
	s.mu.Lock()
	s.closeListenersLocked()
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

func (s *Socks5Server) closeListenersLocked() {
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	s.listeners = nil
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
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConnection(ctx, c, fixedTeam)
		}(conn)
	}
}

func (s *Socks5Server) handleConnection(ctx context.Context, clientConn net.Conn, fixedTeam int) {
	defer clientConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(s.cfg.DialTimeout() + s.cfg.DNSTimeout()))

	team, err := s.negotiateAuth(clientConn, fixedTeam)
	if err != nil {
		slog.Debug("SOCKS5 auth failed", "fixed_team", fixedTeam, "remote", clientConn.RemoteAddr(), "err", err)
		return
	}

	targetHost, targetPort, atyp, cmd, err := s.readRequest(clientConn)
	if err != nil {
		slog.Debug("SOCKS5 invalid request", "team", team, "remote", clientConn.RemoteAddr(), "err", err)
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

	var translatedIP string
	if atyp == atypIPv4 {
		translatedIP, err = s.resolver.TranslateAndValidateIPv4(team, targetHost)
	} else {
		translatedIP, err = s.resolver.Resolve(ctx, team, targetHost)
	}
	if err != nil {
		if errors.Is(err, ErrDestinationNotAllowed) {
			slog.Warn("SOCKS5 rejected disallowed destination",
				"team", team,
				"requested_host", targetHost,
				"port", targetPort,
				"remote", clientConn.RemoteAddr(),
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
	dialer := net.Dialer{Timeout: s.cfg.DialTimeout()}
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
	defer upstreamConn.Close()

	if err := writeSocks5Reply(clientConn, repSucceeded); err != nil {
		return
	}

	slog.Info("SOCKS5 CONNECT established",
		"team", team,
		"requested_host", targetHost,
		"dest_addr", destAddr,
		"remote", clientConn.RemoteAddr(),
	)

	// Clear handshake deadline and pipe bytes with idle timeout refresh.
	_ = clientConn.SetDeadline(time.Time{})
	_ = upstreamConn.SetDeadline(time.Time{})
	pipeConnections(clientConn, upstreamConn, s.cfg.IdleTimeout())
}

func (s *Socks5Server) negotiateAuth(conn io.ReadWriter, fixedTeam int) (int, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}
	if header[0] != socks5Version {
		return 0, fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, err
	}

	hasNoAuth := false
	hasUserPass := false
	for _, m := range methods {
		switch m {
		case methodNoAuth:
			hasNoAuth = true
		case methodUserPass:
			hasUserPass = true
		}
	}

	// Dedicated per-team port (base_socks_port + N): prefer NoAuth (0x00), fallback to UserPass (0x02).
	if fixedTeam > 0 {
		if hasNoAuth {
			if _, err := conn.Write([]byte{socks5Version, methodNoAuth}); err != nil {
				return 0, err
			}
			return fixedTeam, nil
		}
		if hasUserPass {
			if _, err := conn.Write([]byte{socks5Version, methodUserPass}); err != nil {
				return 0, err
			}
			team, err := s.readUserPassAuth(conn, fixedTeam)
			if err != nil {
				return 0, err
			}
			return team, nil
		}
		_, _ = conn.Write([]byte{socks5Version, methodNoAcceptable})
		return 0, errors.New("client offered no supported auth methods")
	}

	// Multiplexed base port (base_socks_port): require Username/Password auth to identify the team.
	if !hasUserPass {
		_, _ = conn.Write([]byte{socks5Version, methodNoAcceptable})
		return 0, errors.New("base port requires RFC 1929 username/password authentication")
	}
	if _, err := conn.Write([]byte{socks5Version, methodUserPass}); err != nil {
		return 0, err
	}
	return s.readUserPassAuth(conn, 0)
}

func (s *Socks5Server) readUserPassAuth(conn io.ReadWriter, fixedTeam int) (int, error) {
	verAndULen := make([]byte, 2)
	if _, err := io.ReadFull(conn, verAndULen); err != nil {
		return 0, err
	}
	if verAndULen[0] != authVersion {
		_, _ = conn.Write([]byte{authVersion, 0x01})
		return 0, fmt.Errorf("unsupported RFC 1929 auth version %d", verAndULen[0])
	}
	uLen := int(verAndULen[1])
	uname := make([]byte, uLen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return 0, err
	}
	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return 0, err
	}
	pLen := int(pLenBuf[0])
	passwd := make([]byte, pLen)
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return 0, err
	}

	if fixedTeam > 0 && len(uname) == 0 {
		if _, err := conn.Write([]byte{authVersion, 0x00}); err != nil {
			return 0, err
		}
		return fixedTeam, nil
	}

	team, err := ParseTeamUsername(string(uname), s.cfg.NumberOfTeams)
	if err != nil || (fixedTeam > 0 && team != fixedTeam) {
		_, _ = conn.Write([]byte{authVersion, 0x01})
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("username team %d does not match port team %d", team, fixedTeam)
	}

	if _, err := conn.Write([]byte{authVersion, 0x00}); err != nil {
		return 0, err
	}
	return team, nil
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
		dLen := int(lenBuf[0])
		domainBuf := make([]byte, dLen)
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
		_ = writeSocks5Reply(conn, repAddressTypeNotSupport)
		return "", 0, atyp, cmd, fmt.Errorf("unsupported ATYP 0x%02x", atyp)
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
		0x00,     // RSV
		atypIPv4, // BND.ADDR type = IPv4
		0, 0, 0, 0,
		0, 0, // BND.PORT = 0
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
