package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookieName = "aweful_session"
	oauthCookieName   = "aweful_oauth_state"
	oauthStateTTL     = 5 * time.Minute
	defaultSessionTTL = 12 * time.Hour
)

var errForbiddenGroup = errors.New("user does not belong to an authorized staff group")

var defaultStaffGroups = []string{
	"WCComps_Discord_Admin",
	"WCComps_GoldTeam",
	"WCComps_WhiteTeam",
	"WCComps_WhiteTeam_Lead",
	"WCComps_OrangeTeam",
	"WCComps_OrangeTeam_Lead",
	"WCComps_RedTeam",
	"WCComps_Ticketing_Admin",
	"WCComps_Ticketing_Support",
}

var defaultTrustedProxyCIDRs = []string{
	"127.0.0.1/32",
	"::1/128",
}

type AuthIdentity struct {
	Username  string   `json:"u"`
	Groups    []string `json:"g"`
	ExpiresAt int64    `json:"exp"`
}

type ipLease struct {
	username  string
	expiresAt time.Time
}

type oauthStatePayload struct {
	Nonce        string `json:"n"`
	CodeVerifier string `json:"cv"`
	Next         string `json:"next"`
	IssuedAt     int64  `json:"iat"`
}

type Authenticator struct {
	mu         sync.RWMutex
	secret     []byte
	leases     map[string]ipLease
	httpClient *http.Client
}

func NewAuthenticator(secretStr string) *Authenticator {
	var secret []byte
	if strings.TrimSpace(secretStr) != "" {
		sum := sha256.Sum256([]byte(secretStr))
		secret = sum[:]
	} else {
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
	}
	return &Authenticator{
		secret: secret,
		leases: make(map[string]ipLease),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (a *Authenticator) Enabled(cfg Config) bool {
	return cfg.RequireSSO || cfg.OIDCClientID != "" || cfg.TrustForwardAuth
}

func (a *Authenticator) AuthorizeIP(ipStr string, id AuthIdentity) {
	host := normalizeIPString(ipStr)
	if host == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, v := range a.leases {
		if now.After(v.expiresAt) {
			delete(a.leases, k)
		}
	}
	a.leases[host] = ipLease{
		username:  id.Username,
		expiresAt: time.Unix(id.ExpiresAt, 0),
	}
}

func (a *Authenticator) RevokeIP(ipStr string) {
	host := normalizeIPString(ipStr)
	if host == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.leases, host)
}

func (a *Authenticator) LookupIPLease(ipStr string) (string, bool) {
	host := normalizeIPString(ipStr)
	if host == "" {
		return "", false
	}
	a.mu.RLock()
	lease, ok := a.leases[host]
	a.mu.RUnlock()
	if !ok || time.Now().After(lease.expiresAt) {
		return "", false
	}
	return lease.username, true
}

func (a *Authenticator) IssueSocksToken(id AuthIdentity) string {
	payload := fmt.Sprintf("socks:%s:%d", id.Username, id.ExpiresAt)
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil)[:16])
	return fmt.Sprintf("%d.%s", id.ExpiresAt, sig)
}

func (a *Authenticator) VerifySocksToken(username, token string) bool {
	if username == "" || token == "" {
		return false
	}
	expStr, sig, ok := strings.Cut(token, ".")
	if !ok || expStr == "" || sig == "" {
		return false
	}
	var exp int64
	if _, err := fmt.Sscanf(expStr, "%d", &exp); err != nil {
		return false
	}
	if time.Now().Unix() > exp {
		return false
	}
	expected := a.IssueSocksToken(AuthIdentity{Username: username, ExpiresAt: exp})
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

func (a *Authenticator) signJSON(v interface{}) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(b64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return b64 + "." + sig, nil
}

func (a *Authenticator) verifyJSON(signed string, out interface{}) error {
	b64, sig, ok := strings.Cut(signed, ".")
	if !ok || b64 == "" || sig == "" {
		return errors.New("malformed signed value")
	}
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(b64))
	wantSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(wantSig)) != 1 {
		return errors.New("invalid signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func (a *Authenticator) AuthenticateRequest(cfg Config, r *http.Request) (*AuthIdentity, error) {
	if cfg.TrustForwardAuth && isTrustedProxyPeer(cfg, r.RemoteAddr) {
		if user := strings.TrimSpace(r.Header.Get("X-authentik-username")); user != "" {
			groups := splitAuthentikGroups(r.Header.Get("X-authentik-groups"))
			if !hasAllowedGroup(cfg, groups) {
				return nil, fmt.Errorf("%w: %q", errForbiddenGroup, user)
			}
			id := &AuthIdentity{
				Username:  user,
				Groups:    groups,
				ExpiresAt: time.Now().Add(cfg.SessionTTL()).Unix(),
			}
			a.AuthorizeIP(ClientIPFromRequest(cfg, r), *id)
			return id, nil
		}
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, errors.New("unauthenticated")
	}
	var id AuthIdentity
	if err := a.verifyJSON(cookie.Value, &id); err != nil {
		return nil, err
	}
	if time.Now().Unix() > id.ExpiresAt {
		return nil, errors.New("session expired")
	}
	if !hasAllowedGroup(cfg, id.Groups) {
		return nil, fmt.Errorf("%w: %q", errForbiddenGroup, id.Username)
	}
	a.AuthorizeIP(ClientIPFromRequest(cfg, r), id)
	return &id, nil
}

func (a *Authenticator) HandleLogin(cfg Config, w http.ResponseWriter, r *http.Request) {
	authURL, _, _, err := oidcEndpoints(cfg.OIDCIssuerURL)
	if err != nil || cfg.OIDCClientID == "" {
		http.Error(w, "OIDC is not configured", http.StatusServiceUnavailable)
		return
	}
	nonceBytes := make([]byte, 16)
	verifierBytes := make([]byte, 32)
	_, _ = rand.Read(nonceBytes)
	_, _ = rand.Read(verifierBytes)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)

	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}

	stateObj := oauthStatePayload{
		Nonce:        nonce,
		CodeVerifier: verifier,
		Next:         next,
		IssuedAt:     time.Now().Unix(),
	}
	signedState, err := a.signJSON(stateObj)
	if err != nil {
		http.Error(w, "failed to create OAuth state", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     oauthCookieName,
		Value:    nonce,
		Path:     "/",
		MaxAge:   int(oauthStateTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPSRequest(cfg, r),
	})

	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])

	q := url.Values{
		"client_id":             {cfg.OIDCClientID},
		"response_type":         {"code"},
		"scope":                 {"openid profile email groups"},
		"redirect_uri":          {buildCallbackURL(cfg, r)},
		"state":                 {signedState},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, authURL+"?"+q.Encode(), http.StatusFound)
}

func (a *Authenticator) HandleCallback(cfg Config, w http.ResponseWriter, r *http.Request) {
	_, tokenURL, userinfoURL, err := oidcEndpoints(cfg.OIDCIssuerURL)
	if err != nil || cfg.OIDCClientID == "" {
		http.Error(w, "OIDC is not configured", http.StatusServiceUnavailable)
		return
	}

	rawState := r.URL.Query().Get("state")
	var stateObj oauthStatePayload
	if err := a.verifyJSON(rawState, &stateObj); err != nil {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}
	if time.Now().Unix()-stateObj.IssuedAt > int64(oauthStateTTL.Seconds()) {
		http.Error(w, "Expired OAuth state", http.StatusBadRequest)
		return
	}
	nonceCookie, err := r.Cookie(oauthCookieName)
	if err != nil || subtle.ConstantTimeCompare([]byte(nonceCookie.Value), []byte(stateObj.Nonce)) != 1 {
		http.Error(w, "OAuth state session mismatch", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oauthCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing OAuth authorization code", http.StatusBadRequest)
		return
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {cfg.OIDCClientID},
		"code":          {code},
		"redirect_uri":  {buildCallbackURL(cfg, r)},
		"code_verifier": {stateObj.CodeVerifier},
	}
	if cfg.OIDCClientSecret != "" {
		form.Set("client_secret", cfg.OIDCClientSecret)
	}

	tokenReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, "Failed to build token request", http.StatusInternalServerError)
		return
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := a.httpClient.Do(tokenReq)
	if err != nil {
		http.Error(w, "Token exchange failed", http.StatusBadGateway)
		return
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode < 200 || tokenResp.StatusCode >= 300 {
		http.Error(w, "Token endpoint rejected authorization code", http.StatusBadGateway)
		return
	}

	var tokenData struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(tokenResp.Body, 64*1024)).Decode(&tokenData); err != nil || tokenData.AccessToken == "" {
		http.Error(w, "Invalid token response", http.StatusBadGateway)
		return
	}

	uiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, userinfoURL, nil)
	if err != nil {
		http.Error(w, "Failed to build userinfo request", http.StatusInternalServerError)
		return
	}
	uiReq.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)

	uiResp, err := a.httpClient.Do(uiReq)
	if err != nil {
		http.Error(w, "Userinfo fetch failed", http.StatusBadGateway)
		return
	}
	defer uiResp.Body.Close()
	if uiResp.StatusCode < 200 || uiResp.StatusCode >= 300 {
		http.Error(w, "Userinfo endpoint returned error", http.StatusBadGateway)
		return
	}

	var claims struct {
		Sub               string   `json:"sub"`
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		Groups            []string `json:"groups"`
	}
	if err := json.NewDecoder(io.LimitReader(uiResp.Body, 64*1024)).Decode(&claims); err != nil {
		http.Error(w, "Invalid userinfo JSON", http.StatusBadGateway)
		return
	}
	username := strings.TrimSpace(claims.PreferredUsername)
	if username == "" {
		username = strings.TrimSpace(claims.Email)
	}
	if username == "" || claims.Sub == "" || strings.ContainsRune(username, '\x00') {
		http.Error(w, "Missing username or sub claim", http.StatusBadGateway)
		return
	}
	if !hasAllowedGroup(cfg, claims.Groups) {
		http.Error(w, "Forbidden: your Authentik account is not in an authorized staff group", http.StatusForbidden)
		return
	}

	id := AuthIdentity{
		Username:  username,
		Groups:    claims.Groups,
		ExpiresAt: time.Now().Add(cfg.SessionTTL()).Unix(),
	}
	signedSession, err := a.signJSON(id)
	if err != nil {
		http.Error(w, "Failed to sign session", http.StatusInternalServerError)
		return
	}
	a.AuthorizeIP(ClientIPFromRequest(cfg, r), id)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    signedSession,
		Path:     "/",
		MaxAge:   int(cfg.SessionTTL().Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   isHTTPSRequest(cfg, r),
	})

	next := stateObj.Next
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func (a *Authenticator) HandleLogout(cfg Config, w http.ResponseWriter, r *http.Request) {
	secFetch := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
	if secFetch != "" && secFetch != "same-origin" && secFetch != "none" {
		http.Error(w, "Forbidden: cross-origin logout rejected", http.StatusForbidden)
		return
	}
	if _, err := a.AuthenticateRequest(cfg, r); err == nil {
		a.RevokeIP(ClientIPFromRequest(cfg, r))
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func oidcEndpoints(issuerURL string) (authURL, tokenURL, userinfoURL string, err error) {
	trimmed := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if trimmed == "" {
		return "", "", "", errors.New("empty OIDC issuer URL")
	}
	u, err := url.Parse(trimmed)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", "", "", fmt.Errorf("invalid OIDC issuer URL %q", issuerURL)
	}
	base := trimmed
	if idx := strings.LastIndex(trimmed, "/"); idx > len(u.Scheme)+3 {
		base = trimmed[:idx]
	}
	return base + "/authorize/", base + "/token/", base + "/userinfo/", nil
}

func buildCallbackURL(cfg Config, r *http.Request) string {
	scheme := "http"
	if isHTTPSRequest(cfg, r) {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = resolveAdvertiseHost(cfg, r)
	}
	return fmt.Sprintf("%s://%s/auth/callback", scheme, host)
}

func isHTTPSRequest(cfg Config, r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if isTrustedProxyPeer(cfg, r.RemoteAddr) {
		return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
	}
	return false
}

func splitAuthentikGroups(headerVal string) []string {
	var groups []string
	for _, part := range strings.FieldsFunc(headerVal, func(r rune) bool {
		return r == '|' || r == ',' || r == ';'
	}) {
		if g := strings.TrimSpace(part); g != "" {
			groups = append(groups, g)
		}
	}
	return groups
}

func hasAllowedGroup(cfg Config, userGroups []string) bool {
	allowed := cfg.AllowedGroups
	if len(allowed) == 0 {
		allowed = defaultStaffGroups
	}
	for _, want := range allowed {
		if slices.Contains(userGroups, want) {
			return true
		}
	}
	return false
}

func ClientIPFromRequest(cfg Config, r *http.Request) string {
	peerIP := normalizeIPString(r.RemoteAddr)
	if isTrustedProxyPeer(cfg, r.RemoteAddr) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				if ip := normalizeIPString(parts[i]); ip != "" {
					return ip
				}
			}
		}
	}
	return peerIP
}

func isTrustedProxyPeer(cfg Config, remoteAddr string) bool {
	ip := parseHostIP(remoteAddr)
	if ip == nil {
		return false
	}
	cidrs := cfg.TrustedProxyCIDRs
	if len(cidrs) == 0 {
		cidrs = defaultTrustedProxyCIDRs
	}
	return ipMatchesAnyCIDR(ip, cidrs)
}

func IsClientAllowed(cfg Config, remoteAddrOrIP string) bool {
	ip := parseHostIP(remoteAddrOrIP)
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		ipStr := ip4.String()
		for team := 1; team <= cfg.NumberOfTeams; team++ {
			if strings.HasPrefix(ipStr, cfg.TeamExternalPrefix(team)) {
				return false
			}
		}
	}
	if len(cfg.AllowedClientCIDRs) > 0 {
		return ipMatchesAnyCIDR(ip, cfg.AllowedClientCIDRs)
	}
	return true
}

func parseHostIP(addrOrIP string) net.IP {
	s := strings.TrimSpace(addrOrIP)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return net.ParseIP(s)
}

func normalizeIPString(addrOrIP string) string {
	ip := parseHostIP(addrOrIP)
	if ip == nil {
		return ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func ipMatchesAnyCIDR(ip net.IP, cidrs []string) bool {
	for _, raw := range cidrs {
		c := strings.TrimSpace(raw)
		if c == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(c); err == nil {
			if ipNet.Contains(ip) {
				return true
			}
		} else if singleIP := net.ParseIP(c); singleIP != nil && singleIP.Equal(ip) {
			return true
		}
	}
	return false
}

func overlapsLocalInterfaceSubnet(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() {
			continue
		}
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func CheckSocksAuth(auth *Authenticator, cfg Config, clientAddr string, username, password string) (string, bool) {
	if auth == nil || !auth.Enabled(cfg) {
		return "", true
	}
	if username != "" && password != "" {
		if auth.VerifySocksToken(username, password) {
			return username, true
		}
	}
	if leasedUser, ok := auth.LookupIPLease(clientAddr); ok {
		return leasedUser, true
	}
	return "", false
}
