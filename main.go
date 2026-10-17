// Command u2i-dev-idp is a generalized, zero-protection OpenID Connect /
// OAuth2 identity provider for use in lower environments only.
//
// It exists so any number of our apps can authenticate in dev / qa /
// preview without a real Google (or other) OAuth callback. There is NO
// security here by design: it accepts any client_id, any redirect_uri,
// any scope, and lets you sign in as anyone by simply typing a username.
// It is meant to run behind a perimeter (e.g. the cluster-edge OAuth
// gate) and must never be deployed to production.
//
// It implements enough of OIDC + OAuth2 to satisfy both flavours of
// client:
//
//	GET  /.well-known/openid-configuration  discovery document
//	GET  /authorize                          login picker -> redirect with code
//	POST /login                              picker form target
//	POST /token                              code -> {access_token, id_token}
//	GET  /userinfo                           bearer -> claims
//	GET  /jwks                               signing public key (RS256)
//	GET  /healthz                            liveness
//
// The authorization code and access token are self-contained signed
// JWTs carrying the chosen identity, so the server holds no state and a
// single shared instance can serve unlimited clients and preview
// environments.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// config is resolved once from the environment at boot.
type config struct {
	issuer        string // public base URL, e.g. https://idp.compliance.u2i.dev
	defaultDomain string // bare usernames become <user>@<defaultDomain>
	addr          string // listen address
}

func loadConfig() config {
	return config{
		issuer:        envOr("ISSUER", "http://localhost:8080"),
		defaultDomain: envOr("DEFAULT_EMAIL_DOMAIN", "u2i.com"),
		addr:          ":" + envOr("PORT", "8080"),
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// server holds the resolved config and the boot-time signing key. The
// key is generated fresh on each start: tokens don't need to survive
// restarts in a dev IdP, and a per-boot key means there are no secrets
// to manage or leak.
type server struct {
	cfg config
	key *rsa.PrivateKey
	kid string
}

func main() {
	cfg := loadConfig()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}

	s := &server{cfg: cfg, key: key, kid: keyID(&key.PublicKey)}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("/authorize", s.authorize)
	mux.HandleFunc("/login", s.login)
	mux.HandleFunc("/token", s.token)
	mux.HandleFunc("/userinfo", s.userinfo)
	mux.HandleFunc("/jwks", s.jwks)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("u2i-dev-idp listening on %s (issuer=%s, default-domain=%s)",
		cfg.addr, cfg.issuer, cfg.defaultDomain)
	log.Printf("WARNING: this is an UNSECURED dev identity provider — never run it in production")

	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// ── discovery ────────────────────────────────────────────────────────

func (s *server) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.cfg.issuer,
		"authorization_endpoint":                s.cfg.issuer + "/authorize",
		"token_endpoint":                        s.cfg.issuer + "/token",
		"userinfo_endpoint":                     s.cfg.issuer + "/userinfo",
		"jwks_uri":                              s.cfg.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"claims_supported": []string{
			"sub", "email", "email_verified", "name", "given_name", "family_name", "hd", "groups",
		},
		"grant_types_supported": []string{"authorization_code"},
	})
}

// ── authorize: render the login picker ───────────────────────────────

func (s *server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// We do NOT validate client_id / redirect_uri / scope — this is an
	// intentionally open dev IdP. We only carry the values through.
	data := pickerData{
		RedirectURI:   q.Get("redirect_uri"),
		State:         q.Get("state"),
		Nonce:         q.Get("nonce"),
		Scope:         q.Get("scope"),
		DefaultDomain: s.cfg.defaultDomain,
	}
	if data.RedirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pickerTmpl.Execute(w, data); err != nil {
		log.Printf("render picker: %v", err)
	}
}

// ── login: picker form target -> redirect with code ──────────────────

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	redirectURI := r.PostFormValue("redirect_uri")
	state := r.PostFormValue("state")
	nonce := r.PostFormValue("nonce")

	if username == "" || redirectURI == "" {
		http.Error(w, "missing username or redirect_uri", http.StatusBadRequest)
		return
	}

	claims := s.claimsFor(username, r.PostForm)
	// The "code" is a short-lived signed token carrying the claims, so
	// /token can reconstruct the identity with no server-side store.
	code, err := s.sign(claims, "code", 5*time.Minute, nonce)
	if err != nil {
		http.Error(w, "sign code", http.StatusInternalServerError)
		return
	}

	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	qp := u.Query()
	qp.Set("code", code)
	if state != "" {
		qp.Set("state", state)
	}
	u.RawQuery = qp.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ── token: code -> {access_token, id_token} ──────────────────────────

func (s *server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	code := r.PostFormValue("code")
	claims, nonce, err := s.verify(code, "code")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	accessToken, err := s.sign(claims, "access", time.Hour, "")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	idToken, err := s.sign(claims, "id", time.Hour, nonce)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        "openid email profile",
	})
}

// ── userinfo: bearer -> claims ───────────────────────────────────────

func (s *server) userinfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == auth { // prefix wasn't present
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	claims, _, err := s.verify(token, "access")
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

// ── jwks: publish the signing public key ─────────────────────────────

func (s *server) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := s.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": s.kid,
			"n":   b64url(pub.N.Bytes()),
			"e":   b64url(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

// ── claims ───────────────────────────────────────────────────────────

// claimsFor builds the identity for a typed username. A bare username
// becomes <username>@<defaultDomain>; a full email is used verbatim.
// Any extra form/query params (e.g. groups=hr) are passed through so
// role-gated apps can be exercised. email_verified is always true.
func (s *server) claimsFor(username string, extra url.Values) map[string]any {
	email := username
	domain := s.cfg.defaultDomain
	if d := extra.Get("domain"); d != "" {
		domain = d
	}
	if !strings.Contains(email, "@") {
		email = email + "@" + domain
	} else {
		domain = email[strings.IndexByte(email, '@')+1:]
	}

	local := email[:strings.IndexByte(email, '@')]
	name := titleizeName(local)

	claims := map[string]any{
		"sub":            email,
		"email":          email,
		"email_verified": true,
		"hd":             domain,
		"name":           name,
	}
	if parts := strings.SplitN(local, ".", 2); len(parts) == 2 {
		claims["given_name"] = titleize(parts[0])
		claims["family_name"] = titleize(parts[1])
	}
	// Pass through any extra claim params except the reserved control
	// ones. groups becomes a list so apps can gate on roles.
	for k, vs := range extra {
		switch k {
		case "username", "redirect_uri", "state", "nonce", "scope", "domain":
			continue
		}
		if len(vs) == 1 {
			claims[k] = vs[0]
		} else {
			claims[k] = vs
		}
	}
	if g, ok := claims["groups"].(string); ok {
		claims["groups"] = strings.Split(g, ",")
	}
	return claims
}

func titleizeName(local string) string {
	parts := strings.FieldsFunc(local, func(r rune) bool { return r == '.' || r == '_' || r == '-' })
	for i, p := range parts {
		parts[i] = titleize(p)
	}
	return strings.Join(parts, " ")
}

func titleize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ── minimal JWT (RS256) ──────────────────────────────────────────────

// sign produces a compact RS256 JWT. use distinguishes code / access /
// id tokens via a private "u2i_use" claim so a code can't be replayed
// as an access token. nonce, when present, is embedded (id tokens echo
// the request nonce per OIDC).
func (s *server) sign(claims map[string]any, use string, ttl time.Duration, nonce string) (string, error) {
	now := time.Now()
	payload := map[string]any{
		"iss":     s.cfg.issuer,
		"aud":     s.cfg.issuer,
		"iat":     now.Unix(),
		"exp":     now.Add(ttl).Unix(),
		"u2i_use": use,
	}
	for k, v := range claims {
		payload[k] = v
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}

	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": s.kid}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	signingInput := b64urlStr(hb) + "." + b64urlStr(pb)

	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, cryptoSHA256, h[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64url(sig), nil
}

// verify checks signature, expiry and intended use, returning the
// non-reserved claims plus any embedded nonce.
func (s *server) verify(token, wantUse string) (map[string]any, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, "", fmt.Errorf("malformed token")
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, "", err
	}
	h := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(&s.key.PublicKey, cryptoSHA256, h[:], sig); err != nil {
		return nil, "", err
	}

	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", err
	}
	var payload map[string]any
	if err := json.Unmarshal(pb, &payload); err != nil {
		return nil, "", err
	}
	if exp, ok := payload["exp"].(float64); !ok || time.Now().Unix() > int64(exp) {
		return nil, "", fmt.Errorf("expired")
	}
	if u, _ := payload["u2i_use"].(string); u != wantUse {
		return nil, "", fmt.Errorf("wrong token use")
	}

	nonce, _ := payload["nonce"].(string)
	for _, k := range []string{"iss", "aud", "iat", "exp", "u2i_use", "nonce"} {
		delete(payload, k)
	}
	return payload, nonce, nil
}

// ── helpers ──────────────────────────────────────────────────────────

func keyID(pub *rsa.PublicKey) string {
	h := sha256.Sum256(pub.N.Bytes())
	return b64url(h[:8])
}

// cryptoSHA256 is the hash identifier passed to RSA sign/verify.
const cryptoSHA256 = crypto.SHA256

func b64url(b []byte) string    { return base64.RawURLEncoding.EncodeToString(b) }
func b64urlStr(b []byte) string { return b64url(b) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// ── login picker template ────────────────────────────────────────────

type pickerData struct {
	RedirectURI   string
	State         string
	Nonce         string
	Scope         string
	DefaultDomain string
}

var pickerTmpl = template.Must(template.New("picker").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>u2i dev sign-in</title>
<style>
 body{font-family:system-ui,sans-serif;background:#f4f4f5;margin:0}
 .card{max-width:26rem;margin:4rem auto;background:#fff;border:1px solid #e4e4e7;border-radius:.5rem;padding:2rem}
 h1{font-size:1.2rem;margin:0 0 .25rem}.sub{color:#71717a;font-size:.85rem;margin:0 0 1.25rem}
 label{display:block;font-size:.8rem;font-weight:600;color:#3f3f46;margin:0 0 .25rem}
 input{width:100%;box-sizing:border-box;padding:.6rem;font-size:.95rem;border:1px solid #d4d4d8;border-radius:.375rem}
 button{width:100%;margin-top:1.25rem;padding:.6rem;background:#18181b;color:#fff;border:none;border-radius:.375rem;font-weight:600;cursor:pointer}
 .banner{background:#fef9c3;border:1px solid #fde047;color:#854d0e;font-size:.72rem;padding:.5rem .7rem;border-radius:.375rem;margin:0 0 1rem}
</style></head>
<body><div class="card">
 <div class="banner">⚠️ Unsecured dev identity provider — lower environments only.</div>
 <h1>Sign in</h1>
 <p class="sub">Type any username (e.g. <code>tom</code>) or full email. No password.</p>
 <form method="post" action="/login">
  <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}"/>
  <input type="hidden" name="state" value="{{.State}}"/>
  <input type="hidden" name="nonce" value="{{.Nonce}}"/>
  <input type="hidden" name="scope" value="{{.Scope}}"/>
  <label for="u">Username or email</label>
  <input id="u" name="username" autofocus autocomplete="off" placeholder="firstname.lastname"/>
  <button type="submit">Continue</button>
 </form>
</div></body></html>`))
