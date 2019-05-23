package loginoauth2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"go.rischmann.fr/caddy-login-oauth2/internal"
	"golang.org/x/oauth2"
	profileapi "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

type handler struct {
	next httpserver.Handler

	definitions []loginDefinition

	jwt jwt.Parser
}

func newHandler() *handler {
	h := new(handler)
	h.jwt.ValidMethods = []string{"HS256"}
	h.jwt.UseJSONNumber = true

	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) (int, error) {
	var (
		p           = req.URL.Path
		tokenString = jwtCookieGet(req)
	)

	for _, def := range h.definitions {
		switch {

		case req.URL.Path == def.paths.login:
			// If we already have a valid JWT there's no need to redo the login: redirect to the success path
			if h.validateJWT(def, tokenString) {
				http.Redirect(w, req, def.paths.protected, http.StatusFound)
				return 0, nil
			}
			jwtCookieDelete(w)

			// Otherwise show the login prompt.
			// It's just a HTML page to notify the user it will be redirected.
			return h.loginPrompt(w, req, def)

		case req.URL.Path == def.goPath():
			// If we already have a valid JWT there's no need to redo the login: redirect to the success path
			if h.validateJWT(def, tokenString) {
				http.Redirect(w, req, def.paths.protected, http.StatusFound)
				return 0, nil
			}
			jwtCookieDelete(w)

			// This will start the OAuth2 flow.
			return h.oauth2Go(w, req, def)

		case req.URL.Path == def.paths.callback:
			// This is called by the OAuth2 provider after the user
			// authorized our app.
			return h.oauth2Callback(w, req, def)

		case strings.HasPrefix(p, def.paths.protected):
			// To access the protected path we must have a valid JWT.
			if h.validateJWT(def, tokenString) {
				return h.next.ServeHTTP(w, req)
			}
			jwtCookieDelete(w)

			// If not redirect to the login path

			http.Redirect(w, req, def.paths.login, http.StatusFound)
			return 0, nil
		}
	}

	return h.next.ServeHTTP(w, req)
}

func (h *handler) validateJWT(def loginDefinition, tokenString string) bool {
	if tokenString == "" {
		return false
	}

	// Parse the token and verify the signature

	token, err := h.jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("invalid signing method %v", token.Header["alg"])
		}

		return []byte(def.secrets.jwt), nil
	})
	if err != nil {
		debugf("unable to parse JWT: %v", err)
		return false
	}

	// Check the claims

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		debugf("no valid claims in token")
		return false
	}

	// Check the claims now

	// Verify exp, iat, nbf
	now := time.Now().Unix()
	if !claims.VerifyIssuedAt(now, true) {
		debugf("iat invalid")
		return false
	}
	if !claims.VerifyNotBefore(now, true) {
		debugf("nbf invalid")
		return false
	}
	if !claims.VerifyExpiresAt(now, true) {
		debugf("exp invalid")
		return false
	}

	// Validate the claims using our ACLs
	if def.rules.Validate(aclValidationData(claims)) {
		return true
	}

	debugf("unable to validate claims")

	return false
}

func (h *handler) oauth2Go(w http.ResponseWriter, req *http.Request, def loginDefinition) (int, error) {
	state := genRandomState()

	stateCookieSet(w, state)

	url := def.oauth2.AuthCodeURL(state,
		oauth2.ApprovalForce,
		oauth2.AccessTypeOnline,
	)

	http.Redirect(w, req, url, http.StatusFound)
	return 0, nil
}

func (h *handler) oauth2Callback(w http.ResponseWriter, req *http.Request, def loginDefinition) (int, error) {
	// Validate state

	state := req.FormValue("state")

	cookieState, err := stateCookieGet(req)
	if err != nil {
		debugf("unable to read oauth2 state cookie: %v", err)
		http.Redirect(w, req, def.paths.login, http.StatusFound)
		return 0, nil
	}

	if state == "" || state != cookieState {
		debugf("invalid state in callback form data")
		http.Redirect(w, req, def.paths.login, http.StatusFound)
		return 0, nil
	}

	// Remove state cookie

	stateDelete(w)

	// Exchange code for access token

	code := req.FormValue("code")

	ctx, cancel := context.WithTimeout(req.Context(), 3*time.Second)
	defer cancel()

	accessToken, err := def.oauth2.Exchange(ctx, code)
	if err != nil {
		debugf("unable to exchange code for token: %v", err)
		http.Redirect(w, req, def.paths.login, http.StatusFound)
		return 0, nil
	}

	// Obtain the user profile

	ctx, cancel = context.WithTimeout(req.Context(), 3*time.Second)
	defer cancel()

	svc, err := profileapi.NewService(ctx, option.WithTokenSource(def.oauth2.TokenSource(ctx, accessToken)))
	if err != nil {
		debugf("unable to obtain create service: %v", err)
		http.Redirect(w, req, def.paths.login, http.StatusFound)
		return 0, nil
	}

	userSvc := profileapi.NewUserinfoService(svc)

	fullProfile, err := userSvc.Get().Do()
	if err != nil {
		debugf("unable to obtain profile: %v", err)
		http.Redirect(w, req, def.paths.login, http.StatusFound)
		return 0, nil
	}

	// Create stripped down profile

	profile := strippedDownProfile(fullProfile)

	// Create JWT token usable by caddy-jwt

	token := createJWT(profile)

	// Validate the claims using our ACLs
	validationData := aclValidationData{
		"sub": profile.Email,
		"hd":  profile.HostedDomain,
	}

	if !def.rules.Validate(validationData) {
		debugf("unable to validate claims")
		http.Redirect(w, req, def.paths.login, http.StatusFound)
		return 0, nil
	}

	tokenString, err := token.SignedString([]byte(def.secrets.jwt))
	if err != nil {
		debugf("unable to create JWT: %v", err)
		http.Redirect(w, req, def.paths.login, http.StatusFound)
		return 0, nil
	}

	// Set the JWT cookie.

	jwtCookieSet(w, tokenString)

	http.Redirect(w, req, def.paths.protected, http.StatusFound)
	return 0, nil
}

func (h *handler) loginPrompt(w http.ResponseWriter, req *http.Request, def loginDefinition) (int, error) {
	data := map[string]interface{}{
		"Provider":  def.loginProvider(),
		"LoginPath": def.paths.login,
	}

	err := h.renderTemplate(w, req, "login.html", data)

	return http.StatusOK, err
}

func (h *handler) renderTemplate(w http.ResponseWriter, req *http.Request, name string, data map[string]interface{}) error {
	f, err := internal.Assets.Open(name)
	if err != nil {
		debugf("unable to open template %s: %v", name, err)
		return myError{err: err}
	}

	tplData, err := ioutil.ReadAll(f)
	if err != nil {
		debugf("unable to read template %s data: %v", name, err)
		return myError{err: err}
	}

	tpl, err := template.New("root").Parse(string(tplData))
	if err != nil {
		debugf("unable to parse template %s data: %v", name, err)
		return myError{err: err}
	}

	w.Header().Set("Content-Type", "text/html")

	err = tpl.Execute(w, data)
	if err != nil {
		debugf("unable to execute template %s: %v", name, err)
	}

	return nil
}

func createJWT(p profile) *jwt.Token {
	now := time.Now()

	claims := jwt.MapClaims{
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(2 * (24 * time.Hour)).Unix(),
		"sub": p.Email,
		"hd":  p.HostedDomain,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token
}

func genRandomState() string {
	var buf [16]byte

	n, err := rand.Read(buf[:])
	if err != nil {
		panic(e("unable to read random bytes: %v", err))
	}
	if n < len(buf) {
		panic(e("unable to read enough random bytes"))
	}

	return base64.URLEncoding.EncodeToString(buf[:])
}

func stateCookieGet(req *http.Request) (string, error) {
	cookie, err := req.Cookie(stateCookieName)
	if err != nil {
		return "", fmt.Errorf("unable to get state cookie: %v", err)
	}

	return cookie.Value, nil
}

func stateCookieSet(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Path:   "/",
		Name:   stateCookieName,
		Value:  state,
		MaxAge: 10 * 60, // 10 minutes
		// Secure:   true,
		HttpOnly: true,
	})
}

func jwtCookieGet(req *http.Request) string {
	cookie, err := req.Cookie(jwtCookieName)
	if err != nil {
		return ""
	}

	return cookie.Value
}

func jwtCookieSet(w http.ResponseWriter, tokenString string) {
	http.SetCookie(w, &http.Cookie{
		Path:   "/",
		Name:   jwtCookieName,
		Value:  tokenString,
		MaxAge: 3 * 86400, // 3 days
		// Secure: true,
		HttpOnly: true,
	})
}

func jwtCookieDelete(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Path:   "/",
		Name:   jwtCookieName,
		MaxAge: -1,
	})
}

func stateDelete(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Path:   "/",
		Name:   stateCookieName,
		MaxAge: -1,
	})
}

const (
	stateCookieName = "state"
	jwtCookieName   = "jwt_token"
)

var _ httpserver.Handler = (*handler)(nil)
