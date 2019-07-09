package loginoauth2

import (
	"fmt"
	"strings"

	"github.com/caddyserver/caddy"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
	"golang.org/x/oauth2/google"
)

func init() {
	caddy.RegisterPlugin("login", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

type myError struct {
	err error
}

func (e myError) Error() string {
	return fmt.Sprintf("[login-oauth2] " + e.err.Error())
}

func e(f string, args ...interface{}) *myError {
	return &myError{err: fmt.Errorf(f, args...)}
}

func setup(c *caddy.Controller) error {
	config := httpserver.GetConfig(c)
	debugf("setup host: %s", config.Host())

	h := newHandler()

	for c.Next() {

		var def loginDefinition

		for c.NextBlock() {
			key := c.Val()

			switch key {
			case "path":
				c.Next()
				def.paths.protected = c.Val()

			case "login_path":
				c.Next()
				def.paths.login = c.Val()

			case "callback_path":
				c.Next()
				def.oauth2.RedirectURL = fmt.Sprintf("%s%s", config.Addr, c.Val())
				def.paths.callback = c.Val()

			case "allow", "deny":
				for c.NextArg() {
					val := c.Val()
					switch val {
					case "sub", "hd":
						c.Next()
						switch key {
						case "allow":
							def.rules.allow.Add(val, c.Val())
						case "deny":
							def.rules.deny.Add(val, c.Val())
						}
					default:
						return e("invalid argument %v", val)
					}
				}

			case "jwt_secret":
				c.Next()
				def.secrets.jwt = c.Val()

			case "google":
				def.oauth2.Endpoint = google.Endpoint
				def.oauth2.Scopes = []string{"profile", "email", "openid"}

				for c.NextArg() {
					val := c.Val()
					switch {
					case strings.HasPrefix(val, "client_id"):
						def.oauth2.ClientID = val[strings.IndexRune(val, '=')+1:]
					case strings.HasPrefix(val, "client_secret"):
						def.oauth2.ClientSecret = val[strings.IndexRune(val, '=')+1:]
					default:
						return e("invalid argument %v", val)
					}
				}
			}
		}

		// Do some validation before using the definition.

		if def.paths.protected == "" {
			return e("no path to protect provided")
		}
		if def.paths.login == "" {
			return e("no login_path provided")
		}
		if def.paths.callback == "" {
			return e("no callback_path provided")
		}
		if def.oauth2.RedirectURL == "" {
			return e("no redirect_url provided")
		}
		if def.secrets.jwt == "" {
			return e("no JWT secret key provided")
		}

		debugf("acl rules: %+v", def.rules)

		h.definitions = append(h.definitions, def)
	}

	config.AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		h.next = next
		return h
	})

	return nil
}
