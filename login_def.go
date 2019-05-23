package loginoauth2

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type loginDefinition struct {
	secrets struct {
		jwt string
	}
	paths struct {
		protected string
		login     string
		callback  string
	}
	rules aclRules

	oauth2 oauth2.Config
}

func (d loginDefinition) goPath() string {
	return d.paths.login + "/go"
}

func (d loginDefinition) loginProvider() string {
	switch {
	case d.oauth2.Endpoint == google.Endpoint:
		return "Google"
	default:
		panic(e("unknown oauth2 endpoint"))
	}
}
