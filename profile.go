package loginoauth2

import (
	profileapi "google.golang.org/api/oauth2/v2"
)

type profile struct {
	Email        string `json:"email"`
	HostedDomain string `json:"hd,omitempty"`
}

func strippedDownProfile(p *profileapi.Userinfoplus) profile {
	return profile{
		Email:        p.Email,
		HostedDomain: p.Hd,
	}
}
