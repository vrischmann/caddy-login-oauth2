package loginoauth2

import (
	"testing"

	"github.com/dgrijalva/jwt-go"
)

func TestACLRules(t *testing.T) {
	testCases := []struct {
		fn     func() aclRules
		claims jwt.MapClaims
		exp    bool
	}{
		{
			func() (rules aclRules) {
				rules.allow.Add("sub", "foobar")
				return
			},
			jwt.MapClaims{},
			false,
		},
		{
			func() (rules aclRules) {
				rules.allow.Add("sub", "foobar")
				return
			},
			jwt.MapClaims{"sub": "jardin"},
			false,
		},
		{
			func() (rules aclRules) {
				rules.allow.Add("sub", "foobar")
				return
			},
			jwt.MapClaims{"sub": 2000},
			false,
		},
		{
			func() (rules aclRules) {
				rules.allow.Add("sub", "foobar")
				return
			},
			jwt.MapClaims{"sub": "foobar"},
			true,
		},
		{
			func() (rules aclRules) {
				rules.allow.Add("sub", "foobar")
				rules.allow.Add("user", "vincent")
				return
			},
			jwt.MapClaims{"user": "vincent"},
			true,
		},
		{
			func() (rules aclRules) {
				rules.allow.Add("sub", "foobar")
				rules.deny.Add("role", "guest")
				return
			},
			jwt.MapClaims{},
			false,
		},
		{
			func() (rules aclRules) {
				rules.allow.Add("sub", "foobar")
				rules.deny.Add("role", "guest")
				return
			},
			jwt.MapClaims{"role": "guest"},
			false,
		},
		{
			func() (rules aclRules) {
				rules.allow.Add("sub", "foobar")
				rules.deny.Add("role", "guest")
				return
			},
			jwt.MapClaims{"role": "developer"},
			true,
		},
		{
			func() (rules aclRules) {
				rules.allow.Add("sub", "foobar")
				rules.deny.Add("role", "guest")
				return
			},
			jwt.MapClaims{"sub": "foobar"},
			true,
		},
		{
			func() (rules aclRules) {
				rules.deny.Add("role", "guest")
				return
			},
			jwt.MapClaims{"role": 200},
			false,
		},
		// Multiple ACLs
		{
			func() (rules aclRules) {
				rules.allow.Add("sub", "vincent")
				rules.allow.Add("sub", "gérard")
				rules.deny.Add("role", "guest")
				return
			},
			jwt.MapClaims{"sub": "vincent"},
			true,
		},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			rules := tc.fn()

			res := rules.Validate(aclValidationData(tc.claims))
			if exp, got := tc.exp, res; exp != got {
				t.Fatalf("expected %v, got %v", exp, got)
			}
		})
	}
}
