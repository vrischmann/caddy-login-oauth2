package loginoauth2

import (
	"log"
	"os"
)

var debug = os.Getenv("LOGIN_OAUTH2_DEBUG") == "1"

func debugf(fmt string, args ...interface{}) {
	if debug {
		log.Printf("[login-oauth2] "+fmt, args...)
	}
}
