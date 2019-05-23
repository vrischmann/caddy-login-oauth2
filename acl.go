package loginoauth2

type aclRules struct {
	allow acl
	deny  acl
}

type aclValidationData map[string]interface{}

func (r aclRules) Validate(claims aclValidationData) bool {
	debugf("acl validation data: %+v", claims)

	// Check any allow rule
	// allow will only grant access if:
	// - the key is present in the claims
	// - the claim value is strictly equal to the rule value.

	for _, el := range r.allow {
		key, value := el.key, el.value

		claim, ok := claims[key]
		if !ok {
			debugf("no claim for key %s", key)
			continue
		}

		claimString, ok := claim.(string)
		if !ok {
			debugf("claim for key %s is not a string: %v", key, claim)
			continue
		}

		if claimString == value {
			debugf("claim for key %s matches (got %q, expected %q), allowing", key, claimString, value)
			return true
		}

		debugf("claim for key %s is not the correct value: got %q, expected: %q", key, claimString, value)
	}

	// Check any deny rule
	// deny will only grant access if:
	// - the key is present in the claims _but_
	// its value is _not_ equal to the rule value.

	for _, el := range r.deny {
		key, value := el.key, el.value

		claim, ok := claims[key]
		if !ok {
			debugf("no claim for key %s", key)
			continue
		}

		claimString, ok := claim.(string)
		if !ok {
			debugf("claim for key %s is not a string", key)
			continue
		}

		if claimString == value {
			debugf("claim for key %s matches value %s, denying", key, value)
			return false
		}
		debugf("claim for key %s does not match value %s, allowing", key, value)
		return true
	}

	debugf("nothing allowed, nothing denied: deny by default")

	// If no access was granted fallback to denying everything.

	return false
}

type acl []struct {
	key   string
	value string
}

func (a *acl) Add(key, value string) {
	*a = append(*a, struct {
		key   string
		value string
	}{
		key:   key,
		value: value,
	})
}
