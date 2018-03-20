package generalisedtransparency

import (
	"errors"
	"strings"

	uuid "github.com/satori/go.uuid"
)

// TableNameValidator validates and canonicalizes a table name
type TableNameValidator interface {
	ValidateAndCanonicaliseTableName(s string) (string, error)
}

// CreateNamedValidator returns a registered tablename validator.
func CreateNamedValidator(registeredName, optionalParam string) (TableNameValidator, error) {
	switch registeredName {
	case "uuid":
		return &UUIDValidator{}, nil
	case "whitelist":
		return NewWhitelistValidator(strings.Split(optionalParam, ","))
	case "insecure-skip-validation":
		return &InsecureSkipTableNameValidator{}, nil
	default:
		return nil, errors.New("table name validator not found")
	}
}

// UUIDValidator allows table names that are in UUID format only
type UUIDValidator struct{}

// ValidateAndCanonicaliseTableName requires s be a UUID
func (v *UUIDValidator) ValidateAndCanonicaliseTableName(s string) (string, error) {
	u, err := uuid.FromString(s)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// InsecureSkipTableNameValidator allows any table name. This should not be used outside of testing.
type InsecureSkipTableNameValidator struct{}

// ValidateAndCanonicaliseTableName returns s
func (v *InsecureSkipTableNameValidator) ValidateAndCanonicaliseTableName(s string) (string, error) {
	return s, nil
}

// WhitelistValidator allows these names only
type WhitelistValidator struct {
	names map[string]interface{}
}

// NewWhitelistValidator returns an initialized table name whitelist
func NewWhitelistValidator(names []string) (*WhitelistValidator, error) {
	rv := &WhitelistValidator{
		names: make(map[string]interface{}),
	}
	for _, n := range names {
		rv.names[n] = nil
	}
	if len(rv.names) == 0 {
		return nil, errors.New("table name whitelist must contain at least one entry")
	}
	return rv, nil
}

// ValidateAndCanonicaliseTableName returns s if it is in the whitelist
func (v *WhitelistValidator) ValidateAndCanonicaliseTableName(s string) (string, error) {
	_, ok := v.names[s]
	if !ok {
		return "", errors.New("table name not in whitelist")
	}
	return s, nil
}
