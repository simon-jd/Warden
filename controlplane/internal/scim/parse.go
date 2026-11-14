package scim

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"warden/controlplane/internal/canonical"
)

const (
	userSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	patchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	listSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	errorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
	maxText     = 256
	maxOps      = 100
)

// objectIDPattern is Entra's object ID form; externalId must carry it so the
// OIDC oid claim can be matched against the provisioned user.
var objectIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var errBadRequest = errors.New("invalid SCIM request")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errBadRequest, fmt.Sprintf(format, a...))
}

// object decodes one JSON object whose member names are matched case-insensitively,
// as SCIM requires. Exact and case-aliased duplicates are both rejected.
func object(raw []byte) (map[string]json.RawMessage, error) {
	if _, err := canonical.JSON(raw); err != nil {
		return nil, invalid("%v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, invalid("expected a JSON object")
	}
	out := make(map[string]json.RawMessage, len(m))
	for k, v := range m {
		lk := strings.ToLower(k)
		if _, dup := out[lk]; dup {
			return nil, invalid("attribute %q given twice", k)
		}
		out[lk] = v
	}
	return out, nil
}

func hasSchema(m map[string]json.RawMessage, want string) bool {
	var schemas []string
	if json.Unmarshal(m["schemas"], &schemas) != nil {
		return false
	}
	for _, s := range schemas {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

func text(raw json.RawMessage, name string, min int) (string, error) {
	var s string
	if json.Unmarshal(raw, &s) != nil || len(s) < min || len(s) > maxText {
		return "", invalid("%s must be a string of %d-%d bytes", name, min, maxText)
	}
	return s, nil
}

func objectID(raw json.RawMessage) (string, error) {
	var s string
	if json.Unmarshal(raw, &s) != nil || !objectIDPattern.MatchString(s) {
		return "", invalid("externalId must be the IdP object ID (lowercase GUID)")
	}
	return s, nil
}

// boolean accepts JSON booleans and Entra's legacy "True"/"False" strings.
func boolean(raw json.RawMessage) (bool, error) {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		switch strings.ToLower(s) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, invalid("active must be a boolean")
}

// parseUser reads a POST/PUT body. Attributes Warden does not store (name,
// emails, enterprise extension, ...) are accepted and ignored.
func parseUser(raw []byte) (User, error) {
	m, err := object(raw)
	if err != nil {
		return User{}, err
	}
	if !hasSchema(m, userSchema) {
		return User{}, invalid("schemas must include %s", userSchema)
	}
	u := User{Active: true}
	if u.UserName, err = text(m["username"], "userName", 1); err != nil {
		return User{}, err
	}
	if u.ExternalID, err = objectID(m["externalid"]); err != nil {
		return User{}, err
	}
	if v, ok := m["displayname"]; ok {
		if u.DisplayName, err = text(v, "displayName", 0); err != nil {
			return User{}, err
		}
	}
	if v, ok := m["active"]; ok {
		if u.Active, err = boolean(v); err != nil {
			return User{}, err
		}
	}
	return u, nil
}

// change is a partial update; nil fields are left as they are.
type change struct {
	active                            *bool
	userName, externalID, displayName *string
}

func (c *change) set(attr string, op string, raw json.RawMessage) error {
	if op == "remove" {
		switch attr {
		case "displayname":
			empty := ""
			c.displayName = &empty
			return nil
		case "active", "username", "externalid":
			return invalid("%s is required and cannot be removed", attr)
		}
		return nil
	}
	switch attr {
	case "active":
		b, err := boolean(raw)
		if err != nil {
			return err
		}
		c.active = &b
	case "username":
		s, err := text(raw, "userName", 1)
		if err != nil {
			return err
		}
		c.userName = &s
	case "externalid":
		s, err := objectID(raw)
		if err != nil {
			return err
		}
		c.externalID = &s
	case "displayname":
		s, err := text(raw, "displayName", 0)
		if err != nil {
			return err
		}
		c.displayName = &s
	}
	// Any other attribute is not stored by Warden; accept it as a no-op.
	return nil
}

func parsePatch(raw []byte) (change, error) {
	m, err := object(raw)
	if err != nil {
		return change{}, err
	}
	if !hasSchema(m, patchSchema) {
		return change{}, invalid("schemas must include %s", patchSchema)
	}
	var ops []json.RawMessage
	if json.Unmarshal(m["operations"], &ops) != nil || len(ops) == 0 || len(ops) > maxOps {
		return change{}, invalid("Operations must hold 1-%d operations", maxOps)
	}
	var c change
	for _, rawOp := range ops {
		o, err := object(rawOp)
		if err != nil {
			return change{}, err
		}
		var op, path string
		if json.Unmarshal(o["op"], &op) != nil {
			return change{}, invalid("op must be a string")
		}
		op = strings.ToLower(op)
		if op != "add" && op != "replace" && op != "remove" {
			return change{}, invalid("unsupported op %q", op)
		}
		if p, ok := o["path"]; ok && json.Unmarshal(p, &path) != nil {
			return change{}, invalid("path must be a string")
		}
		path = strings.ToLower(path)
		path = strings.TrimPrefix(path, strings.ToLower(userSchema)+":")
		if path != "" {
			if err := c.set(path, op, o["value"]); err != nil {
				return change{}, err
			}
			continue
		}
		if op == "remove" {
			return change{}, invalid("remove requires a path")
		}
		attrs, err := object(o["value"])
		if err != nil {
			return change{}, invalid("value without path must be an object")
		}
		for attr, v := range attrs {
			if err := c.set(attr, op, v); err != nil {
				return change{}, err
			}
		}
	}
	return c, nil
}

// filter is the one form provisioning clients use to look a user up:
// `userName eq "..."` or `externalId eq "..."`.
type filter struct{ attr, value string }

var errFilter = errors.New("unsupported filter")

func parseFilter(s string) (filter, error) {
	s = strings.TrimSpace(s)
	attr, rest, ok := strings.Cut(s, " ")
	if !ok {
		return filter{}, errFilter
	}
	var f filter
	switch strings.ToLower(attr) {
	case "username":
		f.attr = "userName"
	case "externalid":
		f.attr = "externalId"
	default:
		return filter{}, errFilter
	}
	op, rest, ok := strings.Cut(strings.TrimLeft(rest, " "), " ")
	if !ok || !strings.EqualFold(op, "eq") {
		return filter{}, errFilter
	}
	lit := strings.TrimSpace(rest)
	if !strings.HasPrefix(lit, `"`) {
		return filter{}, errFilter
	}
	end := 1
	for ; end < len(lit); end++ {
		if lit[end] == '\\' {
			end++
			continue
		}
		if lit[end] == '"' {
			break
		}
	}
	if end >= len(lit) || end != len(lit)-1 {
		return filter{}, errFilter // unterminated, or anything after the literal
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(lit)))
	if dec.Decode(&f.value) != nil || len(f.value) > maxText {
		return filter{}, errFilter
	}
	return f, nil
}
