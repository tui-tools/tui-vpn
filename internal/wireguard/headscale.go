package wireguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// The Headscale CLI answers `--output json`, which is the stable, machine
// readable form of what its human tables show. That is what these parsers read,
// rather than the pterm ASCII tables, whose columns move between versions.
//
// Two shapes are tolerated for every list, because they have both been seen
// across Headscale versions: a bare JSON array of objects, and an object that
// wraps the array under a plural key ({"users": [...]}). An id is accepted as
// either a JSON string or a number for the same reason. Anything that is not
// JSON at all is an error, never a panic: these functions are fuzzed.

// keyPrefixLen is how much of a pre-auth key we ever keep. Headscale returns
// the whole key on a list; a tool that showed it would be leaking a credential,
// so only enough to recognise the row survives.
const keyPrefixLen = 10

// ParseUsers reads `headscale users list --output json`.
func ParseUsers(data []byte) ([]User, error) {
	raw, err := unwrap(data, "users")
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ID          flexString `json:"id"`
		Name        string     `json:"name"`
		DisplayName string     `json:"displayName"`
		Email       string     `json:"email"`
		Provider    string     `json:"provider"`
		ProviderID  string     `json:"providerId"`
		CreatedAt   string     `json:"createdAt"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("users: %w", err)
	}
	users := make([]User, 0, len(rows))
	for _, r := range rows {
		users = append(users, User{
			ID:          string(r.ID),
			Name:        r.Name,
			DisplayName: r.DisplayName,
			Email:       r.Email,
			Provider:    r.Provider,
			ProviderID:  r.ProviderID,
			CreatedAt:   parseTime(r.CreatedAt),
		})
	}
	return users, nil
}

// ParseNodes reads `headscale nodes list --output json`.
func ParseNodes(data []byte) ([]Node, error) {
	raw, err := unwrap(data, "nodes")
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ID             flexString `json:"id"`
		Name           string     `json:"name"`
		GivenName      string     `json:"givenName"`
		User           nameRef    `json:"user"`
		IPAddresses    []string   `json:"ipAddresses"`
		LastSeen       string     `json:"lastSeen"`
		Expiry         string     `json:"expiry"`
		Online         bool       `json:"online"`
		RegisterMethod string     `json:"registerMethod"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("nodes: %w", err)
	}
	nodes := make([]Node, 0, len(rows))
	for _, r := range rows {
		nodes = append(nodes, Node{
			ID:             string(r.ID),
			Name:           r.Name,
			GivenName:      r.GivenName,
			User:           r.User.name(),
			IPAddresses:    r.IPAddresses,
			LastSeen:       parseTime(r.LastSeen),
			Expiry:         parseTime(r.Expiry),
			Online:         r.Online,
			RegisterMethod: r.RegisterMethod,
		})
	}
	return nodes, nil
}

// ParsePreAuthKeys reads `headscale preauthkeys list --output json`.
func ParsePreAuthKeys(data []byte) ([]PreAuthKey, error) {
	raw, err := unwrap(data, "preAuthKeys")
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ID         flexString `json:"id"`
		User       nameRef    `json:"user"`
		Key        string     `json:"key"`
		Reusable   bool       `json:"reusable"`
		Ephemeral  bool       `json:"ephemeral"`
		Used       bool       `json:"used"`
		Expiration string     `json:"expiration"`
		CreatedAt  string     `json:"createdAt"`
		ACLTags    []string   `json:"aclTags"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("preauthkeys: %w", err)
	}
	keys := make([]PreAuthKey, 0, len(rows))
	for _, r := range rows {
		keys = append(keys, PreAuthKey{
			ID:         string(r.ID),
			User:       r.User.name(),
			KeyPrefix:  prefix(r.Key),
			Reusable:   r.Reusable,
			Ephemeral:  r.Ephemeral,
			Used:       r.Used,
			Expiration: parseTime(r.Expiration),
			CreatedAt:  parseTime(r.CreatedAt),
			ACLTags:    r.ACLTags,
		})
	}
	return keys, nil
}

// unwrap returns the JSON array to decode, accepting either a bare array or an
// object wrapping it under key.
func unwrap(data []byte, key string) (json.RawMessage, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty output")
	}
	switch trimmed[0] {
	case '[':
		return trimmed, nil
	case '{':
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil, err
		}
		if arr, ok := obj[key]; ok {
			return arr, nil
		}
		// An object with no known wrapper key is an empty list, not an error:
		// some versions print {} when there is nothing to show.
		return json.RawMessage("[]"), nil
	default:
		return nil, fmt.Errorf("not a JSON array or object")
	}
}

// flexString is a string that also accepts a JSON number, because Headscale has
// emitted an id both ways.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	// A bare number: keep its literal text.
	*f = flexString(strings.TrimSpace(string(b)))
	return nil
}

// nameRef is a reference to a named object that may arrive as an object with a
// "name" field, or as a bare string username (older Headscale).
type nameRef struct {
	value string
}

func (n *nameRef) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		return json.Unmarshal(b, &n.value)
	}
	if b[0] == '{' {
		var obj struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(b, &obj); err != nil {
			return err
		}
		n.value = obj.Name
		return nil
	}
	return nil
}

func (n nameRef) name() string { return n.value }

// parseTime reads an RFC 3339 timestamp, returning the zero time for anything
// empty, unparseable, or the protojson zero-year placeholder.
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "0001-01-01") {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// prefix returns the first keyPrefixLen characters of a key, never the whole
// thing.
func prefix(key string) string {
	key = strings.TrimSpace(key)
	if len(key) <= keyPrefixLen {
		return key
	}
	return key[:keyPrefixLen]
}

// InferOIDC reports whether user identity is coming from an external OpenID
// Connect provider, judged from the users and nodes that were read: a user that
// carries a provider, or a node registered through OIDC, is the evidence.
func InferOIDC(users []User, nodes []Node) bool {
	for _, u := range users {
		if u.Provider != "" || u.ProviderID != "" {
			return true
		}
	}
	for _, n := range nodes {
		if strings.Contains(strings.ToUpper(n.RegisterMethod), "OIDC") {
			return true
		}
	}
	return false
}
