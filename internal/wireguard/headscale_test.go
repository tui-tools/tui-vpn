package wireguard

import "testing"

func TestParseUsers(t *testing.T) {
	users, err := ParseUsers([]byte(readFixture(t, "headscale-users.json")))
	if err != nil {
		t.Fatalf("ParseUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("got %d users, want 2", len(users))
	}
	if users[0].Name != "ana" || users[0].Provider != "oidc" {
		t.Errorf("user 0 = %+v", users[0])
	}
	if users[0].CreatedAt.IsZero() {
		t.Error("user 0 has a created-at time in the fixture")
	}
	if !InferOIDC(users, nil) {
		t.Error("users carrying a provider imply OIDC")
	}
}

func TestParseNodes(t *testing.T) {
	nodes, err := ParseNodes([]byte(readFixture(t, "headscale-nodes.json")))
	if err != nil {
		t.Fatalf("ParseNodes: %v", err)
	}
	if len(nodes) != 3 {
		t.Fatalf("got %d nodes, want 3", len(nodes))
	}
	if nodes[0].User != "ana" {
		t.Errorf("node 0 user = %q, want ana (from the nested object)", nodes[0].User)
	}
	if len(nodes[0].IPAddresses) != 2 {
		t.Errorf("node 0 addresses = %v", nodes[0].IPAddresses)
	}
	// The third node is already expired in the fixture.
	if nodes[2].Expiry.IsZero() {
		t.Error("node 2 has an expiry")
	}
	if !InferOIDC(nil, nodes) {
		t.Error("a node registered via OIDC implies OIDC")
	}
}

func TestParsePreAuthKeys(t *testing.T) {
	keys, err := ParsePreAuthKeys([]byte(readFixture(t, "headscale-preauthkeys.json")))
	if err != nil {
		t.Fatalf("ParsePreAuthKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	k := keys[0]
	if k.User != "ana" || !k.Reusable || k.Used {
		t.Errorf("key = %+v", k)
	}
	// The parser keeps only a short prefix, never the whole key.
	if len(k.KeyPrefix) > keyPrefixLen {
		t.Errorf("key prefix %q is longer than the cap", k.KeyPrefix)
	}
}

// TestParseTolerantShapes covers the variations seen across Headscale versions:
// an object wrapping the array, a numeric id, and a bare-string user.
func TestParseTolerantShapes(t *testing.T) {
	users, err := ParseUsers([]byte(`{"users":[{"id":7,"name":"cara"}]}`))
	if err != nil {
		t.Fatalf("wrapped object: %v", err)
	}
	if len(users) != 1 || users[0].ID != "7" || users[0].Name != "cara" {
		t.Errorf("wrapped/numeric parse = %+v", users)
	}

	nodes, err := ParseNodes([]byte(`[{"id":"9","name":"n","user":"dave","ipAddresses":[]}]`))
	if err != nil {
		t.Fatalf("string user: %v", err)
	}
	if len(nodes) != 1 || nodes[0].User != "dave" {
		t.Errorf("string-user parse = %+v", nodes)
	}

	// An empty object is an empty list, not an error.
	if got, err := ParseUsers([]byte(`{}`)); err != nil || len(got) != 0 {
		t.Errorf("empty object = %v, %v", got, err)
	}
}

func TestParseRejectsNonJSON(t *testing.T) {
	if _, err := ParseUsers([]byte("not json")); err == nil {
		t.Error("expected an error for non-JSON")
	}
	if _, err := ParseNodes([]byte("")); err == nil {
		t.Error("expected an error for empty input")
	}
}
