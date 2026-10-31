package auth

import "testing"

// everyCell is an independent restatement of the matrix in
// web/console/src/lib/roles.ts: role -> permission -> allowed.
var everyCell = map[string]map[string]bool{
	"admin": {
		"agents.read": true, "agents.write": true, "connectors.write": true,
		"approvals.read": true, "approvals.request": true, "approvals.decide": true,
		"revoke": true, "events.read": true, "members.manage": true,
	},
	"security": {
		"agents.read": true, "agents.write": false, "connectors.write": true,
		"approvals.read": true, "approvals.request": false, "approvals.decide": false,
		"revoke": true, "events.read": true, "members.manage": false,
	},
	"agent_owner": {
		"agents.read": true, "agents.write": true, "connectors.write": false,
		"approvals.read": false, "approvals.request": true, "approvals.decide": false,
		"revoke": false, "events.read": true, "members.manage": false,
	},
	"approver": {
		"agents.read": true, "agents.write": false, "connectors.write": false,
		"approvals.read": true, "approvals.request": false, "approvals.decide": true,
		"revoke": false, "events.read": false, "members.manage": false,
	},
	"auditor": {
		"agents.read": true, "agents.write": false, "connectors.write": false,
		"approvals.read": true, "approvals.request": false, "approvals.decide": false,
		"revoke": false, "events.read": true, "members.manage": false,
	},
}

var allPermissions = []string{
	"agents.read", "agents.write", "connectors.write",
	"approvals.read", "approvals.request", "approvals.decide",
	"revoke", "events.read", "members.manage",
}

func TestCanMatchesEveryMatrixCell(t *testing.T) {
	roles := []string{"admin", "security", "agent_owner", "approver", "auditor"}
	checked := 0
	for _, role := range roles {
		want, ok := everyCell[role]
		if !ok {
			t.Fatalf("test data missing role %q", role)
		}
		for _, permission := range allPermissions {
			expected, ok := want[permission]
			if !ok {
				t.Fatalf("test data missing cell %s/%s", role, permission)
			}
			if got := Can(role, permission); got != expected {
				t.Errorf("Can(%q, %q) = %v, want %v", role, permission, got, expected)
			}
			checked++
		}
	}
	if checked != len(roles)*len(allPermissions) {
		t.Fatalf("checked %d cells, want %d", checked, len(roles)*len(allPermissions))
	}
}

func TestCanDeniesUnknownRoleAndPermission(t *testing.T) {
	if Can("", "agents.read") {
		t.Error("Can with empty role must be false")
	}
	if Can("admin", "unknown.permission") {
		t.Error("Can with unknown permission must be false")
	}
	if Can("owner", "agents.write") {
		t.Error("Can with unknown role must be false")
	}
}
