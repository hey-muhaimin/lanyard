package auth

// Permission is a server-side capability checked before any mutating work.
type Permission string

const (
	PermissionAgentsRead       Permission = "agents.read"
	PermissionAgentsWrite      Permission = "agents.write"
	PermissionConnectorsWrite  Permission = "connectors.write"
	PermissionApprovalsRead    Permission = "approvals.read"
	PermissionApprovalsRequest Permission = "approvals.request"
	PermissionApprovalsDecide  Permission = "approvals.decide"
	PermissionRevoke           Permission = "revoke"
	PermissionEventsRead       Permission = "events.read"
	PermissionMembersManage    Permission = "members.manage"
)

// permissionMatrix mirrors web/console/src/lib/roles.ts exactly. The server is
// the authority; the client copy only decides what to render.
var permissionMatrix = map[Permission][]string{
	PermissionAgentsRead:       {"admin", "security", "agent_owner", "approver", "auditor"},
	PermissionAgentsWrite:      {"admin", "agent_owner"},
	PermissionConnectorsWrite:  {"admin", "security"},
	PermissionApprovalsRead:    {"admin", "security", "approver", "auditor"},
	PermissionApprovalsRequest: {"admin", "agent_owner"},
	PermissionApprovalsDecide:  {"admin", "approver"},
	PermissionRevoke:           {"admin", "security"},
	PermissionEventsRead:       {"admin", "security", "agent_owner", "auditor"},
	PermissionMembersManage:    {"admin"},
}

// Can reports whether role grants permission. Unknown roles and permissions are
// denied.
func Can(role, permission string) bool {
	for _, allowed := range permissionMatrix[Permission(permission)] {
		if allowed == role {
			return true
		}
	}
	return false
}
