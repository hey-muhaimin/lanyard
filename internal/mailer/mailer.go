// Package mailer delivers transactional email. It is the only place login codes
// leave the process, and it never returns the code in an error.
package mailer

import (
    "context"
    "fmt"
)

// LoginCodeSender delivers a sign-in code to a member's email address.
type LoginCodeSender interface {
    SendLoginCode(ctx context.Context, to, code string) error
}

const (
    // Subject is the fixed subject line for sign-in codes.
    Subject = "Lanyard sign-in code"
    // Charset is sent with every SES content part.
    Charset = "UTF-8"
    // BodyTemplate is the plain-text body; %s is replaced with the code.
    // The 10-minute expiry matches loginCodeTTL in cmd/controlplane/auth_server.go.
    BodyTemplate = "Your Lanyard sign-in code is %s.\n\nIt expires in 10 minutes. If you did not request this code, ignore this email.\n"
)

// Body renders the plain-text login-code body.
func Body(code string) string {
    return fmt.Sprintf(BodyTemplate, code)
}
