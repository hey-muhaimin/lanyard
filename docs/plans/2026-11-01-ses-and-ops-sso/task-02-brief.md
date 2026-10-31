# Task 02 — `internal/mailer`: SES v2 login-code sender

**Where this fits:** the only place a login code leaves the process. The handler depends
on the `LoginCodeSender` interface, never on SES directly, so tests stay offline.

**Depends on:** nothing.
**Blocks:** 03.

## Files

- `internal/mailer/mailer.go` (create)
- `internal/mailer/ses.go` (create)
- `internal/mailer/ses_test.go` (create)
- `go.mod`, `go.sum` (dependency)

## Dependency

```sh
go get github.com/aws/aws-sdk-go-v2/service/sesv2
go mod tidy
```

`github.com/aws/aws-sdk-go-v2/service/sesv2` and `github.com/aws/aws-sdk-go-v2/aws` become
direct requirements; commit the resolved versions. Do not pin `@latest` in code comments —
whatever `go get` resolves and `go mod tidy` keeps is the version.

## `internal/mailer/mailer.go`

```go
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
```

## `internal/mailer/ses.go`

```go
package mailer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

// sesAPI is the narrow SES surface the sender needs; tests substitute a fake.
type sesAPI interface {
	SendEmail(ctx context.Context, params *sesv2.SendEmailInput, optFns ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error)
}

// SES sends login codes through Amazon SES v2.
type SES struct {
	client sesAPI
	from   string
}

// NewSES builds a sender for region and from. Both are required.
func NewSES(ctx context.Context, region, from string) (*SES, error) {
	if region == "" {
		return nil, errors.New("AWS region is required for SES")
	}
	if !validFrom(from) {
		return nil, errors.New("sender address must be an email address")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration for SES: %w", err)
	}
	return NewSESWithClient(sesv2.NewFromConfig(cfg), from), nil
}

// NewSESWithClient builds a sender over an existing client (used by tests).
func NewSESWithClient(client sesAPI, from string) *SES {
	return &SES{client: client, from: from}
}

// SendLoginCode sends the sign-in code as a plain-text email. The returned error
// never contains the code.
func (s *SES) SendLoginCode(ctx context.Context, to, code string) error {
	if s == nil || s.client == nil {
		return errors.New("SES client is required")
	}
	if to == "" || code == "" {
		return errors.New("recipient and code are required")
	}
	_, err := s.client.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(s.from),
		Destination: &types.Destination{
			ToAddresses: []string{to},
		},
		Content: &types.EmailContent{
			Simple: &types.Message{
				Subject: &types.Content{
					Data:    aws.String(Subject),
					Charset: aws.String(Charset),
				},
				Body: &types.Body{
					Text: &types.Content{
						Data:    aws.String(Body(code)),
						Charset: aws.String(Charset),
					},
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("send login code email: %w", err)
	}
	return nil
}

func validFrom(value string) bool {
	return len(value) <= 254 &&
		strings.Count(value, "@") == 1 &&
		!strings.ContainsAny(value, " \t\r\n")
}
```

## `internal/mailer/ses_test.go`

Fake client:

```go
type fakeSES struct {
	input *sesv2.SendEmailInput
	err   error
}

func (f *fakeSES) SendEmail(ctx context.Context, params *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
	f.input = params
	if f.err != nil {
		return nil, f.err
	}
	return &sesv2.SendEmailOutput{}, nil
}
```

Required cases:

1. `TestSESSendLoginCodeBuildsRequest`
   - `NewSESWithClient(fake, "no-reply@linkedqueue.cloud")`, send to `alice@example.com`
     with code `123456`.
   - assert `*input.FromEmailAddress == "no-reply@linkedqueue.cloud"`
   - assert `input.Destination.ToAddresses == []string{"alice@example.com"}`
   - assert `*input.Content.Simple.Subject.Data == mailer.Subject` and
     `*input.Content.Simple.Subject.Charset == "UTF-8"`
   - assert `*input.Content.Simple.Body.Text.Charset == "UTF-8"`
   - assert `*input.Content.Simple.Body.Text.Data` contains `123456` and contains
     `10 minutes`, and has **no** HTML part (`input.Content.Simple.Body.Html == nil`).
2. `TestSESSendLoginCodePropagatesErrorWithoutCode`
   - fake returns `errors.New("MessageRejected: Email address is not verified")`.
   - assert returned error is non-nil, `strings.Contains(err.Error(), "MessageRejected")`,
     and `!strings.Contains(err.Error(), "123456")`.
3. `TestSESSendLoginCodeRequiresClient` — `NewSESWithClient(nil, "a@b.co")` returns non-nil
   and `SendLoginCode` errors.
4. `TestSESSendLoginCodeRejectsEmptyArguments` — empty `to` and empty `code` both error
   and never call the client.

## Verification

```sh
go test ./internal/mailer/ -v
go build ./... && go vet ./internal/mailer/
```

No network call is made by the tests; the AWS client is faked.
