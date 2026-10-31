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

// NewSES builds a sender for region and from address. Both are required.
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
    return len(value) <= 254 && strings.Count(value, "@") == 1 && !strings.ContainsAny(value, " \t\r\n")
}
