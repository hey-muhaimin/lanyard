package mailer

import (
    "context"
    "errors"
    "strings"
    "testing"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"

)

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

func TestSESSendLoginCodeBuildsRequest(t *testing.T) {
    fake := &fakeSES{}
    s := NewSESWithClient(fake, "no-reply@linkedqueue.cloud")
    err := s.SendLoginCode(context.Background(), "alice@example.com", "123456")
    if err != nil {
        t.Fatalf("SendLoginCode returned error: %v", err)
    }
    if fake.input == nil {
        t.Fatal("SendEmailInput was nil")
    }
    if got, want := *fake.input.FromEmailAddress, "no-reply@linkedqueue.cloud"; got != want {
        t.Fatalf("FromEmailAddress = %q, want %q", got, want)
    }
    if got := fake.input.Destination.ToAddresses; len(got) != 1 || got[0] != "alice@example.com" {
        t.Fatalf("Destination = %v, want [alice@example.com]", got)
    }
    if subj := fake.input.Content.Simple.Subject; subj == nil || subj.Data == nil || *subj.Data != Subject {
        t.Fatalf("Subject.Data = %v, want %q", subj.Data, Subject)
    }
    if charset := fake.input.Content.Simple.Subject.Charset; charset == nil || *charset != Charset {
        t.Fatalf("Subject.Charset = %v, want %q", charset, Charset)
    }
	if txt := fake.input.Content.Simple.Body.Text; txt == nil || txt.Data == nil || !strings.Contains(*txt.Data, "123456") || !strings.Contains(*txt.Data, "10 minutes") {
			t.Fatalf("Body.Text.Data = %q, must contain code and expiry", *txt.Data)

	}
	if txt := fake.input.Content.Simple.Body.Text; txt.Charset == nil || *txt.Charset != Charset {
		t.Fatalf("Body.Text.Charset = %v, want %q", txt.Charset, Charset)
	}

    if fake.input.Content.Simple.Body.Html != nil {
        t.Fatalf("Expected no HTML body, got %v", fake.input.Content.Simple.Body.Html)
    }
}

func TestSESSendLoginCodePropagatesErrorWithoutCode(t *testing.T) {
    fake := &fakeSES{err: errors.New("MessageRejected: Email address is not verified")}
    s := NewSESWithClient(fake, "no-reply@linkedqueue.cloud")
    err := s.SendLoginCode(context.Background(), "alice@example.com", "123456")
    if err == nil {
        t.Fatal("expected error, got nil")
    }
    if !strings.Contains(err.Error(), "MessageRejected") {
        t.Fatalf("error does not contain expected text: %v", err)
    }
    if strings.Contains(err.Error(), "123456") {
        t.Fatalf("error must not contain the code: %v", err)
    }
}

func TestSESSendLoginCodeRequiresClient(t *testing.T) {
    s := NewSESWithClient(nil, "a@b.co")
    if err := s.SendLoginCode(context.Background(), "bob@example.com", "654321"); err == nil {
        t.Fatal("expected error due to nil client")
    }
}

func TestSESSendLoginCodeRejectsEmptyArguments(t *testing.T) {
    fake := &fakeSES{}
    s := NewSESWithClient(fake, "no-reply@linkedqueue.cloud")
    if err := s.SendLoginCode(context.Background(), "", "123456"); err == nil {
        t.Fatal("expected error for empty recipient")
    }
    if err := s.SendLoginCode(context.Background(), "alice@example.com", ""); err == nil {
        t.Fatal("expected error for empty code")
    }
}
