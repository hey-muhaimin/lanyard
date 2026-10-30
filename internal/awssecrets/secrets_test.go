package awssecrets

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type fakeClient struct {
	output *secretsmanager.GetSecretValueOutput
	err    error
	input  *secretsmanager.GetSecretValueInput
}

func (c *fakeClient) GetSecretValue(_ context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	c.input = input
	return c.output, c.err
}

func TestStringLoadsSecretByARN(t *testing.T) {
	client := &fakeClient{output: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("value")}}
	reader := NewWithClient(client)
	got, err := reader.String(context.Background(), "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:production/test")
	if err != nil {
		t.Fatalf("String() error = %v", err)
	}
	if got != "value" {
		t.Fatalf("String() = %q, want %q", got, "value")
	}
	if client.input == nil || aws.ToString(client.input.SecretId) == "" {
		t.Fatal("String() did not request the configured secret ARN")
	}
}

func TestStringRejectsMissingARNAndEmptySecret(t *testing.T) {
	reader := NewWithClient(&fakeClient{output: &secretsmanager.GetSecretValueOutput{}})
	if _, err := reader.String(context.Background(), ""); err == nil {
		t.Fatal("String() accepted an empty ARN")
	}
	if _, err := reader.String(context.Background(), "arn:example"); err == nil {
		t.Fatal("String() accepted an empty secret value")
	}
}

func TestStringPropagatesProviderErrors(t *testing.T) {
	want := errors.New("provider failure")
	reader := NewWithClient(&fakeClient{err: want})
	if _, err := reader.String(context.Background(), "arn:example"); !errors.Is(err, want) {
		t.Fatalf("String() error = %v, want %v", err, want)
	}
}

func TestPostgresURLUsesTLSAndEscapesCredentials(t *testing.T) {
	client := &fakeClient{output: &secretsmanager.GetSecretValueOutput{SecretString: aws.String(`{"engine":"postgres","host":"db.example","port":5432,"username":"lanyard user","password":"p@ss:word","dbname":"lanyard"}`)}}
	reader := NewWithClient(client)
	url, err := reader.PostgresURL(context.Background(), "arn:example")
	if err != nil {
		t.Fatalf("PostgresURL() error = %v", err)
	}
	if !strings.HasPrefix(url, "postgres://lanyard%20user:p%40ss%3Aword@db.example:5432/lanyard?") || !strings.Contains(url, "sslmode=verify-full") {
		t.Fatalf("PostgresURL() = %q, want escaped credentials and TLS verification", url)
	}
}
