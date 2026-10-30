package awssecrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type API interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type Reader struct {
	client API
}

func NewFromEnv(ctx context.Context, region string) (*Reader, error) {
	if region == "" {
		return nil, errors.New("AWS region is required for Secrets Manager")
	}
	config, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration for Secrets Manager: %w", err)
	}
	return NewWithClient(secretsmanager.NewFromConfig(config)), nil
}

func NewWithClient(client API) *Reader {
	return &Reader{client: client}
}

func (r *Reader) String(ctx context.Context, secretARN string) (string, error) {
	if r == nil || r.client == nil {
		return "", errors.New("Secrets Manager client is required")
	}
	if secretARN == "" {
		return "", errors.New("Secrets Manager secret ARN is required")
	}
	output, err := r.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: &secretARN})
	if err != nil {
		return "", fmt.Errorf("get Secrets Manager value: %w", err)
	}
	if output == nil || output.SecretString == nil || *output.SecretString == "" {
		return "", errors.New("Secrets Manager secret has no string value")
	}
	return *output.SecretString, nil
}

func (r *Reader) PostgresURL(ctx context.Context, secretARN string) (string, error) {
	raw, err := r.String(ctx, secretARN)
	if err != nil {
		return "", err
	}
	var credentials struct {
		Engine   string `json:"engine"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
		Database string `json:"dbname"`
	}
	if err := json.Unmarshal([]byte(raw), &credentials); err != nil {
		return "", fmt.Errorf("decode PostgreSQL secret: %w", err)
	}
	if credentials.Engine != "postgres" || credentials.Host == "" || credentials.Username == "" || credentials.Password == "" {
		return "", errors.New("PostgreSQL secret is missing required connection fields")
	}
	if credentials.Port == 0 {
		credentials.Port = 5432
	}
	if credentials.Port < 1 || credentials.Port > 65535 {
		return "", errors.New("PostgreSQL secret has an invalid port")
	}
	if credentials.Database == "" {
		credentials.Database = "postgres"
	}
	connectionURL := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(credentials.Username, credentials.Password),
		Host:   net.JoinHostPort(credentials.Host, fmt.Sprint(credentials.Port)),
		Path:   "/" + credentials.Database,
	}
	query := connectionURL.Query()
	query.Set("sslmode", "verify-full")
	connectionURL.RawQuery = query.Encode()
	return connectionURL.String(), nil
}
