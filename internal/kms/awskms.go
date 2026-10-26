package kms

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/example/lanyard/internal/vault"
)

// Client is the narrow subset of the AWS KMS API this adapter needs, so tests
// can substitute a fake without importing the full SDK surface.
type Client interface {
	GenerateDataKey(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	Decrypt(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// Adapter implements vault.KMS using AWS KMS.
type Adapter struct {
	client  Client
	keyID   string
	retries int
}

// NewFromEnv builds an Adapter using the default AWS credential chain
// (instance role / IMDS) and the region from AWS_REGION.
func NewFromEnv(ctx context.Context, keyID, region string) (*Adapter, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	client := kms.NewFromConfig(cfg)
	return &Adapter{
		client:  client,
		keyID:   keyID,
		retries: 3,
	}, nil
}

// NewWithClient is the test constructor.
func NewWithClient(client Client, keyID string) *Adapter {
	return &Adapter{
		client:  client,
		keyID:   keyID,
		retries: 3,
	}
}

// Compile-time assertion that Adapter implements vault.KMS.
var _ vault.KMS = (*Adapter)(nil)

// GenerateDataKey returns a fresh plaintext DEK and its KMS-wrapped form.
func (a *Adapter) GenerateDataKey(ctx context.Context, keyID string, encryptionContext map[string]string) ([]byte, []byte, error) {
	if len(encryptionContext) == 0 {
		return nil, nil, errors.New("encryption context is required")
	}

	kid := keyID
	if kid == "" {
		kid = a.keyID
	}

	input := &kms.GenerateDataKeyInput{
		KeyId:             &kid,
		KeySpec:           types.DataKeySpecAes256,
		EncryptionContext: encryptionContext,
	}

	var lastErr error
	for attempt := 1; attempt <= a.retries; attempt++ {
		out, err := a.client.GenerateDataKey(ctx, input)
		if err == nil {
			if out == nil {
				return nil, nil, fmt.Errorf("%w", vault.ErrKMSUnavailable)
			}
			return out.Plaintext, out.CiphertextBlob, nil
		}
		mapped := mapError(err)
		lastErr = mapped
		if !errors.Is(mapped, vault.ErrKMSUnavailable) {
			return nil, nil, mapped
		}
		if attempt < a.retries {
			sleepWithJitter(backoffDuration(attempt))
		}
	}
	return nil, nil, lastErr
}

// Decrypt unwraps a DEK. Returns ErrKMSTenantMismatch when the encryption
// context does not match the one used at generation.
func (a *Adapter) Decrypt(ctx context.Context, keyID string, wrappedDEK []byte, encryptionContext map[string]string) ([]byte, error) {
	if len(encryptionContext) == 0 {
		return nil, errors.New("encryption context is required")
	}

	kid := keyID
	if kid == "" {
		kid = a.keyID
	}

	input := &kms.DecryptInput{
		CiphertextBlob:    wrappedDEK,
		EncryptionContext: encryptionContext,
		KeyId:             &kid,
	}

	var lastErr error
	for attempt := 1; attempt <= a.retries; attempt++ {
		out, err := a.client.Decrypt(ctx, input)
		if err == nil {
			if out == nil {
				return nil, fmt.Errorf("%w", vault.ErrKMSUnavailable)
			}
			return out.Plaintext, nil
		}
		mapped := mapError(err)
		lastErr = mapped
		if !errors.Is(mapped, vault.ErrKMSUnavailable) {
			return nil, mapped
		}
		if attempt < a.retries {
			sleepWithJitter(backoffDuration(attempt))
		}
	}
	return nil, lastErr
}

func backoffDuration(attempt int) time.Duration {
	base := 50 * time.Millisecond
	d := base * time.Duration(1<<uint(attempt-1))
	return d
}

func sleepWithJitter(d time.Duration) {
	jitter := 0.8 + rand.Float64()*0.4
	d = time.Duration(float64(d) * jitter)
	if d < 0 {
		d = 0
	}
	time.Sleep(d)
}

func mapError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	var ike *types.IncorrectKeyException
	if errors.As(err, &ike) {
		return fmt.Errorf("%w: %s", vault.ErrKMSTenantMismatch, ike.Error())
	}
	// decryption-context failure -> ErrKMSTenantMismatch
	if contains(errStr, "IncorrectKey") || contains(errStr, "encryption context") || contains(errStr, "EncryptionContext") {
		return fmt.Errorf("%w: %s", vault.ErrKMSTenantMismatch, errStr)
	}

	var nfe *types.NotFoundException
	if errors.As(err, &nfe) {
		return fmt.Errorf("%w: %s", vault.ErrKMSNotFound, nfe.Error())
	}
	var ice *types.InvalidCiphertextException
	if errors.As(err, &ice) {
		// Check if it's actually a context issue - we already checked above
		if contains(ice.Error(), "context") || contains(ice.Error(), "IncorrectKey") {
			return fmt.Errorf("%w: %s", vault.ErrKMSTenantMismatch, ice.Error())
		}
		return fmt.Errorf("%w: %s", vault.ErrKMSNotFound, ice.Error())
	}
	// AccessDeniedException, ThrottlingException and a few others are generic
	// smithy errors in this SDK version (not modelled in service/kms/types), so
	// they can only be identified by their API error code.
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDeniedException":
			return fmt.Errorf("%w: %s", vault.ErrKMSDenied, errStr)
		case "ThrottlingException", "KMSInternalException", "DependencyTimeoutException", "LimitExceededException":
			return fmt.Errorf("%w: %s", vault.ErrKMSUnavailable, errStr)
		}
	}

	var kie2 *types.KMSInternalException
	if errors.As(err, &kie2) {
		return fmt.Errorf("%w: %s", vault.ErrKMSUnavailable, kie2.Error())
	}
	var dte *types.DependencyTimeoutException
	if errors.As(err, &dte) {
		return fmt.Errorf("%w: %s", vault.ErrKMSUnavailable, dte.Error())
	}

	if contains(errStr, "timeout") || contains(errStr, "Timeout") ||
		contains(errStr, "Throttl") || contains(errStr, "RequestLimitExceeded") ||
		contains(errStr, "connection") || contains(errStr, "network") ||
		contains(errStr, "KMSInternalException") {
		return fmt.Errorf("%w: %s", vault.ErrKMSUnavailable, errStr)
	}

	return fmt.Errorf("%w: %s", vault.ErrKMSUnavailable, err.Error())
}

func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
