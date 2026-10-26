package kms

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/example/lanyard/internal/vault"
)

type fakeClient struct {
	generateDataKeyFunc func(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
	decryptFunc         func(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	generateCalls       int
	decryptCalls        int
}

func (f *fakeClient) GenerateDataKey(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	f.generateCalls++
	if f.generateDataKeyFunc != nil {
		return f.generateDataKeyFunc(ctx, in, optFns...)
	}
	return &kms.GenerateDataKeyOutput{
		Plaintext:      []byte("plaintextdek"),
		CiphertextBlob: []byte("wrappeddek"),
	}, nil
}

func (f *fakeClient) Decrypt(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.decryptCalls++
	if f.decryptFunc != nil {
		return f.decryptFunc(ctx, in, optFns...)
	}
	return &kms.DecryptOutput{
		Plaintext: []byte("plaintextdek"),
	}, nil
}

func TestCompileTimeAssertion(t *testing.T) {
	var _ vault.KMS = (*Adapter)(nil)
}

func TestGenerateDataKeySuccess(t *testing.T) {
	fc := &fakeClient{}
	a := NewWithClient(fc, "key1")
	enc := map[string]string{"tenant_id": "t1", "purpose": "secret"}
	pt, wrapped, err := a.GenerateDataKey(context.Background(), "", enc)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(pt) != "plaintextdek" || string(wrapped) != "wrappeddek" {
		t.Fatalf("bad outputs")
	}
	if fc.generateCalls != 1 {
		t.Fatalf("expected 1 call, got %d", fc.generateCalls)
	}
}

func TestGenerateDataKeyKeyIDOverride(t *testing.T) {
	fc := &fakeClient{
		generateDataKeyFunc: func(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
			if in.KeyId == nil || *in.KeyId != "override" {
				t.Fatalf("expected override key")
			}
			if in.KeySpec != types.DataKeySpecAes256 {
				t.Fatalf("expected AES_256")
			}
			if in.EncryptionContext["tenant_id"] != "t1" {
				t.Fatalf("bad context")
			}
			return &kms.GenerateDataKeyOutput{Plaintext: []byte("p"), CiphertextBlob: []byte("c")}, nil
		},
	}
	a := NewWithClient(fc, "default")
	_, _, err := a.GenerateDataKey(context.Background(), "override", map[string]string{"tenant_id": "t1", "purpose": "secret"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestGenerateDataKeyEmptyContext(t *testing.T) {
	fc := &fakeClient{}
	a := NewWithClient(fc, "key1")
	_, _, err := a.GenerateDataKey(context.Background(), "", map[string]string{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if errors.Is(err, vault.ErrKMSUnavailable) {
		t.Fatalf("should not be ErrKMSUnavailable")
	}
}

func TestDecryptSuccess(t *testing.T) {
	fc := &fakeClient{}
	a := NewWithClient(fc, "key1")
	pt, err := a.Decrypt(context.Background(), "", []byte("wrapped"), map[string]string{"tenant_id": "t1", "purpose": "secret"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(pt) != "plaintextdek" {
		t.Fatalf("bad pt")
	}
}

func TestErrorMappingNotFound(t *testing.T) {
	fc := &fakeClient{
		generateDataKeyFunc: func(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
			return nil, &types.NotFoundException{Message: awsString("not found")}
		},
	}
	a := NewWithClient(fc, "key1")
	_, _, err := a.GenerateDataKey(context.Background(), "", map[string]string{"t": "1"})
	if !errors.Is(err, vault.ErrKMSNotFound) {
		t.Fatalf("expected ErrKMSNotFound, got %v", err)
	}
}

func TestErrorMappingInvalidCiphertext(t *testing.T) {
	fc := &fakeClient{
		decryptFunc: func(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			return nil, &types.InvalidCiphertextException{Message: awsString("bad")}
		},
	}
	a := NewWithClient(fc, "key1")
	_, err := a.Decrypt(context.Background(), "", []byte("w"), map[string]string{"t": "1"})
	if !errors.Is(err, vault.ErrKMSTenantMismatch) {
		t.Fatalf("expected ErrKMSTenantMismatch, got %v", err)
	}
}

func TestErrorMappingAccessDenied(t *testing.T) {
	fc := &fakeClient{
		generateDataKeyFunc: func(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
			return nil, &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}
		},
	}
	a := NewWithClient(fc, "key1")
	_, _, err := a.GenerateDataKey(context.Background(), "", map[string]string{"t": "1"})
	if !errors.Is(err, vault.ErrKMSDenied) {
		t.Fatalf("expected ErrKMSDenied, got %v", err)
	}
}

func TestErrorMappingIncorrectKey(t *testing.T) {
	fc := &fakeClient{
		decryptFunc: func(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			return nil, &types.IncorrectKeyException{Message: awsString("bad key")}
		},
	}
	a := NewWithClient(fc, "key1")
	_, err := a.Decrypt(context.Background(), "", []byte("w"), map[string]string{"t": "1"})
	if !errors.Is(err, vault.ErrKMSTenantMismatch) {
		t.Fatalf("expected ErrKMSTenantMismatch, got %v", err)
	}
}

func TestErrorMappingContextFailure(t *testing.T) {
	fc := &fakeClient{
		decryptFunc: func(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			return nil, errors.New("InvalidCiphertextException due to encryption context")
		},
	}
	a := NewWithClient(fc, "key1")
	_, err := a.Decrypt(context.Background(), "", []byte("w"), map[string]string{"t": "1"})
	if !errors.Is(err, vault.ErrKMSTenantMismatch) {
		t.Fatalf("expected ErrKMSTenantMismatch, got %v", err)
	}
}

func TestErrorMappingThrottling(t *testing.T) {
	fc := &fakeClient{
		generateDataKeyFunc: func(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
			return nil, &smithy.GenericAPIError{Code: "ThrottlingException", Message: "throttle"}
		},
	}
	a := NewWithClient(fc, "key1")
	_, _, err := a.GenerateDataKey(context.Background(), "", map[string]string{"t": "1"})
	if !errors.Is(err, vault.ErrKMSUnavailable) {
		t.Fatalf("expected ErrKMSUnavailable, got %v", err)
	}
}

func TestErrorMappingKMSInternal(t *testing.T) {
	fc := &fakeClient{
		generateDataKeyFunc: func(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
			return nil, &types.KMSInternalException{Message: awsString("internal")}
		},
	}
	a := NewWithClient(fc, "key1")
	_, _, err := a.GenerateDataKey(context.Background(), "", map[string]string{"t": "1"})
	if !errors.Is(err, vault.ErrKMSUnavailable) {
		t.Fatalf("expected ErrKMSUnavailable, got %v", err)
	}
}

func TestRetryThrottleThenSucceed(t *testing.T) {
	calls := 0
	fc := &fakeClient{
		generateDataKeyFunc: func(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
			calls++
			if calls < 3 {
				return nil, &smithy.GenericAPIError{Code: "ThrottlingException", Message: "throttle"}
			}
			return &kms.GenerateDataKeyOutput{Plaintext: []byte("p"), CiphertextBlob: []byte("c")}, nil
		},
	}
	a := NewWithClient(fc, "key1")
	pt, wrapped, err := a.GenerateDataKey(context.Background(), "", map[string]string{"t": "1"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(pt) != "p" || string(wrapped) != "c" {
		t.Fatalf("bad")
	}
	if calls != 3 {
		t.Fatalf("expected exactly 3 attempts, got %d", calls)
	}
}

func TestNoRetryOnDenied(t *testing.T) {
	calls := 0
	fc := &fakeClient{
		generateDataKeyFunc: func(ctx context.Context, in *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
			calls++
			return nil, &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}
		},
	}
	a := NewWithClient(fc, "key1")
	_, _, err := a.GenerateDataKey(context.Background(), "", map[string]string{"t": "1"})
	if !errors.Is(err, vault.ErrKMSDenied) {
		t.Fatalf("expected ErrKMSDenied")
	}
	if calls != 1 {
		t.Fatalf("expected no retry, got %d calls", calls)
	}
}

func TestNoRetryOnTenantMismatch(t *testing.T) {
	calls := 0
	fc := &fakeClient{
		decryptFunc: func(ctx context.Context, in *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			calls++
			return nil, &types.IncorrectKeyException{Message: awsString("bad")}
		},
	}
	a := NewWithClient(fc, "key1")
	_, err := a.Decrypt(context.Background(), "", []byte("w"), map[string]string{"t": "1"})
	if !errors.Is(err, vault.ErrKMSTenantMismatch) {
		t.Fatalf("expected ErrKMSTenantMismatch")
	}
	if calls != 1 {
		t.Fatalf("expected no retry, got %d calls", calls)
	}
}

func awsString(s string) *string {
	return &s
}
