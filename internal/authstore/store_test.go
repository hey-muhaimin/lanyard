package authstore

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const expectedPolicyBody = `permit (principal is Agent, action, resource is Resource) when { principal.status == "active" && principal.tenantId == context.tenantId && context.connector == resource.connector && context.rowLimit <= 1000 && context.ttlSeconds <= 600 };`

func TestDefaultPolicyBodyMatchesSpec(t *testing.T) {
	if defaultPolicyBody != expectedPolicyBody {
		t.Fatalf("defaultPolicyBody =\n%q\nwant\n%q", defaultPolicyBody, expectedPolicyBody)
	}
}

func TestNewReturnsStore(t *testing.T) {
	if New(nil) == nil {
		t.Fatal("New(nil) returned nil")
	}
}

func connectAuthIntegration(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL must be set in CI")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("connect to TEST_DATABASE_URL: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestAuthStoreIntegration exercises the 003_auth.sql functions end to end. It
// requires a migrated database as lanyard_app and is skipped without
// TEST_DATABASE_URL.
func TestAuthStoreIntegration(t *testing.T) {
	pool := connectAuthIntegration(t)
	store := New(pool)
	ctx := context.Background()

	suffix := time.Now().UnixNano()
	email := fmt.Sprintf("__vg_email_%d__", suffix)
	tenantName := fmt.Sprintf("authstore-test-%d", suffix)

	tenantID, err := store.CreateTenantWithAdmin(ctx, tenantName, strings.ToUpper(email), "admin")
	if err != nil {
		t.Fatalf("CreateTenantWithAdmin() error = %v", err)
	}
	if tenantID == "" {
		t.Fatal("CreateTenantWithAdmin() returned an empty tenant id")
	}

	// Verify the member and published policy the transaction created.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin verification transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
		t.Fatalf("set tenant context: %v", err)
	}
	var memberEmail, role, body, status string
	var version int
	if err := tx.QueryRow(ctx, `SELECT email, role FROM members`).Scan(&memberEmail, &role); err != nil {
		t.Fatalf("read member: %v", err)
	}
	if err := tx.QueryRow(ctx, `SELECT body, status, version FROM policies`).Scan(&body, &status, &version); err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if memberEmail != email {
		t.Fatalf("member email = %q, want lowercased %q", memberEmail, email)
	}
	if role != "admin" {
		t.Fatalf("member role = %q, want admin", role)
	}
	if body != expectedPolicyBody || status != "published" || version != 1 {
		t.Fatalf("policy = {status:%q version:%d body:%q}", status, version, body)
	}

	code := "424242"
	codeHash := sha256.Sum256([]byte(code))
	stored, err := store.RequestCode(ctx, email, codeHash[:], time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("RequestCode() error = %v", err)
	}
	if !stored {
		t.Fatal("RequestCode() = false, want true for an active member")
	}

	wrongHash := sha256.Sum256([]byte("111111"))
	if _, ok, err := store.VerifyCode(ctx, email, wrongHash[:]); err != nil || ok {
		t.Fatalf("VerifyCode(wrong) = ok:%v err:%v, want false, nil", ok, err)
	}
	member, ok, err := store.VerifyCode(ctx, email, codeHash[:])
	if err != nil {
		t.Fatalf("VerifyCode() error = %v", err)
	}
	if !ok {
		t.Fatal("VerifyCode() = false, want true")
	}
	if member.TenantID != tenantID || member.MemberID == "" || member.Role != "admin" {
		t.Fatalf("VerifyCode() member = %#v, want admin in %s", member, tenantID)
	}
	if _, ok, _ := store.VerifyCode(ctx, email, codeHash[:]); ok {
		t.Fatal("a code must be consumed after a successful verify")
	}

	tokenHash := sha256.Sum256([]byte("integration-token"))
	if err := store.CreateSession(ctx, tokenHash[:], member.MemberID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	session, ok, err := store.GetSession(ctx, tokenHash[:], 2*time.Hour)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if !ok {
		t.Fatal("GetSession() = false, want true")
	}
	if session.Email != email || session.TenantID != tenantID || session.MemberID != member.MemberID || session.Role != "admin" {
		t.Fatalf("GetSession() = %#v", session)
	}

	if err := store.EndSession(ctx, tokenHash[:]); err != nil {
		t.Fatalf("EndSession() error = %v", err)
	}
	if _, ok, err := store.GetSession(ctx, tokenHash[:], 2*time.Hour); err != nil || ok {
		t.Fatalf("GetSession() after EndSession = ok:%v err:%v, want false, nil", ok, err)
	}
}
