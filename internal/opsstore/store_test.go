package opsstore

import (
    "context"
    "crypto/sha256"
    "errors"
    "fmt"
    "os"
    "testing"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
)

func TestNewReturnsStore(t *testing.T) {
    if New(nil) == nil {
        t.Fatal("New(nil) returned nil")
    }
}

func TestProvisionMemberRejectsEmptyInput(t *testing.T) {
    s := New(nil)
    if _, err := s.ProvisionMember(context.Background(), "", "sub"); err == nil {
        t.Fatalf("expected error for empty email")
    }
    if _, err := s.ProvisionMember(context.Background(), "email@example.com", ""); err == nil {
        t.Fatalf("expected error for empty cognito subject")
    }
    if _, err := s.ProvisionMember(context.Background(), "   ", "  "); err == nil {
        t.Fatalf("expected error for whitespace-only inputs")
    }
}

func TestProvisionRoleIsLeastPrivileged(t *testing.T) {
    if provisionRole != "ops_support" {
        t.Fatalf("provisionRole = %q, want \"ops_support\"", provisionRole)
    }
}

// Integration test – runs only when TEST_DATABASE_URL is set.
func TestOpsStoreIntegration(t *testing.T) {
    databaseURL := os.Getenv("TEST_DATABASE_URL")
    if databaseURL == "" {
        if os.Getenv("CI") != "" {
            t.Fatal("TEST_DATABASE_URL must be set in CI")
        }
        t.Skip("TEST_DATABASE_URL not set")
    }
    adminURL := os.Getenv("TEST_ADMIN_DATABASE_URL")
    if adminURL == "" {
        t.Skip("TEST_ADMIN_DATABASE_URL not set")
    }
    pool, err := pgxpool.New(context.Background(), databaseURL)
    if err != nil {
        t.Fatalf("connect to TEST_DATABASE_URL: %v", err)
    }
    t.Cleanup(pool.Close)

    adminPool, err := pgxpool.New(context.Background(), adminURL)
    if err != nil {
        t.Fatalf("connect to TEST_ADMIN_DATABASE_URL: %v", err)
    }
    t.Cleanup(adminPool.Close)

    store := New(pool)
    ctx := context.Background()
    suffix := time.Now().UnixNano()
    email := fmt.Sprintf("__ops_email_%d__", suffix)
    cognitoSub := fmt.Sprintf("sub-%d", suffix)

    // First provisioning – creates active member.
    m1, err := store.ProvisionMember(ctx, email, cognitoSub)
    if err != nil {
        t.Fatalf("ProvisionMember first error: %v", err)
    }
    if m1.ID == "" || m1.Role != "ops_support" || m1.Status != "active" || m1.CognitoSub != cognitoSub {
        t.Fatalf("unexpected member after first provision: %+v", m1)
    }
    // Idempotent – same sub returns same ID.
    m2, err := store.ProvisionMember(ctx, email, cognitoSub)
    if err != nil {
        t.Fatalf("ProvisionMember second error: %v", err)
    }
    if m2.ID != m1.ID {
        t.Fatalf("member ID changed on idempotent provision: %s vs %s", m1.ID, m2.ID)
    }
    // Conflict – different sub for same email.
    if _, err := store.ProvisionMember(ctx, email, "other-sub"); !errors.Is(err, ErrIdentityConflict) {
        t.Fatalf("expected ErrIdentityConflict, got %v", err)
    }

    // Suspend the member via admin pool.
    if _, err := adminPool.Exec(ctx, `UPDATE ops_members SET status='suspended' WHERE email=$1`, email); err != nil {
        t.Fatalf("suspend member error: %v", err)
    }
    // Provision again – should return suspended status, same role, not reactivate.
    m3, err := store.ProvisionMember(ctx, email, cognitoSub)
    if err != nil {
        t.Fatalf("ProvisionMember after suspend error: %v", err)
    }
    if m3.Status != "suspended" {
        t.Fatalf("expected suspended status after suspend, got %s", m3.Status)
    }
    if m3.Role != "ops_support" {
        t.Fatalf("role changed after suspend: %s", m3.Role)
    }

    // Session handling for active member – create new active member for session tests.
    email2 := fmt.Sprintf("__ops_email2_%d__", suffix)
    mActive, err := store.ProvisionMember(ctx, email2, cognitoSub+"-active")
    if err != nil {
        t.Fatalf("ProvisionMember for session test error: %v", err)
    }
    tokenHash := sha256.Sum256([]byte(fmt.Sprintf("ops-token-%d", suffix)))
    if err := store.CreateSession(ctx, tokenHash[:], mActive.ID, time.Now().Add(time.Hour), true); err != nil {
        t.Fatalf("CreateSession error: %v", err)
    }
    sess, ok, err := store.GetSession(ctx, tokenHash[:], 2*time.Hour)
    if err != nil {
        t.Fatalf("GetSession error: %v", err)
    }
    if !ok {
        t.Fatal("GetSession returned not ok for active session")
    }
    if sess.HardwareKey != true || sess.Email != email2 || sess.Role != "ops_support" || sess.MemberID != mActive.ID {
        t.Fatalf("unexpected session data: %+v", sess)
    }
    // Suspended member session should not be created.
    tokenHashSusp := sha256.Sum256([]byte(fmt.Sprintf("ops-token-suspend-%d", suffix)))
    if err := store.CreateSession(ctx, tokenHashSusp[:], m3.ID, time.Now().Add(time.Hour), false); err != nil {
        // ignore error, GetSession will be false.
    }
    if _, ok, _ = store.GetSession(ctx, tokenHashSusp[:], 2*time.Hour); ok {
        t.Fatal("expected GetSession to be false for suspended member session")
    }
    // End session and verify it's gone.
    if err := store.EndSession(ctx, tokenHash[:]); err != nil {
        t.Fatalf("EndSession error: %v", err)
    }
    if _, ok, err = store.GetSession(ctx, tokenHash[:], 2*time.Hour); err != nil || ok {
        t.Fatalf("expected session to be gone after EndSession, ok=%v err=%v", ok, err)
    }
    // Random hash returns false.
    var randomHash [32]byte
    if _, ok, err = store.GetSession(ctx, randomHash[:], time.Hour); err != nil || ok {
        t.Fatalf("expected GetSession to be false for unknown hash, ok=%v err=%v", ok, err)
    }
}
