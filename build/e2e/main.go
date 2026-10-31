package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	token "github.com/example/lanyard/internal"
)

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: e2e <keygen|grant|proxy> [flags]")
	}
	switch os.Args[1] {
	case "keygen":
		keygen()
	case "pub":
		priv := loadKey()
		fmt.Println(base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
	case "grant":
		grant()
	case "proxy":
		proxyCall()
	default:
		fail("unknown mode %q", os.Args[1])
	}
}

func keygen() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fail("generate key: %v", err)
	}
	seed := base64.RawURLEncoding.EncodeToString(priv.Seed())
	if err := os.WriteFile("/tmp/e2e-agent.key", []byte(seed), 0o600); err != nil {
		fail("write key: %v", err)
	}
	fmt.Println(base64.RawURLEncoding.EncodeToString(pub))
}

func loadKey() ed25519.PrivateKey {
	raw, err := os.ReadFile("/tmp/e2e-agent.key")
	if err != nil {
		fail("read key: %v", err)
	}
	key, err := token.DecodeEd25519PrivateKey(strings.TrimSpace(string(raw)))
	if err != nil {
		fail("decode key: %v", err)
	}
	return key
}

func grant() {
	actor := os.Getenv("E2E_ACTOR")
	connector := os.Getenv("E2E_CONNECTOR")
	resource := os.Getenv("E2E_RESOURCE")
	if actor == "" || connector == "" || resource == "" {
		fail("E2E_ACTOR, E2E_CONNECTOR, E2E_RESOURCE are required")
	}
	body := map[string]any{
		"subject": "user:ops",
		"actor":   actor,
		"task_id": "task-e2e-1",
		"purpose": "production smoke test",
		"resources": []map[string]any{{
			"connector": connector,
			"action":    "read",
			"resource":  resource,
			"max_rows":  10,
		}},
		"ttl_seconds": 300,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		fail("marshal request: %v", err)
	}
	proof, err := token.NewDPoPRequestProof(loadKey(), http.MethodPost,
		"https://127.0.0.1:8080/grant", fmt.Sprintf("jti-grant-%d", time.Now().UnixNano()), time.Now())
	if err != nil {
		fail("build proof: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/grant", bytes.NewReader(payload))
	if err != nil {
		fail("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", proof)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("grant request: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	fmt.Printf("grant_status=%d\n", resp.StatusCode)
	fmt.Printf("grant_body=%.400s\n", string(respBody))
	if resp.StatusCode != http.StatusOK {
		os.Exit(2)
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil || parsed.AccessToken == "" {
		fail("parse token: %v", err)
	}
	if err := os.WriteFile("/tmp/e2e-token.jwt", []byte(parsed.AccessToken), 0o600); err != nil {
		fail("write token: %v", err)
	}
	fmt.Println("token_saved=/tmp/e2e-token.jwt")
}

func proxyCall() {
	raw, err := os.ReadFile("/tmp/e2e-token.jwt")
	if err != nil {
		fail("read token: %v", err)
	}
	jwt := strings.TrimSpace(string(raw))
	proof, err := token.NewDPoPProof(loadKey(), jwt, http.MethodGet,
		"http://127.0.0.1:8081/proxy", fmt.Sprintf("jti-proxy-%d", time.Now().UnixNano()), time.Now())
	if err != nil {
		fail("build proof: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8081/proxy", nil)
	if err != nil {
		fail("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("DPoP", proof)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("proxy request: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	fmt.Printf("proxy_status=%d\n", resp.StatusCode)
	fmt.Printf("proxy_body=%.300s\n", string(respBody))
}
