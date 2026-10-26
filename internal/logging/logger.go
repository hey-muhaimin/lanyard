package logging

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

// Logger writes JSON logs with a request-scoped identity when available.
type Logger struct {
	base      *log.Logger
	requestID string
	tenantID  string
}

func NewJSONLogger() *Logger {
	return &Logger{base: log.New(os.Stdout, "", 0)}
}

func (l *Logger) Info(msg string, fields map[string]any) {
	l.emit("info", msg, fields)
}

func (l *Logger) Warn(msg string, fields map[string]any) {
	l.emit("warn", msg, fields)
}

func (l *Logger) Error(msg string, fields map[string]any) {
	l.emit("error", msg, fields)
}

func (l *Logger) With(requestID, tenantID string) *Logger {
	return &Logger{base: l.base, requestID: requestID, tenantID: tenantID}
}

func (l *Logger) emit(level string, msg string, fields map[string]any) {
	payload := map[string]any{
		"level": level,
		"msg":   msg,
	}
	if l.requestID != "" {
		payload["request_id"] = l.requestID
	}
	if l.tenantID != "" {
		payload["tenant_id"] = l.tenantID
	}
	for k, v := range fields {
		payload[k] = v
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		encoded = []byte(fmt.Sprintf("{\"level\":%q,\"msg\":%q,\"error\":%q}", level, msg, err.Error()))
	}
	l.base.Println(string(encoded))
}

// Redact replaces known secret values before writing to logs or error messages.
func Redact(input string, secrets ...string) string {
	output := input
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		output = strings.ReplaceAll(output, secret, "[REDACTED]")
	}
	return output
}
