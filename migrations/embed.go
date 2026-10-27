package migrations

import "embed"

// Files contains the ordered SQL migrations shipped with the application.
//
//go:embed *.sql
var Files embed.FS
