// Temporary deployment helper for bringing up the Lanyard RDS instance.
// Not part of the product; deleted after bootstrap.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: bootstrap <createdb|alterrole|list|tables>")
		os.Exit(2)
	}
	ctx := context.Background()
	url := os.Getenv("MASTER_URL")
	if url == "" {
		fmt.Fprintln(os.Stderr, "MASTER_URL required")
		os.Exit(2)
	}
	conn, err := pgx.Connect(ctx, url)
	must(err)
	defer conn.Close(ctx)

	switch os.Args[1] {
	case "createdb":
		var exists bool
		must(conn.QueryRow(ctx, "select exists(select 1 from pg_database where datname='lanyard')").Scan(&exists))
		if exists {
			fmt.Println("database lanyard: exists")
			return
		}
		_, err = conn.Exec(ctx, "CREATE DATABASE lanyard")
		must(err)
		fmt.Println("database lanyard: created")

	case "alterrole":
		pw := os.Getenv("APP_PASSWORD")
		if pw == "" {
			fmt.Fprintln(os.Stderr, "APP_PASSWORD required")
			os.Exit(2)
		}
		_, err = conn.Exec(ctx, "ALTER ROLE lanyard_app LOGIN PASSWORD "+quote(pw))
		must(err)
		fmt.Println("role lanyard_app: password set")

	case "list":
		rows, err := conn.Query(ctx, "select datname from pg_database where not datistemplate order by 1")
		must(err)
		for rows.Next() {
			var n string
			must(rows.Scan(&n))
			fmt.Println(n)
		}
		must(rows.Err())

	case "tables":
		rows, err := conn.Query(ctx, "select table_name from information_schema.tables where table_schema='public' order by 1")
		must(err)
		for rows.Next() {
			var n string
			must(rows.Scan(&n))
			fmt.Println(n)
		}
		must(rows.Err())

	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}
