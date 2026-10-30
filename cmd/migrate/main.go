package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/example/lanyard/internal/awssecrets"
	"github.com/example/lanyard/internal/db"
	"github.com/example/lanyard/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		secretARN := os.Getenv("DATABASE_SECRET_ARN")
		if secretARN == "" {
			log.Fatal("DATABASE_SECRET_ARN is required")
		}
		secrets, err := awssecrets.NewFromEnv(context.Background(), os.Getenv("AWS_REGION"))
		if err != nil {
			log.Fatalf("initialize Secrets Manager: %v", err)
		}
		databaseURL, err = secrets.PostgresURL(context.Background(), secretARN)
		if err != nil {
			log.Fatalf("load PostgreSQL credentials: %v", err)
		}
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		log.Fatalf("connect to database: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("ping database: %v", err)
	}
	if err := db.ApplyMigrations(ctx, pool, migrations.Files); err != nil {
		log.Fatalf("run migrations: %v", err)
	}
	fmt.Println("database migrations are up to date")
}
