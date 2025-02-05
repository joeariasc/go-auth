package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/joeariasc/go-auth/internal/auth/fingerprint"
	"github.com/joeariasc/go-auth/internal/auth/token"
	"github.com/joeariasc/go-auth/internal/config"
	"github.com/joeariasc/go-auth/internal/db"
	"github.com/joeariasc/go-auth/internal/handlers"
	"github.com/joeariasc/go-auth/internal/middleware"
)

func main() {
	configFile := "./.env"

	cfg, err := config.LoadEnvFile(configFile)

	if err != nil {
		log.Fatal(err)
	}

	stringConnection := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.DbUser, cfg.DbPassword, cfg.DbHost, cfg.DbPort, cfg.DbName)

	conn, err := db.NewConnection(stringConnection)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	fingerprintManager := fingerprint.NewManager()

	tokenConfig := token.ManagerConfig{
		SecretKey:     []byte(cfg.SecretKey),
		TokenDuration: time.Duration(cfg.TokenDuration) * time.Second,
	}

	tokenManager := token.NewManager(tokenConfig)

	// Initialize handlers
	authHandler := handlers.NewHandler(fingerprintManager, tokenManager, conn)

	// Setup routes with middleware
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/register", authHandler.Register)
	mux.HandleFunc("POST /api/auth/login", authHandler.Login)
	mux.HandleFunc("/api/auth/verify", authHandler.Verify)
	mux.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World!"))
	})

	// Setup CORS middleware
	handler := middleware.NewCORSMiddleware(cfg.AllowedOrigins)(mux)

	// Start server
	serverAddr := cfg.ServerAddress
	log.Printf("Starting server on %s", serverAddr)
	if err := http.ListenAndServe(serverAddr, handler); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
