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
		Conn:          conn,
		TokenDuration: time.Duration(cfg.TokenDuration) * time.Second,
	}

	tokenManager := token.NewManager(tokenConfig)

	// Initialize handlers & middlweware
	authHandler := handlers.NewHandler(fingerprintManager, tokenManager, conn)
	middleware := middleware.NewMiddleware(fingerprintManager, tokenManager)

	// Setup routes with middleware
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/register", authHandler.Register)
	mux.HandleFunc("POST /api/auth/login", authHandler.Login)
	mux.HandleFunc("GET /api/auth/verify", middleware.AuthMiddleware(authHandler.Verify))
	mux.HandleFunc("GET /api/test", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World!"))
	})

	// Setup CORS middleware
	handler := middleware.CORSMiddleware(cfg.AllowedOrigins)(mux)

	// Start server
	serverAddr := cfg.ServerAddress
	log.Printf("Starting server on %s", serverAddr)
	if err := http.ListenAndServe(serverAddr, handler); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
